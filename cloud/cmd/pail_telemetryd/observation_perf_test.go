// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"encoding/json"
	"fmt"
	"github.com/glowfly/pail/services/internal/ledgerq"
	"github.com/glowfly/pail/services/internal/telemetry"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestMOBS_HTTPFourReadersLarge(t *testing.T) {
	if os.Getenv("MOBS_LARGE") != "1" {
		t.Skip("explicit large fixture job required")
	}
	old := ledgerIndex
	defer func() { ledgerIndex = old }()
	for _, target := range []int64{220000000, 2000000000} {
		t.Run(fmt.Sprint(target), func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "decisions-01.jsonl")
			f, e := os.Create(p)
			if e != nil {
				t.Fatal(e)
			}
			shape := `{"v":1,"kind":"burst","ms":1000000000000,"seq":1,"event":"BLOCK","reason_value":0,"robot":"aa","token":"bb","sig":"bad","dup":false,"raw":"` + strings.Repeat("00", 120) + `"}`
			var bytes, lines int64
			begin := time.Now()
			for bytes < target {
				r := strings.Replace(shape, "1000000000000", fmt.Sprint(1000000000000+lines), 1)
				r += "\n"
				n, e := io.WriteString(f, r)
				if e != nil {
					t.Fatal(e)
				}
				bytes += int64(n)
				lines++
			}
			permit := fmt.Sprintf(`{"v":1,"kind":"permit","ms":%d,"robot":"aa","sig":"ok","mode":"enforce","tick_ms":500,"permit_age_ms":30,"deadman_window_ms":100,"permit_seq":8,"mirror_seq":2,"raw":"00"}`, time.Now().UnixMilli())
			io.WriteString(f, permit+"\n")
			f.Close()
			fixtureSeconds := time.Since(begin).Seconds()
			d, e := ledgerq.Open(filepath.Join(dir, "ledger.sqlite"))
			if e != nil {
				t.Fatal(e)
			}
			defer d.Close()
			ledgerIndex = d
			begin = time.Now()
			st, e := d.IngestTelemetry(dir, time.Now())
			if e != nil || st.Bursts != lines {
				t.Fatal(st, e)
			}
			coldMs := time.Since(begin).Milliseconds()
			// Requests cannot reopen raw data: the source path is now a directory.
			if e = os.Rename(p, p+".hidden"); e != nil {
				t.Fatal(e)
			}
			os.Mkdir(p, 0700)
			server := httptest.NewServer(newMux("", dir, time.Second))
			defer server.Close()
			paths := []string{"decisions", "liveness", "permits"}
			var mu sync.Mutex
			var wg sync.WaitGroup
			lat := make([][]float64, 3)
			query := fmt.Sprintf("?from_ms=%d&to_ms=%d&limit=200", 1000000000000, 1000000000000+lines)
			cpuBefore, _ := os.ReadFile("/sys/fs/cgroup/cpu.stat")
			var ruBefore syscall.Rusage
			syscall.Getrusage(syscall.RUSAGE_SELF, &ruBefore)
			begin = time.Now()
			for reader := 0; reader < 4; reader++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					client := &http.Client{Timeout: 3 * time.Second}
					defer client.CloseIdleConnections()
					for i := 0; i < 25; i++ {
						for k, path := range paths {
							start := time.Now()
							res, e := client.Get(server.URL + "/v1/telemetry/" + path + query)
							if e != nil {
								t.Error(e)
								return
							}
							b, e := io.ReadAll(io.LimitReader(res.Body, 1<<20+1))
							res.Body.Close()
							elapsed := float64(time.Since(start).Microseconds()) / 1000
							if e != nil || res.StatusCode != 200 || len(b) > 1<<20 {
								t.Errorf("%s status=%d err=%v bytes=%d", path, res.StatusCode, e, len(b))
								return
							}
							switch k {
							case 0:
								var v telemetry.QueryResult
								if e = json.Unmarshal(b, &v); e != nil || len(v.Rows) != 200 || v.Matched != int(lines) || !v.Truncated {
									t.Errorf("bad decisions: %v %d/%d", e, len(v.Rows), v.Matched)
									return
								}
							case 1:
								var v telemetry.Coverage
								if e = json.Unmarshal(b, &v); e != nil || len(v.Gaps) != 1 || v.ListenedRatio != 0 {
									t.Errorf("bad liveness %v", e)
									return
								}
							case 2:
								var v []telemetry.PermitVerdict
								if e = json.Unmarshal(b, &v); e != nil || len(v) != 1 {
									t.Errorf("bad permits %v", e)
									return
								}
							}
							mu.Lock()
							lat[k] = append(lat[k], elapsed)
							mu.Unlock()
						}
					}
				}()
			}
			wg.Wait()
			seconds := time.Since(begin).Seconds()
			out := map[string]any{"raw_bytes": bytes + int64(len(permit)+1), "burst_records": lines, "readers": 4, "requests": 300, "http": "real loopback HTTP using production newMux", "fixture_profile": "dense unpadded bursts, 240-character synthetic packet hex, plus one permit; entire historical fixture window, newest 200-row response", "fixture_generation_seconds": fixtureSeconds, "cold_rebuild_ms": coldMs, "query_seconds": seconds, "request_raw_fullscans": 0, "cpu_before": string(cpuBefore)}
			for k, path := range paths {
				sort.Float64s(lat[k])
				if len(lat[k]) != 100 {
					t.Fatalf("%s missing requests %d", path, len(lat[k]))
				}
				p95 := lat[k][94]
				out[path] = map[string]any{"p95_ms": p95, "max_ms": lat[k][99]}
				max := 1000.0
				if k == 2 {
					max = 250
				}
				if p95 > max {
					t.Errorf("%s p95 %f > %f", path, p95, max)
				}
			}
			var ru syscall.Rusage
			syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
			out["rusage_before"] = ruBefore
			out["rusage_after"] = ru
			for _, name := range []string{"memory.peak", "memory.current", "cpu.stat", "memory.max", "cpu.max"} {
				if b, e := os.ReadFile("/sys/fs/cgroup/" + name); e == nil {
					out[name] = string(b)
				}
			}
			var disk int64
			for _, suffix := range []string{"", "-wal", "-shm"} {
				if s, e := os.Stat(d.Path() + suffix); e == nil {
					disk += s.Size()
				}
			}
			out["db_wal_bytes"] = disk
			b, _ := json.MarshalIndent(out, "", "  ")
			t.Log(string(b))
			if dest := os.Getenv("MOBS_EVIDENCE"); dest != "" {
				if e = os.WriteFile(filepath.Join(dest, fmt.Sprintf("http-performance-%d.json", target)), b, 0600); e != nil {
					t.Fatal(e)
				}
			}
		})
	}
}
