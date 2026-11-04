// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package ledgerq

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)
import "github.com/glowfly/pail/services/internal/telemetry"

func obsDB(t *testing.T) (*DB, string) {
	t.Helper()
	dir := t.TempDir()
	d, e := Open(filepath.Join(dir, "ledger.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { d.Close() })
	return d, dir
}
func obsWrite(t *testing.T, dir, name, body string) {
	t.Helper()
	if e := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); e != nil {
		t.Fatal(e)
	}
}
func obsIngest(t *testing.T, d *DB, dir string) {
	t.Helper()
	if _, e := d.IngestTelemetry(dir, time.Now()); e != nil {
		t.Fatal(e)
	}
}

const obsBurst = `{"v":1,"kind":"burst","ms":1100,"seq":1,"event":"BLOCK","reason_value":0,"robot":"aa","token":"bb","sig":"bad","dup":false,"raw":"00"}`
const obsPermit = `{"v":1,"kind":"permit","ms":1200,"robot":"aa","sig":"ok","mode":"enforce","tick_ms":500,"permit_age_ms":30,"deadman_window_ms":100,"permit_seq":8,"mirror_seq":2,"raw":"00"}`

func TestMOBS_LegacyDifferential(t *testing.T) {
	d, dir := obsDB(t)
	// Deliberately non-monotonic wall times, duplicate and bad signature, bad
	// line and a late-discovered earlier day. Compare the actual legacy reader.
	body := `{"v":1,"kind":"tick","ms":1000}` + "\n" + obsBurst + "\n" + obsPermit + "\n" + strings.ReplaceAll(obsBurst, `"dup":false`, `"dup":true`) + "\n" + `{"v":1,"kind":"tick","ms":9000}` + "\nBAD\n" + strings.ReplaceAll(strings.ReplaceAll(obsBurst, `"reason_value":0`, `"reason_value":17`), `"event":"BLOCK"`, `"event":"ESTOP"`) + "\n"
	obsWrite(t, dir, "decisions-02.jsonl", body)
	obsIngest(t, d, dir)
	obsWrite(t, dir, "decisions-01.jsonl", strings.ReplaceAll(obsPermit, `"robot":"aa"`, `"robot":"cc"`)+"\n"+strings.ReplaceAll(obsBurst, `"ms":1100`, `"ms":1400`)+"\n")
	obsIngest(t, d, dir)
	recs, bad, e := telemetry.LoadDir(dir)
	if e != nil || bad["decisions-02.jsonl"] != 1 {
		t.Fatal(e, bad)
	}
	zero := uint16(0)
	filters := []telemetry.Filter{{FromMs: 1, ToMs: 10000, Limit: 200}, {FromMs: 1000, ToMs: 1300, Limit: 1}, {FromMs: 1, ToMs: 10000, Reason: &zero, Robot: "aa", Limit: 200}, {FromMs: 1, ToMs: 10000, Event: "PERMIT", Limit: 200}, {FromMs: 20000, ToMs: 30000, Limit: 200}, {FromMs: 0, Limit: 200}}
	for _, f := range filters {
		got, e := d.ObservationDecisions(context.Background(), f, time.Second)
		want := telemetry.Query(recs, f, time.Second)
		if e != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("filter=%+v error=%v\ngot=%+v\nwant=%+v", f, e, got, want)
		}
		var ticks []telemetry.Record
		for _, r := range recs {
			if r.Kind == telemetry.KindTick {
				ticks = append(ticks, r)
			}
		}
		c, e := d.ObservationLiveness(context.Background(), f, time.Second)
		if e != nil || !reflect.DeepEqual(c, telemetry.CoverageOf(ticks, f.FromMs, f.ToMs, time.Second)) {
			t.Fatal(c, e)
		}
	}
	now := time.UnixMilli(1500)
	got, e := d.ObservationPermits(context.Background(), now)
	if e != nil || !reflect.DeepEqual(got, telemetry.PermitStates(recs, now)) {
		t.Fatal(got, e)
	}
	// Prove queries do not open the raw input: replace it with a directory.
	os.Remove(filepath.Join(dir, "decisions-02.jsonl"))
	os.Mkdir(filepath.Join(dir, "decisions-02.jsonl"), 0700)
	if _, e = d.ObservationDecisions(context.Background(), filters[0], time.Second); e != nil {
		t.Fatal(e)
	}
	if _, e = d.ObservationPermits(context.Background(), now); e != nil {
		t.Fatal(e)
	}
}
func TestMOBS_PartialRestartAndAtomicOffset(t *testing.T) {
	d, dir := obsDB(t)
	path := filepath.Join(dir, "decisions-01.jsonl")
	obsWrite(t, dir, filepath.Base(path), obsBurst+"\n"+obsPermit[:50])
	obsIngest(t, d, dir)
	var off, n int64
	d.sql.QueryRow(`SELECT durable_offset FROM observation_files`).Scan(&off)
	if off != int64(len(obsBurst)+1) {
		t.Fatal(off)
	}
	obsIngest(t, d, dir)
	d.sql.QueryRow(`SELECT COUNT(*) FROM observation_records`).Scan(&n)
	if n != 1 {
		t.Fatal(n)
	}
	d.Close()
	var e error
	d, e = Open(filepath.Join(dir, "ledger.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	if _, e = d.ObservationPermits(context.Background(), time.Now()); e == nil {
		t.Fatal("restart before catch-up served READY")
	}
	f, e := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	f.WriteString(obsPermit[50:] + "\n")
	f.Close()
	obsIngest(t, d, dir)
	got, e := d.ObservationPermits(context.Background(), time.Now())
	if e != nil || len(got) != 1 || got[0].State != telemetry.PermitUnknown {
		t.Fatal(got, e)
	}
	d.sql.Exec(`CREATE TRIGGER fail_insert BEFORE INSERT ON observation_records BEGIN SELECT RAISE(ABORT,'injected disk failure'); END`)
	f, _ = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	f.WriteString(obsBurst + "\n")
	f.Close()
	var before int64
	d.sql.QueryRow(`SELECT durable_offset FROM observation_files`).Scan(&before)
	if _, e = d.IngestTelemetry(dir, time.Now()); e == nil {
		t.Fatal("injected failure accepted")
	}
	d.sql.QueryRow(`SELECT durable_offset FROM observation_files`).Scan(&off)
	if off != before {
		t.Fatal("offset committed without row")
	}
	if _, e = d.ObservationPermits(context.Background(), time.Now()); e == nil {
		t.Fatal("failed index served READY")
	}
	d.sql.Exec(`DROP TRIGGER fail_insert`)
	obsIngest(t, d, dir)
	d.sql.QueryRow(`SELECT COUNT(*) FROM observation_records`).Scan(&n)
	if n != 3 {
		t.Fatal(n)
	}
}
func TestMOBS_BoundsMissingSchemaAndCancel(t *testing.T) {
	d, dir := obsDB(t)
	obsWrite(t, dir, "decisions-01.jsonl", strings.Repeat("x", 2<<20)+"\n"+obsBurst+"\n")
	s, e := d.IngestTelemetry(dir, time.Now())
	if e != nil || s.BadLines != 1 {
		t.Fatal(s, e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = d.ObservationDecisions(ctx, telemetry.Filter{}, time.Second); e == nil {
		t.Fatal("ignored canceled context")
	}
	d.sql.Exec(`DROP TABLE observation_latest`)
	if _, e = d.ObservationDecisions(context.Background(), telemetry.Filter{}, time.Second); e == nil {
		t.Fatal("missing schema looked healthy")
	}
	var nilDB *DB
	if _, e = nilDB.ObservationPermits(context.Background(), time.Now()); e == nil {
		t.Fatal("nil DB healthy")
	}
}
func TestMOBS_LargeFourReaders(t *testing.T) {
	if os.Getenv("MOBS_LARGE") != "1" {
		t.Skip("explicit large fixture job required")
	}
	for _, target := range []int64{220000000, 2000000000} {
		t.Run(fmt.Sprint(target), func(t *testing.T) {
			d, dir := obsDB(t)
			p := filepath.Join(dir, "decisions-20260929.jsonl")
			f, e := os.Create(p)
			if e != nil {
				t.Fatal(e)
			}
			// Real allocated JSONL bytes, not sparse files. Padding stresses the raw
			// reader separately from the semantic row density (4096 bytes/record).
			shapes := []string{obsBurst, obsPermit, `{"v":1,"kind":"tick","ms":1100}`, strings.ReplaceAll(obsBurst, `"robot":"aa"`, `"robot":"cc"`)}
			chunks := make([][]byte, len(shapes))
			for i, s := range shapes {
				chunks[i] = []byte(s + strings.Repeat(" ", 4095-len(s)) + "\n")
			}
			var written, lines int64
			for written < target {
				b := []byte(strings.Replace(string(chunks[lines%4]), fmt.Sprintf("\"ms\":%d", []int{1100, 1200, 1100, 1100}[lines%4]), fmt.Sprintf("\"ms\":%d", 1000000000000+lines), 1))
				n, e := f.Write(b)
				if e != nil {
					t.Fatal(e)
				}
				written += int64(n)
				lines++
			}
			f.Close()
			start := time.Now()
			obsIngest(t, d, dir)
			buildMs := time.Since(start).Milliseconds()
			var indexed int64
			d.sql.QueryRow(`SELECT COUNT(*) FROM observation_records`).Scan(&indexed)
			if indexed != lines {
				t.Fatalf("indexed=%d raw=%d", indexed, lines)
			}
			// Remove raw accessibility only after successful ingest. Any fallback open
			// is now an error rather than a silently successful full scan.
			if e = os.Rename(p, p+".hidden"); e != nil {
				t.Fatal(e)
			}
			os.Mkdir(p, 0700)
			lat := make([][]float64, 3)
			var mu sync.Mutex
			var wg sync.WaitGroup
			start = time.Now()
			for reader := 0; reader < 4; reader++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := 0; i < 12; i++ {
						for kind := 0; kind < 3; kind++ {
							begin := time.Now()
							var e error
							switch kind {
							case 0:
								var r telemetry.QueryResult
								r, e = d.ObservationDecisions(context.Background(), telemetry.Filter{FromMs: uint64(1000000000000 + lines - 400), ToMs: uint64(1000000000000 + lines), Limit: 200}, time.Second)
								if e == nil && (len(r.Rows) != 200 || r.Matched != 200) {
									e = fmt.Errorf("wrong page: %d/%d", len(r.Rows), r.Matched)
								}
							case 1:
								_, e = d.ObservationLiveness(context.Background(), telemetry.Filter{FromMs: uint64(1000000000000 + lines - 400), ToMs: uint64(1000000000000 + lines)}, time.Second)
							case 2:
								var r []telemetry.PermitVerdict
								r, e = d.ObservationPermits(context.Background(), time.UnixMilli(1000000000000+lines+100))
								if e == nil && (len(r) != 1 || r[0].State != telemetry.PermitAlive) {
									e = fmt.Errorf("wrong permit: %+v", r)
								}
							}
							ms := float64(time.Since(begin).Microseconds()) / 1000
							mu.Lock()
							lat[kind] = append(lat[kind], ms)
							mu.Unlock()
							if e != nil {
								t.Error(e)
								return
							}
						}
					}
				}()
			}
			wg.Wait()
			querySeconds := time.Since(start).Seconds()
			measure := map[string]any{"target_bytes": target, "allocated_raw_bytes": written, "records": lines, "indexed": indexed, "raw_profile": "mixed burst/permit/tick, 4096-byte whitespace-padded valid JSONL", "readers": 4, "requests": 144, "query_seconds": querySeconds, "cold_build_ms": buildMs, "request_raw_fullscans": 0}
			for k, name := range []string{"decisions", "liveness", "permits"} {
				sort.Float64s(lat[k])
				if len(lat[k]) != 48 {
					t.Fatalf("%s only %d requests", name, len(lat[k]))
				}
				p95 := lat[k][45]
				measure[name] = map[string]any{"p95_ms": p95, "max_ms": lat[k][47]}
				threshold := 1000.0
				if k == 2 {
					threshold = 250
				}
				if p95 > threshold {
					t.Errorf("%s p95 %.2f > %.2f", name, p95, threshold)
				}
			}
			var usage syscall.Rusage
			syscall.Getrusage(syscall.RUSAGE_SELF, &usage)
			measure["rusage"] = usage
			for _, file := range []string{"memory.peak", "memory.current", "cpu.stat", "memory.max", "cpu.max"} {
				if b, e := os.ReadFile("/sys/fs/cgroup/" + file); e == nil {
					measure[file] = string(b)
				}
			}
			var bytes int64
			for _, suffix := range []string{"", "-wal", "-shm"} {
				if s, e := os.Stat(filepath.Join(dir, "ledger.sqlite") + suffix); e == nil {
					bytes += s.Size()
				}
			}
			measure["db_wal_bytes"] = bytes
			b, _ := json.MarshalIndent(measure, "", "  ")
			t.Log(string(b))
			if dest := os.Getenv("MOBS_EVIDENCE"); dest != "" {
				if e = os.WriteFile(filepath.Join(dest, fmt.Sprintf("performance-%d.json", target)), b, 0600); e != nil {
					t.Fatal(e)
				}
			}
		})
	}
}

func TestMOBS_RebuildPreservesOldSchemaAndFailedBuild(t *testing.T) {
	d, dir := obsDB(t)
	obsWrite(t, dir, "decisions-01.jsonl", obsBurst+"\n")
	obsIngest(t, d, dir)
	d.sql.Exec(`UPDATE meta SET value='3' WHERE key='schema'`)
	d.Close()
	p := filepath.Join(dir, "ledger.sqlite")
	old, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Open(p); e == nil {
		t.Fatal("old schema should require rebuild")
	}
	now, _ := os.ReadFile(p)
	if sha256.Sum256(old) != sha256.Sum256(now) {
		t.Fatal("Open changed old schema bytes")
	}
	fresh, _, _, e := Rebuild(p, filepath.Join(dir, "absent-blackbox"), dir, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	defer fresh.Close()
	backups, _ := filepath.Glob(p + ".previous-*")
	mainBackups := []string{}
	for _, p := range backups {
		if !strings.HasSuffix(p, "-wal") && !strings.HasSuffix(p, "-shm") && !strings.HasSuffix(p, "-journal") {
			mainBackups = append(mainBackups, p)
		}
	}
	backups = mainBackups
	if len(backups) != 1 {
		t.Fatal(backups)
	}
	b, _ := os.ReadFile(backups[0])
	if sha256.Sum256(b) != sha256.Sum256(old) {
		t.Fatal("rollback DB not preserved")
	}
	fresh.Close()
	before, _ := os.ReadFile(p)
	// A failed build cannot replace or erase the usable old index.
	if _, _, _, e = Rebuild(p, filepath.Join(dir, "absent-blackbox"), filepath.Join(dir, "no-telemetry"), time.Now()); e == nil {
		t.Fatal("missing input should fail")
	}
	after, _ := os.ReadFile(p)
	if sha256.Sum256(before) != sha256.Sum256(after) {
		t.Fatal("failed build replaced index")
	}
	if _, _, _, e = Rebuild(p, filepath.Join(dir, "absent-blackbox"), dir, time.Now()); e == nil {
		t.Fatal("unreviewed .building was overwritten")
	}
	if e = publishIndex(p, filepath.Join(dir, "decisions-01.jsonl")); e == nil {
		t.Fatal("publish accepted raw file")
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "decisions-01.jsonl"))
	if string(raw) != obsBurst+"\n" {
		t.Fatal("raw changed")
	}
}

func TestMOBS_PageBounds(t *testing.T) {
	d, dir := obsDB(t)
	obsWrite(t, dir, "decisions-01.jsonl", strings.Repeat(obsBurst+"\n", 1100))
	obsIngest(t, d, dir)
	for _, tc := range []struct{ limit, want int }{{0, 200}, {200, 200}, {1000, 1000}, {5000, 1000}} {
		r, e := d.ObservationDecisions(context.Background(), telemetry.Filter{Limit: tc.limit}, time.Second)
		if e != nil || len(r.Rows) != tc.want || r.Matched != 1100 || !r.Truncated {
			t.Fatal(tc, r.Matched, len(r.Rows), e)
		}
	}
	obsWrite(t, dir, "decisions-02.jsonl", strings.Repeat(strings.Replace(obsBurst, `"raw":"00"`, `"raw":"`+strings.Repeat("a", 60000)+`"`, 1)+"\n", 30))
	obsIngest(t, d, dir)
	r, e := d.ObservationDecisions(context.Background(), telemetry.Filter{Limit: 1000}, time.Second)
	b, _ := json.Marshal(r)
	if e != nil || !r.Truncated || len(b) > 1<<20 || len(r.Rows) >= 30 {
		t.Fatal("byte bound", len(b), len(r.Rows), e)
	}
}

func TestMOBS_ReceiptEdgesOutOfOrder(t *testing.T) {
	d, dir := obsDB(t)
	path := filepath.Join(dir, "decisions-01.jsonl")
	for _, ms := range []int{1000, 9000, 4000, 4000, 7000, 0, 10000} {
		f, e := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if e != nil {
			t.Fatal(e)
		}
		fmt.Fprintf(f, "{\"v\":1,\"kind\":\"tick\",\"ms\":%d}\n", ms)
		f.Close()
		obsIngest(t, d, dir)
		recs, _, e := telemetry.LoadDir(dir)
		if e != nil {
			t.Fatal(e)
		}
		for _, window := range [][2]uint64{{0, 11000}, {2000, 8000}, {0, 0}, {15000, 20000}, {4000, 4000}} {
			for _, gap := range []time.Duration{time.Second, 3 * time.Second, 30 * time.Second} {
				got, e := d.ObservationLiveness(context.Background(), telemetry.Filter{FromMs: window[0], ToMs: window[1]}, gap)
				want := telemetry.CoverageOf(recs, window[0], window[1], gap)
				if e != nil || !reflect.DeepEqual(got, want) {
					t.Fatalf("%v %v after %d got %+v want %+v err %v", window, gap, ms, got, want, e)
				}
			}
		}
	}
}

func TestMOBS_MissingTableOnRestartIsNotRecreatedAsEmpty(t *testing.T) {
	d, dir := obsDB(t)
	obsWrite(t, dir, "decisions-01.jsonl", obsBurst+"\n")
	obsIngest(t, d, dir)
	if _, e := d.sql.Exec(`DROP TABLE observation_records`); e != nil {
		t.Fatal(e)
	}
	d.Close()
	p := filepath.Join(dir, "ledger.sqlite")
	before, _ := os.ReadFile(p)
	if _, e := Open(p); e == nil {
		t.Fatal("lost records silently recreated; durable offsets would skip all raw rows")
	}
	after, _ := os.ReadFile(p)
	if sha256.Sum256(before) != sha256.Sum256(after) {
		t.Fatal("refusal mutated damaged DB")
	}
}

func TestMOBS_ExactBucketCountDifferential(t *testing.T) {
	d, dir := obsDB(t)
	var body strings.Builder
	for i := 0; i < 2300; i++ {
		ms := uint64((i * 7919) % 17000)
		b := false
		r := telemetry.Record{V: 1, Kind: telemetry.KindBurst, Ms: ms, Robot: []string{"aa", "bb"}[i%2], Event: []string{"BLOCK", "ESTOP", "PERMIT"}[i%3], ReasonValue: uint16(i % 7), Sig: telemetry.SigBad, Dup: &b, Raw: "00"}
		line, e := json.Marshal(r)
		if e != nil {
			t.Fatal(e)
		}
		body.Write(line)
		body.WriteByte('\n')
	}
	obsWrite(t, dir, "decisions-01.jsonl", body.String())
	obsIngest(t, d, dir)
	obsIngest(t, d, dir)
	recs, _, e := telemetry.LoadDir(dir)
	if e != nil {
		t.Fatal(e)
	}
	reason := uint16(0)
	for _, window := range [][2]uint64{{0, 0}, {999, 1000}, {1000, 1999}, {1, 16999}, {1001, 1998}, {1500, 2600}, {9000, 8500}, {16001, 19000}} {
		for _, filter := range []telemetry.Filter{{}, {Robot: "aa"}, {Robot: "bb", Event: "ESTOP"}, {Reason: &reason}, {Event: "NO_MATCH"}} {
			filter.FromMs = window[0]
			filter.ToMs = window[1]
			filter.Limit = 200
			got, e := d.ObservationDecisions(context.Background(), filter, time.Second)
			want := telemetry.Query(recs, filter, time.Second)
			if e != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("filter %+v err=%v got %d want %d", filter, e, got.Matched, want.Matched)
			}
		}
	}
}
