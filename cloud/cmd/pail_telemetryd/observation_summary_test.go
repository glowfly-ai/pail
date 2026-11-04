// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/glowfly/pail/services/internal/ledgerq"
	"github.com/glowfly/pail/services/internal/observability"
)

const summaryRun = "8be30882-0700-4297-89d4-2ef81fa19a40"
const summaryDeployment = "5e8b24a0-2319-4a53-b5cf-a03afc977301"

func summaryConfig(binding string) string {
	robot := func(n string) string {
		return `{"provider_id":"r` + n + `","kind":"normalized_jsonl","expected_deployment_id":"` + summaryDeployment + `","expected_robot_id":"robot-` + n + `","expected_identity":"robot-` + n + `","path_ref":"/observations/r` + n + `/observation.jsonl","endpoint_ref":"","allowed_event_kinds":["motion","pose","gate","permit","liveness"],"expected_owner":"` + summaryRun + `","expected_run_id":"` + summaryRun + `","expected_stream_id":"8be30882-0700-4297-89d4-2ef81fa19a4` + n + `","trust_basis":"local_self_report","role":"primary"` + binding + `}`
	}
	return `{"schema_version":1,"source_map":{"schema_version":1,"source_id":"c68d3bdd-62b0-4721-9aec-9ea0d4ab0301","deployment_id":"` + summaryDeployment + `","providers":[` + robot("1") + `,` + robot("2") + `,
 {"provider_id":"ledger","kind":"collector_ledger","allowed_event_kinds":["plan","ledger"],"trust_basis":"collector_verified","role":"primary"}]}}`
}

// thisClock names the monotonic clock of this process the way a producer on
// the same kernel does, and reads it.
func thisClock(t *testing.T) (string, func() string) {
	t.Helper()
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		t.Fatal(e)
	}
	offsets, e := os.ReadFile("/proc/self/timens_offsets")
	if e != nil {
		t.Fatal(e)
	}
	offset := ""
	for _, line := range strings.Split(string(offsets), "\n") {
		if f := strings.Fields(line); len(f) == 3 && f[0] == "monotonic" {
			s, _ := strconv.ParseInt(f[1], 10, 64)
			n, _ := strconv.ParseInt(f[2], 10, 64)
			offset = strconv.FormatInt(s*1000000000+n, 10)
		}
	}
	if offset == "" {
		t.Fatal("no monotonic offset")
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(string(boot)) + ":monotonic-offset-ns=" + offset))
	return "mono-" + hex.EncodeToString(sum[:]), func() string {
		var ts syscall.Timespec
		if _, _, e := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, 1, uintptr(unsafe.Pointer(&ts)), 0); e != 0 {
			t.Fatal(e)
		}
		return strconv.FormatInt(ts.Nano(), 10)
	}
}

type summaryView struct {
	Robots []struct {
		Key     observability.RobotKey `json:"robot_key"`
		Summary map[string]any         `json:"summary"`
	} `json:"robots"`
}

// T10 T11 through the real ledger walk, the real clock of this machine and the
// HTTP answer.
func TestOpsviewSummaryEndToEnd(t *testing.T) {
	clock, mono := thisClock(t)
	bb := issuerLedger(t)
	for name, c := range map[string]struct {
		binding, clock string
		want           map[string][2]any
	}{
		"bound":              {`,"clock_binding":"shared_kernel_monotonic"`, clock, map[string][2]any{"robot-1": {"IDLE_READY", float64(9)}, "robot-2": {"ATTENTION", float64(4)}}},
		"no binding request": {"", clock, map[string][2]any{"robot-1": {"UNKNOWN", float64(2)}, "robot-2": {"UNKNOWN", float64(2)}}},
		"another clock":      {`,"clock_binding":"shared_kernel_monotonic"`, "mono-0000000000000000000000000000000000000000000000000000000000000000", map[string][2]any{"robot-1": {"UNKNOWN", float64(2)}, "robot-2": {"UNKNOWN", float64(2)}}},
	} {
		_, col, err := parseObservationConfig([]byte(summaryConfig(c.binding)))
		if err != nil {
			t.Fatal(name, err)
		}
		idx, err := ledgerq.Open(filepath.Join(t.TempDir(), "ledger.sqlite"))
		if err != nil {
			t.Fatal(err)
		}
		connectLedger(idx, col)
		if cs, err := idx.IngestChain(bb, time.Now()); err != nil || cs.State != "ok" {
			t.Fatal(name, cs, err)
		}
		seq := 0
		send := func(n, kind string, v observability.Value) {
			t.Helper()
			for i := 0; i < 2; i++ {
				seq++
				ms := time.Now().UnixMilli()
				e := observability.Event{SchemaVersion: 2, DeploymentID: summaryDeployment, RobotID: "robot-" + n, Identity: "robot-" + n, Owner: summaryRun, RunID: summaryRun, Kind: kind, Producer: "2457dd0a-d7b1-42f6-b089-6ce0d5b2d8c3", Stream: "8be30882-0700-4297-89d4-2ef81fa19a4" + n, Seq: strconv.Itoa(seq), Observed: &ms, ClockID: c.clock, MonoNS: mono(), Value: v}
				if err := col.Observe("r"+n, e); err != nil {
					t.Fatal(name, err)
				}
			}
		}
		zero := 0.0
		for _, n := range []string{"1", "2"} {
			send(n, "liveness", observability.Value{State: "ALIVE", Component: "adapter"})
			send(n, "motion", observability.Value{State: "OBSERVED_ZERO", LinearMPS: &zero, AngularRPS: &zero, FrameID: "odom", SourceKind: "simulation_applied_velocity"})
		}
		w := httptest.NewRecorder()
		observability.NewAPI(col).Robots(w, httptest.NewRequest("GET", "/v2/observation/robots", nil))
		var v summaryView
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &v) != nil || len(v.Robots) != 2 {
			t.Fatal(name, w.Code, w.Body.String())
		}
		for _, r := range v.Robots {
			s := r.Summary
			in, ok := s["inputs"].(map[string]any)
			if !ok || len(s) != 5 || s["physical_stop_proven"] != false || s["state"] != c.want[r.Key.RobotID][0] || s["decided_by_rule"] != c.want[r.Key.RobotID][1] {
				t.Fatalf("%s %s: %v", name, r.Key.RobotID, s)
			}
			if in["ledger"] != "CHAIN_OK" || in["source"] != "CONNECTED" {
				t.Fatalf("%s %s: %v", name, r.Key.RobotID, in)
			}
			if name != "bound" && (in["liveness"] != "NOT_BOUND" || in["motion"] != "NOT_BOUND") {
				t.Fatalf("%s %s: %v", name, r.Key.RobotID, in)
			}
		}
		idx.Close()
	}
}
