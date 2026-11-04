// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package telemetry

import (
	"encoding/json"
	"testing"
)

// DB-4 (implementation contract D9) — 조회 API 행은 자기 종류의 칸만 싣는다.
//
// as-is: Record 는 burst 칸과 permit 칸을 한 구조체에 두고 omitempty 가 없어, 조회
// 응답의 burst 행이 `"permit_age_ms":0,"deadman_window_ms":0,"mode":""` 을 함께 실어
// 나른다. 그 0 은 「미관찰」이라는 진술과 같은 바이트다(deadman 0 = 미관찰, mode ""
// = 미관찰) — burst 행에서는 뜻이 없는 칸이 뜻 있는 값의 옷을 입고 도착한다(H-B2).
// 동결(v1)할 표면이 이 형상이어서는 안 된다.
func TestDB4_QueryRowCarriesOnlyItsKindsFields(t *testing.T) {
	dup := false
	burst := Record{V: 1, Kind: KindBurst, Ms: 10, Seq: 1, Event: "BLOCK",
		ReasonValue: 0x15, Robot: "ab", Token: "cd", Sig: SigOK, Dup: &dup, Raw: "00"}
	permit := Record{V: 1, Kind: KindPermit, Ms: 11, Robot: "ab", Sig: SigOK,
		Mode: ModeEnforce, TickMs: 500, PermitAgeMs: 10, DeadmanMs: 100,
		PermitSeq: 3, MirrorSeq: 4, Raw: "00"}
	out, err := json.Marshal(QueryResult{Rows: []Record{burst, permit}})
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Rows []map[string]any `json:"rows"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Rows) != 2 {
		t.Fatalf("rows=%d", len(got.Rows))
	}
	for _, k := range []string{"permit_age_ms", "deadman_window_ms", "mode", "tick_ms", "mirror_seq", "permit_seq"} {
		if _, ok := got.Rows[0][k]; ok {
			t.Errorf("burst 행에 permit 칸 %q 가 실렸다 — 0 이 「미관찰」과 같은 바이트로 도착한다", k)
		}
	}
	for _, k := range []string{"seq", "event", "reason_value", "token", "dup"} {
		if _, ok := got.Rows[1][k]; ok {
			t.Errorf("permit 행에 burst 칸 %q 가 실렸다", k)
		}
	}
	// 자기 칸은 전부 있어야 한다 — 0 값도 진술이다(reason_value 0 · dup false).
	for _, k := range []string{"v", "kind", "ms", "seq", "event", "reason_value", "robot", "token", "sig", "dup", "raw"} {
		if _, ok := got.Rows[0][k]; !ok {
			t.Errorf("burst 행에 %q 가 없다", k)
		}
	}
	for _, k := range []string{"v", "kind", "ms", "robot", "sig", "mode", "tick_ms", "permit_age_ms", "deadman_window_ms", "permit_seq", "mirror_seq", "raw"} {
		if _, ok := got.Rows[1][k]; !ok {
			t.Errorf("permit 행에 %q 가 없다", k)
		}
	}
}

// 행의 JSON 은 JSONL 줄과 바이트 동일해야 한다 — 두 표면이 갈리면 문서가 하나를
// 적을 때 다른 하나가 낡는다.
func TestDB4_QueryRowEqualsJSONLLine(t *testing.T) {
	dup := true
	r := Record{V: 1, Kind: KindBurst, Ms: 10, Seq: 1, Event: "BLOCK",
		ReasonValue: 0x15, Robot: "ab", Token: "cd", Sig: SigBad, Dup: &dup, Raw: "00"}
	line, err := r.MarshalBurst()
	if err != nil {
		t.Fatal(err)
	}
	row, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(line) != string(row) {
		t.Fatalf("JSONL 줄과 조회 행이 다르다:\n line=%s\n row =%s", line, row)
	}
}
