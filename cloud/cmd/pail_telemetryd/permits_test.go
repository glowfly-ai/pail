// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/glowfly/pail/services/internal/ledgerq"
	"github.com/glowfly/pail/services/internal/telemetry"
)

// permitFixture writes one day-file of mirror records and returns its dir.
//
// 줄을 손으로 쓰는 것은 의도다 — 여기서 재려는 것은 수집 경로가 아니라
// **조회 표면**이고, 저장된 줄에서 판정이 어떻게 서는지다.
func permitFixture(t *testing.T, lines ...string) string {
	t.Helper()
	dir := t.TempDir()
	body := ""
	for _, l := range lines {
		body += l + "\n"
	}
	name := filepath.Join(dir, "decisions-"+time.Now().UTC().Format("20060102")+".jsonl")
	if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func permitLine(t *testing.T, robot, sig string, ms uint64, tickMs, deadmanMs uint16, ageMs uint32) string {
	t.Helper()
	rec := telemetry.Record{
		V: 1, Kind: telemetry.KindPermit, Ms: ms,
		Robot: robot, Sig: sig, Mode: "enforce",
		TickMs: tickMs, DeadmanMs: deadmanMs, PermitAgeMs: ageMs,
		MirrorSeq: 1, PermitSeq: 7,
	}
	line, err := rec.MarshalPermit()
	if err != nil {
		t.Fatal(err)
	}
	return string(line)
}

func getPermits(t *testing.T, dir string) []telemetry.PermitVerdict {
	t.Helper()
	previous := ledgerIndex
	idx, err := ledgerq.Open(filepath.Join(dir, "test.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()
	ledgerIndex = idx
	defer func() { ledgerIndex = previous }()
	if _, err = idx.IngestTelemetry(dir, time.Now()); err != nil {
		t.Fatal(err)
	}
	mux := newMux("", dir, 30*time.Second)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/telemetry/permits", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /v1/telemetry/permits → %d (body %q)", rr.Code, rr.Body.String())
	}
	var out []telemetry.PermitVerdict
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("응답이 PermitVerdict 목록이 아니다: %v (body %q)", err, rr.Body.String())
	}
	return out
}

// 로봇마다 한 행. 이름은 수집기가 발명하지 않고 도착한 레코드에서만 나온다 —
// 설정에서 읽으면 "설정에 있으나 한 번도 말한 적 없는 로봇"이 회색이 아니라
// 아예 표에서 사라진다.
func TestDB2_PermitsEndpointReturnsOneRowPerRobot(t *testing.T) {
	now := uint64(time.Now().UnixMilli())
	dir := permitFixture(t,
		permitLine(t, "aa11", telemetry.SigOK, now-100, 500, 100, 40),
		permitLine(t, "bb22", telemetry.SigOK, now-100, 500, 100, 40),
		permitLine(t, "aa11", telemetry.SigOK, now-50, 500, 100, 30),
	)
	rows := getPermits(t, dir)
	if len(rows) != 2 {
		t.Fatalf("로봇 행 %d개, 2개를 기대했다: %+v", len(rows), rows)
	}
	byRobot := map[string]telemetry.PermitVerdict{}
	for _, r := range rows {
		byRobot[r.Robot] = r
	}
	for _, want := range []string{"aa11", "bb22"} {
		got, ok := byRobot[want]
		if !ok {
			t.Fatalf("로봇 %s 의 행이 없다: %+v", want, rows)
		}
		if got.State != telemetry.PermitAlive {
			t.Fatalf("%s state=%s why=%q, alive 를 기대했다", want, got.State, got.Why)
		}
	}
	// 마지막 레코드가 판정 재료다: aa11 의 나이는 30 이어야 한다(40 이면 첫 줄을
	// 읽고 있다 — 오래된 진술이 현재로 도착하는 형태).
	if byRobot["aa11"].PermitAgeMs != 30 {
		t.Fatalf("aa11 permit_age_ms=%d, 마지막 레코드의 30 을 기대했다", byRobot["aa11"].PermitAgeMs)
	}
}

// 미검증 서명은 초록이 아니다. 이 관측점이 없으면 아무 UDP 발신자나 화면을
// 켤 수 있고, 그 초록은 누구의 증언인지를 잃는다.
func TestDB2_PermitsEndpointUnverifiedIsNotAlive(t *testing.T) {
	now := uint64(time.Now().UnixMilli())
	dir := permitFixture(t,
		permitLine(t, "cc33", telemetry.SigUnverifiable, now-100, 500, 100, 40),
	)
	rows := getPermits(t, dir)
	if len(rows) != 1 {
		t.Fatalf("행 %d개, 1개를 기대했다", len(rows))
	}
	if rows[0].State != telemetry.PermitUnknown {
		t.Fatalf("state=%s, unknown 을 기대했다", rows[0].State)
	}
	if rows[0].KeyRole != "" {
		t.Fatalf("key_role=%q, 미검증 진술은 신원을 갖지 않는다", rows[0].KeyRole)
	}
}

// permit 레코드가 하나도 없으면 표는 **비어 있다**. 여기서 로봇 이름을
// 발명하면 "아직 아무도 말하지 않았다"가 "모른다"가 아니라 행 없음으로 접힌다.
func TestDB2_PermitsEndpointEmptyIsEmptyList(t *testing.T) {
	dir := permitFixture(t)
	rows := getPermits(t, dir)
	if len(rows) != 0 {
		t.Fatalf("행 %d개, 0개를 기대했다: %+v", len(rows), rows)
	}
}
