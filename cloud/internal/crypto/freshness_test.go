// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// `B9-1`/`B9-2` 행위 유닛 — 신뢰 기점의 시간축 게이트가 **실제로 멈추는가**.
//
// 구조 검사(`RB-12`)는 `Ticker` 와 `Check` 의 **존재**를 잰다. 존재는 행위가
// 아니다 — §7.2 가 요구하는 증거는 `rc=78`과 사유, 즉 만료 시각을 넘긴 뒤 판정이
// 실제로 뒤집히는 것이다.
//
// 죽는 자리를 각각 잰다(`H-B9`). 만료 · 미설치 · 출처 미선언은 서로 다른 규칙이고
// (`S20d`/`S20f`), 한 유닛으로 접으면 하나가 열려도 나머지가 초록을 만든다.
// 판정은 사유 문구가 아니라 `deploysec.RuleID` 로 잰다 — 문구로 재면 문구만 바꿔도
// 판정이 뒤집힌다.
package crypto

import (
	"testing"
	"time"

	"github.com/glowfly/pail/services/internal/deploysec"
)

func wantRule(t *testing.T, err error, id string) {
	t.Helper()
	if err == nil {
		t.Fatalf("거부되어야 한다 (%s) — nil 이 왔다", id)
	}
	if got := deploysec.RuleID(err); got != id {
		t.Fatalf("rule=%q, want %q (err=%v)", got, id, err)
	}
}

// TestFreshnessRefusesPastExpiry — `B-R2` 의 핵심. 적재는 성공했고 프로세스는
// 살아 있는데 만료 시각만 지났다. 이것 하나만 깨서 잰다.
func TestFreshnessRefusesPastExpiry(t *testing.T) {
	exp := time.Now().Add(1 * time.Hour)
	f, err := TrustFreshnessFromBundle(exp.Unix())
	if err != nil {
		t.Fatalf("생성: %v", err)
	}
	// 전제: 만료 전에는 통과해야 한다. 통과하지 않으면 아래 거부는 만료가 아니라
	// 다른 이유일 수 있고, 그 둘은 같은 붉은 줄이다.
	if err := f.CheckAt(exp.Add(-time.Second)); err != nil {
		t.Fatalf("전제 위반 — 만료 전인데 거부됐다: %v", err)
	}
	wantRule(t, f.CheckAt(exp.Add(time.Second)), "S20d")
	// 경계: `>=` 다. 만료 **시각 그 자체**가 통과하면 창이 1초 길어진다.
	wantRule(t, f.CheckAt(exp), "S20d")
}

// TestFreshnessRefusesWhenNotInstalled — `H-B2`. nil 은 "만료 없음"이 아니라
// "게이트를 설치한 적 없음"이고, 그것이 통과로 읽히면 배선을 빠뜨린 컴포넌트가
// **아무 로그도 없이** 상한 밖에서 돈다.
func TestFreshnessRefusesWhenNotInstalled(t *testing.T) {
	var f *TrustFreshness
	wantRule(t, f.Check(), "S20f")
	if got := f.Describe(); got != "trust freshness: NOT INSTALLED" {
		t.Fatalf("Describe()=%q — 미설치가 로그에서 만료 없음과 구별되지 않는다", got)
	}
}

// TestFreshnessRefusesUndeclaredSource — 영값 구조체. 새 적재 경로가 출처를
// 대지 않고 `&TrustFreshness{}` 를 만들면 거부되어야 한다.
func TestFreshnessRefusesUndeclaredSource(t *testing.T) {
	wantRule(t, (&TrustFreshness{}).Check(), "S20f")
	// 만료 값만 있고 출처가 없는 경우도 같다 — 값이 있다고 확인한 것이 아니다.
	wantRule(t, (&TrustFreshness{expiresAtUnix: time.Now().Add(time.Hour).Unix()}).Check(), "S20f")
}

// TestFreshnessFromBundleRefusesZeroExpiry — 적재 경로가 만료를 잃어버린 경우.
// 0 을 "만료 없음"으로 접으면 잃어버린 사실이 통과로 나타난다.
func TestFreshnessFromBundleRefusesZeroExpiry(t *testing.T) {
	_, err := TrustFreshnessFromBundle(0)
	wantRule(t, err, "S20f")
	_, err = TrustFreshnessFromBundle(-1)
	wantRule(t, err, "S20f")
}

// TestFreshnessUnsignedDevPasses — 양성 대조. 이것이 없으면 위 셋이 전부 초록인
// 채로 dev 경로가 통째로 멈출 수 있고, 그때 이것은 게이트가 아니라 벽이다.
func TestFreshnessUnsignedDevPasses(t *testing.T) {
	f := TrustFreshnessUnsignedDev()
	if err := f.CheckAt(time.Now().Add(100 * 365 * 24 * time.Hour)); err != nil {
		t.Fatalf("unsigned-dev 는 만료가 없다 — 100년 뒤에도 통과해야 한다: %v", err)
	}
	if got := f.Describe(); got == "" || got == "trust freshness: NOT INSTALLED" {
		t.Fatalf("Describe()=%q — 만료 없음이 소리 내어 말해지지 않는다", got)
	}
}

// TestFreshnessWatchReportsExpiry — `B-R1` 의 **주기성**. 요청이 하나도 오지
// 않는 프로세스에서 만료가 관측되는지 잰다. `Check` 만 있으면 놀고 있는 발급자의
// 만료는 다음 요청까지 아무 로그에도 안 나타난다.
//
// 이미 만료된 기점으로 시작해 짧은 틱을 준다 — 실제 시각을 기다리지 않고 주기
// 재검사 **경로 자체**가 도는지를 잰다.
func TestFreshnessWatchReportsExpiry(t *testing.T) {
	f, err := TrustFreshnessFromBundle(time.Now().Add(-time.Hour).Unix())
	if err != nil {
		t.Fatalf("생성: %v", err)
	}
	if f.ObservedExpired() {
		t.Fatal("전제 위반 — 감시가 돌기 전인데 이미 관측됐다고 한다")
	}
	stop := make(chan struct{})
	defer close(stop)
	seen := make(chan error, 4)
	go f.Watch(5*time.Millisecond, stop, func(err error) { seen <- err })

	select {
	case err := <-seen:
		if id := deploysec.RuleID(err); id != "S20d" {
			t.Fatalf("감시가 보고한 rule=%q, want S20d", id)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("주기 재검사가 만료를 보고하지 않았다 — 적재 시점에만 보는 것과 구별되지 않는다")
	}
	if !f.ObservedExpired() {
		t.Fatal("ObservedExpired() 가 false — 관측 상태가 남지 않았다")
	}
	// 같은 줄을 틱마다 쌓지 않는다. 쌓이면 그 줄은 읽히지 않는다.
	select {
	case err := <-seen:
		t.Fatalf("만료 보고가 반복됐다: %v", err)
	case <-time.After(60 * time.Millisecond):
	}
}

// TestFreshnessWatchSilentWhileFresh — 감시가 만료 아닌 것을 만료라고 하지
// 않는지. 이것이 없으면 위 시험은 "항상 보고한다"로도 초록이다.
func TestFreshnessWatchSilentWhileFresh(t *testing.T) {
	f, err := TrustFreshnessFromBundle(time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatalf("생성: %v", err)
	}
	stop := make(chan struct{})
	defer close(stop)
	seen := make(chan error, 4)
	go f.Watch(5*time.Millisecond, stop, func(err error) { seen <- err })
	select {
	case err := <-seen:
		t.Fatalf("유효한 기점을 만료라고 보고했다: %v", err)
	case <-time.After(120 * time.Millisecond):
	}
	if f.ObservedExpired() {
		t.Fatal("ObservedExpired() 가 true — 유효한데 만료로 표시됐다")
	}
}
