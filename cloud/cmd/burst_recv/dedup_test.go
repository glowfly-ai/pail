// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

import (
	"fmt"
	"testing"
	"time"
)

// D §7.4 (C-B14 잔여 N-11): 만료 없는 dedup 은 (a) 장기 실행에서 집합이 무한
// 성장하고 (b) burst_seq 를 재사용하는 재접속이 영원히 무시된다. 신선도 창은
// 수신 시각 기준이고, 창을 벗어난 항목은 제거된다.
func TestDedupFreshnessWindow(t *testing.T) {
	// 초록인 실행이 자기 조건 id 를 부른다 — `ob4_closure.py` 의 결속 표식.
	t.Log("[D14-C4] §8 — N-11 burst 신선도 창 + dedup 만료 (D §7.4)")

	d := newDedup(5 * time.Second)
	t0 := time.Unix(1700000000, 0)

	if !d.first("true|r1|1", t0) {
		t.Fatal("처음 보는 키가 억제됐다")
	}
	// §6 스케줄(0/50/200/500/1000ms)의 재전송 4발 — 전부 창 안이므로 억제.
	for _, ms := range []int64{50, 200, 500, 1000} {
		if d.first("true|r1|1", t0.Add(time.Duration(ms)*time.Millisecond)) {
			t.Fatalf("창 안 재전송(+%dms)이 억제되지 않았다", ms)
		}
	}
	// 다른 키(다른 seq)는 억제 대상이 아니다.
	if !d.first("true|r1|2", t0.Add(time.Second)) {
		t.Fatal("다른 seq 가 같은 키로 접혔다")
	}

	// 창을 넘긴 재도착은 다시 방출된다 — 재접속 후 seq 재사용이 영원히
	// 무시되면 그 로봇의 이후 안전 이벤트가 전부 증발한다.
	if !d.first("true|r1|1", t0.Add(6*time.Second)) {
		t.Fatal("창(5s)을 넘긴 재도착이 여전히 억제된다 — 만료가 없다")
	}

	// 타임스탬프는 중복 도착으로 갱신되지 않는다: 같은 키가 계속 흘러들어도
	// 창마다 한 번은 방출된다 — 홍수가 침묵을 사는 구조가 아니다.
	tf := t0.Add(20 * time.Second)
	if !d.first("true|r9|7", tf) {
		t.Fatal("전제: 새 키")
	}
	for s := 1; s <= 4; s++ {
		if d.first("true|r9|7", tf.Add(time.Duration(s)*time.Second)) {
			t.Fatalf("창 안(+%ds) 중복이 방출됐다", s)
		}
	}
	if !d.first("true|r9|7", tf.Add(6*time.Second)) {
		t.Fatal("첫 수신 +6s(창 밖) 재도착이 억제된다 — 중복이 타임스탬프를 갱신하고 있다")
	}
}

// 집합의 크기는 가동 시간이 아니라 창 안의 서로 다른 이벤트 수에 묶인다.
func TestDedupSetBounded(t *testing.T) {
	d := newDedup(5 * time.Second)
	t0 := time.Unix(1700000000, 0)
	for i := 0; i < 1000; i++ {
		d.first(fmt.Sprintf("true|r1|%d", i), t0.Add(time.Duration(i)*time.Second))
	}
	// 마지막 호출 시각 기준 창(5s) 안의 키만 남아야 한다.
	if n := len(d.seen); n > 6 {
		t.Fatalf("만료된 항목이 남아 있다: len=%d (want <=6) — 집합이 가동 시간에 비례해 자란다", n)
	}
}
