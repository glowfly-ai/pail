// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package telemetry

import (
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestLiveSignalsIndependentChannelsAndNoPermitPromotion(t *testing.T) {
	t0 := time.Now()
	l := NewLiveSignals("burst", "mirror")
	dup := false
	l.Observe(Record{Kind: KindBurst, Robot: "robot-hash", Sig: SigOK, Seq: 4, Event: "CHECKPOINT", Dup: &dup, Raw: "do-not-return", Token: "do-not-return"}, t0)
	v := l.Snapshot(t0.Add(time.Second), "nonce")
	if len(v.Signals) != 1 || v.Signals[0].Mirror.State != "NEVER" || v.Signals[0].Burst.Event != "CHECKPOINT" || v.Signals[0].Burst.MirrorStatement != nil || v.Signals[0].Mirror.MirrorStatement != nil || v.SourceFreshness != "NOT_PROVEN_BY_LEGACY_WIRE" {
		t.Fatal(v)
	}
	l.Observe(Record{Kind: KindPermit, Robot: "robot-hash", Sig: SigOK, MirrorSeq: 7, PermitAgeMs: 0, DeadmanMs: 200, TickMs: 100, Mode: ModeEnforce}, t0.Add(time.Second))
	v = l.Snapshot(t0.Add(2*time.Second), "nonce")
	if v.Signals[0].Mirror.AdvancingAgeMS != 1000 || v.Signals[0].Burst.AdvancingAgeMS != 2000 {
		t.Fatal(v)
	}
	again := l.Snapshot(t0.Add(2*time.Second), "nonce")
	if !reflect.DeepEqual(v, again) {
		t.Fatal("query changes observation state")
	}
	restarted := NewLiveSignals("burst", "mirror").Snapshot(t0, "nonce")
	if len(restarted.Signals) != 0 || restarted.InstanceID == v.InstanceID {
		t.Fatal("old process evidence survived restart")
	}
}
func TestDuplicatesAndBackwardSequencesDoNotRefreshEvidence(t *testing.T) {
	t0 := time.Now()
	l := NewLiveSignals("burst", "mirror")
	for _, kind := range []string{KindBurst, KindPermit} {
		l.Observe(Record{Kind: kind, Robot: "r", Sig: SigOK, Seq: 100, MirrorSeq: 100}, t0)
		l.Observe(Record{Kind: kind, Robot: "r", Sig: SigOK, Seq: 100, MirrorSeq: 100}, t0.Add(time.Hour))
		l.Observe(Record{Kind: kind, Robot: "r", Sig: SigOK, Seq: 99, MirrorSeq: 99}, t0.Add(time.Hour+time.Second))
	}
	v := l.Snapshot(t0.Add(time.Hour+time.Second), "nonce").Signals[0]
	if v.Burst.AdvancingAgeMS != 3601000 || v.Mirror.AdvancingAgeMS != 3601000 || v.Burst.NonAdvancing != 2 || v.Mirror.ProgressSamples != 1 {
		t.Fatal(v)
	}
	l.Observe(Record{Kind: KindPermit, Robot: "r", Sig: SigOK, MirrorSeq: 101}, t0.Add(2*time.Hour))
	v = l.Snapshot(t0.Add(2*time.Hour), "nonce").Signals[0]
	if v.Mirror.AdvancingAgeMS != 0 || v.Mirror.ProgressSamples != 2 {
		t.Fatal(v)
	}
}
func TestUnverifiedClockAndSequenceWrap(t *testing.T) {
	t0 := time.Now()
	l := NewLiveSignals("burst", "mirror")
	l.Observe(Record{Kind: KindPermit, Robot: "unknown", Sig: SigBad}, t0)
	if len(l.Snapshot(t0, "").Signals) != 0 {
		t.Fatal("unverified subject allocated")
	}
	l.Observe(Record{Kind: KindPermit, Robot: "r", Sig: SigOK, MirrorSeq: ^uint32(0)}, t0)
	l.Observe(Record{Kind: KindPermit, Robot: "r", Sig: SigOK, MirrorSeq: 0}, t0.Add(time.Second))
	v := l.Snapshot(t0.Add(time.Second), "")
	if v.Signals[0].Mirror.ProgressSamples != 2 {
		t.Fatal("serial wrap refused")
	}
	l.Observe(Record{Kind: KindPermit, Robot: "r", Sig: SigBad, MirrorSeq: 1}, t0.Add(2*time.Second))
	v = l.Snapshot(t0.Add(2*time.Second), "")
	if v.Signals[0].Mirror.State != "UNVERIFIED" || v.Signals[0].Mirror.KeyRole != "" || v.Signals[0].Mirror.ProgressSamples != 2 {
		t.Fatal(v)
	}
	v = l.Snapshot(t0, "")
	if v.Signals[0].Mirror.State != "CLOCK_UNCERTAIN" {
		t.Fatal("negative age passed")
	}
}
func TestLiveSignalsMemoryBound(t *testing.T) {
	l := NewLiveSignals("burst", "mirror")
	for i := 0; i < maxLiveSubjects+1; i++ {
		l.Observe(Record{Kind: KindBurst, Robot: time.Unix(int64(i), 0).String(), Sig: SigOK}, time.Now())
	}
	v := l.Snapshot(time.Now(), "")
	if len(v.Signals) != maxLiveSubjects || v.DroppedSubjects != 1 {
		t.Fatal("unbounded subjects")
	}
}
func TestConcurrentSignalObservationAndSnapshots(t *testing.T) {
	l := NewLiveSignals("burst", "mirror")
	var wg sync.WaitGroup
	for writer := 0; writer < 4; writer++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			robot := fmt.Sprint(n)
			for seq := uint32(1); seq <= 100; seq++ {
				l.Observe(Record{Kind: KindPermit, Robot: robot, Sig: SigOK, MirrorSeq: seq}, time.Now())
				l.Snapshot(time.Now(), "nonce")
			}
		}(writer)
	}
	wg.Wait()
	v := l.Snapshot(time.Now(), "nonce")
	if len(v.Signals) != 4 {
		t.Fatal(v)
	}
	for _, row := range v.Signals {
		if row.Mirror.ProgressSamples != 100 || row.Mirror.Sequence != 100 {
			t.Fatal("lost observation", row)
		}
	}
}
