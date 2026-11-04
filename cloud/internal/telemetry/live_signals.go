// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package telemetry

import (
	ops "github.com/glowfly/pail/services/pkg/robotops"
	"github.com/google/uuid"
	"sort"
	"sync"
	"time"
)

const maxLiveSubjects = 1024

type receivedSignal struct {
	seen                bool
	last                Record
	received            time.Time
	advancing           time.Time
	seq                 uint32
	count, nonadvancing uint64
	state               string
}
type subjectSignals struct{ burst, mirror receivedSignal }
type LiveSignals struct {
	mu                              sync.Mutex
	instance, burstRole, mirrorRole string
	subjects                        map[string]*subjectSignals
	dropped, unverified             uint64
}

func NewLiveSignals(burstRole, mirrorRole string) *LiveSignals {
	return &LiveSignals{instance: uuid.NewString(), burstRole: burstRole, mirrorRole: mirrorRole, subjects: map[string]*subjectSignals{}}
}

// Observe is wired to the already-verified live Dispatcher result, not disk
// history. It performs no signature fallback, token query or store append.
func (l *LiveSignals) Observe(r Record, now time.Time) {
	if r.Kind != KindBurst && r.Kind != KindPermit {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.subjects[r.Robot]
	if s == nil {
		if r.Sig != SigOK {
			l.unverified++
			return
		}
		if len(l.subjects) >= maxLiveSubjects {
			l.dropped++
			return
		}
		s = &subjectSignals{}
		l.subjects[r.Robot] = s
	}
	slot := &s.burst
	seq := r.Seq
	if r.Kind == KindPermit {
		slot = &s.mirror
		seq = r.MirrorSeq
	}
	// Retain only fields needed for diagnostics. No raw packet or token material.
	r.Raw = ""
	r.Token = ""
	slot.seen = true
	slot.last = r
	slot.received = now
	if r.Sig != SigOK {
		slot.state = "UNVERIFIED"
		return
	}
	duplicate := r.Kind == KindBurst && r.Dup != nil && *r.Dup
	if duplicate || (slot.count > 0 && (seq-slot.seq == 0 || seq-slot.seq >= 1<<31)) {
		slot.nonadvancing++
		slot.state = "NONADVANCING"
		return
	}
	slot.seq = seq
	slot.advancing = now
	slot.count++
	slot.state = "RECEIVED"
}
func signalView(s receivedSignal, role string, now time.Time) ops.SignalReceipt {
	v := ops.SignalReceipt{State: "NEVER", LatestAgeMS: -1, AdvancingAgeMS: -1, KeyRole: role}
	if role == "none" {
		v.KeyRole = ""
	}
	if !s.seen {
		return v
	}
	v.State = s.state
	v.Signature = s.last.Sig
	v.LatestAgeMS = now.Sub(s.received).Milliseconds()
	v.Sequence = s.seq
	v.ProgressSamples = s.count
	v.NonAdvancing = s.nonadvancing
	if s.count > 0 {
		v.AdvancingAgeMS = now.Sub(s.advancing).Milliseconds()
	}
	v.Event = s.last.Event

	if s.last.Kind == KindPermit {
		v.MirrorStatement = &ops.MirrorStatement{PermitAgeMS: s.last.PermitAgeMs, DeadmanMS: s.last.DeadmanMs, TickMS: s.last.TickMs, Mode: s.last.Mode}
	}

	if now.Sub(s.received) < 0 || (s.count > 0 && now.Sub(s.advancing) < 0) {
		v.State = "CLOCK_UNCERTAIN"
		v.LatestAgeMS = -1
		v.AdvancingAgeMS = -1
	}
	if s.last.Sig != SigOK {
		v.KeyRole = ""
	}
	return v
}

// Snapshot is non-mutating. Age is measured in the collector's monotonic clock
// while running; wall-clock steps are not subtracted from sender timestamps.
// Current samples the receiver clock AFTER taking the lock, so a concurrent
// observation cannot appear to come from the future merely due to lock waiting.
func (l *LiveSignals) Current(nonce string) ops.SignalProbe {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.snapshotLocked(time.Now(), nonce)
}

// Snapshot permits deterministic time-bound tests; live HTTP uses Current.
func (l *LiveSignals) Snapshot(now time.Time, nonce string) ops.SignalProbe {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.snapshotLocked(now, nonce)
}
func (l *LiveSignals) snapshotLocked(now time.Time, nonce string) ops.SignalProbe {
	out := ops.SignalProbe{SchemaVersion: 1, Component: "telemetryd", InstanceID: l.instance, ClockID: l.instance, Nonce: nonce, GeneratedAtMS: now.UnixMilli(), Signals: []ops.RobotSignals{}, RegistryRobots: []ops.CollectorRobot{}, DroppedSubjects: l.dropped, UntrackedUnverified: l.unverified, EvidenceKind: "live_receiver_memory", SourceFreshness: "NOT_PROVEN_BY_LEGACY_WIRE", IdentityBasis: "role_signature_over_claimed_robot_hash; no_per_robot_key_binding"}
	ids := []string{}
	for id := range l.subjects {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		s := l.subjects[id]
		out.Signals = append(out.Signals, ops.RobotSignals{RobotHash: id, Burst: signalView(s.burst, l.burstRole, now), Mirror: signalView(s.mirror, l.mirrorRole, now)})
	}
	return out
}
