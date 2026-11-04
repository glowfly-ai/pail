// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package telemetry

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/glowfly/pail/services/internal/burst"
)

// DedupWindow bounds how long a (sig-class, robot, seq) key marks re-arrivals
// as duplicates. Derived, not invented (same derivation as burst_recv): the
// §6 retransmission schedule ends at 1000ms, so 5x that span covers every
// scheduled duplicate with delivery jitter to spare.
const DedupWindow = 5 * time.Second

// Ingester turns received burst packets into telemetry records: field
// extraction, 3-valued signature verdict, duplicate marking.
//
// Unlike burst_recv, duplicates are RECORDED with dup:true, never suppressed
// (implementation contract D1): a replayed seq is replay-observation material, and dropping
// it erases the fact that a replay happened.
type Ingester struct {
	keys []ed25519.PublicKey
	seen map[string]time.Time
}

func NewIngester(keys []ed25519.PublicKey) *Ingester {
	return &Ingester{keys: keys, seen: map[string]time.Time{}}
}

// sigVerdict classifies a v2 packet's signature against the trust anchor set.
// Three values, not a bool: with no keys loaded nothing was checked, and
// "could not check" must not wear the same value as "checked and fine" (H-B2).
func (in *Ingester) sigVerdict(pkt []byte) string {
	if len(in.keys) == 0 {
		return SigUnverifiable
	}
	for _, k := range in.keys {
		if burst.VerifyPacketV2(k, pkt) {
			return SigOK
		}
	}
	return SigBad
}

// dup reports whether key re-arrived inside the window and records first
// arrivals. Entries past the window are pruned on every call, so the set is
// bounded by distinct events per window, not uptime. The timestamp is not
// refreshed by duplicates: a key that keeps arriving is re-marked fresh once
// per window instead of staying "dup" for as long as a flood lasts.
func (in *Ingester) dup(key string, now time.Time) bool {
	for k, t := range in.seen {
		if now.Sub(t) > DedupWindow {
			delete(in.seen, k)
		}
	}
	if _, ok := in.seen[key]; ok {
		return true
	}
	in.seen[key] = now
	return false
}

// Observe records one received v2 burst packet at receipt time now.
// Framing errors (wrong size, magic, version) are returned, not recorded —
// the caller counts them as malformed traffic.
func (in *Ingester) Observe(pkt []byte, now time.Time) (Record, error) {
	if len(pkt) != burst.V2PacketSize {
		return Record{}, fmt.Errorf("packet size %d, want %d", len(pkt), burst.V2PacketSize)
	}
	if string(pkt[0:4]) != "PAIL" || pkt[4] != 2 {
		return Record{}, fmt.Errorf("bad magic/version")
	}
	sig := in.sigVerdict(pkt)
	robot := hex.EncodeToString(pkt[16:32])
	seq := binary.LittleEndian.Uint32(pkt[48:52])
	// The sig class is part of the dedup key so a forged packet can never
	// pre-claim a (robot, seq) slot and make the authentic event arrive
	// wearing dup:true (same shape as burst_recv's validity-in-key rule).
	isDup := in.dup(fmt.Sprintf("%s|%s|%d", sig, robot, seq), now)
	rec := Record{
		V:           1,
		Kind:        KindBurst,
		Ms:          uint64(now.UnixMilli()),
		Seq:         seq,
		Event:       burst.EventName(pkt[5]),
		ReasonValue: binary.LittleEndian.Uint16(pkt[6:8]),
		Robot:       robot,
		Token:       hex.EncodeToString(pkt[32:48]),
		Sig:         sig,
		Dup:         &isDup,
		Raw:         hex.EncodeToString(pkt),
	}
	return rec, nil
}
