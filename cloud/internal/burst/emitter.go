// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package burst

import "crypto/ed25519"

// Emitter abstracts beacon emission (D1 split, 배치형상 §7.3).
//
// Combined/legacy binary: SignedEmitter signs and sends UDP directly.
// Split cloud-services: relay.Hub forwards events to the robot-agent,
// which owns the single burst_seq counter and the UDP socket. Receivers
// deduplicate on the global seq, so exactly one process may sign/send.
type Emitter interface {
	Emit(event byte, reason uint16, unixMs uint64, robotID string, tokenHash16 [16]byte)
}

// SignedEmitter preserves the pre-split behavior: build, sign and transmit
// the 120B burst v2 packet in-process.
type SignedEmitter struct {
	Sender *Sender
	Key    ed25519.PrivateKey
}

func (e *SignedEmitter) Emit(event byte, reason uint16, unixMs uint64, robotID string, tokenHash16 [16]byte) {
	e.Sender.SendBurst(BuildPacketV2(e.Key, event, reason, unixMs, robotID, tokenHash16, e.Sender.NextSeq()))
}
