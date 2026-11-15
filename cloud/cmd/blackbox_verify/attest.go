// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

import (
	"encoding/hex"
	"errors"
	"fmt"
)

// exitUnattestedTail is returned when the chain is intact and signed, but the
// last records sit after the final signed CHECKPOINT (SEC-H07). It is its own
// code so that a script reading only the exit status cannot take "part of this
// journal is outside every signature" for a pass.
const exitUnattestedTail = 7

// coverage tracks how much of the walked journal is under a verified signature.
//
// The hash chain can be recomputed by anyone who can write the files; only a
// signed CHECKPOINT cannot. A checkpoint signs the head hash, and the head hash
// is bound to every earlier record — across segments, through the inherited
// tail in each segment header, which the chain walk has already checked by the
// time a checkpoint is counted here. So one verified checkpoint attests every
// record before it, and "attested" is simply "seen so far" at that moment.
type coverage struct {
	seen     int // records walked
	attested int // records up to and including the last verified checkpoint
	verified int // checkpoints whose signature was verified
	lastSeg  string
	lastIdx  int
}

func (c *coverage) record() { c.seen++ }

// checkpoint marks the record just counted by record() as a verified checkpoint.
func (c *coverage) checkpoint(seg string, idx int) {
	c.verified++
	c.attested = c.seen
	c.lastSeg, c.lastIdx = seg, idx
}

func (c *coverage) tail() int { return c.seen - c.attested }

func (c *coverage) line() string {
	if c.verified == 0 {
		return fmt.Sprintf("ATTESTED: nothing (0 records); unattested tail: %d record(s)", c.tail())
	}
	return fmt.Sprintf("ATTESTED: through %s record[%d] (%d records); unattested tail: %d record(s)",
		c.lastSeg, c.lastIdx, c.attested, c.tail())
}

// parseExpectHead reads the externally held head: the this_hash of some record
// the caller knows the journal contained (an anchor record's head, a checkpoint
// announcement, a value noted at an earlier verification).
func parseExpectHead(s string) (head [32]byte, err error) {
	raw, derr := hex.DecodeString(s)
	if derr != nil || len(raw) != len(head) {
		return head, errors.New("-expect-head must be 64 hex characters")
	}
	copy(head[:], raw)
	return head, nil
}
