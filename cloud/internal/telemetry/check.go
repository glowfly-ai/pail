// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package telemetry

import (
	"fmt"
	"io"
	"time"
)

// Report is the gap checker's verdict material, inheriting the anchor probe's
// Report grammar (D §7.4): counts, gaps and unparseable lines travel BESIDE
// the verdict, never folded into it. Bad lines are listed by number and
// excluded from gap math.
type Report struct {
	Records  int    `json:"records"`
	BadLines []int  `json:"bad_lines"`
	MaxGapMs uint64 `json:"max_gap_ms"`
	FromMs   uint64 `json:"from_ms"`
	ToMs     uint64 `json:"to_ms"`
	Gaps     []Gap  `json:"gaps"`
}

// Check judges liveness continuity of one decisions JSONL stream.
// A timestamp rewind is an error, not a negative gap — a file whose clock ran
// backwards cannot be judged, and "could not judge" must not print as "no
// gaps" (H-B2).
func Check(r io.Reader, maxGap time.Duration) (Report, error) {
	recs, bad, err := ReadAll(r)
	if err != nil {
		return Report{}, err
	}
	rep := Report{
		Records:  len(recs),
		BadLines: bad,
		MaxGapMs: uint64(maxGap / time.Millisecond),
		Gaps:     []Gap{},
	}
	if rep.BadLines == nil {
		rep.BadLines = []int{}
	}
	if len(recs) == 0 {
		return rep, nil
	}
	prev := recs[0].Ms
	rep.FromMs = prev
	for _, rc := range recs[1:] {
		if rc.Ms < prev {
			return Report{}, fmt.Errorf("timestamp rewind: %d after %d", rc.Ms, prev)
		}
		if rc.Ms-prev > rep.MaxGapMs {
			rep.Gaps = append(rep.Gaps, Gap{FromMs: prev, ToMs: rc.Ms})
		}
		prev = rc.Ms
	}
	rep.ToMs = prev
	return rep, nil
}
