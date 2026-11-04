// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package telemetry

import (
	"sort"
	"time"
)

// Gap is a span in which the collector was not provably listening.
type Gap struct {
	FromMs uint64 `json:"from_ms"`
	ToMs   uint64 `json:"to_ms"`
}

// Coverage travels with every decisions answer (implementation contract D2): the answer
// itself says whether "0 rows" means "nothing happened" or "nobody was
// listening" — leaving that split to client goodwill makes every consumer
// wrong in its own way.
type Coverage struct {
	FromMs        uint64  `json:"from_ms"`
	ToMs          uint64  `json:"to_ms"`
	Gaps          []Gap   `json:"gaps"`
	ListenedRatio float64 `json:"listened_ratio"`
}

// Filter selects burst rows. Reason is a pointer because reason 0 is a real
// value — "no filter" and "filter on zero" must not share a literal.
type Filter struct {
	FromMs uint64
	ToMs   uint64
	Event  string
	Reason *uint16
	Robot  string
	Limit  int
}

// QueryResult carries its own bound as well as its own absence (G-DSH-07):
// Matched is the row count before the page limit, Truncated says the limit
// cut. A cut page that does not say so reads as the whole window — the status
// board drew "calm" over 165 blocks it never received (2026-09-04 실측).
type QueryResult struct {
	Rows      []Record `json:"rows"`
	Matched   int      `json:"matched"`
	Truncated bool     `json:"truncated"`
	Coverage  Coverage `json:"coverage"`
}

// Query filters burst rows out of recs and computes coverage for the window.
//
// Limit keeps the NEWEST rows (the tail of reception order) and the answer
// declares the cut. The first version kept the head and stopped: a 6-hour
// window of 525 rows answered with the oldest 200 — all CHECKPOINT — and the
// 165 BLOCKs after 14:33 never reached the screen (2026-09-04 observed regression).
// Reception order is preserved inside the kept page, so consumers that read
// the shape (oldest→newest) see the same shape, just the right end of it.
func Query(recs []Record, f Filter, maxGap time.Duration) QueryResult {
	rows := []Record{}
	for _, r := range recs {
		if r.Kind != KindBurst {
			continue
		}
		if r.Ms < f.FromMs || (f.ToMs > 0 && r.Ms > f.ToMs) {
			continue
		}
		if f.Event != "" && r.Event != f.Event {
			continue
		}
		if f.Reason != nil && r.ReasonValue != *f.Reason {
			continue
		}
		if f.Robot != "" && r.Robot != f.Robot {
			continue
		}
		rows = append(rows, r)
	}
	matched := len(rows)
	truncated := false
	if f.Limit > 0 && matched > f.Limit {
		rows = rows[matched-f.Limit:]
		truncated = true
	}
	return QueryResult{
		Rows:      rows,
		Matched:   matched,
		Truncated: truncated,
		Coverage:  CoverageOf(recs, f.FromMs, f.ToMs, maxGap),
	}
}

// CoverageOf computes listening evidence for [fromMs, toMs]. Every record's
// timestamp is a liveness point — a received burst proves listening exactly as
// a tick does. A span between adjacent points (window edges included) longer
// than maxGap is a gap: the collector cannot prove it heard that span, so
// "0 rows there" must not read as "nothing happened" (G-DB-1, H-B2).
//
// toMs == 0 means "no upper bound" in Filter; the coverage window then ends at
// the last liveness point (cmd wiring passes now() explicitly instead).
func CoverageOf(recs []Record, fromMs, toMs uint64, maxGap time.Duration) Coverage {
	var points []uint64
	for _, r := range recs {
		if r.Ms < fromMs || (toMs > 0 && r.Ms > toMs) {
			continue
		}
		points = append(points, r.Ms)
	}
	sort.Slice(points, func(i, j int) bool { return points[i] < points[j] })
	if toMs == 0 {
		toMs = fromMs
		if n := len(points); n > 0 && points[n-1] > toMs {
			toMs = points[n-1]
		}
	}
	cov := Coverage{FromMs: fromMs, ToMs: toMs, Gaps: []Gap{}}
	span := int64(toMs) - int64(fromMs)
	if span <= 0 {
		// an empty window asks about nothing; there is nothing to have missed
		cov.ListenedRatio = 1.0
		return cov
	}
	gapMs := uint64(maxGap / time.Millisecond)
	var gapTotal uint64
	prev := fromMs
	for _, p := range append(points, toMs) {
		if p-prev > gapMs {
			cov.Gaps = append(cov.Gaps, Gap{FromMs: prev, ToMs: p})
			gapTotal += p - prev
		}
		prev = p
	}
	cov.ListenedRatio = 1.0 - float64(gapTotal)/float64(span)
	return cov
}
