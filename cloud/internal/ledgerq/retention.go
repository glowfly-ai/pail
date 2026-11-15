// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package ledgerq

// OBS-RET: the index keeps a window of observation rows.
//
// The index is derived from the raw observation files and the journal and can
// be rebuilt from them. It used to keep every row for ever and, at a fixed
// size, refuse new ones — so the thing that can be rebuilt blocked the thing
// that cannot be repeated, seeing what happens now. Here the oldest
// observation rows leave: by age (the retention window) and, when the space
// the index may use runs out, by need. Journal rows (events.src='chain') are
// never touched.

import (
	"context"
	"database/sql"
	"log"
	"math"
	"time"
)

const (
	dayMs = int64(24 * time.Hour / time.Millisecond)
	// burstBucketMs is the width of an observation_burst_counts bucket.
	burstBucketMs = 1000
	// pruneAgeLimit bounds the rows one pass removes per table for age, so a
	// first run over a long history shares the writer with ingest and queries.
	pruneAgeLimit = 20000
	// When space is needed one step removes about a twentieth of what the
	// index may use, between pruneSpaceMinRows and pruneSpaceMaxRows of the
	// oldest observation rows (indexRowBytes is the measured cost of one);
	// pruneSpaceSteps bounds the steps per check.
	pruneSpaceMinRows = 256
	pruneSpaceMaxRows = 4000
	pruneSpaceSteps   = 64
	indexRowBytes     = 1200
	// The index starts making room at highWater of what it may use and stops
	// at lowWater, so that it does not prune on every batch.
	highWater = 0.95
	lowWater  = 0.85
	// A day's growth is not stated from less than this much history.
	rateMinSpanMs = int64(time.Hour / time.Millisecond)

	gib = int64(1) << 30
)

// IndexWindow is the guidance about the index window and the disk it lives
// on (storage health `window`). All byte values are what this process measured;
// RateBytesPerDay is an estimate from the span the index currently covers and
// includes the journal rows, so it errs towards "needs more".
type IndexWindow struct {
	RetainDays      int     `json:"retain_days"`
	CoversFromMs    int64   `json:"covers_from_ms"`
	PrunedThroughMs int64   `json:"pruned_through_ms"`
	UsedBytes       int64   `json:"used_bytes"`
	FileBytes       int64   `json:"file_bytes"`
	BudgetBytes     int64   `json:"budget_bytes"`
	RateBytesPerDay int64   `json:"rate_bytes_per_day"`
	WindowNeedBytes int64   `json:"window_need_bytes"`
	DiskFreeBytes   int64   `json:"disk_free_bytes"`
	DiskTotalBytes  int64   `json:"disk_total_bytes"`
	DiskFloorBytes  int64   `json:"disk_floor_bytes"`
	DiskDaysLeft    float64 `json:"disk_days_left"`
	Guidance        string  `json:"guidance"`
}

// Guidance words.
const (
	GuidanceKeepAll     = "KEEP_ALL"             // no retention window: nothing is removed
	GuidanceMeasuring   = "MEASURING"            // too little history to state a daily growth
	GuidanceOK          = "OK"                   // the window fits the space the index may use
	GuidanceDiskLow     = "DISK_LOW"             // at this rate the disk reaches its floor before the window is full
	GuidanceCutByBudget = "WINDOW_CUT_BY_BUDGET" // db_max_bytes keeps less than the window
	GuidanceCutByDisk   = "WINDOW_CUT_BY_DISK"   // the disk floor keeps less than the window
)

// usage is what the index really occupies. A SQLite file does not shrink when
// rows are deleted — the pages go to a free list and are reused — so the file
// size says how large the index once was, not how full it is.
func (d *DB) usage() (used, file int64, err error) {
	var pages, free, size int64
	for q, dst := range map[string]*int64{"PRAGMA page_count": &pages, "PRAGMA freelist_count": &free, "PRAGMA page_size": &size} {
		if err = d.sql.QueryRow(q).Scan(dst); err != nil {
			return 0, 0, err
		}
	}
	return (pages - free) * size, pages * size, nil
}

func (d *DB) diskFloor(total int64) int64 {
	if d.storageConfig.DiskFreeMinBytes > 0 {
		return d.storageConfig.DiskFreeMinBytes
	}
	floor := total / 10
	if floor < gib {
		floor = gib
	}
	if floor > 20*gib {
		floor = 20 * gib
	}
	return floor
}

// room is how much the index may use, and which bound sets it ("budget",
// "disk" or ""). The disk bound lets the file grow by whatever the filesystem
// has above its floor; once the disk is at the floor the index may fill the
// file it already has and no more.
func (d *DB) room(file int64) (limit int64, by string) {
	limit = math.MaxInt64
	if b := d.storageConfig.DBMaxBytes; b > 0 {
		limit, by = b, "budget"
	}
	if free, total, ok := diskUsage(d.path); ok {
		grow := free - d.diskFloor(total)
		if grow < 0 {
			grow = 0
		}
		if file+grow < limit {
			limit, by = file+grow, "disk"
		}
	}
	return limit, by
}

// pruneBefore removes observation rows older than cutMs, at most limit per
// table, and reports whether older rows remain. One transaction: a reader
// never sees a record without its event.
func (d *DB) pruneBefore(cutMs int64, limit int) (more bool, err error) {
	tx, err := d.sql.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	steps := []struct {
		q    string
		args []any
	}{
		{`DELETE FROM observation_records WHERE ingest_id IN (SELECT ingest_id FROM observation_records WHERE source_id=? AND received_ms<? ORDER BY received_ms LIMIT ?)`,
			[]any{observationSource, cutMs, limit}},
		// The src='telemetry' literal is what lets the planner use the partial
		// index, and what keeps journal rows (src='chain') out of reach.
		{`DELETE FROM events WHERE seq IN (SELECT seq FROM events WHERE src='telemetry' AND ms<? ORDER BY ms LIMIT ?)`, []any{cutMs, limit}},
		{`DELETE FROM observation_points WHERE rowid IN (SELECT rowid FROM observation_points WHERE facet='all' AND ms<? ORDER BY ms LIMIT ?)`, []any{cutMs, limit}},
		{`DELETE FROM observation_points WHERE rowid IN (SELECT rowid FROM observation_points WHERE facet='tick' AND ms<? ORDER BY ms LIMIT ?)`, []any{cutMs, limit}},
		{`DELETE FROM ticks WHERE ms IN (SELECT ms FROM ticks WHERE ms<? ORDER BY ms LIMIT ?)`, []any{cutMs, limit}},
	}
	for _, s := range steps {
		res, e := tx.Exec(s.q, s.args...)
		if e != nil {
			return false, e
		}
		if n, _ := res.RowsAffected(); n >= int64(limit) {
			more = true
		}
	}
	// A bucket that straddles the edge still counts lines inside the window.
	if _, err = tx.Exec(`DELETE FROM observation_burst_counts WHERE source_id=? AND bucket_ms<?`, observationSource, cutMs-burstBucketMs); err != nil {
		return false, err
	}
	return more, tx.Commit()
}

// pruneForSpace removes the oldest `rows` observation rows (and what belongs
// to them in the other tables). false means there was nothing to remove.
func (d *DB) pruneForSpace(by string, rows int) (bool, error) {
	var cut sql.NullInt64
	err := d.sql.QueryRow(`SELECT received_ms FROM observation_records WHERE source_id=? ORDER BY received_ms LIMIT 1 OFFSET ?`, observationSource, rows).Scan(&cut)
	if err == sql.ErrNoRows {
		// fewer rows than one step: take them all
		err = d.sql.QueryRow(`SELECT MAX(received_ms)+1 FROM observation_records WHERE source_id=?`, observationSource).Scan(&cut)
	}
	if err != nil {
		return false, err
	}
	if !cut.Valid {
		return false, nil // no observation rows at all
	}
	if _, err = d.pruneBefore(cut.Int64, rows*2); err != nil {
		return false, err
	}
	if cut.Int64 > d.spaceCutMs {
		d.spaceCutMs, d.spaceCutBy = cut.Int64, by
	}
	return true, d.setPrunedThrough(cut.Int64)
}

func (d *DB) setPrunedThrough(ms int64) error {
	_, err := d.sql.Exec(`INSERT INTO observation_storage(key,value) VALUES('index_pruned_through_ms',?) ON CONFLICT(key) DO UPDATE SET value=MAX(CAST(value AS INTEGER),CAST(excluded.value AS INTEGER))`, ms)
	return err
}

// makeRoom is the size half of checkStorage. It returns true when the index is
// within what it may use — after removing the oldest observation rows if that
// was needed — and false when nothing removable is left and it is still over.
func (d *DB) makeRoom() (bool, error) {
	used, file, err := d.usage()
	if err != nil {
		return false, err
	}
	limit, by := d.room(file)
	if float64(used) >= float64(limit)*highWater {
		rows := int(limit / 20 / indexRowBytes)
		if rows < pruneSpaceMinRows {
			rows = pruneSpaceMinRows
		}
		if rows > pruneSpaceMaxRows {
			rows = pruneSpaceMaxRows
		}
		for i := 0; i < pruneSpaceSteps; i++ {
			removed, err := d.pruneForSpace(by, rows)
			if err != nil {
				return false, err
			}
			if !removed {
				break
			}
			if used, _, err = d.usage(); err != nil {
				return false, err
			}
			if float64(used) < float64(limit)*lowWater {
				break
			}
		}
	}
	return used < limit, nil
}

// retentionCut is the age edge of this pass: rows older than it are not kept.
// 0 means no window.
func (d *DB) retentionCut(now time.Time) int64 {
	if d.storageConfig.IndexRetainDays <= 0 {
		return 0
	}
	return now.UnixMilli() - int64(d.storageConfig.IndexRetainDays)*dayMs
}

// refreshGuidance computes the index window and what the disk allows, stores
// it in the health and logs a line when the guidance word changes.
func (d *DB) refreshGuidance(now time.Time) {
	w := IndexWindow{RetainDays: d.storageConfig.IndexRetainDays, BudgetBytes: d.storageConfig.DBMaxBytes, DiskDaysLeft: -1}
	ctx := context.Background()
	if used, file, err := d.usage(); err == nil {
		w.UsedBytes, w.FileBytes = used, file
	}
	var from, pruned sql.NullInt64
	if d.sql.QueryRowContext(ctx, `SELECT MIN(received_ms) FROM observation_records WHERE source_id=?`, observationSource).Scan(&from) == nil && from.Valid {
		w.CoversFromMs = from.Int64
	}
	if d.sql.QueryRowContext(ctx, `SELECT CAST(value AS INTEGER) FROM observation_storage WHERE key='index_pruned_through_ms'`).Scan(&pruned) == nil && pruned.Valid {
		w.PrunedThroughMs = pruned.Int64
	}
	if span := now.UnixMilli() - w.CoversFromMs; w.CoversFromMs > 0 && span >= rateMinSpanMs {
		w.RateBytesPerDay = int64(float64(w.UsedBytes) * float64(dayMs) / float64(span))
		w.WindowNeedBytes = w.RateBytesPerDay * int64(w.RetainDays)
	}
	free, total, diskKnown := diskUsage(d.path)
	if diskKnown {
		w.DiskFreeBytes, w.DiskTotalBytes, w.DiskFloorBytes = free, total, d.diskFloor(total)
		if w.RateBytesPerDay > 0 {
			w.DiskDaysLeft = math.Max(0, float64(free-w.DiskFloorBytes)) / float64(w.RateBytesPerDay)
		}
	}
	cut := d.retentionCut(now)
	switch {
	case w.RetainDays <= 0:
		w.Guidance = GuidanceKeepAll
	case d.spaceCutMs > cut && d.spaceCutBy == "disk":
		w.Guidance = GuidanceCutByDisk
	case d.spaceCutMs > cut && d.spaceCutBy == "budget":
		w.Guidance = GuidanceCutByBudget
	case w.RateBytesPerDay == 0:
		w.Guidance = GuidanceMeasuring
	case w.BudgetBytes > 0 && w.WindowNeedBytes > w.BudgetBytes:
		w.Guidance = GuidanceCutByBudget
	case diskKnown && w.WindowNeedBytes-w.UsedBytes > free-w.DiskFloorBytes:
		w.Guidance = GuidanceDiskLow
	default:
		w.Guidance = GuidanceOK
	}
	d.storageMu.Lock()
	changed := d.storageHealth.Window.Guidance != w.Guidance
	d.storageHealth.Window = w
	d.storageMu.Unlock()
	if changed {
		log.Printf("ledger index window: guidance=%s retain_days=%d used=%.1fMiB rate=%.1fMiB/day window_needs=%.1fMiB budget=%.1fMiB disk_free=%.1fGiB disk_floor=%.1fGiB disk_days_left=%.1f covers_from_ms=%d",
			w.Guidance, w.RetainDays, mib(w.UsedBytes), mib(w.RateBytesPerDay), mib(w.WindowNeedBytes), mib(w.BudgetBytes),
			float64(w.DiskFreeBytes)/float64(gib), float64(w.DiskFloorBytes)/float64(gib), w.DiskDaysLeft, w.CoversFromMs)
	}
}

func mib(n int64) float64 { return float64(n) / (1 << 20) }
