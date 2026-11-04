// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package ledgerq

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/glowfly/pail/services/internal/telemetry"
)

// Additive extension of the existing derived index. Old telemetry offsets are
// deliberately not reused: they did not index permits or all receipt points.
const observationSchema = `
CREATE TABLE IF NOT EXISTS observation_files (
 file_id TEXT PRIMARY KEY, source_id TEXT NOT NULL, durable_offset INTEGER NOT NULL CHECK(durable_offset>=0),
 lines INTEGER NOT NULL, bad_lines INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS observation_records (
 ingest_id INTEGER PRIMARY KEY, source_id TEXT NOT NULL, file_id TEXT NOT NULL,
 file_offset INTEGER NOT NULL, kind TEXT NOT NULL, received_ms INTEGER NOT NULL,
 robot_hash TEXT NOT NULL, event TEXT NOT NULL, reason INTEGER NOT NULL, payload TEXT NOT NULL,
 UNIQUE(file_id,file_offset));
CREATE INDEX IF NOT EXISTS observation_time ON observation_records(source_id,received_ms,ingest_id);
CREATE INDEX IF NOT EXISTS observation_robot_time ON observation_records(source_id,robot_hash,received_ms,ingest_id);
CREATE INDEX IF NOT EXISTS observation_kind_time ON observation_records(kind,received_ms,ingest_id);
CREATE INDEX IF NOT EXISTS observation_decision_filter ON observation_records(source_id,kind,received_ms,robot_hash,event,reason);
CREATE INDEX IF NOT EXISTS observation_kind_origin ON observation_records(kind,file_id DESC,file_offset DESC);
CREATE TABLE IF NOT EXISTS observation_burst_counts (
 source_id TEXT NOT NULL,bucket_ms INTEGER NOT NULL,robot_hash TEXT NOT NULL,
 event TEXT NOT NULL,reason INTEGER NOT NULL,n INTEGER NOT NULL CHECK(n>0),
 PRIMARY KEY(source_id,bucket_ms,robot_hash,event,reason)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS observation_points (
 facet TEXT NOT NULL, ms INTEGER NOT NULL, prev_ms INTEGER, gap_ms INTEGER,
 PRIMARY KEY(facet,ms));
CREATE INDEX IF NOT EXISTS observation_point_gaps ON observation_points(facet,gap_ms,ms);
CREATE TABLE IF NOT EXISTS observation_latest (
 robot_hash TEXT PRIMARY KEY, file_id TEXT NOT NULL, file_offset INTEGER NOT NULL, payload TEXT NOT NULL);
`

var ErrIndexUnavailable = errors.New("INDEX_UNAVAILABLE")

const observationSource = "legacy-telemetry"
const observationLineMax = 1 << 20
const observationEventMax = 64 << 10

// One coordinator parses each complete line once and commits origins, legacy
// burst projection, receipt points, latest permits and durable offsets together.
// Memory and writer transactions are bounded independently of raw file size.
func (d *DB) ingestObservations(dir string, now time.Time) (st TelemetryStatus, err error) {
	d.observationMu.Lock()
	defer d.observationMu.Unlock()
	defer func() {
		if err != nil {
			d.storageError(storageCode(err))
		}
	}()
	if err = d.checkStorage(); err != nil {
		return st, err
	}
	if err = d.loadRawHealth(dir); err != nil {
		return st, err
	}
	names, err := filepath.Glob(filepath.Join(dir, "decisions-*.jsonl"))
	if err != nil {
		return st, err
	}
	if _, err = os.Stat(dir); err != nil {
		return st, err
	}
	sort.Strings(names)
	for _, path := range names {
		if err = d.ingestObservationFile(path, &st); err != nil {
			return st, err
		}
		st.Files++
	}
	err = d.setMeta("last_ingest_ms", strconv.FormatInt(now.UnixMilli(), 10))
	if err == nil {
		d.observationReady.Store(true)
		d.storageMu.Lock()
		d.storageHealth.State = "READY"
		d.storageHealth.Error = ""
		d.storageMu.Unlock()
	}
	return st, err
}

func (d *DB) ingestObservationFile(path string, st *TelemetryStatus) error {
	basename := filepath.Base(path)
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	lst, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, lst) || lst.Mode()&os.ModeSymlink != 0 {
		return errors.New("INPUT_REPLACED")
	}
	name, err := d.resolveOrigin(basename, f, info)
	if err != nil {
		return err
	}
	var pos, lines, bad int64
	err = d.sql.QueryRow(`SELECT durable_offset,lines,bad_lines FROM observation_files WHERE file_id=?`, name).Scan(&pos, &lines, &bad)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if info.Size() < pos {
		return errors.New("INPUT_REPLACED")
	}
	if _, err = f.Seek(pos, io.SeekStart); err != nil {
		return err
	}
	rd := bufio.NewReaderSize(f, 256<<10)
	for {
		if err = d.checkStorage(); err != nil {
			return err
		}
		tx, err := d.sql.Begin()
		if err != nil {
			return err
		}
		end := false
		for n := 0; n < 256; n++ {
			// ReadSlice never allocates an unbounded malformed line. A missing final
			// newline leaves the durable cursor at the start of that line.
			start := pos
			line := make([]byte, 0, 4096)
			var size int64
			oversized := false
			for {
				part, e := rd.ReadSlice('\n')
				size += int64(len(part))
				if size > observationLineMax {
					oversized = true
					line = nil
				} else if !oversized {
					line = append(line, part...)
				}
				if e == bufio.ErrBufferFull {
					continue
				}
				if e == io.EOF {
					end = true
					break
				}
				if e != nil {
					tx.Rollback()
					return e
				}
				break
			}
			if end {
				break
			}
			pos += size
			lines++
			var rec telemetry.Record
			var perr error
			if oversized {
				perr = errors.New("INPUT_LINE_OVERSIZE")
			} else {
				rec, perr = telemetry.ParseLine(line)
			}
			if perr == nil && rec.Ms > 1<<53-1 {
				perr = errors.New("INVALID_TIME")
			}
			var payload []byte
			if perr == nil {
				payload, perr = json.Marshal(rec)
			}
			if perr == nil && len(payload) > observationEventMax {
				perr = errors.New("PAYLOAD_OVERSIZE")
			}
			if perr != nil {
				bad++
				st.BadLines++
				continue
			}
			inserted, insertErr := tx.Exec(`INSERT OR IGNORE INTO observation_records(source_id,file_id,file_offset,kind,received_ms,robot_hash,event,reason,payload) VALUES(?,?,?,?,?,?,?,?,?)`, observationSource, name, start, rec.Kind, int64(rec.Ms), rec.Robot, rec.Event, int64(rec.ReasonValue), string(payload))
			if insertErr != nil {
				tx.Rollback()
				return insertErr
			}
			insertedCount, err := inserted.RowsAffected()
			if err != nil {
				tx.Rollback()
				return err
			}
			if insertedCount > 0 && rec.Kind == telemetry.KindBurst {
				_, err = tx.Exec(`INSERT INTO observation_burst_counts(source_id,bucket_ms,robot_hash,event,reason,n) VALUES(?,?,?,?,?,1) ON CONFLICT(source_id,bucket_ms,robot_hash,event,reason) DO UPDATE SET n=n+1`, observationSource, int64(rec.Ms/1000*1000), rec.Robot, rec.Event, int64(rec.ReasonValue))
				if err != nil {
					tx.Rollback()
					return err
				}
			}
			if err = insertObservationPoint(tx, "all", int64(rec.Ms)); err != nil {
				tx.Rollback()
				return err
			}
			switch rec.Kind {
			case telemetry.KindTick:
				if err = insertObservationPoint(tx, "tick", int64(rec.Ms)); err != nil {
					tx.Rollback()
					return err
				}
				_, err = tx.Exec(`INSERT OR IGNORE INTO ticks(ms) VALUES(?)`, int64(rec.Ms))
				st.Ticks++
			case telemetry.KindBurst:
				err = insertRow(tx, rowFromBurst(rec, name, lines))
				st.Bursts++
			case telemetry.KindPermit:
				// Preserve the v1 last-in-file-order contract, including backwards wall
				// time and unverified last statements. This is NOT a fresh motion cache.
				_, err = tx.Exec(`INSERT INTO observation_latest(robot_hash,file_id,file_offset,payload) VALUES(?,?,?,?) ON CONFLICT(robot_hash) DO UPDATE SET file_id=excluded.file_id,file_offset=excluded.file_offset,payload=excluded.payload WHERE excluded.file_id>observation_latest.file_id OR (excluded.file_id=observation_latest.file_id AND excluded.file_offset>observation_latest.file_offset)`, rec.Robot, name, start, string(payload))
			}
			if err != nil {
				tx.Rollback()
				return err
			}
		}
		_, err = tx.Exec(`INSERT INTO observation_files(file_id,source_id,durable_offset,lines,bad_lines) VALUES(?,?,?,?,?) ON CONFLICT(file_id) DO UPDATE SET durable_offset=excluded.durable_offset,lines=excluded.lines,bad_lines=excluded.bad_lines`, name, observationSource, pos, lines, bad)
		if err == nil {
			_, err = tx.Exec(`INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, "tel:"+name, strconv.FormatInt(pos, 10))
		}
		if err == nil {
			_, err = tx.Exec(`INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, "tel_lines:"+name, strconv.FormatInt(lines, 10))
		}
		if err != nil {
			tx.Rollback()
			return err
		}
		prefixSize := pos
		if prefixSize > 4096 {
			prefixSize = 4096
		}
		prefix, pe := prefixHash(f, prefixSize)
		if pe != nil {
			tx.Rollback()
			return pe
		}
		if err == nil {
			_, err = tx.Exec(`UPDATE observation_origins SET seen_size=MAX(seen_size,?),prefix_size=?,prefix_hash=? WHERE name=?`, pos, prefixSize, prefix, basename)
		}
		if err != nil {
			tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
		if end {
			current, e := os.Lstat(path)
			if e != nil || !os.SameFile(info, current) || current.Size() < pos {
				return errors.New("INPUT_REPLACED")
			}
			return d.checkStorage()
		}
	}
}

// Each response uses one SQLite snapshot and a deadline (including connection
// pool/busy waits). No query method opens any raw file or invokes LoadDir.
func (d *DB) observationRead(ctx context.Context) (*sql.Tx, error) {
	if d == nil || !d.observationReady.Load() || d.StorageHealth().Raw.State == "OBSERVATION_LOSS" {
		return nil, ErrIndexUnavailable
	}
	tx, err := d.observationReader.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	// Missing extension tables cannot masquerade as an empty healthy response.
	for _, table := range []string{"observation_files", "observation_records", "observation_latest", "observation_points", "observation_burst_counts", "observation_origins", "observation_storage"} {
		var n int
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&n); err != nil || n != 1 {
			tx.Rollback()
			return nil, ErrIndexUnavailable
		}
	}
	return tx, nil
}

// Adjacent receipt points are indexed transactionally. Inserting an old point
// splits the successor edge; duplicate timestamps do not invent new receipts.
// Query-time gap thresholds remain configurable rather than frozen at ingest.
func insertObservationPoint(tx *sql.Tx, facet string, ms int64) error {
	result, err := tx.Exec(`INSERT OR IGNORE INTO observation_points(facet,ms) VALUES(?,?)`, facet, ms)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil || n == 0 {
		return err
	}
	_, err = tx.Exec(`UPDATE observation_points SET prev_ms=(SELECT MAX(ms) FROM observation_points WHERE facet=? AND ms<?), gap_ms=?-(SELECT MAX(ms) FROM observation_points WHERE facet=? AND ms<?) WHERE facet=? AND ms=?`, facet, ms, ms, facet, ms, facet, ms)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`UPDATE observation_points SET prev_ms=?,gap_ms=ms-? WHERE facet=? AND ms=(SELECT MIN(ms) FROM observation_points WHERE facet=? AND ms>?)`, ms, ms, facet, facet, ms)
	return err
}
func observationCoverage(ctx context.Context, tx *sql.Tx, from, to uint64, gap time.Duration, ticksOnly bool) (telemetry.Coverage, error) {
	cov := telemetry.Coverage{FromMs: from, ToMs: to, Gaps: []telemetry.Gap{}}
	facet := "all"
	if ticksOnly {
		facet = "tick"
	}
	if to == 0 {
		var end sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT MAX(ms) FROM observation_points WHERE facet=? AND ms>=?`, facet, from).Scan(&end); err != nil {
			return cov, err
		}
		to = from
		if end.Valid {
			to = uint64(end.Int64)
		}
		cov.ToMs = to
	}
	if to <= from {
		cov.ListenedRatio = 1
		return cov, nil
	}
	var first, last sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT (SELECT ms FROM observation_points WHERE facet=? AND ms>=? AND ms<=? ORDER BY ms LIMIT 1),(SELECT ms FROM observation_points WHERE facet=? AND ms>=? AND ms<=? ORDER BY ms DESC LIMIT 1)`, facet, from, to, facet, from, to).Scan(&first, &last); err != nil {
		return cov, err
	}
	var lost uint64
	add := func(a, b uint64) {
		if b > a && b-a > uint64(gap/time.Millisecond) {
			cov.Gaps = append(cov.Gaps, telemetry.Gap{FromMs: a, ToMs: b})
			lost += b - a
		}
	}
	if !first.Valid {
		add(from, to)
	} else {
		add(from, uint64(first.Int64))
		rows, err := tx.QueryContext(ctx, `SELECT prev_ms,ms FROM observation_points INDEXED BY observation_point_gaps WHERE facet=? AND gap_ms>? AND prev_ms>=? AND ms<=? ORDER BY ms LIMIT 1001`, facet, int64(gap/time.Millisecond), from, to)
		if err != nil {
			return cov, err
		}
		for rows.Next() {
			var a, b uint64
			if err = rows.Scan(&a, &b); err != nil {
				break
			}
			add(a, b)
			if len(cov.Gaps) > 1000 {
				err = errors.New("COVERAGE_PAGE_REQUIRED")
				break
			}
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return cov, err
		}
		add(uint64(last.Int64), to)
	}
	if len(cov.Gaps) > 1000 {
		return cov, errors.New("COVERAGE_PAGE_REQUIRED")
	}
	cov.ListenedRatio = 1 - float64(lost)/float64(to-from)
	return cov, nil
}

// Full millisecond buckets use an exact transactional count, not an estimate.
// At most two boundary buckets read individual rows. Filters remain exact and
// nonmonotonic reception timestamps do not change their original meaning.
func observationMatched(ctx context.Context, tx *sql.Tx, f telemetry.Filter) (int, error) {
	to := f.ToMs
	if to == 0 {
		to = 1<<53 - 1
	}
	if f.FromMs > to {
		return 0, nil
	}
	if f.FromMs > 1<<53-1 || to > 1<<53-1 {
		return 0, errors.New("INVALID_TIME")
	}
	dims := `source_id=?`
	args := []any{observationSource}
	if f.Robot != "" {
		dims += ` AND robot_hash=?`
		args = append(args, f.Robot)
	}
	if f.Event != "" {
		dims += ` AND event=?`
		args = append(args, f.Event)
	}
	if f.Reason != nil {
		dims += ` AND reason=?`
		args = append(args, *f.Reason)
	}
	boundary := func(from, end uint64) (int, error) {
		if from >= end {
			return 0, nil
		}
		var n int
		a := append(append([]any{}, args...), from, end)
		err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM observation_records INDEXED BY observation_decision_filter WHERE kind='burst' AND `+dims+` AND received_ms>=? AND received_ms<?`, a...).Scan(&n)
		return n, err
	}
	first := (f.FromMs + 999) / 1000 * 1000
	end := (to + 1) / 1000 * 1000
	if first >= end {
		return boundary(f.FromMs, to+1)
	}
	var full int
	a := append(append([]any{}, args...), first, end)
	err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(n),0) FROM observation_burst_counts WHERE `+dims+` AND bucket_ms>=? AND bucket_ms<?`, a...).Scan(&full)
	if err != nil {
		return 0, err
	}
	left, err := boundary(f.FromMs, first)
	if err != nil {
		return 0, err
	}
	right, err := boundary(end, to+1)
	return full + left + right, err
}

func (d *DB) ObservationDecisions(ctx context.Context, f telemetry.Filter, gap time.Duration) (telemetry.QueryResult, error) {
	out := telemetry.QueryResult{Rows: []telemetry.Record{}}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := d.observationRead(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	where := `source_id=? AND kind='burst' AND received_ms>=?`
	args := []any{observationSource, f.FromMs}
	if f.ToMs > 0 {
		where += ` AND received_ms<=?`
		args = append(args, f.ToMs)
	}
	if f.Robot != "" {
		where += ` AND robot_hash=?`
		args = append(args, f.Robot)
	}
	if f.Event != "" {
		where += ` AND event=?`
		args = append(args, f.Event)
	}
	if f.Reason != nil {
		where += ` AND reason=?`
		args = append(args, *f.Reason)
	}
	out.Matched, err = observationMatched(ctx, tx, f)
	if err != nil {
		return out, err
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	if limit > 1000 {
		limit = 1000
	}
	// Small historical windows use the time range index before sorting; large
	// windows can stop at the newest matching origins without sorting all rows.
	rowIndex := "observation_decision_filter"
	if out.Matched > 4096 {
		rowIndex = "observation_kind_origin"
	}
	rows, err := tx.QueryContext(ctx, `SELECT payload FROM observation_records INDEXED BY `+rowIndex+` WHERE `+where+` ORDER BY file_id DESC,file_offset DESC LIMIT ?`, append(args, limit)...)
	if err != nil {
		return out, err
	}
	bytes := 0
	for rows.Next() {
		var p string
		if err = rows.Scan(&p); err != nil {
			break
		}
		if bytes+len(p) > 900<<10 {
			break
		}
		bytes += len(p)
		var rec telemetry.Record
		if err = json.Unmarshal([]byte(p), &rec); err != nil {
			break
		}
		out.Rows = append(out.Rows, rec)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return out, err
	}
	for i, j := 0, len(out.Rows)-1; i < j; i, j = i+1, j-1 {
		out.Rows[i], out.Rows[j] = out.Rows[j], out.Rows[i]
	}
	out.Truncated = out.Matched > len(out.Rows)
	out.Coverage, err = observationCoverage(ctx, tx, f.FromMs, f.ToMs, gap, false)
	return out, err
}
func (d *DB) ObservationLiveness(ctx context.Context, f telemetry.Filter, gap time.Duration) (telemetry.Coverage, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := d.observationRead(ctx)
	if err != nil {
		return telemetry.Coverage{}, err
	}
	defer tx.Rollback()
	return observationCoverage(ctx, tx, f.FromMs, f.ToMs, gap, true)
}
func (d *DB) ObservationPermits(ctx context.Context, now time.Time) ([]telemetry.PermitVerdict, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := d.observationRead(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT payload FROM observation_latest ORDER BY robot_hash LIMIT 1025`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []telemetry.PermitVerdict{}
	bytes := 0
	for rows.Next() {
		var p string
		if err = rows.Scan(&p); err != nil {
			return nil, err
		}
		var r telemetry.Record
		if err = json.Unmarshal([]byte(p), &r); err != nil {
			return nil, err
		}
		v := telemetry.PermitState([]telemetry.Record{r}, r.Robot, now)
		encoded, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		bytes += len(encoded) + 1
		if bytes > 900<<10 {
			return nil, errors.New("SUBJECT_PAGE_REQUIRED")
		}
		out = append(out, v)
		if len(out) > 1024 {
			return nil, errors.New("SUBJECT_LIMIT")
		}
	}
	return out, rows.Err()
}
