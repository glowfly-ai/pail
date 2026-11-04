// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// Package ledgerq — AL-1 (implementation contract D6): a query index over the action ledger.
//
// The index is DERIVED, never authoritative. Every chain row carries its
// derivation origin (segment name + byte offset) and must be re-derivable from
// those bytes through the same blackbox reader that verified the chain; a row
// that cannot be reproduced has betrayed the ledger (G-LED-02). Deleting the
// index file loses nothing — `Rebuild` recreates the same row set from the
// segments and the telemetry JSONL.
//
// This package never writes to the blackbox directory. It reads it only through
// blackbox.WalkDir, which verifies hash-chain linkage as it walks — so the walk
// that fills the index is also the chain check the response reports
// (`verify.state`). What the walk does NOT do is verify checkpoint signatures
// or compare against an anchor; those states (`anchored`) are reserved and
// never claimed here (H-B2: an unclaimed check is not a passed check).
package ledgerq

import (
	"database/sql"
	"fmt"
	"github.com/glowfly/pail/services/internal/telemetry"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"

	_ "modernc.org/sqlite" // pure-Go driver; no CGO on the robot image
)

// SchemaVersion is bumped when the events table shape changes; an index with
// another version is rebuilt rather than migrated (it is not a ledger).
const SchemaVersion = 7 // 7: trusted journal identity and transactional frontier; 6: raw generations and retained-origin diagnostics; 5: MOBS observation records and transactional offsets; 2: +reject_code (AL-2) · 3: +target_unverified (AL-3) · 4: +site_model_hash (AL-4)

const schemaSQL = `
CREATE TABLE IF NOT EXISTS events (
  seq            INTEGER PRIMARY KEY,
  src            TEXT NOT NULL,          -- chain | telemetry
  seg            TEXT NOT NULL,          -- segment file | jsonl file
  off            INTEGER NOT NULL,       -- byte offset | line number
  chain_seq      INTEGER,                -- position in the chain walk (chain rows)
  ms             INTEGER NOT NULL,
  robot_hash     TEXT,
  robot_id       TEXT,                   -- chain rows only (payload plaintext)
  kind           TEXT NOT NULL,          -- record type name | burst
  plan_id        TEXT,
  step_id        TEXT,
  token_id       TEXT,
  token_hash     TEXT,                   -- hex sha256(token_id)[:16] — burst correlation
  target         TEXT,
  zone           TEXT,
  action_class   INTEGER,
  action_name    TEXT,
  registered     INTEGER,
  outcome        TEXT NOT NULL,
  reason         INTEGER,
  requester_kind TEXT,
  requester_id   TEXT,
  sig            TEXT,
  chain_id       TEXT,
  key_id         TEXT,
  reject_code    TEXT,
  target_unverified INTEGER,
  site_model_hash TEXT
);
CREATE INDEX IF NOT EXISTS ev_zone_ms     ON events(zone, ms);
CREATE INDEX IF NOT EXISTS ev_ms          ON events(ms, seq);
CREATE INDEX IF NOT EXISTS ev_robot_ms    ON events(robot_hash, ms);
CREATE INDEX IF NOT EXISTS ev_plan        ON events(plan_id);
CREATE INDEX IF NOT EXISTS ev_token       ON events(token_id);
CREATE INDEX IF NOT EXISTS ev_token_hash  ON events(token_hash);
CREATE INDEX IF NOT EXISTS ev_target_ms   ON events(target, ms);
CREATE INDEX IF NOT EXISTS ev_outcome_ms  ON events(outcome, ms);
CREATE UNIQUE INDEX IF NOT EXISTS ev_origin ON events(src, seg, off);
CREATE TABLE IF NOT EXISTS ticks (ms INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
`

// DB is an open index.
type DB struct {
	snapshotCopied    func() // deterministic source-update seam; nil in production
	chainAvailable    atomic.Bool
	chainMu           sync.Mutex
	chainVerifying    atomic.Bool
	observationReader *sql.DB
	sql               *sql.DB
	path              string
	storageMu         sync.Mutex
	storageConfig     telemetry.StorageConfig
	storageHealth     IndexStorageHealth
	observationMu     sync.Mutex
	observationReady  atomic.Bool
	// ZoneResolver (AL-4) resolves zones of rows that predate zone_id from a
	// kept site-model snapshot. Optional; nil = "unresolved" for such rows.
	ZoneResolver ZoneResolver
	// ChainWalker, when set, supplies a receiver for each verification pass.
	// Optional; set before the first IngestChain.
	ChainWalker func() ChainWalk
}

// Open creates or opens the index at path. A schema mismatch is refused
// without altering the old index. Rebuild publishes a separately built DB.
// The directory must exist.
func Open(path string) (*DB, error) {
	if path == "" {
		return nil, fmt.Errorf("ledgerq: empty index path")
	}
	// Inspect an existing schema read-only before running any CREATE/UPDATE.
	// Old/corrupt indexes require the explicit side-by-side rebuild path.
	if _, err := os.Stat(path); err == nil {
		check, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: "mode=ro"}).String())
		if err != nil {
			return nil, err
		}
		var version int
		err = check.QueryRow("SELECT value FROM meta WHERE key='schema'").Scan(&version)
		if err == nil && version == SchemaVersion {
			// CREATE IF NOT EXISTS must not conceal missing durable tables
			// after a restart: offsets without records would look like zero events.
			for _, table := range []string{"events", "ticks", "meta", "observation_files", "observation_records", "observation_latest", "observation_points", "observation_burst_counts", "observation_origins", "observation_storage"} {
				var count int
				err = check.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&count)
				if err != nil || count != 1 {
					err = fmt.Errorf("missing required index table: %s", table)
					break
				}
			}
		}
		check.Close()
		if err != nil || version != SchemaVersion {
			return nil, fmt.Errorf("INDEX_REBUILD_REQUIRED: schema %d (expected %d)", version, SchemaVersion)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	d, err := open(path)
	if err != nil {
		return nil, err
	}
	if err := d.setMeta("schema", strconv.Itoa(SchemaVersion)); err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}

func open(path string) (*DB, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("ledgerq: open %s: %w", path, err)
	}
	db.SetMaxOpenConns(1) // one writer, serialised readers — enough for a robot-side index
	if _, err := db.Exec(schemaSQL + observationSchema + storageSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("ledgerq: schema %s: %w", path, err)
	}
	reader, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: "mode=ro&_pragma=busy_timeout(5000)"}).String())
	if err != nil {
		db.Close()
		return nil, err
	}
	reader.SetMaxOpenConns(4)
	return &DB{sql: db, observationReader: reader, path: path, storageConfig: telemetry.DefaultStorageConfig(), storageHealth: IndexStorageHealth{State: "BUILDING"}}, nil
}

// removeIndexFiles deletes the index and its WAL side files. It is the ONLY
// deletion this package performs, and it touches only the index path — the
// blackbox directory is never a write target (structural test pins this).
func removeIndexFiles(path string) error {
	for _, p := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("ledgerq: remove %s: %w", p, err)
		}
	}
	return nil
}

// Close releases the handle.
func (d *DB) Close() error { d.observationReader.Close(); return d.sql.Close() }

// Path is the index file location.
func (d *DB) Path() string { return d.path }

func (d *DB) meta(key string) (string, bool) {
	var v string
	err := d.sql.QueryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if err != nil {
		return "", false
	}
	return v, true
}

func (d *DB) metaInt(key string) (int64, bool) {
	v, ok := d.meta(key)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func (d *DB) setMeta(key, value string) error {
	_, err := d.sql.Exec(`INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

func (d *DB) count(where string, args ...any) (int64, error) {
	var n int64
	err := d.sql.QueryRow(`SELECT COUNT(*) FROM events `+where, args...).Scan(&n)
	return n, err
}

// Stats is the index's own bookkeeping — shown in responses so a stale index
// never arrives looking like "no events".
type Stats struct {
	FrontierJSON   string `json:"-"`
	Path           string `json:"path"`
	ChainRows      int64  `json:"chain_rows"`
	TelemetryRows  int64  `json:"telemetry_rows"`
	Ticks          int64  `json:"ticks"`
	LastIngestMs   uint64 `json:"last_ingest_ms"`
	ChainState     string `json:"chain_state"` // ok | chain_error | absent | never
	ChainError     string `json:"chain_error,omitempty"`
	CheckedToSeq   int64  `json:"checked_to_seq"`
	CheckedToMs    uint64 `json:"checked_to_ms"`
	ChainWalkMs    uint64 `json:"chain_walk_ms"`
	TelemetryFiles int64  `json:"telemetry_files"`
}

// Stats reads the bookkeeping.
type ledgerReader interface {
	QueryRow(string, ...any) *sql.Row
	Query(string, ...any) (*sql.Rows, error)
}

func (d *DB) Stats() (Stats, error) {
	tx, err := d.observationReader.Begin()
	if err != nil {
		return Stats{}, err
	}
	defer tx.Rollback()
	return d.stats(tx, true)
}

// StatsAsRecorded is Stats for a process that does not run the live chain
// verifier because it verified the chain itself just now: the offline
// -reindex. The live override ("unverified / VERIFICATION_UNAVAILABLE" when no
// verifier runs in this process) describes a serving collector, and printed by
// -reindex beside "chain: ok" it read as a failure.
func (d *DB) StatsAsRecorded() (Stats, error) {
	tx, err := d.observationReader.Begin()
	if err != nil {
		return Stats{}, err
	}
	defer tx.Rollback()
	return d.stats(tx, false)
}

func (d *DB) stats(r ledgerReader, live bool) (Stats, error) {
	var s Stats
	s.Path = filepath.Base(d.path)
	var err error
	if s.ChainRows, err = countRead(r, `WHERE src = 'chain'`); err != nil {
		return s, err
	}
	if s.TelemetryRows, err = countRead(r, `WHERE src = 'telemetry'`); err != nil {
		return s, err
	}
	if err = r.QueryRow(`SELECT COUNT(*) FROM ticks`).Scan(&s.Ticks); err != nil {
		return s, err
	}
	if err = r.QueryRow(`SELECT COUNT(*) FROM meta WHERE key LIKE 'tel:%'`).Scan(&s.TelemetryFiles); err != nil {
		return s, err
	}
	if v, ok := metaIntRead(r, "last_ingest_ms"); ok {
		s.LastIngestMs = uint64(v)
	}
	s.ChainState = "never"
	if v, ok := metaRead(r, "chain_state"); ok {
		s.ChainState = v
	}
	s.ChainError, _ = metaRead(r, "chain_error")
	if v, ok := metaIntRead(r, "chain_checked_to_seq"); ok {
		s.CheckedToSeq = v
	}
	if v, ok := metaIntRead(r, "chain_checked_to_ms"); ok {
		s.CheckedToMs = uint64(v)
	}
	if v, ok := metaIntRead(r, "chain_walk_ms"); ok {
		s.ChainWalkMs = uint64(v)
	}
	s.FrontierJSON, _ = metaRead(r, "chain_diagnostic")
	if !live {
		return s, nil
	}
	if d.chainVerifying.Load() {
		s.ChainState = "verifying"
	} else if !d.chainAvailable.Load() && s.ChainState == "ok" {
		s.ChainState = "unverified"
		s.ChainError = "VERIFICATION_UNAVAILABLE"
	}
	return s, nil
}

// DefaultIndexPath places the index beside the telemetry JSONL.
func DefaultIndexPath(telemetryDir string) string {
	return filepath.Join(telemetryDir, "ledger.sqlite")
}

func metaRead(r ledgerReader, key string) (string, bool) {
	var v string
	err := r.QueryRow("SELECT value FROM meta WHERE key=?", key).Scan(&v)
	return v, err == nil
}
func metaIntRead(r ledgerReader, key string) (int64, bool) {
	v, ok := metaRead(r, key)
	if !ok {
		return 0, false
	}
	n, e := strconv.ParseInt(v, 10, 64)
	return n, e == nil
}
func countRead(r ledgerReader, where string, args ...any) (int64, error) {
	var n int64
	err := r.QueryRow("SELECT COUNT(*) FROM events "+where, args...).Scan(&n)
	return n, err
}
