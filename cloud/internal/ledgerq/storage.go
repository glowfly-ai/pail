// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package ledgerq

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/glowfly/pail/services/internal/telemetry"
)

const storageSchema = `
CREATE TABLE IF NOT EXISTS observation_origins (
 name TEXT PRIMARY KEY, file_id TEXT NOT NULL, identity TEXT NOT NULL,
 prefix_size INTEGER NOT NULL, prefix_hash TEXT NOT NULL, seen_size INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS observation_storage (
 key TEXT PRIMARY KEY, value TEXT NOT NULL);
`

type IndexStorageHealth struct {
	State            string                  `json:"state"`
	Error            string                  `json:"error,omitempty"`
	ReplacementCount uint64                  `json:"replacement_count"`
	DBBytes          int64                   `json:"db_bytes"`
	WALBytes         int64                   `json:"wal_bytes"`
	Raw              telemetry.StorageHealth `json:"raw"`
}

func (d *DB) StorageHealth() IndexStorageHealth {
	if d == nil {
		return IndexStorageHealth{State: "INDEX_UNAVAILABLE"}
	}
	d.storageMu.Lock()
	defer d.storageMu.Unlock()
	return d.storageHealth
}
func (d *DB) ConfigureStorage(c telemetry.StorageConfig) error {
	if e := c.Validate(); e != nil {
		return e
	}
	d.observationMu.Lock()
	defer d.observationMu.Unlock()
	d.storageConfig = c
	return nil
}
func (d *DB) storageError(code string) {
	d.observationReady.Store(false)
	d.storageMu.Lock()
	d.storageHealth.State = "INDEX_UNAVAILABLE"
	d.storageHealth.Error = code
	d.storageMu.Unlock()
}
func sizeOf(path string) (int64, error) {
	st, e := os.Stat(path)
	if os.IsNotExist(e) {
		return 0, nil
	}
	if e != nil {
		return 0, e
	}
	return st.Size(), nil
}

// CheckStorage is worker-only: HTTP reads the cached diagnostic, never raw
// files. A pinned WAL reader is not success just because PRAGMA returned nil.
func (d *DB) CheckStorage() error {
	d.observationMu.Lock()
	defer d.observationMu.Unlock()
	return d.checkStorage()
}
func (d *DB) checkStorage() error {
	db, e := sizeOf(d.path)
	if e != nil {
		d.storageError("DB_STAT_FAILED")
		return e
	}
	wal, e := sizeOf(d.path + "-wal")
	if e != nil {
		d.storageError("WAL_STAT_FAILED")
		return e
	}
	d.storageMu.Lock()
	d.storageHealth.DBBytes = db
	d.storageHealth.WALBytes = wal
	d.storageMu.Unlock()
	if db >= d.storageConfig.DBMaxBytes {
		d.storageError("DB_DISK_PRESSURE")
		return errors.New("DB_DISK_PRESSURE")
	}
	if wal >= d.storageConfig.WALMaxBytes {
		// Dedicated writer connection; restore the normal bounded wait afterwards.
		conn, e := d.sql.Conn(context.Background())
		if e != nil {
			return e
		}
		defer conn.Close()
		if _, e = conn.ExecContext(context.Background(), "PRAGMA busy_timeout=100"); e != nil {
			return e
		}
		defer conn.ExecContext(context.Background(), "PRAGMA busy_timeout=5000")
		var busy, log, done int
		e = conn.QueryRowContext(context.Background(), "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &log, &done)
		if e != nil || busy != 0 || log != done {
			d.storageError("WAL_BUSY")
			return errors.New("WAL_BUSY")
		}
		wal, e = sizeOf(d.path + "-wal")
		if e != nil || wal >= d.storageConfig.WALMaxBytes {
			d.storageError("WAL_DISK_PRESSURE")
			return errors.New("WAL_DISK_PRESSURE")
		}
		db, e = sizeOf(d.path)
		if e != nil {
			return e
		}
		d.storageMu.Lock()
		d.storageHealth.DBBytes = db
		d.storageHealth.WALBytes = wal
		d.storageMu.Unlock()
		if db >= d.storageConfig.DBMaxBytes {
			d.storageError("DB_DISK_PRESSURE")
			return errors.New("DB_DISK_PRESSURE")
		}
	}
	return nil
}
func prefixHash(f *os.File, n int64) (string, error) {
	h := sha256.New()
	if _, e := io.CopyN(h, io.NewSectionReader(f, 0, n), n); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// resolveOrigin detects replacement before an old byte offset can be reused.
// The detection pass records the new generation + gap, returns an error/503;
// the next pass starts at zero. Old derived origins are never overwritten.
func (d *DB) resolveOrigin(name string, f *os.File, st os.FileInfo) (string, error) {
	if !st.Mode().IsRegular() || telemetry.FileIdentity(st) == "" {
		return "", errors.New("INPUT_NOT_REGULAR")
	}
	var id, identity, hash string
	var n, seen int64
	e := d.sql.QueryRow(`SELECT file_id,identity,prefix_size,prefix_hash,seen_size FROM observation_origins WHERE name=?`, name).Scan(&id, &identity, &n, &hash, &seen)
	if e != nil && e != sql.ErrNoRows {
		return "", e
	}
	fresh := e == sql.ErrNoRows
	replaced := !fresh && (identity != telemetry.FileIdentity(st) || st.Size() < seen)
	if !fresh && !replaced {
		got, e := prefixHash(f, n)
		if e != nil {
			return "", e
		}
		replaced = got != hash
	}
	if fresh || replaced {
		id = name
		if replaced {
			var generation uint64
			ge := d.sql.QueryRow(`SELECT value FROM observation_storage WHERE key='replacement_count'`).Scan(&generation)
			if ge != nil && ge != sql.ErrNoRows {
				return "", ge
			}
			id = fmt.Sprintf("%s#%020d", name, generation+1)
		}
		n = st.Size()
		if n > 4096 {
			n = 4096
		}
		hash, e = prefixHash(f, n)
		if e != nil {
			return "", e
		}
		tx, e := d.sql.Begin()
		if e != nil {
			return "", e
		}
		defer tx.Rollback()
		_, e = tx.Exec(`INSERT INTO observation_origins(name,file_id,identity,prefix_size,prefix_hash,seen_size) VALUES(?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET file_id=excluded.file_id,identity=excluded.identity,prefix_size=excluded.prefix_size,prefix_hash=excluded.prefix_hash,seen_size=excluded.seen_size`, name, id, telemetry.FileIdentity(st), n, hash, st.Size())
		if e != nil {
			return "", e
		}
		if replaced {
			_, e = tx.Exec(`INSERT INTO observation_storage(key,value) VALUES('replacement_count','1') ON CONFLICT(key) DO UPDATE SET value=CAST(value AS INTEGER)+1`)
			if e != nil {
				return "", e
			}
		}
		if e = tx.Commit(); e != nil {
			return "", e
		}
		if replaced {
			d.storageError("INPUT_REPLACED")
			return "", errors.New("INPUT_REPLACED")
		}
	}
	return id, nil
}
func (d *DB) loadRawHealth(dir string) error {
	m, e := telemetry.ReadRawManifest(dir)
	if e != nil {
		return fmt.Errorf("RAW_MANIFEST_INVALID: %w", e)
	}
	// A missing file must have a durable tombstone, not simply vanish from Glob.
	states := map[string]string{}
	for _, r := range m.Files {
		states[r.Name] = r.State
	}
	rows, e := d.sql.Query(`SELECT name FROM observation_origins`)
	if e != nil {
		return e
	}
	var names []string
	for rows.Next() {
		var n string
		if e = rows.Scan(&n); e != nil {
			rows.Close()
			return e
		}
		names = append(names, n)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, name := range names {
		_, e := os.Stat(filepath.Join(dir, name))
		if os.IsNotExist(e) {
			switch states[name] {
			case "delete_intent", "trash", "deleted":
			default:
				return errors.New("INPUT_MISSING")
			}
		} else if e != nil {
			return e
		}
	}
	b, e := json.Marshal(m.Health)
	if e != nil {
		return e
	}
	if _, e = d.sql.Exec(`INSERT INTO observation_storage(key,value) VALUES('raw_health',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, string(b)); e != nil {
		return e
	}
	var replacements uint64
	e = d.sql.QueryRow(`SELECT value FROM observation_storage WHERE key='replacement_count'`).Scan(&replacements)
	if e != nil && e != sql.ErrNoRows {
		return e
	}
	d.storageMu.Lock()
	d.storageHealth.Raw = m.Health
	d.storageHealth.ReplacementCount = replacements
	d.storageMu.Unlock()
	return nil
}

// IndexedRaw proves the *current generation* has consumed the entire closed
// file. The caller also checks the immutable closed hash before durable intent.
func (d *DB) IndexedRaw(r telemetry.RawFile) (bool, error) {
	d.observationMu.Lock()
	defer d.observationMu.Unlock()
	if !d.observationReady.Load() {
		return false, ErrIndexUnavailable
	}
	var off int64
	var identity string
	e := d.sql.QueryRow(`SELECT f.durable_offset,o.identity FROM observation_origins o JOIN observation_files f ON f.file_id=o.file_id WHERE o.name=?`, r.Name).Scan(&off, &identity)
	if e == sql.ErrNoRows {
		return false, nil
	}
	return e == nil && off == r.Size && identity == r.Identity, e
}

func storageCode(e error) string {
	for _, c := range []string{"DB_DISK_PRESSURE", "WAL_DISK_PRESSURE", "WAL_BUSY", "INPUT_REPLACED", "INPUT_MISSING", "RAW_MANIFEST_INVALID"} {
		if strings.Contains(e.Error(), c) {
			return c
		}
	}
	return "INGEST_FAILED"
}
