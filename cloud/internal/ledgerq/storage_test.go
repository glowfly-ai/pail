// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package ledgerq

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/glowfly/pail/services/internal/telemetry"
)

func TestMOBSStorageGenerationReplacement(t *testing.T) {
	for _, mode := range []string{"inode_same_size", "truncate", "rewrite_same_inode"} {
		t.Run(mode, func(t *testing.T) {
			d, dir := obsDB(t)
			name := "decisions-01.jsonl"
			path := filepath.Join(dir, name)
			body := obsBurst + "\n"
			obsWrite(t, dir, name, body)
			obsIngest(t, d, dir)
			switch mode {
			case "inode_same_size":
				if e := os.Rename(path, path+".old"); e != nil {
					t.Fatal(e)
				}
				obsWrite(t, dir, name, strings.Replace(body, `"ms":1100`, `"ms":2100`, 1))
			case "truncate":
				obsWrite(t, dir, name, `{"v":1,"kind":"tick","ms":2100}`+"\n")
			case "rewrite_same_inode":
				obsWrite(t, dir, name, strings.Replace(body, `"ms":1100`, `"ms":2100`, 1))
			}
			if _, e := d.IngestTelemetry(dir, time.Now()); e == nil || !strings.Contains(e.Error(), "INPUT_REPLACED") {
				t.Fatal("replacement silent", e)
			}
			if _, e := d.ObservationPermits(context.Background(), time.Now()); e == nil {
				t.Fatal("replacement READY")
			}
			obsIngest(t, d, dir)
			var count, origins int
			d.sql.QueryRow(`SELECT COUNT(*) FROM observation_records`).Scan(&count)
			d.sql.QueryRow(`SELECT COUNT(*) FROM observation_files`).Scan(&origins)
			if count != 2 || origins != 2 || d.StorageHealth().ReplacementCount != 1 {
				t.Fatal(count, origins, d.StorageHealth())
			}
			obsIngest(t, d, dir)
			d.sql.QueryRow(`SELECT COUNT(*) FROM observation_records`).Scan(&count)
			if count != 2 {
				t.Fatal("retry duplicated", count)
			}
			d.Close()
			var e error
			d, e = Open(filepath.Join(dir, "ledger.sqlite"))
			if e != nil {
				t.Fatal(e)
			}
			defer d.Close()
			obsIngest(t, d, dir)
			if d.StorageHealth().ReplacementCount != 1 {
				t.Fatal("restart lost gap")
			}
		})
	}
}
func TestMOBSStorageMissingInputIsNotEmptySuccess(t *testing.T) {
	d, dir := obsDB(t)
	obsWrite(t, dir, "decisions-01.jsonl", obsBurst+"\n")
	obsIngest(t, d, dir)
	os.Rename(filepath.Join(dir, "decisions-01.jsonl"), filepath.Join(dir, "saved.raw"))
	if _, e := d.IngestTelemetry(dir, time.Now()); e == nil || !strings.Contains(e.Error(), "INPUT_MISSING") {
		t.Fatal(e)
	}
	if _, e := d.ObservationDecisions(context.Background(), telemetry.Filter{}, time.Second); e == nil {
		t.Fatal("missing input READY")
	}
}
func TestMOBSStorageRetentionRealIndexBoundary(t *testing.T) {
	d, dir := obsDB(t)
	c := telemetry.DefaultStorageConfig()
	c.RetentionMode = "managed"
	c.RawMaxBytes = 2 << 30
	c.RetainDays = 7
	c.TrashGraceSeconds = 1
	s, e := telemetry.OpenStoreWithConfig(dir, c)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	at := time.UnixMilli(1700000000000)
	for _, dt := range []time.Duration{0, 24 * time.Hour} {
		b, _ := telemetry.MarshalTick(uint64(at.Add(dt).UnixMilli()))
		if e = s.AppendLine(b, at.Add(dt)); e != nil {
			t.Fatal(e)
		}
	}
	m, e := telemetry.ReadRawManifest(dir)
	if e != nil {
		t.Fatal(e)
	}
	closed := m.Files[0]
	// Before ingest no proof is available; after ingest exact byte offset is needed.
	if ok, _ := d.IndexedRaw(closed); ok {
		t.Fatal("unindexed proof")
	}
	obsIngest(t, d, dir)
	if ok, e := d.IndexedRaw(closed); !ok || e != nil {
		t.Fatal(ok, e)
	}
	d.sql.Exec(`UPDATE observation_files SET durable_offset=durable_offset-1 WHERE file_id=?`, closed.Name)
	if e = s.Maintain(at.Add(10*24*time.Hour), d.IndexedRaw); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(dir, closed.Name)); e != nil {
		t.Fatal("incomplete deleted", e)
	}
	d.sql.Exec(`UPDATE observation_files SET durable_offset=durable_offset+1 WHERE file_id=?`, closed.Name)
	if e = s.Maintain(at.Add(10*24*time.Hour), d.IndexedRaw); e != nil {
		t.Fatal(e)
	}
	obsIngest(t, d, dir)
	if !d.StorageHealth().Raw.RawIncomplete || d.StorageHealth().Raw.DeletionRevision != 1 {
		t.Fatal(d.StorageHealth())
	}
	if _, e = d.ObservationLiveness(context.Background(), telemetry.Filter{}, time.Second); e != nil {
		t.Fatal(e)
	}
	d.Close()
	d, e = Open(filepath.Join(dir, "ledger.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	obsIngest(t, d, dir)
	if !d.StorageHealth().Raw.RawIncomplete {
		t.Fatal("restart raw absence hidden")
	}
}
func TestMOBSStorageWALBusyAndRecovery(t *testing.T) {
	d, dir := obsDB(t)
	obsWrite(t, dir, "decisions-01.jsonl", obsBurst+"\n")
	obsIngest(t, d, dir)
	if _, e := d.sql.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); e != nil {
		t.Fatal(e)
	}
	tx, e := d.observationReader.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	var n int
	if e = tx.QueryRow(`SELECT COUNT(*) FROM observation_records`).Scan(&n); e != nil {
		t.Fatal(e)
	}
	if _, e = d.sql.Exec(`PRAGMA wal_autocheckpoint=0`); e != nil {
		t.Fatal(e)
	}
	if _, e = d.sql.Exec(`INSERT INTO observation_storage(key,value) VALUES('test','one')`); e != nil {
		t.Fatal(e)
	}
	c := telemetry.DefaultStorageConfig()
	c.WALMaxBytes = 1
	if e = d.ConfigureStorage(c); e != nil {
		t.Fatal(e)
	}
	start := time.Now()
	e = d.CheckStorage()
	if e == nil || !strings.Contains(e.Error(), "WAL_BUSY") {
		t.Fatal("pinned reader did not block checkpoint", e)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("unbounded busy wait")
	}
	if _, e = d.ObservationPermits(context.Background(), time.Now()); e == nil {
		t.Fatal("WAL failure READY")
	}
	t.Logf("real pinned-reader WAL busy: duration=%s health=%+v", time.Since(start), d.StorageHealth())
	tx.Rollback()
	c.WALMaxBytes = 256 << 20
	d.ConfigureStorage(c)
	if e = d.CheckStorage(); e != nil {
		t.Fatal(e)
	}
	obsIngest(t, d, dir)
	if d.StorageHealth().State != "READY" {
		t.Fatal(d.StorageHealth())
	}
}
func TestMOBSStorageDBBudgetAndSchemaLoss(t *testing.T) {
	d, dir := obsDB(t)
	obsWrite(t, dir, "decisions-01.jsonl", obsBurst+"\n")
	obsIngest(t, d, dir)
	c := telemetry.DefaultStorageConfig()
	c.DBMaxBytes = 1
	d.ConfigureStorage(c)
	if e := d.CheckStorage(); e == nil || !strings.Contains(e.Error(), "DB_DISK_PRESSURE") {
		t.Fatal(e)
	}
	if _, e := d.ObservationDecisions(context.Background(), telemetry.Filter{}, time.Second); e == nil {
		t.Fatal("budget failure READY")
	}
	d.ConfigureStorage(telemetry.DefaultStorageConfig())
	obsIngest(t, d, dir)
	d.sql.Exec(`DROP TABLE observation_origins`)
	if _, e := d.ObservationPermits(context.Background(), time.Now()); e == nil {
		t.Fatal("missing identity table READY")
	}
	d.Close()
	if other, e := Open(filepath.Join(dir, "ledger.sqlite")); e == nil {
		other.Close()
		t.Fatal("missing table recreated")
	}
}

func TestMOBSStorageInitiallyEmptyFileGrowsThenRewrites(t *testing.T) {
	d, dir := obsDB(t)
	name := "decisions-01.jsonl"
	obsWrite(t, dir, name, "")
	obsIngest(t, d, dir)
	obsWrite(t, dir, name, obsBurst+"\n")
	obsIngest(t, d, dir)
	obsWrite(t, dir, name, strings.Replace(obsBurst, `"ms":1100`, `"ms":2100`, 1)+"\n")
	if _, e := d.IngestTelemetry(dir, time.Now()); e == nil || !strings.Contains(e.Error(), "INPUT_REPLACED") {
		t.Fatal("empty prefix hid rewrite", e)
	}
}

func TestMOBSStorageSQLiteFullRollsBackOffset(t *testing.T) {
	d, dir := obsDB(t)
	name := "decisions-01.jsonl"
	obsWrite(t, dir, name, obsBurst+"\n")
	obsIngest(t, d, dir)
	var pages, before, after, count int64
	if e := d.sql.QueryRow(`PRAGMA page_count`).Scan(&pages); e != nil {
		t.Fatal(e)
	}
	if _, e := d.sql.Exec(fmt.Sprintf("PRAGMA max_page_count=%d", pages)); e != nil {
		t.Fatal(e)
	}
	if e := d.sql.QueryRow(`SELECT durable_offset FROM observation_files WHERE file_id=?`, name).Scan(&before); e != nil {
		t.Fatal(e)
	}
	f, e := os.OpenFile(filepath.Join(dir, name), os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.WriteString(strings.Repeat(obsBurst+"\n", 256)); e != nil {
		t.Fatal(e)
	}
	f.Close()
	_, e = d.IngestTelemetry(dir, time.Now())
	if e == nil || !strings.Contains(strings.ToLower(e.Error()), "full") {
		t.Fatalf("actual SQLite page quota did not fail: %v", e)
	}
	d.sql.QueryRow(`SELECT durable_offset FROM observation_files WHERE file_id=?`, name).Scan(&after)
	d.sql.QueryRow(`SELECT COUNT(*) FROM observation_records`).Scan(&count)
	if before != after || count != 1 {
		t.Fatal("SQLITE_FULL committed partial offset/rows", before, after, count)
	}
	if _, qe := d.ObservationDecisions(context.Background(), telemetry.Filter{}, time.Second); qe == nil {
		t.Fatal("SQLITE_FULL served READY")
	}
	t.Logf("SQLite real page quota error=%v; offset_before=%d offset_after=%d records=%d", e, before, after, count)
}
