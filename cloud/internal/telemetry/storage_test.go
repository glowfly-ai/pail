// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package telemetry

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func mustStore(t *testing.T, dir string, c StorageConfig) *Store {
	t.Helper()
	s, e := OpenStoreWithConfig(dir, c)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func appendTick(t *testing.T, s *Store, at time.Time) {
	t.Helper()
	b, e := MarshalTick(uint64(at.UnixMilli()))
	if e != nil {
		t.Fatal(e)
	}
	if e = s.AppendLine(b, at); e != nil {
		t.Fatal(e)
	}
}
func managedConfig() StorageConfig {
	c := DefaultStorageConfig()
	c.RetentionMode = "managed"
	c.RawMaxBytes = 2 << 30
	c.RetainDays = 7
	c.TrashGraceSeconds = 1
	return c
}
func TestMOBSStorageRotation64MiB(t *testing.T) {
	dir := t.TempDir()
	s := mustStore(t, dir, DefaultStorageConfig())
	at := time.Unix(1700000000, 0)
	line := append([]byte(`{"padding":"`), bytes.Repeat([]byte("x"), 65521)...)
	line = append(line, []byte(`"}`)...)
	for i := 0; i < 1100; i++ {
		if e := s.AppendLine(line, at); e != nil {
			t.Fatal(e)
		}
	}
	if len(s.m.Files) != 2 || s.m.Files[0].State != "closed" || s.m.Files[0].Size > 64<<20 || s.m.Files[0].Size < 63<<20 {
		t.Fatalf("rotation %+v", s.m.Files)
	}
	n, h, _, e := hashRaw(filepath.Join(dir, s.m.Files[0].Name))
	if e != nil || h != s.m.Files[0].SHA256 || n != s.m.Files[0].Size {
		t.Fatal(n, h, e)
	}
	appendTick(t, s, at.Add(24*time.Hour))
	if len(s.m.Files) != 3 {
		t.Fatal("UTC roll", len(s.m.Files))
	}
	appendTick(t, s, at) // backwards wall time creates a new segment, never reopens closed bytes
	if len(s.m.Files) != 4 {
		t.Fatal("reopened a closed file")
	}
	t.Logf("actual first closed bytes=%d; limit=%d", n, RawSegmentBytes)
}
func TestMOBSStorageLockRestartAndReplacement(t *testing.T) {
	dir := t.TempDir()
	s := mustStore(t, dir, DefaultStorageConfig())
	at := time.Unix(1700000000, 0)
	appendTick(t, s, at)
	if other, e := OpenStore(dir); e == nil {
		other.Close()
		t.Fatal("concurrent writer accepted")
	}
	original := s.m.Files[0].Name
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	s = mustStore(t, dir, DefaultStorageConfig())
	appendTick(t, s, at)
	if s.m.Files[0].State != "closed" || s.m.Files[1].Name == original {
		t.Fatal("restart reused closed file")
	}
	p := filepath.Join(dir, s.m.Files[1].Name)
	b, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(p, p+".old"); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(p, b, 0600); e != nil {
		t.Fatal(e)
	}
	if e = s.AppendLine([]byte(`{"v":1,"kind":"tick","ms":9}`), at); e == nil || !strings.Contains(e.Error(), "INPUT_REPLACED") {
		t.Fatal(e)
	}
	if s.Health().LossCount != 1 {
		t.Fatal(s.Health())
	}
	if got, _ := os.ReadFile(p); !bytes.Equal(got, b) {
		t.Fatal("foreign replacement written")
	}
}
func TestMOBSStorageCrashRestart(t *testing.T) {
	if dir := os.Getenv("MOBS_CRASH_WRITER"); dir != "" {
		s, e := OpenStore(dir)
		if e != nil {
			os.Exit(3)
		}
		if e = s.AppendLine([]byte(`{"v":1,"kind":"tick","ms":4}`), time.UnixMilli(4)); e != nil {
			os.Exit(4)
		}
		os.Exit(0)
	}
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestMOBSStorageCrashRestart$")
	cmd.Env = append(os.Environ(), "MOBS_CRASH_WRITER="+dir)
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatal(string(b), e)
	}
	s := mustStore(t, dir, DefaultStorageConfig())
	if len(s.m.Files) != 1 || s.m.Files[0].State != "closed" || s.m.Files[0].Size == 0 {
		t.Fatal(s.m)
	}
	appendTick(t, s, time.UnixMilli(5))
	if len(s.m.Files) != 2 {
		t.Fatal("crash epoch reused")
	}
}
func TestMOBSStorageRetentionGuardsAndGrace(t *testing.T) {
	dir := t.TempDir()
	s := mustStore(t, dir, managedConfig())
	at := time.Unix(1700000000, 0)
	appendTick(t, s, at)
	appendTick(t, s, at.Add(24*time.Hour))
	blackbox := filepath.Join(dir, "pail_blackbox.seg")
	os.WriteFile(blackbox, []byte("canonical"), 0600)
	legacy := filepath.Join(dir, "decisions-20200101.jsonl")
	os.WriteFile(legacy, []byte("legacy"), 0600)
	now := at.Add(10 * 24 * time.Hour)
	if e := s.Maintain(now, func(RawFile) (bool, error) { return false, nil }); e != nil {
		t.Fatal(e)
	}
	if s.m.Files[0].State != "closed" {
		t.Fatal("unindexed deleted")
	}
	if e := s.Maintain(now, func(RawFile) (bool, error) { return true, nil }); e != nil {
		t.Fatal(e)
	}
	if s.m.Files[0].State != "trash" || s.m.Files[1].State != "active" || !s.Health().RawIncomplete || s.Health().DeletionRevision != 1 {
		t.Fatal(s.m)
	}
	trash := filepath.Join(dir, ".observation-trash", s.m.Files[0].ID+".jsonl")
	if _, e := os.Stat(trash); e != nil {
		t.Fatal("grace missing", e)
	}
	if e := s.Maintain(now.Add(2*time.Second), nil); e != nil {
		t.Fatal(e)
	}
	if s.m.Files[0].State != "deleted" {
		t.Fatal(s.m)
	}
	for p, want := range map[string]string{blackbox: "canonical", legacy: "legacy"} {
		b, e := os.ReadFile(p)
		if e != nil || string(b) != want {
			t.Fatal(p, e)
		}
	}
	m, e := ReadRawManifest(dir)
	if e != nil || !m.Health.RawIncomplete || m.Health.RawRemovedThroughMs != at.UnixMilli() {
		t.Fatal(m, e)
	}
}
func TestMOBSStorageNoImplicitDeletionQuotaAndInvalidLine(t *testing.T) {
	c := DefaultStorageConfig()
	c.RawMaxBytes = 80
	dir := t.TempDir()
	s := mustStore(t, dir, c)
	at := time.UnixMilli(1000)
	appendTick(t, s, at)
	before := s.m.Files[0].Size
	if e := s.AppendLine(bytes.Repeat([]byte("x"), RawLineBytes+1), at); e == nil {
		t.Fatal("oversized accepted")
	}
	if s.m.Files[0].Size != before {
		t.Fatal("oversize wrote partial")
	}
	for i := 0; i < 5; i++ {
		s.AppendLine([]byte(`{"v":1,"kind":"tick","ms":1000}`), at)
	}
	if s.Health().LastError != "DISK_PRESSURE" || s.Health().LossCount == 0 {
		t.Fatal(s.Health())
	}
	s.Close()
	s = mustStore(t, dir, c)
	if e := s.Maintain(at.Add(100*24*time.Hour), func(RawFile) (bool, error) { return true, nil }); e != nil {
		t.Fatal(e)
	}
	if s.m.Files[0].State != "closed" {
		t.Fatal("implicit retention")
	}
}
func TestMOBSStorageDeletionFailureAndIntentRecovery(t *testing.T) {
	for _, point := range []string{"intent", "renamed", "unlinked"} {
		t.Run(point, func(t *testing.T) {
			dir := t.TempDir()
			s := mustStore(t, dir, managedConfig())
			at := time.UnixMilli(1000)
			appendTick(t, s, at)
			appendTick(t, s, at.Add(24*time.Hour))
			r := &s.m.Files[0]
			r.State = "delete_intent"
			r.DeleteAfterMs = 1
			s.m.Health.RawIncomplete = true
			s.m.Health.DeletionRevision = 1
			if e := s.save(); e != nil {
				t.Fatal(e)
			}
			if point != "intent" {
				if e := s.moveToTrash(0); e != nil {
					t.Fatal(e)
				}
			}
			if point == "renamed" {
				r.State = "delete_intent"
				if e := s.save(); e != nil {
					t.Fatal(e)
				}
			}
			if point == "unlinked" {
				if e := os.Remove(filepath.Join(dir, ".observation-trash", r.ID+".jsonl")); e != nil {
					t.Fatal(e)
				}
			}
			s.Close()
			s = mustStore(t, dir, managedConfig())
			if !s.Health().RawIncomplete {
				t.Fatal("lost tombstone")
			}
			if e := s.Maintain(at.Add(48*time.Hour), nil); e != nil {
				t.Fatal(e)
			}
			if s.m.Files[0].State != "deleted" {
				t.Fatal(s.m)
			}
		})
	}
	dir := t.TempDir()
	s := mustStore(t, dir, managedConfig())
	at := time.UnixMilli(1000)
	appendTick(t, s, at)
	appendTick(t, s, at.Add(24*time.Hour))
	// A real filesystem conflict, not a mocked os.Rename return code.
	os.WriteFile(filepath.Join(dir, ".observation-trash"), []byte("obstacle"), 0600)
	if e := s.Maintain(at.Add(10*24*time.Hour), func(RawFile) (bool, error) { return true, nil }); e == nil {
		t.Fatal("delete failure accepted")
	}
	if s.Health().LastError != "RETENTION_MOVE_FAILED" || s.m.Files[0].State != "delete_intent" {
		t.Fatal(s.m)
	}
	if _, e := os.Stat(filepath.Join(dir, s.m.Files[0].Name)); e != nil {
		t.Fatal("source lost", e)
	}
}
func TestMOBSStorageRealENOSPC(t *testing.T) {
	root := os.Getenv("MOBS_QUOTA_DIR")
	if root == "" {
		t.Skip("requires bounded tmpfs fixture")
	}
	dir, e := os.MkdirTemp(root, "enospc-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	s := mustStore(t, dir, DefaultStorageConfig())
	line := []byte(`{"data":"` + strings.Repeat("x", 900000) + `"}`)
	if e = s.AppendLine(line, time.Now()); e != nil {
		t.Fatal(e)
	}
	e = s.AppendLine(line, time.Now())
	if e == nil || !strings.Contains(e.Error(), "RAW_WRITE_FAILED") {
		t.Fatalf("expected actual ENOSPC write failure: %v", e)
	}
	if s.Health().LossCount != 1 || s.Health().State != "OBSERVATION_LOSS" {
		t.Fatal(s.Health())
	}
	t.Logf("bounded tmpfs failure: %v; health=%+v", e, s.Health())
}
func TestMOBSStorageStrictConfig(t *testing.T) {
	good := `{"schema_version":1,"retention_mode":"managed","raw_max_bytes":2147483648,"retain_days":7}`
	c, e := ParseStorageConfig([]byte(good))
	if e != nil || c.RetainDays != 7 {
		t.Fatal(c, e)
	}
	for _, b := range []string{`{}`, `{"schema_version":1,"schema_version":1}`, `{"schema_version":2}`, `{"schema_version":1,"x":2}`, `{"schema_version":1,"db_max_bytes":0}`, `{"schema_version":1,"raw_max_bytes":-1}`, `{"schema_version":1,"retention_mode":"managed"}`, good + ` {}`, `{"schema_version":1,"retain_days":1.2}`} {
		if _, e := ParseStorageConfig([]byte(b)); e == nil {
			t.Fatal("accepted", b)
		}
	}
	b, _ := json.Marshal(DefaultStorageConfig())
	if _, e = ParseStorageConfig(b); e != nil {
		t.Fatal(e)
	}
}

func TestMOBSStorageIntentMustPrecedeMove(t *testing.T) {
	dir := t.TempDir()
	s := mustStore(t, dir, managedConfig())
	at := time.UnixMilli(1000)
	appendTick(t, s, at)
	appendTick(t, s, at.Add(24*time.Hour))
	path := filepath.Join(dir, manifestName)
	if e := os.Rename(path, path+".saved"); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(path, 0700); e != nil {
		t.Fatal(e)
	}
	if e := s.Maintain(at.Add(10*24*time.Hour), func(RawFile) (bool, error) { return true, nil }); e == nil {
		t.Fatal("undurable intent accepted")
	}
	if _, e := os.Stat(filepath.Join(dir, s.m.Files[0].Name)); e != nil {
		t.Fatal("raw moved before durable intent", e)
	}
	if _, e := os.Stat(filepath.Join(dir, ".observation-trash", s.m.Files[0].ID+".jsonl")); !os.IsNotExist(e) {
		t.Fatal("trash exists before intent")
	}
}
func TestMOBSStoragePurgeFailurePreservesTombstone(t *testing.T) {
	dir := t.TempDir()
	s := mustStore(t, dir, managedConfig())
	at := time.UnixMilli(1000)
	appendTick(t, s, at)
	appendTick(t, s, at.Add(24*time.Hour))
	now := at.Add(10 * 24 * time.Hour)
	if e := s.Maintain(now, func(RawFile) (bool, error) { return true, nil }); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, ".observation-trash", s.m.Files[0].ID+".jsonl")
	if e := os.Rename(path, path+".saved"); e != nil {
		t.Fatal(e)
	}
	os.Mkdir(path, 0700)
	if e := s.Maintain(now.Add(2*time.Second), nil); e == nil {
		t.Fatal("foreign trash accepted")
	}
	if s.m.Files[0].State != "trash" || !s.Health().RawIncomplete || s.Health().State != "OBSERVATION_LOSS" {
		t.Fatal(s.m)
	}
	if _, e := os.Stat(path + ".saved"); e != nil {
		t.Fatal("saved evidence lost", e)
	}
}
func TestMOBSStorageRecoveredTornTailDeclared(t *testing.T) {
	dir := t.TempDir()
	s := mustStore(t, dir, DefaultStorageConfig())
	appendTick(t, s, time.UnixMilli(1000))
	// Model process death with a partial last write and an active manifest.
	s.f.Write([]byte(`{"v":1`))
	s.failed = true
	s.Close()
	s = mustStore(t, dir, DefaultStorageConfig())
	if s.Health().LastError != "RAW_TORN_TAIL" || s.Health().LossCount != 1 {
		t.Fatal(s.Health())
	}
	b, e := os.ReadFile(filepath.Join(dir, s.m.Files[0].Name))
	if e != nil || !bytes.HasSuffix(b, []byte(`{"v":1`)) {
		t.Fatal("torn tail rewritten", e)
	}
}

func TestMOBSStorageIngressBoundedDuringDiskStall(t *testing.T) {
	s := mustStore(t, t.TempDir(), DefaultStorageConfig())
	at := time.UnixMilli(1000)
	// Block only the disk worker. Producer and HTTP health use separate locks.
	s.mu.Lock()
	q := NewIngress(s, nil)
	line := []byte(`{"padding":"` + strings.Repeat("x", 900000) + `"}`)
	start := time.Now()
	accepted := 0
	for i := 0; i < 20; i++ {
		if e := q.AppendLine(line, at); e == nil {
			accepted++
		}
	}
	h := q.Health()
	q.mu.Lock()
	reserved := q.bytes
	q.mu.Unlock()
	s.mu.Unlock()
	q.Close()
	if time.Since(start) > 2*time.Second || accepted < 1 || accepted > 4 || reserved > 4<<20 {
		t.Fatal(accepted, reserved, time.Since(start))
	}
	if h.LossCount != uint64(20-accepted) || h.State != "OBSERVATION_LOSS" {
		t.Fatal(h)
	}
	if s.Health().IngressLossCount != h.LossCount {
		t.Fatal("overflow not persisted", s.Health(), h)
	}
	t.Logf("disk-stalled producer accepted=%d dropped=%d reserved_bytes=%d duration=%s", accepted, h.LossCount, reserved, time.Since(start))
}

func TestMOBSStorageLegacyConsumesQuotaButIsNotDeleted(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "decisions-20200101.jsonl")
	body := bytes.Repeat([]byte("x"), 1000)
	os.WriteFile(legacy, body, 0600)
	c := managedConfig()
	c.RawMaxBytes = 1000
	s := mustStore(t, dir, c)
	if e := s.AppendLine([]byte(`{"v":1,"kind":"tick","ms":1000}`), time.Now()); e == nil || !strings.Contains(e.Error(), "DISK_PRESSURE") {
		t.Fatal(e)
	}
	if e := s.Maintain(time.Now(), func(RawFile) (bool, error) { return true, nil }); e != nil {
		t.Fatal(e)
	}
	got, e := os.ReadFile(legacy)
	if e != nil || !bytes.Equal(got, body) {
		t.Fatal("unmanaged raw removed", e)
	}
}

func TestMOBSStorageConcurrentIngressCounts(t *testing.T) {
	s := mustStore(t, t.TempDir(), DefaultStorageConfig())
	q := NewIngress(s, nil)
	var accepted atomic.Int64
	var wg sync.WaitGroup
	for producer := 0; producer < 2; producer++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				if e := q.AppendLine([]byte(`{"v":1,"kind":"tick","ms":1000}`), time.UnixMilli(1000)); e == nil {
					accepted.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	q.Close()
	recs, bad, e := LoadDir(s.dir)
	if e != nil || len(bad) != 0 || int64(len(recs)) != accepted.Load() || q.Health().LossCount != uint64(2000-accepted.Load()) {
		t.Fatal(len(recs), accepted.Load(), bad, e, q.Health())
	}
}
