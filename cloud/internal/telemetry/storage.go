// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package telemetry

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const RawSegmentBytes int64 = 64 << 20
const RawLineBytes = 1 << 20
const manifestName = "observation-manifest.json"

var managedName = regexp.MustCompile(`^decisions-[0-9]{8}-[0-9]{6,20}\.jsonl$`)

// StorageConfig never enables deletion implicitly. The same strict document
// configures raw retention and derived-index budgets; no safety-plane limits.
type StorageConfig struct {
	SchemaVersion     int    `json:"schema_version"`
	RetentionMode     string `json:"retention_mode"`
	RawMaxBytes       int64  `json:"raw_max_bytes"`
	RetainDays        int    `json:"retain_days"`
	TrashGraceSeconds int64  `json:"trash_grace_seconds"`
	DBMaxBytes        int64  `json:"db_max_bytes"`
	WALMaxBytes       int64  `json:"wal_max_bytes"`
	// [OBS-RET] The query index is derived and can be rebuilt; it must not
	// stop taking in what is happening now because it kept everything that
	// ever happened. IndexRetainDays is how long observation rows stay in it
	// (0 = keep all; journal rows are never removed by it). DiskFreeMinBytes is
	// what the index leaves free on its filesystem (0 = automatic: a tenth of
	// the filesystem, between 1 GiB and 20 GiB). DBMaxBytes is now an optional
	// fixed budget (0 = none); reaching either bound removes the oldest
	// observation rows instead of refusing new ones.
	IndexRetainDays  int   `json:"index_retain_days"`
	DiskFreeMinBytes int64 `json:"disk_free_min_bytes"`
}

func DefaultStorageConfig() StorageConfig {
	return StorageConfig{SchemaVersion: 1, RetentionMode: "retain_no_delete", TrashGraceSeconds: 3600,
		WALMaxBytes: 256 << 20, IndexRetainDays: 7}
}
func ParseStorageConfig(b []byte) (StorageConfig, error) {
	c := DefaultStorageConfig()
	// DisallowUnknownFields does not reject duplicate keys. Inspect them first.
	dec := json.NewDecoder(bytes.NewReader(b))
	tok, e := dec.Token()
	if e != nil || tok != json.Delim('{') {
		return c, errors.New("OBSERVABILITY_CONFIG: expected object")
	}
	seen := map[string]bool{}
	for dec.More() {
		k, e := dec.Token()
		if e != nil {
			return c, e
		}
		key, ok := k.(string)
		if !ok || seen[key] {
			return c, errors.New("OBSERVABILITY_CONFIG: duplicate key")
		}
		seen[key] = true
		var v json.RawMessage
		if e = dec.Decode(&v); e != nil {
			return c, e
		}
	}
	if !seen["schema_version"] {
		return c, errors.New("OBSERVABILITY_CONFIG: schema_version required")
	}
	dec = json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if e = dec.Decode(&c); e != nil {
		return c, e
	}
	var extra any
	if e = dec.Decode(&extra); e != io.EOF {
		return c, errors.New("OBSERVABILITY_CONFIG: trailing data")
	}
	if e = c.Validate(); e != nil {
		return c, e
	}
	return c, nil
}
func (c StorageConfig) Validate() error {
	if c.SchemaVersion != 1 || (c.RetentionMode != "retain_no_delete" && c.RetentionMode != "managed") || c.RawMaxBytes < 0 || c.RetainDays < 0 || c.RetainDays > 36500 || c.TrashGraceSeconds < 1 || c.TrashGraceSeconds > 31536000 || c.DBMaxBytes < 0 || c.WALMaxBytes <= 0 ||
		c.IndexRetainDays < 0 || c.IndexRetainDays > 36500 || c.DiskFreeMinBytes < 0 {
		return errors.New("OBSERVABILITY_CONFIG: invalid limits")
	}
	if c.RetentionMode == "managed" && (c.RawMaxBytes <= 0 || c.RetainDays <= 0) {
		return errors.New("OBSERVABILITY_CONFIG: managed requires explicit bytes and days")
	}
	return nil
}

type RawFile struct {
	ID            string `json:"file_id"`
	Name          string `json:"name"`
	Day           string `json:"day"`
	Size          int64  `json:"closed_size"`
	SHA256        string `json:"closed_hash"`
	Identity      string `json:"identity"`
	State         string `json:"state"` // active, closed, delete_intent, trash, deleted
	FirstMs       int64  `json:"first_ms"`
	LastMs        int64  `json:"last_ms"`
	DeleteAfterMs int64  `json:"delete_after_ms,omitempty"`
}
type StorageHealth struct {
	IngressLossCount    uint64 `json:"ingress_loss_count"`
	State               string `json:"state"`
	LossCount           uint64 `json:"loss_count"`
	FirstErrorMs        int64  `json:"first_error_ms,omitempty"`
	LastErrorMs         int64  `json:"last_error_ms,omitempty"`
	LastError           string `json:"last_error,omitempty"`
	DeletionRevision    uint64 `json:"deletion_revision"`
	RawIncomplete       bool   `json:"raw_incomplete"`
	RawRemovedThroughMs int64  `json:"raw_removed_through_ms,omitempty"`
}
type RawManifest struct {
	Version int           `json:"schema_version"`
	Next    uint64        `json:"next_segment"`
	Files   []RawFile     `json:"files"`
	Health  StorageHealth `json:"health"`
}

// Store holds an OS directory lock across the whole writer lifetime. A durable
// manifest, not filename age, grants ownership and deletion authority.
type Store struct {
	maintenanceCursor int
	otherBytes        int64
	health            atomic.Value
	mu                sync.Mutex
	dir               string
	lock              *os.File
	f                 *os.File
	active            int
	config            StorageConfig
	m                 RawManifest
	failed            bool
}

func FileIdentity(info os.FileInfo) string {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%d:%d", st.Dev, st.Ino)
	}
	return ""
}
func syncDir(dir string) error {
	f, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func ReadRawManifest(dir string) (RawManifest, error) {
	var m RawManifest
	f, e := os.Open(filepath.Join(dir, manifestName))
	if os.IsNotExist(e) {
		return RawManifest{Version: 1, Health: StorageHealth{State: "OK"}}, nil
	}
	if e != nil {
		return m, e
	}
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, 16<<20))
	dec.DisallowUnknownFields()
	if e = dec.Decode(&m); e != nil {
		return m, e
	}
	var extra any
	if e = dec.Decode(&extra); e != io.EOF {
		return m, errors.New("MANIFEST_INVALID")
	}
	if m.Version != 1 || len(m.Files) > 100000 {
		return m, errors.New("MANIFEST_INVALID")
	}
	names := map[string]bool{}
	ids := map[string]bool{}
	active := 0
	for _, r := range m.Files {
		if _, e := hex.DecodeString(r.ID); e != nil {
			return m, errors.New("MANIFEST_INVALID")
		}
		if _, e := hex.DecodeString(r.SHA256); e != nil {
			return m, errors.New("MANIFEST_INVALID")
		}
		if !managedName.MatchString(r.Name) || len(r.ID) != 32 || names[r.Name] || ids[r.ID] || r.Size < 0 {
			return m, errors.New("MANIFEST_INVALID")
		}
		names[r.Name] = true
		ids[r.ID] = true
		switch r.State {
		case "active":
			active++
		case "closed", "delete_intent", "trash", "deleted":
			if len(r.SHA256) != 64 {
				return m, errors.New("MANIFEST_INVALID")
			}
		default:
			return m, errors.New("MANIFEST_INVALID")
		}
	}
	if active > 1 {
		return m, errors.New("MANIFEST_INVALID")
	}
	return m, nil
}
func (s *Store) save() error {
	s.health.Store(s.m.Health)
	b, e := json.Marshal(s.m)
	if e != nil {
		return e
	}
	if len(b) > 16<<20 {
		return errors.New("MANIFEST_LIMIT")
	}
	f, e := os.CreateTemp(s.dir, ".observation-manifest-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(name, filepath.Join(s.dir, manifestName)); e != nil {
		return e
	}
	return syncDir(s.dir)
}
func OpenStore(dir string) (*Store, error) { return OpenStoreWithConfig(dir, DefaultStorageConfig()) }
func OpenStoreWithConfig(dir string, c StorageConfig) (*Store, error) {
	if e := c.Validate(); e != nil {
		return nil, e
	}
	if e := os.MkdirAll(dir, 0755); e != nil {
		return nil, e
	}
	l, e := os.OpenFile(filepath.Join(dir, ".observation-writer.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(l.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		l.Close()
		return nil, errors.New("WRITER_LOCKED")
	}
	s := &Store{dir: dir, lock: l, active: -1, config: c}
	s.m, e = ReadRawManifest(dir)
	if e == nil {
		e = s.recover()
	}
	if e == nil {
		e = s.refreshRawUsage()
	}
	if e != nil {
		syscall.Flock(int(l.Fd()), syscall.LOCK_UN)
		l.Close()
		return nil, e
	}
	s.health.Store(s.m.Health)
	return s, nil
}
func hashRaw(path string) (int64, string, string, error) {
	f, e := os.Open(path)
	if e != nil {
		return 0, "", "", e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() {
		return 0, "", "", errors.New("INPUT_REPLACED")
	}
	lst, e := os.Lstat(path)
	if e != nil || !os.SameFile(st, lst) || lst.Mode()&os.ModeSymlink != 0 {
		return 0, "", "", errors.New("INPUT_REPLACED")
	}
	if st.Size() > RawSegmentBytes {
		return 0, "", "", errors.New("RAW_SEGMENT_OVERSIZE")
	}
	h := sha256.New()
	n, e := io.CopyBuffer(h, io.NewSectionReader(f, 0, st.Size()), make([]byte, 256<<10))
	return n, hex.EncodeToString(h.Sum(nil)), FileIdentity(st), e
}
func (s *Store) seal(i int) error {
	r := &s.m.Files[i]
	n, h, id, e := hashRaw(filepath.Join(s.dir, r.Name))
	if e != nil {
		return e
	}
	if r.Identity != "" && r.Identity != id {
		return errors.New("INPUT_REPLACED")
	}
	if n < r.Size {
		return errors.New("INPUT_REPLACED")
	}
	if n > 0 {
		f, e := os.Open(filepath.Join(s.dir, r.Name))
		if e != nil {
			return e
		}
		var tail [1]byte
		_, e = f.ReadAt(tail[:], n-1)
		f.Close()
		if e != nil {
			return e
		}
		if tail[0] != '\n' {
			s.m.Health.State = "OBSERVATION_LOSS"
			s.m.Health.LastError = "RAW_TORN_TAIL"
			s.m.Health.LossCount++
			s.m.Health.LastErrorMs = time.Now().UnixMilli()
			if s.m.Health.FirstErrorMs == 0 {
				s.m.Health.FirstErrorMs = s.m.Health.LastErrorMs
			}
		}
	}
	r.Size = n
	r.SHA256 = h
	r.Identity = id
	r.State = "closed"
	return s.save()
}
func (s *Store) recover() error {
	// Never append to a prior process's file (including a torn final line).
	for i := range s.m.Files {
		r := &s.m.Files[i]
		if r.State == "active" {
			if e := s.seal(i); e != nil {
				return e
			}
		}
		if r.State == "delete_intent" || r.State == "trash" {
			if e := s.moveToTrash(i); e != nil {
				return e
			}
		}
	}
	return nil
}
func (s *Store) fault(code string, now time.Time, loss bool) error {
	s.m.Health.State = "OBSERVATION_LOSS"
	s.m.Health.LastError = code
	s.m.Health.LastErrorMs = now.UnixMilli()
	if s.m.Health.FirstErrorMs == 0 {
		s.m.Health.FirstErrorMs = now.UnixMilli()
	}
	if loss {
		s.m.Health.LossCount++
	}
	// ENOSPC can also prevent persistence. The in-memory diagnostic and returned
	// error remain truthful; no persistent count is claimed in that case.
	e := s.save()
	if e != nil {
		return fmt.Errorf("%s: health persistence failed: %w", code, e)
	}
	return errors.New(code)
}
func (s *Store) Health() StorageHealth {
	if h := s.health.Load(); h != nil {
		return h.(StorageHealth)
	}
	return StorageHealth{State: "BUILDING"}
}
func (s *Store) AppendLine(line []byte, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return errors.New("STORE_CLOSED")
	}
	if len(line)+1 > RawLineBytes || bytes.ContainsAny(line, "\r\n") || !json.Valid(line) {
		return s.fault("INPUT_LINE_INVALID", now, true)
	}
	if s.failed {
		return s.fault("WRITER_RECOVERY_REQUIRED", now, true)
	}
	if s.f != nil {
		r := s.m.Files[s.active]
		st, e := os.Lstat(filepath.Join(s.dir, r.Name))
		if e != nil || FileIdentity(st) != r.Identity || st.Size() != r.Size {
			s.failed = true
			return s.fault("INPUT_REPLACED", now, true)
		}
	}
	total := s.otherBytes
	for _, r := range s.m.Files {
		if r.State != "deleted" {
			total += r.Size
		}
	}
	if s.config.RawMaxBytes > 0 && total+int64(len(line)+1) > s.config.RawMaxBytes {
		return s.fault("DISK_PRESSURE", now, true)
	}
	if s.f != nil && (s.m.Files[s.active].Day != dayOf(now) || s.m.Files[s.active].Size+int64(len(line)+1) > RawSegmentBytes) {
		if e := s.f.Sync(); e != nil {
			s.failed = true
			return s.fault("RAW_SYNC_FAILED", now, true)
		}
		if e := s.f.Close(); e != nil {
			s.failed = true
			return s.fault("RAW_CLOSE_FAILED", now, true)
		}
		s.f = nil
		if e := s.seal(s.active); e != nil {
			s.failed = true
			return s.fault("MANIFEST_WRITE_FAILED", now, true)
		}
	}
	if s.f == nil {
		if len(s.m.Files) >= 100000 {
			return s.fault("MANIFEST_LIMIT", now, true)
		}
		s.m.Next++
		name := fmt.Sprintf("decisions-%s-%06d.jsonl", dayOf(now), s.m.Next)
		f, e := os.OpenFile(filepath.Join(s.dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if e != nil {
			return s.fault("RAW_CREATE_FAILED", now, true)
		}
		st, e := f.Stat()
		if e != nil {
			f.Close()
			return e
		}
		id := make([]byte, 16)
		if _, e = rand.Read(id); e != nil {
			f.Close()
			return e
		}
		s.m.Files = append(s.m.Files, RawFile{ID: hex.EncodeToString(id), Name: name, Day: dayOf(now), Identity: FileIdentity(st), State: "active", FirstMs: now.UnixMilli(), LastMs: now.UnixMilli()})
		s.active = len(s.m.Files) - 1
		if e = s.save(); e != nil {
			f.Close()
			s.failed = true
			return s.fault("MANIFEST_WRITE_FAILED", now, true)
		}
		s.f = f
	}
	b := make([]byte, len(line)+1)
	copy(b, line)
	b[len(line)] = '\n'
	n, e := s.f.Write(b)
	s.m.Files[s.active].Size += int64(n)
	s.m.Files[s.active].LastMs = now.UnixMilli()
	if e != nil || n != len(b) {
		s.failed = true
		return s.fault("RAW_WRITE_FAILED", now, true)
	}
	return nil
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return nil
	}
	var e error
	if s.f != nil {
		e = s.f.Sync()
		ce := s.f.Close()
		s.f = nil
		if e == nil {
			e = ce
		}
		if e == nil && !s.failed {
			e = s.seal(s.active)
		}
	}
	syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
	ce := s.lock.Close()
	s.lock = nil
	if e == nil {
		e = ce
	}
	return e
}

// Indexed is a caller-supplied proof check against a committed raw origin.
// false means incomplete, never permission to delete. No callback receives a
// blackbox path. Retention only operates on manifest-owned closed JSONL files.
type Indexed func(RawFile) (bool, error)

func (s *Store) Maintain(now time.Time, indexed Indexed) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return errors.New("STORE_CLOSED")
	}
	if s.failed {
		return errors.New("WRITER_RECOVERY_REQUIRED")
	}
	if e := s.refreshRawUsage(); e != nil {
		return s.fault("RAW_STAT_FAILED", now, false)
	}
	if s.config.RetentionMode != "managed" {
		return nil
	}
	total := s.otherBytes
	for _, r := range s.m.Files {
		if r.State != "deleted" {
			total += r.Size
		}
	}
	// At most 64 metadata candidates and two file operations per pass. A
	// rolling cursor prevents an unindexed first candidate starving others.
	inspected, operations := 0, 0
	for inspected < len(s.m.Files) && inspected < 64 && operations < 2 {
		i := s.maintenanceCursor % len(s.m.Files)
		s.maintenanceCursor = (i + 1) % len(s.m.Files)
		inspected++
		r := &s.m.Files[i]
		if r.State == "delete_intent" || r.State == "trash" {
			operations++
			if e := s.moveToTrash(i); e != nil {
				return s.fault("RETENTION_MOVE_FAILED", now, false)
			}
			if now.UnixMilli() >= r.DeleteAfterMs {
				if e := s.purge(i); e != nil {
					return s.fault("RETENTION_DELETE_FAILED", now, false)
				}
				total -= r.Size
			}
			continue
		}
		if r.State != "closed" || indexed == nil {
			continue
		}
		if now.UnixMilli()-r.LastMs < int64(s.config.RetainDays)*86400000 && total <= s.config.RawMaxBytes-RawSegmentBytes {
			continue
		}
		ok, e := indexed(*r)
		if e != nil {
			return s.fault("RETENTION_INDEX_FAILED", now, false)
		}
		if !ok {
			continue
		}
		operations++
		n, h, id, e := hashRaw(filepath.Join(s.dir, r.Name))
		if e != nil || n != r.Size || h != r.SHA256 || id != r.Identity {
			return s.fault("INPUT_REPLACED", now, false)
		}
		r.State = "delete_intent"
		r.DeleteAfterMs = now.Add(time.Duration(s.config.TrashGraceSeconds) * time.Second).UnixMilli()
		s.m.Health.DeletionRevision++
		s.m.Health.RawIncomplete = true
		if r.LastMs > s.m.Health.RawRemovedThroughMs {
			s.m.Health.RawRemovedThroughMs = r.LastMs
		}
		// fsync(file)+rename+fsync(parent) commits intent BEFORE a raw rename.
		if e = s.save(); e != nil {
			s.failed = true
			return s.fault("RETENTION_INTENT_FAILED", now, false)
		}
		if e = s.moveToTrash(i); e != nil {
			return s.fault("RETENTION_MOVE_FAILED", now, false)
		}
	}
	return nil
}
func (s *Store) moveToTrash(i int) error {
	r := &s.m.Files[i]
	trash := filepath.Join(s.dir, ".observation-trash")
	if e := os.MkdirAll(trash, 0700); e != nil {
		return e
	}
	st, e := os.Lstat(trash)
	if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return errors.New("TRASH_INVALID")
	}
	src := filepath.Join(s.dir, r.Name)
	dst := filepath.Join(trash, r.ID+".jsonl")
	_, se := os.Lstat(src)
	_, de := os.Lstat(dst)
	if se == nil && os.IsNotExist(de) {
		n, h, id, e := hashRaw(src)
		if e != nil || n != r.Size || h != r.SHA256 || id != r.Identity {
			return errors.New("INPUT_REPLACED")
		}
		if e = os.Rename(src, dst); e != nil {
			return e
		}
	} else if os.IsNotExist(se) && de == nil {
		n, h, id, e := hashRaw(dst)
		if e != nil || n != r.Size || h != r.SHA256 || id != r.Identity {
			return errors.New("TRASH_REPLACED")
		}
	} else if os.IsNotExist(se) && os.IsNotExist(de) && r.State == "trash" { // crash after unlink, before tombstone
		r.State = "deleted"
		return s.save()
	} else {
		return errors.New("RETENTION_RECOVERY_REQUIRED")
	}
	if e = syncDir(s.dir); e != nil {
		return e
	}
	if e = syncDir(trash); e != nil {
		return e
	}
	r.State = "trash"
	return s.save()
}
func (s *Store) purge(i int) error {
	r := &s.m.Files[i]
	dir := filepath.Join(s.dir, ".observation-trash")
	p := filepath.Join(dir, r.ID+".jsonl")
	n, h, id, e := hashRaw(p)
	if e != nil || n != r.Size || h != r.SHA256 || id != r.Identity {
		return errors.New("TRASH_REPLACED")
	}
	if e = os.Remove(p); e != nil {
		return e
	}
	if e = syncDir(dir); e != nil {
		return e
	}
	r.State = "deleted"
	return s.save()
}

// RecordIngressLoss runs only on the disk worker; producers never wait for it.
func (s *Store) RecordIngressLoss(total uint64, first, last int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if total <= s.m.Health.IngressLossCount {
		return nil
	}
	s.m.Health.LossCount += total - s.m.Health.IngressLossCount
	s.m.Health.IngressLossCount = total
	s.m.Health.State = "OBSERVATION_LOSS"
	s.m.Health.LastError = "INGRESS_FULL"
	if s.m.Health.FirstErrorMs == 0 {
		s.m.Health.FirstErrorMs = first
	}
	s.m.Health.LastErrorMs = last
	return s.save()
}

// Existing legacy files are never owned, but still consume configured raw
// capacity. Refresh on open/maintenance; the writer accounts its own appends
// synchronously. Foreign writers must honor the same directory lock.
func (s *Store) refreshRawUsage() error {
	var actual, owned int64
	for _, r := range s.m.Files {
		if r.State != "deleted" {
			owned += r.Size
		}
	}
	names, e := filepath.Glob(filepath.Join(s.dir, "decisions-*.jsonl"))
	if e != nil {
		return e
	}
	trash, e := filepath.Glob(filepath.Join(s.dir, ".observation-trash", "*.jsonl"))
	if e != nil {
		return e
	}
	for _, p := range append(names, trash...) {
		st, e := os.Lstat(p)
		if e != nil {
			return e
		}
		if !st.Mode().IsRegular() {
			return errors.New("RAW_NOT_REGULAR")
		}
		actual += st.Size()
	}
	s.otherBytes = actual - owned
	if s.otherBytes < 0 {
		s.otherBytes = 0
	}
	return nil
}
