// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package ledgerq

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/glowfly/pail/services/internal/blackbox"
)

type ChainFrontier struct {
	Sequence     int64  `json:"sequence,string"`
	SegmentID    string `json:"segment_id"`
	Offset       int64  `json:"offset,string"`
	Hash         string `json:"hash"`
	VerifiedAtMs int64  `json:"verified_at_ms"`
}
type ChainFault struct {
	Code      string `json:"code"`
	SegmentID string `json:"segment_id,omitempty"`
	Offset    *int64 `json:"offset,omitempty,string"`
}
type ChainTip struct {
	Sequence     *int64 `json:"sequence_or_null,string"`
	ObservedAtMs int64  `json:"observed_at_ms"`
}
type ChainLag struct {
	Records *int64 `json:"records_or_null"`
	AgeMs   int64  `json:"age_ms"`
}
type ChainDiagnostic struct {
	ChainState      string         `json:"chain_state"`
	VerifiedThrough *ChainFrontier `json:"verified_through"`
	ObservedTip     ChainTip       `json:"observed_tip"`
	IndexLag        ChainLag       `json:"index_lag"`
	Error           *ChainFault    `json:"error"`
	RecoveryState   string         `json:"recovery_state"`
	// PendingTailBytes is the length of the incomplete record the snapshot of
	// the active segment ended in: bytes the writer had not finished, which the
	// next pass will see complete (or the writer's restart will cut). Not a
	// fault (review 15/21).
	PendingTailBytes int64 `json:"pending_tail_bytes,omitempty"`
}

// copyChainSnapshot copies only regular journal segments, with bounded buffers.
// The original directory is never written. A second digest pass over the source
// (dst == "") is compared with the copy by snapshotStable; mtime/size are not
// integrity proofs.
//
// The journal is append-only and the robot keeps writing while the collector
// verifies, so the ACTIVE (last) segment is copied up to its Lstat size and
// bytes appended during the copy are left to the next pass. A closed segment
// must not change at all: one byte more or less is SOURCE_UNSTABLE. The active
// segment shrinking under the copy is SOURCE_UNSTABLE too.
type segmentSnapshot struct {
	Hash string
	Size int64
}

func copyChainSnapshot(ctx context.Context, dir, dst string) (map[string]segmentSnapshot, error) {
	directory, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	entries, err := directory.ReadDir(8193)
	directory.Close()
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(entries) > 8192 {
		return nil, fmt.Errorf("VERIFY_BUDGET_EXCEEDED")
	}
	names := []string{}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "pail_blackbox.") && strings.HasSuffix(e.Name(), ".seg") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if len(names) > 4096 {
		return nil, fmt.Errorf("VERIFY_BUDGET_EXCEEDED")
	}
	for i, name := range names {
		if name != segmentName(uint64(i+1)) {
			return nil, fmt.Errorf("SEGMENT_SET_INCOMPLETE")
		}
	}
	var total int64
	sums := map[string]segmentSnapshot{}
	for i, name := range names {
		active := i == len(names)-1
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		total += info.Size()
		if info.Size() > 128<<20 || total > 2<<30 {
			return nil, fmt.Errorf("VERIFY_BUDGET_EXCEEDED")
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("non-regular segment")
		}
		src, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		h := sha256.New()
		var out *os.File
		var w io.Writer = h
		if dst != "" {
			out, err = os.OpenFile(filepath.Join(dst, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				src.Close()
				return nil, err
			}
			w = io.MultiWriter(h, out)
		}
		limit := info.Size() + 1 // a closed segment that grew is caught by the extra byte
		if active {
			limit = info.Size() // the active segment may grow; what came after the Lstat is the next pass's
		}
		n, copyErr := io.CopyBuffer(w, &verificationReader{ctx: ctx, r: io.LimitReader(src, limit)}, make([]byte, 64<<10))
		err = copyErr
		if err == nil && n != info.Size() {
			err = fmt.Errorf("SOURCE_UNSTABLE")
		}
		src.Close()
		if out != nil {
			ce := out.Close()
			if err == nil {
				err = ce
			}
		}
		if err != nil {
			return nil, err
		}
		sums[name] = segmentSnapshot{Hash: hex.EncodeToString(h.Sum(nil)), Size: n}
	}
	return sums, nil
}

// IngestChain is a single full-verification worker. Index rows and frontier
// metadata publish atomically. Failed/unstable passes cannot refresh chain_ok.
func (d *DB) IngestChain(dir string, now time.Time) (st ChainStatus, err error) {
	d.chainMu.Lock()
	defer d.chainMu.Unlock()
	var diag ChainDiagnostic
	var walk ChainWalk
	if d.ChainWalker != nil {
		walk = d.ChainWalker()
		// The verdict is handed over when the pass has ended, whatever way it
		// ended: after the index transaction, or with the error that prevented it.
		defer func() { walk.Done(chainVerdict(st, diag, now, err == nil)) }()
	}
	d.chainAvailable.Store(false)
	d.chainVerifying.Store(true)
	defer d.chainVerifying.Store(false)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st = ChainStatus{State: "ok"}
	diag = ChainDiagnostic{ChainState: "OK", RecoveryState: "NONE", ObservedTip: ChainTip{ObservedAtMs: now.UnixMilli()}}
	fail := func(state, code string) {
		st.State = state
		st.Error = code
		diag.ChainState = strings.ToUpper(state)
		diag.Error = chainFault(code)
		diag.RecoveryState = "EVIDENCE_REQUIRED"
	}
	snap, err := os.MkdirTemp(filepath.Dir(d.path), ".ledger-verify-")
	if err != nil {
		return st, err
	}
	defer os.RemoveAll(snap)
	sums, err := copyChainSnapshot(ctx, dir, snap)
	if err != nil {
		if os.IsNotExist(err) {
			fail("absent", "SOURCE_ABSENT")
		} else {
			fail("unverified", "SOURCE_UNSTABLE")
			if strings.Contains(err.Error(), "SEGMENT_SET_INCOMPLETE") {
				fail("unverified", "SEGMENT_SET_INCOMPLETE")
			}
			if strings.Contains(err.Error(), "VERIFY_BUDGET_EXCEEDED") || ctx.Err() != nil {
				fail("unverified", "VERIFY_BUDGET_EXCEEDED")
			}
		}
	}
	if d.snapshotCopied != nil {
		d.snapshotCopied()
	}
	if err == nil && len(sums) == 0 {
		fail("absent", "SOURCE_ABSENT")
	}
	// Preserve the last trusted identity across errors. A shorter/replaced valid
	// journal cannot silently become the new authority on the following pass.
	var trustedSegments map[string]segmentSnapshot
	if raw, ok := d.meta("chain_trusted_segments"); ok {
		if json.Unmarshal([]byte(raw), &trustedSegments) != nil {
			return st, fmt.Errorf("INDEX_METADATA_INVALID")
		}
	}
	var trusted ChainFrontier
	if raw, ok := d.meta("chain_trusted_frontier"); ok {
		if json.Unmarshal([]byte(raw), &trusted) != nil {
			return st, fmt.Errorf("INDEX_METADATA_INVALID")
		}
	}
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return st, err
	}
	defer tx.Rollback()
	last, _ := metaIntRead(tx, "chain_checked_to_seq")
	var seq int64
	if st.State == "ok" {
		// The end of the last complete record of the segment the walk is in: the
		// prefix of the active segment this pass may trust when its snapshot ends
		// inside a record the writer had not finished (review 15/21).
		var walkSeg uint64
		var cleanEnd int64
		torn, werr := blackbox.WalkDir(snap, func(rec blackbox.Record) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			walkSeg = rec.SegmentSeq
			cleanEnd = rec.Offset + 20 + int64(len(rec.Payload)) + 64
			f, e := os.Open(filepath.Join(snap, segmentName(rec.SegmentSeq)))
			if e != nil {
				return e
			}
			hash := make([]byte, 32)
			_, e = f.ReadAt(hash, rec.Offset+20+int64(len(rec.Payload))+32)
			f.Close()
			if e != nil {
				return e
			}
			seq++
			frontier := ChainFrontier{Sequence: seq, SegmentID: segmentName(rec.SegmentSeq), Offset: rec.Offset, Hash: hex.EncodeToString(hash), VerifiedAtMs: now.UnixMilli()}
			if seq == trusted.Sequence && (frontier.Hash != trusted.Hash || frontier.SegmentID != trusted.SegmentID || frontier.Offset != trusted.Offset) {
				seq--
				return fmt.Errorf("JOURNAL_IDENTITY_CHANGED")
			}
			if walk != nil {
				walk.Record(seq, rec)
			}
			// A verified prefix may be shown after a failure, but never the old suffix.
			if seq > last {
				if e := insertRow(tx, rowFromChain(rec, seq)); e != nil {
					return e
				}
				var inserted int64
				if e := tx.QueryRow("SELECT changes()").Scan(&inserted); e != nil {
					return e
				}
				st.Inserted += inserted
			}
			diag.VerifiedThrough = &frontier
			st.CheckedToMs = rec.UnixMs
			return nil
		})
		st.TornTail = torn
		st.Records = seq
		st.CheckedToSeq = seq
		if werr != nil {
			fail("chain_error", sanitizeChainError(werr, snap))
		} else if seq < trusted.Sequence {
			fail("chain_error", "JOURNAL_REGRESSION")
		} else if torn {
			// A torn tail of the ACTIVE segment is the writer mid-record, not a
			// fault (the reader already refuses a torn closed segment): confirm
			// through the last complete record and trust only that prefix, so the
			// writer's own cut of the tail on restart is not read as tampering.
			activeName, activeEnd := activeCleanPrefix(sums, walkSeg, cleanEnd)
			full := sums[activeName]
			var pref segmentSnapshot
			pref, err = snapshotPrefix(ctx, filepath.Join(snap, activeName), activeEnd)
			if err != nil {
				return st, err
			}
			sums[activeName] = pref
			diag.PendingTailBytes = full.Size - activeEnd
		}
		if werr != nil && strings.Contains(werr.Error(), "JOURNAL_IDENTITY_CHANGED") {
			tx.Rollback()
			tx, err = d.sql.BeginTx(ctx, nil)
			if err != nil {
				return st, err
			}
			defer tx.Rollback()
			st.CheckedToSeq = 0
			st.CheckedToMs = 0
			st.Inserted = 0
			diag.VerifiedThrough = nil
		}
		if st.State == "ok" && seq == 0 {
			fail("absent", "NO_VERIFIED_RECORDS")
		}
		// Only a stable byte snapshot can publish rows or a verification verdict.
		// Stable means: closed segments identical, the active segment extended
		// with its trusted prefix preserved, new segments only as a continuation.
		after, e := copyChainSnapshot(ctx, dir, "")
		if e != nil || !snapshotStable(ctx, dir, sums, after) {
			tx.Rollback()
			fail("unverified", "SOURCE_UNSTABLE")
			diag.VerifiedThrough = nil
			st.CheckedToSeq = 0
			st.CheckedToMs = 0
			st.Inserted = 0
			tx, err = d.sql.BeginTx(ctx, nil)
			if err != nil {
				return st, err
			}
			defer tx.Rollback()
		}
		if st.State == "ok" {
			previousNames := make([]string, 0, len(trustedSegments))
			for name := range trustedSegments {
				previousNames = append(previousNames, name)
			}
			sort.Strings(previousNames)
			for i, name := range previousNames {
				sum, exists := sums[name]
				if !exists {
					fail("chain_error", "SEGMENT_MISSING")
					break
				}
				if i < len(previousNames)-1 && sum != trustedSegments[name] {
					fail("chain_error", "CLOSED_SEGMENT_CHANGED")
					break
				}
				if i == len(previousNames)-1 && !snapshotExtends(ctx, filepath.Join(snap, name), sum, trustedSegments[name]) {
					fail("chain_error", "JOURNAL_PREFIX_CHANGED")
					break
				}
			}
			if st.State != "ok" {
				tx.Rollback()
				tx, err = d.sql.BeginTx(ctx, nil)
				if err != nil {
					return st, err
				}
				defer tx.Rollback()
				st.CheckedToSeq = 0
				st.CheckedToMs = 0
				st.Inserted = 0
				diag.VerifiedThrough = nil
			}
		}
		if st.State == "ok" {
			n := seq
			diag.ObservedTip.Sequence = &n
			z := int64(0)
			diag.IndexLag.Records = &z
		}
	}
	if st.State != "unverified" || st.Error != "SOURCE_UNSTABLE" {
		if _, err = tx.Exec("DELETE FROM events WHERE src='chain' AND chain_seq>?", st.CheckedToSeq); err != nil {
			return st, err
		}
	}
	if st.State == "ok" {
		b, _ := json.Marshal(sums)
		if err = setMetaTx(tx, "chain_trusted_segments", string(b)); err != nil {
			return st, err
		}
	}
	if st.State == "ok" && diag.VerifiedThrough != nil {
		b, _ := json.Marshal(diag.VerifiedThrough)
		if err = setMetaTx(tx, "chain_trusted_frontier", string(b)); err != nil {
			return st, err
		}
	}
	b, _ := json.Marshal(diag)
	values := map[string]string{"chain_state": st.State, "chain_error": st.Error, "chain_checked_to_seq": strconv.FormatInt(st.CheckedToSeq, 10), "chain_checked_to_ms": strconv.FormatUint(st.CheckedToMs, 10), "chain_walk_ms": strconv.FormatInt(now.UnixMilli(), 10), "last_ingest_ms": strconv.FormatInt(now.UnixMilli(), 10), "chain_diagnostic": string(b)}
	for k, v := range values {
		if err = setMetaTx(tx, k, v); err != nil {
			return st, err
		}
	}
	err = tx.Commit()
	if err == nil {
		d.chainAvailable.Store(true)
	}
	return st, err
}
func setMetaTx(tx *sql.Tx, k, v string) error {
	_, err := tx.Exec("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", k, v)
	return err
}
func sanitizeChainError(err error, dir string) string {
	// Reader errors contain only segment names in normal operation. Redact the
	// staging root for filesystem errors too; never publish an absolute path.
	return strings.ReplaceAll(err.Error(), dir, "[journal]")
}

// Budget checks bound ordinary local-file work. Kernel I/O stalls are not a
// real-time deadline guarantee. The canonical reader still verifies all bytes.
type verificationReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *verificationReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

var faultSegment = regexp.MustCompile(`pail_blackbox\.[0-9]+\.seg`)
var faultOffset = regexp.MustCompile(`offset=([0-9]+)`)

func chainFault(message string) *ChainFault {
	f := &ChainFault{Code: message, SegmentID: faultSegment.FindString(message)}
	if m := faultOffset.FindStringSubmatch(message); len(m) == 2 {
		n, _ := strconv.ParseInt(m[1], 10, 64)
		f.Offset = &n
	}
	switch {
	case strings.Contains(message, "prev_segment_tail_hash"):
		f.Code = "SEGMENT_LINK_MISMATCH"
	case strings.Contains(message, "prev_hash"):
		f.Code = "PREVIOUS_HASH_MISMATCH"
	case strings.Contains(message, "this_hash"):
		f.Code = "RECORD_HASH_MISMATCH"
	case strings.Contains(message, "JOURNAL_IDENTITY_CHANGED"):
		f.Code = "JOURNAL_IDENTITY_CHANGED"
	case strings.Contains(message, "blackbox reader:"):
		f.Code = "CHAIN_FORMAT_ERROR"
	}
	return f
}

// activeCleanPrefix names the active (last) segment of the snapshot and the
// end of its trusted prefix: the last complete record the walk saw in it, the
// bare header when it holds no complete record, nothing when even the header
// is incomplete (the reader treats such a newest segment as not there yet).
func activeCleanPrefix(sums map[string]segmentSnapshot, walkSeg uint64, cleanEnd int64) (string, int64) {
	names := make([]string, 0, len(sums))
	for name := range sums {
		names = append(names, name)
	}
	sort.Strings(names)
	active := names[len(names)-1]
	if walkSeg != 0 && segmentName(walkSeg) == active {
		return active, cleanEnd
	}
	if sums[active].Size >= int64(blackbox.SegmentHeaderSize) {
		return active, int64(blackbox.SegmentHeaderSize)
	}
	return active, 0
}

// snapshotPrefix digests the first end bytes of a snapshot segment.
func snapshotPrefix(ctx context.Context, path string, end int64) (segmentSnapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return segmentSnapshot{}, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.CopyBuffer(h, &verificationReader{ctx: ctx, r: io.LimitReader(f, end)}, make([]byte, 64<<10))
	if err != nil {
		return segmentSnapshot{}, err
	}
	if n != end {
		return segmentSnapshot{}, fmt.Errorf("SNAPSHOT_PREFIX_SHORT")
	}
	return segmentSnapshot{Hash: hex.EncodeToString(h.Sum(nil)), Size: n}, nil
}

// snapshotStable says whether the directory read after the walk (after) still
// holds what the walk verified (sums): every closed segment byte-identical, the
// active segment extended with its trusted prefix preserved (compared against
// the LIVE file, as the cross-cycle rule does), and any segment that is new
// since the snapshot a continuation after the active one (rotation during the
// pass — both listings are contiguous from 1, see copyChainSnapshot). Growth
// of an append-only journal is not instability; a changed, shrunk or vanished
// segment is (review 15/21).
func snapshotStable(ctx context.Context, dir string, sums, after map[string]segmentSnapshot) bool {
	names := make([]string, 0, len(sums))
	for name := range sums {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return false
	}
	active := names[len(names)-1]
	for _, name := range names[:len(names)-1] {
		if a, ok := after[name]; !ok || a != sums[name] {
			return false
		}
	}
	a, ok := after[active]
	if !ok || !snapshotExtends(ctx, filepath.Join(dir, active), a, sums[active]) {
		return false
	}
	for name := range after {
		if _, known := sums[name]; !known && name <= active {
			return false
		}
	}
	return true
}

// The previously active segment may grow, but its already observed bytes may
// not be rewritten, including an empty segment header transparent to WalkDir.
func snapshotExtends(ctx context.Context, path string, current, previous segmentSnapshot) bool {
	if current.Size < previous.Size {
		return false
	}
	if current.Size == previous.Size {
		return current.Hash == previous.Hash
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.CopyBuffer(h, &verificationReader{ctx: ctx, r: io.LimitReader(f, previous.Size)}, make([]byte, 64<<10))
	return err == nil && n == previous.Size && hex.EncodeToString(h.Sum(nil)) == previous.Hash
}
