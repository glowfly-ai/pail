// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package blackbox

// HA1 replay reader (LLD §3.1). Walks every segment in order and surfaces each
// record AFTER verifying the hash chain incrementally: segment header
// participation, per-record prev/this hash, and cross-segment tail
// inheritance (empty segments transparent).
//
// Deliberately NOT shared with cmd/blackbox_verify (LLD D3): the independent
// auditor must not share a parser with the code it audits.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Record is one chain-verified blackbox record.
type Record struct {
	SegmentSeq uint64
	Type       uint32
	UnixMs     uint64
	Payload    []byte
	// Offset is the record's start byte within its segment file — the
	// derivation origin a ledger index row must be able to point back to
	// (AL-1, G-LED-02: an index row that cannot be re-derived from its origin
	// has betrayed the ledger). Filled by scanSegment; zero-cost to carry.
	Offset int64
	// Index is the record's position within its segment (0-based) and PrevHash
	// the chain value just before it — the segment header's hash for the first
	// record. A CHECKPOINT can only be judged against these two (its head and
	// its count), so the scan hands them over instead of every verifier
	// re-deriving them (SEC-H08).
	Index    uint64
	PrevHash [32]byte
}

// WalkDir replays all records in dir in segment order, calling fn for each.
//
// A truncated FINAL record in the newest segment is tolerated (tornTail=true):
// the writer died mid-write, so that record was never acknowledged to any
// caller — exactly the state replay must not apply. Any other corruption
// (hash mismatch, truncation mid-history, broken tail inheritance) returns an
// error and the caller fails closed.
func WalkDir(dir string, fn func(Record) error) (tornTail bool, err error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	var names []string
	for _, e := range entries {
		var seq uint64
		if !e.IsDir() {
			if _, err := fmt.Sscanf(e.Name(), "pail_blackbox.%d.seg", &seq); err == nil {
				names = append(names, e.Name())
			}
		}
	}
	sort.Strings(names) // zero-padded seq sorts lexicographically

	var expectTail [32]byte // zeros for the very first segment
	for i, name := range names {
		last := i == len(names)-1
		torn, tail, err := walkSegment(filepath.Join(dir, name), expectTail, last, fn)
		if err != nil {
			return false, fmt.Errorf("blackbox reader: %s: %w", name, err)
		}
		if torn {
			return true, nil // only possible in the final segment
		}
		expectTail = tail
	}
	return false, nil
}

// walkSegment applies the READER's policy to the shared scan (scan.go,
// `DUR-L1`): a torn tail is history-mid corruption unless this is the newest
// segment. The writer's startup path applies a different policy to the same
// bytes — that difference is now a deliberate one line here, not two parsers
// that drifted apart.
func walkSegment(path string, expectTail [32]byte, allowTorn bool, fn func(Record) error) (torn bool, tail [32]byte, err error) {
	res, err := scanSegment(path, &expectTail, fn)
	if err != nil {
		return false, expectTail, err
	}
	if res.abortedHeader {
		// [F-DUR-7] 헤더가 미완인 세그먼트는 레코드를 담을 수 없다 — 최신이면
		// 생성 직후의 전원 상실(또는 ENOSPC)이고, 그 뒤로 쓰인 것이 없으므로
		// 재생은 여기서 끝난다. 상속 tail 도 대조하지 않는다: 이 파일은 tail 을
		// 선언한 적이 없다.
		if allowTorn {
			return true, expectTail, nil
		}
		// 이력 **중간**의 미완 헤더는 다른 사건이다 — 뒤 세그먼트들이 이 파일에
		// 없는 tail 을 상속했다고 주장하고 있다는 뜻이다. fail-closed.
		return false, expectTail, fmt.Errorf("aborted segment header (%d bytes) mid-history", res.tornBytes)
	}
	if res.tornBytes > 0 {
		if allowTorn {
			return true, expectTail, nil
		}
		return false, expectTail, fmt.Errorf("truncated %s at offset=%d", res.tornWhat, res.cleanSize)
	}
	return false, res.cleanTail, nil
}
