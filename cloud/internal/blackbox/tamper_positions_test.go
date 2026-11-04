// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// G-EVI-04 : flipping ONE byte at ANY structural position of the
// journal must fail the walk. The pre-existing TestWalkDirTamperFails covers a
// single payload byte; this battery enumerates every structural position, each
// tried in a middle record and in the final record, because the final record
// sits inside the torn-tail tolerance and the whole question is whether
// tolerance and tampering stay distinguishable.
//
// Honesty rule (implementation contract gray zone): where the flip is ABSORBED by the
// torn-tail crash tolerance (payload_len grown past EOF in the last segment),
// the case asserts exactly that — tornTail=true, tampered record and its
// successors NOT delivered — and is marked tolerated_by_design. A tolerance
// found is written down as a tolerance, not as a detection.
package blackbox

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

type recSpan struct {
	off  int
	plen int
}

// tamperPayloads: distinct sizes so a length flip has a distinct signature.
var tamperPayloads = [][]string{
	{`{"n":1}`, `{"n":22}`, `{"n":333}`},  // segment 1
	{`{"n":4444}`, `{"n":5}`, `{"n":66}`}, // segment 2 (the last)
}

func buildTamperJournal(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cfg := Config{Signer: testSigner(testKey(t))}
	ms := uint64(1000)
	for _, batch := range tamperPayloads {
		w, err := OpenDir(dir, cfg)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range batch {
			if err := w.Append(RecordGateDecision, ms, []byte(p)); err != nil {
				t.Fatal(err)
			}
			ms++
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func segFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, filepath.Join(dir, e.Name()))
	}
	if len(names) != 2 {
		t.Fatalf("segments=%d, want 2", len(names))
	}
	return names
}

func parseSpans(t *testing.T, path string) []recSpan {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var spans []recSpan
	off := segHeaderSize
	for off < len(data) {
		plen := int(binary.LittleEndian.Uint32(data[off+16 : off+20]))
		spans = append(spans, recSpan{off: off, plen: plen})
		off += 20 + plen + 64
	}
	return spans
}

func flipByte(t *testing.T, path string, off int, mask byte) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if off >= len(data) {
		t.Fatalf("flip offset %d beyond file size %d", off, len(data))
	}
	data[off] ^= mask
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func collectWalk(dir string) (recs []Record, torn bool, err error) {
	torn, err = WalkDir(dir, func(r Record) error {
		recs = append(recs, r)
		return nil
	})
	return recs, torn, err
}

func TestTamperPositions_EveryStructuralByte(t *testing.T) {
	// pristine baseline first: 6 records, no torn tail, payloads verbatim
	{
		dir := buildTamperJournal(t)
		recs, torn, err := collectWalk(dir)
		if err != nil || torn || len(recs) != 6 {
			t.Fatalf("G-EVI-04 baseline: recs=%d torn=%t err=%v, want 6/false/nil", len(recs), torn, err)
		}
		i := 0
		for _, batch := range tamperPayloads {
			for _, p := range batch {
				if string(recs[i].Payload) != p {
					t.Fatalf("G-EVI-04 baseline: record %d payload %q, want %q", i, recs[i].Payload, p)
				}
				i++
			}
		}
	}

	// spans[seg][rec]; mid record = seg0 rec1, last record = seg1 rec2 (the
	// journal tail, inside torn tolerance), lastSegMid = seg1 rec0 (mid record
	// of the LAST segment — the masquerade-radius probe).
	type target struct {
		name          string
		seg           int
		off           func(spans []recSpan) int
		mask          byte
		wantTorn      bool // tolerated_by_design: absorbed into torn-tail tolerance
		wantDelivered int  // for wantTorn: records delivered before the cut
	}
	fixed := func(o int) func([]recSpan) int { return func([]recSpan) int { return o } }
	cases := []target{
		// -------- segment header (offsets: writer.go buildHeader) --------
		{"hdr_magic_seg1", 0, fixed(0), 0xFF, false, 0},
		{"hdr_magic_seg2", 1, fixed(0), 0xFF, false, 0},
		{"hdr_version_seg1", 0, fixed(4), 0xFF, false, 0},
		{"hdr_version_seg2", 1, fixed(4), 0xFF, false, 0},
		{"hdr_segment_seq_seg1", 0, fixed(8), 0xFF, false, 0},
		{"hdr_segment_seq_seg2", 1, fixed(8), 0xFF, false, 0},
		{"hdr_prev_tail_seg1", 0, fixed(16), 0xFF, false, 0},  // vs zero tail
		{"hdr_prev_tail_seg2", 1, fixed(16), 0xFF, false, 0},  // vs seg1 tail — cross-segment inheritance
		{"hdr_created_ms_seg1", 0, fixed(48), 0xFF, false, 0}, // header hash participates in the chain
		{"hdr_created_ms_seg2", 1, fixed(48), 0xFF, false, 0},
		// -------- record header (appendRecord layout) --------
		{"rec_version_mid", 0, func(s []recSpan) int { return s[1].off + 0 }, 0xFF, false, 0},
		{"rec_version_last", 1, func(s []recSpan) int { return s[2].off + 0 }, 0xFF, false, 0},
		{"rec_type_mid", 0, func(s []recSpan) int { return s[1].off + 4 }, 0xFF, false, 0},
		{"rec_type_last", 1, func(s []recSpan) int { return s[2].off + 4 }, 0xFF, false, 0},
		{"rec_unix_ms_mid", 0, func(s []recSpan) int { return s[1].off + 8 }, 0xFF, false, 0},
		{"rec_unix_ms_last", 1, func(s []recSpan) int { return s[2].off + 8 }, 0xFF, false, 0},
		// -------- payload_len: in-bounds flip (8 -> 0) is a hash mismatch --------
		{"payload_len_inbounds_mid", 0, func(s []recSpan) int { return s[1].off + 16 }, 0x08, false, 0},
		{"payload_len_inbounds_last", 1, func(s []recSpan) int { return s[2].off + 16 }, 0x08, false, 0},
		// -------- payload_len: grown past EOF --------
		// mid-history: hard error (truncation mid-history is never tolerated)
		{"payload_len_pastEOF_mid", 0, func(s []recSpan) int { return s[1].off + 16 }, 0xFF, false, 0},
		// journal tail: ABSORBED by torn-tail tolerance — tolerated_by_design.
		// The 5 intact records deliver; the tampered tail does not.
		{"payload_len_pastEOF_last", 1, func(s []recSpan) int { return s[2].off + 16 }, 0xFF, true, 5},
		// mid record of the LAST segment: also absorbed, and it SWALLOWS the
		// following intact record (delivered drops to 3). This is the measured
		// masquerade radius of the crash tolerance (implementation contract 미결 5).
		{"payload_len_pastEOF_lastSegMid", 1, func(s []recSpan) int { return s[0].off + 16 }, 0xFF, true, 3},
		// -------- payload / hash fields --------
		{"payload_mid", 0, func(s []recSpan) int { return s[1].off + 20 }, 0xFF, false, 0},
		{"payload_last", 1, func(s []recSpan) int { return s[2].off + 20 }, 0xFF, false, 0},
		{"prev_hash_mid", 0, func(s []recSpan) int { return s[1].off + 20 + s[1].plen }, 0xFF, false, 0},
		{"prev_hash_last", 1, func(s []recSpan) int { return s[2].off + 20 + s[2].plen }, 0xFF, false, 0},
		{"this_hash_mid", 0, func(s []recSpan) int { return s[1].off + 20 + s[1].plen + 32 }, 0xFF, false, 0},
		{"this_hash_last", 1, func(s []recSpan) int { return s[2].off + 20 + s[2].plen + 32 }, 0xFF, false, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := buildTamperJournal(t)
			files := segFiles(t, dir)
			path := files[tc.seg]
			flipByte(t, path, tc.off(parseSpans(t, path)), tc.mask)

			recs, torn, err := collectWalk(dir)
			if tc.wantTorn {
				// tolerated_by_design: the flip is indistinguishable from a
				// mid-write crash. The contract is that NOTHING tampered (nor
				// anything after the cut) is delivered as verified.
				if err != nil {
					t.Fatalf("G-EVI-04 [%s]: expected torn-tail absorption, got error %v", tc.name, err)
				}
				if !torn {
					t.Fatalf("G-EVI-04 [%s]: expected tornTail=true", tc.name)
				}
				if len(recs) != tc.wantDelivered {
					t.Fatalf("G-EVI-04 [%s]: delivered=%d, want %d (prefix before the cut only)",
						tc.name, len(recs), tc.wantDelivered)
				}
				return
			}
			if err == nil {
				t.Fatalf("G-EVI-04 [%s]: one flipped byte walked clean (torn=%t, recs=%d) — tamper undetected",
					tc.name, torn, len(recs))
			}
		})
	}
}
