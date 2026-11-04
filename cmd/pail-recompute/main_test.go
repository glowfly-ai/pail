// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// Tests for pail-recompute. Most are negative: a verifier that has only been
// shown honest material has demonstrated that it can say yes. The fixture
// under testdata/ was written by the issuer itself (its test harness ran a
// site model, seven context events and five plans against a real journal
// writer), so every negative below is a controlled edit of bytes the issuer
// produced, re-chained so that only the intended rule is what changes.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixture = "testdata/fixture1"

// vectorDir locates the frozen set in either layout: the internal tree and the
// public snapshot keep it under different names, both two levels above this
// module.
func vectorDir(t *testing.T) string {
	t.Helper()
	for _, p := range []string{"../../spec/vectors/subgraph", "../../spec/subgraph-vectors"} {
		if _, err := os.Stat(filepath.Join(p, "MANIFEST.sha256")); err == nil {
			return p
		}
	}
	t.Fatal("subgraph vectors not found in either layout")
	return ""
}

func capture(t *testing.T, args ...string) (int, string) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	code := run(args, f, f)
	f.Close()
	b, _ := os.ReadFile(f.Name())
	return code, string(b)
}

// ── journal rewriting: edit payloads, re-chain, write a valid segment ───────

type rawRecord struct {
	typ     uint32
	unixMs  uint64
	payload []byte
}

func readRaw(t *testing.T, path string) (hdr []byte, recs []rawRecord) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	hdr = append([]byte(nil), data[:56]...)
	off := 56
	for off+20 <= len(data) {
		plen := int(binary.LittleEndian.Uint32(data[off+16 : off+20]))
		recs = append(recs, rawRecord{
			typ:     binary.LittleEndian.Uint32(data[off+4 : off+8]),
			unixMs:  binary.LittleEndian.Uint64(data[off+8 : off+16]),
			payload: append([]byte(nil), data[off+20:off+20+plen]...),
		})
		off += 20 + plen + 64
	}
	return hdr, recs
}

func writeChained(t *testing.T, path string, hdr []byte, recs []rawRecord) {
	t.Helper()
	var out bytes.Buffer
	out.Write(hdr)
	prev := sha256.Sum256(hdr)
	for _, r := range recs {
		rh := make([]byte, 16)
		binary.LittleEndian.PutUint32(rh[0:4], 1)
		binary.LittleEndian.PutUint32(rh[4:8], r.typ)
		binary.LittleEndian.PutUint64(rh[8:16], r.unixMs)
		h := sha256.New()
		h.Write(rh)
		h.Write(r.payload)
		h.Write(prev[:])
		this := h.Sum(nil)
		out.Write(rh)
		var l [4]byte
		binary.LittleEndian.PutUint32(l[:], uint32(len(r.payload)))
		out.Write(l[:])
		out.Write(r.payload)
		out.Write(prev[:])
		out.Write(this)
		copy(prev[:], this)
	}
	if err := os.WriteFile(path, out.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

// copyFixture returns a private copy of the fixture with every record's JSON
// payload passed through edit (type, payload) → payload. Records whose payload
// is not JSON are copied as they are.
func copyFixture(t *testing.T, edit func(typ uint32, m map[string]any) map[string]any) (site, journal string) {
	t.Helper()
	dir := t.TempDir()
	site = filepath.Join(dir, "site.yaml")
	b, err := os.ReadFile(filepath.Join(fixture, "site.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(site, b, 0o644); err != nil {
		t.Fatal(err)
	}
	journal = filepath.Join(dir, "journal")
	if err := os.MkdirAll(journal, 0o755); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(fixture, "journal", "pail_blackbox.00000001.seg")
	hdr, recs := readRaw(t, src)
	for i := range recs {
		var m map[string]any
		if json.Unmarshal(recs[i].payload, &m) != nil {
			continue
		}
		m2 := edit(recs[i].typ, m)
		if m2 == nil {
			continue
		}
		nb, err := json.Marshal(m2)
		if err != nil {
			t.Fatal(err)
		}
		recs[i].payload = nb
	}
	writeChained(t, filepath.Join(journal, "pail_blackbox.00000001.seg"), hdr, recs)
	return site, journal
}

// ── positive ────────────────────────────────────────────────────────────────

func TestVectorsSelfTest(t *testing.T) {
	code, out := capture(t, "vectors", "-dir", vectorDir(t))
	if code != 0 {
		t.Fatalf("vectors: exit %d\n%s", code, out)
	}
	if !strings.Contains(out, "findings 0") {
		t.Fatalf("unexpected output: %s", out)
	}
}

func TestFixtureAllVerified(t *testing.T) {
	code, out := capture(t, "ledger", "-site", filepath.Join(fixture, "site.yaml"), "-journal", filepath.Join(fixture, "journal"), "-v")
	if code != 0 {
		t.Fatalf("ledger: exit %d\n%s", code, out)
	}
	if strings.Count(out, "VERIFIED") != 5 || !strings.Contains(out, "verified 5 · mismatch 0 · cannot 0") {
		t.Fatalf("expected five verified tokens:\n%s", out)
	}
	// The rewriting helper must reproduce the fixture byte for byte, or every
	// negative below would be measuring the helper rather than the tool.
	site, journal := copyFixture(t, func(uint32, map[string]any) map[string]any { return nil })
	orig, _ := os.ReadFile(filepath.Join(fixture, "journal", "pail_blackbox.00000001.seg"))
	got, _ := os.ReadFile(filepath.Join(journal, "pail_blackbox.00000001.seg"))
	if !bytes.Equal(orig, got) {
		t.Fatal("copyFixture without edits does not reproduce the segment bytes")
	}
	if code, _ := capture(t, "ledger", "-site", site, "-journal", journal); code != 0 {
		t.Fatalf("identical copy: exit %d", code)
	}
}

// ── negative: exit 2, cannot ────────────────────────────────────────────────

func TestNoArgsIsCannot(t *testing.T) {
	if code, _ := capture(t); code != 2 {
		t.Fatalf("no arguments: exit %d, want 2", code)
	}
	if code, _ := capture(t, "ledger", "-site", "x"); code != 2 {
		t.Fatalf("missing -journal: exit %d, want 2", code)
	}
	if code, _ := capture(t, "vectors", "-dir", vectorDir(t), "extra"); code != 2 {
		t.Fatalf("stray positional argument: exit %d, want 2", code)
	}
}

func TestWrongSiteFileIsCannot(t *testing.T) {
	// A site file that compiles but is not the one the issuer loaded: the
	// hash it journaled differs, so nothing can be recomputed and nothing may
	// be called a finding either.
	site, journal := copyFixture(t, func(uint32, map[string]any) map[string]any { return nil })
	b, _ := os.ReadFile(site)
	if err := os.WriteFile(site, bytes.Replace(b, []byte("type: charge"), []byte("type: dock"), 1), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out := capture(t, "ledger", "-site", site, "-journal", journal)
	if code != 2 || !strings.Contains(out, "issued against site model") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

func TestEventWithoutZoneIsCannot(t *testing.T) {
	// A pre-2026-09-18 record: event_node_id and arg absent. HUMAN_ENTER can no
	// longer be replayed, so tokens issued after it are "cannot", not "verified".
	site, journal := copyFixture(t, func(typ uint32, m map[string]any) map[string]any {
		if typ == 50 && m["mutation_kind"] == "HUMAN_ENTER" {
			delete(m, "event_node_id")
			delete(m, "arg")
			return m
		}
		return nil
	})
	code, out := capture(t, "ledger", "-site", site, "-journal", journal, "-v")
	if code != 0 || strings.Count(out, "VERIFIED") != 1 || strings.Count(out, "CANNOT") != 4 {
		t.Fatalf("expected 1 verified (before the event) and 4 cannot: exit %d\n%s", code, out)
	}
}

// ── negative: exit 1, finding ───────────────────────────────────────────────

func TestChainBreakIsFinding(t *testing.T) {
	site, journal := copyFixture(t, func(uint32, map[string]any) map[string]any { return nil })
	p := filepath.Join(journal, "pail_blackbox.00000001.seg")
	b, _ := os.ReadFile(p)
	b[len(b)/2] ^= 0x01
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	code, out := capture(t, "ledger", "-site", site, "-journal", journal)
	if code != 1 || !strings.Contains(out, "hash chain broken") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

func TestLedgerHashEditIsMismatch(t *testing.T) {
	// The ledger's copy of the hash disagrees with the signed field 61.
	site, journal := copyFixture(t, func(typ uint32, m map[string]any) map[string]any {
		if typ == 10 {
			h := m["subgraph_snapshot_hash_hex"].(string)
			m["subgraph_snapshot_hash_hex"] = "00" + h[2:]
			return m
		}
		return nil
	})
	code, out := capture(t, "ledger", "-site", site, "-journal", journal)
	if code != 1 || strings.Count(out, "MISMATCH") != 5 || !strings.Contains(out, "signed field 61") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

func TestReplayDisagreementIsFinding(t *testing.T) {
	// The ledger claims a version the rules of section 6.2 do not produce.
	site, journal := copyFixture(t, func(typ uint32, m map[string]any) map[string]any {
		if typ == 50 && m["mutation_kind"] == "OBJECT_MOVE" {
			m["new_version"] = float64(9)
			return m
		}
		return nil
	})
	code, out := capture(t, "ledger", "-site", site, "-journal", journal)
	if code != 1 || !strings.Contains(out, "replays as") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

func TestSignedFieldEditIsMismatch(t *testing.T) {
	// The signed bytes themselves carry a different world hash than the
	// specification yields for that robot, target and epoch. The ledger copy is
	// edited to agree with the signed bytes so that only the recomputation can
	// object. (The signature is not this tool's question; pail-verify and the
	// gate own it.)
	site, journal := copyFixture(t, func(typ uint32, m map[string]any) map[string]any {
		if typ != 10 {
			return nil
		}
		raw, err := base64.StdEncoding.DecodeString(m["signed_token_b64"].(string))
		if err != nil {
			t.Fatal(err)
		}
		st, err := pbParse(raw)
		if err != nil {
			t.Fatal(err)
		}
		atb := pbBytes(st, 4)
		want, _ := hexDecode(m["subgraph_snapshot_hash_hex"].(string))
		idx := bytes.Index(atb, want)
		if idx < 0 {
			t.Fatal("field 61 bytes not found inside action_token_bytes")
		}
		// flip one byte of the 32-byte hash inside the signed token; the outer
		// message keeps its length so no re-framing is needed. SignedToken also
		// carries the same bytes as its informational `token` (field 1), which
		// serializes first — the signed copy is the LAST occurrence.
		pos := bytes.LastIndex(raw, atb) + idx
		raw[pos] ^= 0xff
		m["signed_token_b64"] = base64.StdEncoding.EncodeToString(raw)
		flipped := append([]byte(nil), want...)
		flipped[0] ^= 0xff
		m["subgraph_snapshot_hash_hex"] = hexEncode(flipped)
		return m
	})
	code, out := capture(t, "ledger", "-site", site, "-journal", journal)
	if code != 1 || strings.Count(out, "MISMATCH") != 5 || !strings.Contains(out, "recomputed") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

func TestVectorTamperIsFinding(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"MANIFEST.sha256", "cases.json", "selection.json", "world.json"} {
		b, err := os.ReadFile(filepath.Join(vectorDir(t), name))
		if err != nil {
			t.Fatal(err)
		}
		if name == "cases.json" {
			b = append(b, '\n')
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	code, out := capture(t, "vectors", "-dir", dir)
	if code != 1 || !strings.Contains(out, "hash differs from the manifest") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

// ── exit literals: the documented 0/1/2 are measured, not the constants ─────

func TestExitLiterals(t *testing.T) {
	if exitVerified != 0 || exitFinding != 1 || exitCannot != 2 {
		t.Fatalf("exit literals drifted: %d %d %d", exitVerified, exitFinding, exitCannot)
	}
}

func hexDecode(s string) ([]byte, error) {
	out := make([]byte, len(s)/2)
	for i := range out {
		var v byte
		for j := 0; j < 2; j++ {
			c := s[2*i+j]
			switch {
			case c >= '0' && c <= '9':
				v = v<<4 | (c - '0')
			case c >= 'a' && c <= 'f':
				v = v<<4 | (c - 'a' + 10)
			default:
				return nil, os.ErrInvalid
			}
		}
		out[i] = v
	}
	return out, nil
}

func hexEncode(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 2*len(b))
	for i, x := range b {
		out[2*i], out[2*i+1] = digits[x>>4], digits[x&15]
	}
	return string(out)
}
