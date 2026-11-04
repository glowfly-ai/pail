// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// Tests for pail-verify. Two thirds of them are negative: a verifier that has
// only ever been shown valid material has demonstrated that it can say yes.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// vectors locates the frozen sets. The internal tree and the public snapshot
// keep them under different names; both sit two levels above this module, so
// the test runs unchanged in either layout rather than being a check that only
// works where it was written.
func vectors(t *testing.T, kind string) string {
	t.Helper()
	for _, p := range map[string][]string{
		"proof":  {"../../spec/vectors/proof", "../../spec/proof-vectors"},
		"merkle": {"../../spec/vectors/merkle", "../../spec/merkle-vectors"},
	}[kind] {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Fatalf("%s vectors not found in either layout", kind)
	return ""
}

func frozenTrust(t *testing.T, origin string) *trust {
	t.Helper()
	tr, err := loadTrust(filepath.Join(vectors(t, "proof"), "checkpoint.vkey"), origin)
	if err != nil {
		t.Fatalf("loadTrust: %v", err)
	}
	return tr
}

func frozenNote(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vectors(t, "proof"), "checkpoint.note"))
	if err != nil {
		t.Fatalf("checkpoint.note: %v", err)
	}
	return b
}

// --- trust root -------------------------------------------------------------

// An unconfigured trust root must refuse. If it instead accepted everything, a
// deployment that forgot to configure it would report every log as fine.
func TestEmptyTrustRootRefuses(t *testing.T) {
	if _, err := loadTrust("", "glowfly-anchor-log"); err == nil {
		t.Fatal("missing -vkey was accepted")
	}
	if _, err := loadTrust(filepath.Join(vectors(t, "proof"), "checkpoint.vkey"), ""); err == nil {
		t.Fatal("missing -origin was accepted")
	}
	empty := filepath.Join(t.TempDir(), "empty.vkey")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTrust(empty, "glowfly-anchor-log"); err == nil {
		t.Fatal("an empty key file was accepted as a verifier list")
	}
}

// The hint is derived, not copied. A key file whose halves disagree is a
// different failure from a note that does not verify, and must not be silently
// repaired by trusting the declared hex.
func TestVkeyHintIsRederived(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectors(t, "proof"), "checkpoint.vkey"))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(strings.TrimSpace(string(raw)), "+", 3)
	bad := parts[0] + "+00000000+" + parts[2]
	p := filepath.Join(t.TempDir(), "bad.vkey")
	if err := os.WriteFile(p, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTrust(p, "glowfly-anchor-log"); err == nil {
		t.Fatal("a key file that contradicts itself was accepted")
	}
}

// The field separator is a member of the payload's own alphabet: base64 emits
// `+`. A key body is 44 base64 characters, so roughly three keys in four contain
// one and split into more than three fields. A parser that demands exactly three
// refuses most legitimate trust roots — the acquisition path in TRUST_ROOT.md
// hands an operator a key the verifier then rejects. That is not fail-closed; it
// is a wall. The key shipped today happens to have none, so nothing else in this
// file would notice.
func TestVkeyBodyMayContainPlus(t *testing.T) {
	var pub ed25519.PublicKey
	var blob []byte
	for i := 0; i < 4096; i++ {
		seed := sha256.Sum256([]byte{byte(i), byte(i >> 8)})
		pub = ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
		blob = append([]byte{0x01}, pub...)
		if strings.Contains(base64.StdEncoding.EncodeToString(blob), "+") {
			break
		}
		blob = nil
	}
	if blob == nil {
		t.Fatal("no seed produced a body containing `+` — the premise cannot be set up")
	}
	const name = "glowfly-anchor-log"
	sum := sha256.Sum256(append(append([]byte(name), 0x0A), blob...))
	vkey := name + "+" + hex.EncodeToString(sum[:4]) + "+" +
		base64.StdEncoding.EncodeToString(blob)
	p := filepath.Join(t.TempDir(), "plus.vkey")
	if err := os.WriteFile(p, []byte(vkey), 0o600); err != nil {
		t.Fatal(err)
	}
	tr, err := loadTrust(p, name)
	if err != nil {
		t.Fatalf("a well-formed key whose body contains `+` was refused: %v", err)
	}
	if !bytes.Equal(tr.pub, pub) {
		t.Error("the parsed key is not the one in the file")
	}
}

// --- the two gates ----------------------------------------------------------

func TestCheckpointAuthenticates(t *testing.T) {
	cp, err := authenticate(frozenNote(t), frozenTrust(t, "glowfly-anchor-log"))
	if err != nil {
		t.Fatalf("frozen note did not open: %v", err)
	}
	if cp.size != 4 {
		t.Errorf("size = %d, want 4", cp.size)
	}
	if len(cp.root) != sha256.Size {
		t.Errorf("root is %d bytes", len(cp.root))
	}
}

// Gate 2 must fire on its own. With only gate 1, a sibling log run by the same
// operator — whose checkpoint is perfectly valid — is accepted as yours.
func TestOriginGateFiresAlone(t *testing.T) {
	_, err := authenticate(frozenNote(t), frozenTrust(t, "some-other-log"))
	if !errors.Is(err, errOrigin) {
		t.Fatalf("want errOrigin, got %v", err)
	}
}

func TestForgedSignatureRejected(t *testing.T) {
	note := frozenNote(t)
	cut := bytes.Index(note, []byte("\n\n"))
	forged := append([]byte{}, note...)
	forged[len(forged)-3] ^= 0x01 // one bit of the signature blob
	if _, err := authenticate(forged, frozenTrust(t, "glowfly-anchor-log")); !errors.Is(err, errSignature) {
		t.Fatalf("flipped signature: want errSignature, got %v", err)
	}

	// A rewritten body with the original signature: the note still parses, still
	// yields a 32-byte root, and is still not vouched for by anyone.
	tampered := append([]byte{}, note...)
	tampered[cut-4] ^= 0x01
	if _, err := authenticate(tampered, frozenTrust(t, "glowfly-anchor-log")); !errors.Is(err, errSignature) {
		t.Fatalf("rewritten body: want errSignature, got %v", err)
	}
}

// §2.1: the signature lines begin with U+2014, not a hyphen. An implementation
// that splits on "- " finds no signature and reports the note as unsigned.
func TestHyphenIsNotAnEmDash(t *testing.T) {
	note := string(frozenNote(t))
	hyphenated := strings.Replace(note, emDash, "- ", 1)
	if _, err := authenticate([]byte(hyphenated), frozenTrust(t, "glowfly-anchor-log")); !errors.Is(err, errSignature) {
		t.Fatalf("want errSignature, got %v", err)
	}
}

// §2.4, sig_message: the signed span is the body, not the file. Both spans
// produce a note that parses; only one verifies. Measured in both directions —
// checking only that the body verifies would leave a whole-file implementation
// looking correct.
func TestSignedSpanIsBodyOnly(t *testing.T) {
	note := frozenNote(t)
	tr := frozenTrust(t, "glowfly-anchor-log")
	cut := bytes.Index(note, []byte("\n\n"))
	body := note[:cut+1]

	var sig []byte
	for _, line := range strings.Split(string(note[cut+2:]), "\n") {
		if !strings.HasPrefix(line, emDash) {
			continue
		}
		f := strings.Fields(line[len(emDash):])
		blob, err := base64.StdEncoding.DecodeString(f[1])
		if err != nil {
			t.Fatal(err)
		}
		sig = blob[4:]
	}
	if sig == nil {
		t.Fatal("no signature line")
	}
	if !ed25519.Verify(tr.pub, body, sig) {
		t.Error("signature does not verify over the body")
	}
	if ed25519.Verify(tr.pub, note, sig) {
		t.Error("signature also verifies over the whole file — the span is not pinned")
	}
}

// §2.3: a truncated note splits into three fields whose last is empty, and
// base64 decodes "" without complaint. Without the width check, no root travels
// onward as a root.
func TestTruncatedNoteIsNotAZeroLengthRoot(t *testing.T) {
	// Signed with a key we control, so what is under test is the parse rule and
	// not the signature: a genuinely signed note whose body is short must still
	// be refused.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	tr := &trust{name: "glowfly-anchor-log", origin: "glowfly-anchor-log",
		hint: []byte{1, 2, 3, 4}, pub: pub}
	sign := func(body string) []byte {
		blob := append(append([]byte{}, tr.hint...), ed25519.Sign(priv, []byte(body))...)
		return []byte(body + "\n" + emDash + tr.name + " " +
			base64.StdEncoding.EncodeToString(blob) + "\n")
	}
	for _, tc := range []struct{ name, body string }{
		// §2.3's own example: splits into three fields whose last is empty.
		{"no root line", "glowfly-anchor-log\n4\n"},
		// A root that decodes cleanly but to the wrong width. Without the width
		// check the caller receives it as a root.
		{"short root", "glowfly-anchor-log\n4\nAAAA\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cp, err := authenticate(sign(tc.body), tr)
			if !errors.Is(err, errMalformed) {
				t.Fatalf("want errMalformed, got %v", err)
			}
			if cp != nil {
				t.Errorf("a checkpoint travelled onward alongside the error")
			}
		})
	}
}

// --- RFC 6962 against the frozen wire vectors -------------------------------

func TestInclusionAgainstFrozenCheckpoint(t *testing.T) {
	cp, err := authenticate(frozenNote(t), frozenTrust(t, "glowfly-anchor-log"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"inclusion_size4_idx0.json", "inclusion_size4_idx3.json"} {
		var r inclusionResp
		if err := readJSON(filepath.Join(vectors(t, "proof"), name), &r); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		leaf, err := base64.StdEncoding.DecodeString(r.LeafB64)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := decodeAll(r.ProofB64, "proof_b64")
		if err != nil {
			t.Fatal(err)
		}
		got, err := verifyInclusion(r.LeafIndex, r.TreeSize, leafHash(leaf), proof)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(got, cp.root) {
			t.Errorf("%s: derived %s, authenticated %s", name, b64(got), b64(cp.root))
		}

		// §1: a wholesale-rewritten proof still terminates and still produces
		// 32 bytes. Only the comparison against an authenticated root catches it.
		rewritten := make([][]byte, len(proof))
		for i := range proof {
			h := sha256.Sum256([]byte{byte(i)})
			rewritten[i] = h[:]
		}
		if len(rewritten) > 0 {
			bad, err := verifyInclusion(r.LeafIndex, r.TreeSize, leafHash(leaf), rewritten)
			if err != nil {
				t.Fatalf("%s: rewritten proof did not even terminate: %v", name, err)
			}
			if len(bad) != sha256.Size {
				t.Errorf("%s: rewritten proof yielded %d bytes", name, len(bad))
			}
			if bytes.Equal(bad, cp.root) {
				t.Errorf("%s: rewritten proof reached the authenticated root", name)
			}
		}
	}
}

// §5.1: at a historical size the server declines to echo a root. That is not an
// error, and the verifier must supply the root itself — which, with only one
// frozen checkpoint, it cannot. The honest answer is "cannot verify", not a pass.
func TestHistoricalSizeCannotBeVerifiedFromTheLatestCheckpoint(t *testing.T) {
	var r inclusionResp
	if err := readJSON(filepath.Join(vectors(t, "proof"), "inclusion_size2_idx0.json"), &r); err != nil {
		t.Fatal(err)
	}
	if r.RootB64 != "" {
		t.Fatalf("vector no longer carries the empty-root case: %q", r.RootB64)
	}
	cp, err := authenticate(frozenNote(t), frozenTrust(t, "glowfly-anchor-log"))
	if err != nil {
		t.Fatal(err)
	}
	if r.TreeSize == cp.size {
		t.Fatal("vector is no longer at a historical size")
	}
	if got := cmdInclusion(cp, filepath.Join(vectors(t, "proof"), "inclusion_size2_idx0.json")); got != exitCannot {
		t.Errorf("exit %d, want %d (cannot verify)", got, exitCannot)
	}
}

// The response's own `root_b64` is not a root. This is §1 in its most direct
// form: a log that rewrites the proof and echoes the root that proof derives to
// is internally consistent, and a verifier that compares the two agrees with it.
// The frozen vectors cannot catch this on their own — there the echoed root and
// the authenticated root are equal, so trusting the wrong one looks identical.
func TestEchoedRootIsNotTrusted(t *testing.T) {
	pv := vectors(t, "proof")
	cp, err := authenticate(frozenNote(t), frozenTrust(t, "glowfly-anchor-log"))
	if err != nil {
		t.Fatal(err)
	}
	var r inclusionResp
	if err := readJSON(filepath.Join(pv, "inclusion_size4_idx0.json"), &r); err != nil {
		t.Fatal(err)
	}
	leaf, err := base64.StdEncoding.DecodeString(r.LeafB64)
	if err != nil {
		t.Fatal(err)
	}
	fabricated := make([][]byte, len(r.ProofB64))
	enc := make([]string, len(r.ProofB64))
	for i := range fabricated {
		h := sha256.Sum256([]byte{0xAA, byte(i)})
		fabricated[i] = h[:]
		enc[i] = b64(h[:])
	}
	selfRoot, err := verifyInclusion(r.LeafIndex, r.TreeSize, leafHash(leaf), fabricated)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(selfRoot, cp.root) {
		t.Fatal("fabricated proof reached the real root")
	}

	dir := t.TempDir()
	write := func(name string, root string, proof []string) string {
		r2 := r
		r2.RootB64 = root
		r2.ProofB64 = proof
		blob, err := json.Marshal(r2)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, blob, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, tc := range []struct {
		name  string
		root  string
		proof []string
		want  int
	}{
		{"self-consistent forgery", b64(selfRoot), enc, exitFinding},
		// The form the echo check alone defends: the log signed root R, then
		// asserted X != R in the proof response while shipping a proof that
		// honestly derives to R. The derivation comparison is satisfied here, so
		// without the echo check nothing reports the contradiction.
		{"contradicting echo, honest proof", b64(selfRoot), r.ProofB64, exitFinding},
		// §5.1: an absent echo is the server declining to assert. It must not
		// become an excuse to accept whatever the proof derives to.
		{"absent echo, forged proof", "", enc, exitFinding},
		{"absent echo, honest proof", "", r.ProofB64, exitVerified},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := cmdInclusion(cp, write(tc.name+".json", tc.root, tc.proof)); got != tc.want {
				t.Errorf("exit %d, want %d", got, tc.want)
			}
		})
	}
}

// §5.2: for a power-of-two `from`, root@from is an input to the algorithm, not
// merely the value compared at the end. Supply the wrong one and the derivation
// still completes — so the test is that it completes and still fails.
func TestConsistencyPowerOfTwoTrap(t *testing.T) {
	cp, err := authenticate(frozenNote(t), frozenTrust(t, "glowfly-anchor-log"))
	if err != nil {
		t.Fatal(err)
	}
	var r consistencyResp
	if err := readJSON(filepath.Join(vectors(t, "proof"), "consistency_2_4.json"), &r); err != nil {
		t.Fatal(err)
	}
	if r.From&(r.From-1) != 0 {
		t.Fatalf("vector `from`=%d is no longer a power of two", r.From)
	}
	proof, err := decodeAll(r.ProofB64, "proof_b64")
	if err != nil {
		t.Fatal(err)
	}
	wrong := sha256.Sum256([]byte("not the root at size 2"))
	if err := verifyConsistency(r.From, r.To, wrong[:], cp.root, proof); err == nil {
		t.Fatal("a fabricated root@from was accepted")
	}
}

// --- RFC 6962 against the conformance corpus --------------------------------

// Inclusion and consistency are separate tests on purpose. They are separate
// algorithms with separate failure modes — the boundary fold belongs to one and
// the seed selection to the other. Under one name a break in either produces the
// same red line, and "which of the two is still measured" stops being readable.
func TestMerkleCorpusInclusion(t *testing.T) {
	dir := vectors(t, "merkle")

	var incl struct {
		Cases []struct {
			Size, Index uint64
			LeafHash    string   `json:"leaf_hash"`
			Proof       []string `json:"proof"`
			Root        string   `json:"root"`
		} `json:"cases"`
	}
	if err := readJSON(filepath.Join(dir, "inclusion.json"), &incl); err != nil {
		t.Fatal(err)
	}
	if len(incl.Cases) == 0 {
		t.Fatal("inclusion corpus is empty — an empty corpus passes every implementation")
	}
	nonPow := 0
	for _, c := range incl.Cases {
		if c.Size&(c.Size-1) != 0 {
			nonPow++
		}
		got, err := verifyInclusion(c.Index, c.Size, mustHex(t, c.LeafHash), mustHexes(t, c.Proof))
		if err != nil {
			t.Fatalf("size=%d index=%d: %v", c.Size, c.Index, err)
		}
		if hex.EncodeToString(got) != c.Root {
			t.Errorf("size=%d index=%d: derived %s, want %s", c.Size, c.Index,
				hex.EncodeToString(got), c.Root)
		}
	}
	if nonPow == 0 {
		t.Error("inclusion corpus has no non-power-of-two tree — an implementation " +
			"with no boundary folding passes a power-of-two-only corpus")
	}
}

func TestMerkleCorpusConsistency(t *testing.T) {
	dir := vectors(t, "merkle")

	var cons struct {
		Cases []struct {
			Size1, Size2 uint64
			Proof        []string `json:"proof"`
			Root1        string   `json:"root1"`
			Root2        string   `json:"root2"`
		} `json:"cases"`
	}
	if err := readJSON(filepath.Join(dir, "consistency.json"), &cons); err != nil {
		t.Fatal(err)
	}
	if len(cons.Cases) == 0 {
		t.Fatal("consistency corpus is empty")
	}
	nonPow := 0
	for _, c := range cons.Cases {
		if c.Size1&(c.Size1-1) != 0 {
			nonPow++
		}
		r1, r2 := mustHex(t, c.Root1), mustHex(t, c.Root2)
		if err := verifyConsistency(c.Size1, c.Size2, r1, r2, mustHexes(t, c.Proof)); err != nil {
			t.Errorf("%d..%d: %v", c.Size1, c.Size2, err)
		}
		// Same case, one root fabricated. Every honest case must have a
		// dishonest twin that fails, or "it verified" means only "it ran".
		wrong := sha256.Sum256([]byte(c.Root2))
		if err := verifyConsistency(c.Size1, c.Size2, r1, wrong[:], mustHexes(t, c.Proof)); err == nil {
			t.Errorf("%d..%d: a fabricated root@to was accepted", c.Size1, c.Size2)
		}
	}
	if nonPow == 0 {
		t.Error("consistency corpus has no non-power-of-two `from` — the seed-selection " +
			"branch is never exercised")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustHexes(t *testing.T, in []string) [][]byte {
	t.Helper()
	out := make([][]byte, 0, len(in))
	for _, s := range in {
		out = append(out, mustHex(t, s))
	}
	return out
}

// --- the bundle is transport, not evidence ----------------------------------

// The bundle envelope here is synthesised; the proof material inside it is the
// frozen inclusion vector. That split is deliberate: this test measures that the
// tool reads only proof material out of a bundle, not that the envelope's field
// names are right — the field names are pinned to the emitter in §8.
func TestBundleIsUsedOnlyAsTransport(t *testing.T) {
	pv := vectors(t, "proof")
	var r inclusionResp
	if err := readJSON(filepath.Join(pv, "inclusion_size4_idx0.json"), &r); err != nil {
		t.Fatal(err)
	}
	leafBytes, err := base64.StdEncoding.DecodeString(r.LeafB64)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	leafPath := filepath.Join(dir, "leaf.bin")
	if err := os.WriteFile(leafPath, leafBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	mk := func(verdict string, proof []string) string {
		blob, err := json.Marshal(map[string]any{
			"verdict":         verdict,
			"log_consistency": true,
			"log_root_hex":    strings.Repeat("00", 32),
			"log_size":        999,
			"inclusion_proofs": []map[string]any{{
				"leaf_index": r.LeafIndex, "sth_tree_size": r.TreeSize, "proof_base64": proof,
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, verdict+".json")
		if err := os.WriteFile(p, blob, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	args := func(bundle string) []string {
		return []string{"bundle",
			"-vkey", filepath.Join(pv, "checkpoint.vkey"),
			"-origin", "glowfly-anchor-log",
			"-note", filepath.Join(pv, "checkpoint.note"),
			"-bundle", bundle, "-leaf", leafPath, "-leaf-index", "0"}
	}

	// The bundle claims MISMATCH and a root of all zeros at size 999. None of
	// that is read; the proof material still verifies against our checkpoint.
	if got := run(args(mk("MISMATCH", r.ProofB64))); got != exitVerified {
		t.Errorf("honest proof material in a hostile envelope: exit %d, want 0", got)
	}
	// The bundle claims MATCH and the proof material is fabricated. The claim
	// buys it nothing.
	bad := make([]string, len(r.ProofB64))
	for i := range bad {
		h := sha256.Sum256([]byte{byte(i)})
		bad[i] = b64(h[:])
	}
	if got := run(args(mk("MATCH", bad))); got != exitFinding {
		t.Errorf("fabricated proof material in a friendly envelope: exit %d, want %d",
			got, exitFinding)
	}
}

// An argument the tool does not understand must stop it. Ignoring it would let
// a misspelt flag run as though nothing had been asked for, and report on
// whatever it did check.
func TestUnknownArgumentRefuses(t *testing.T) {
	pv := vectors(t, "proof")
	if got := run([]string{"checkpoint",
		"-vkey", filepath.Join(pv, "checkpoint.vkey"),
		"-origin", "glowfly-anchor-log",
		"-note", filepath.Join(pv, "checkpoint.note"),
		"stray"}); got != exitCannot {
		t.Errorf("exit %d, want %d", got, exitCannot)
	}
	if got := run([]string{"verify-everything"}); got != exitCannot {
		t.Errorf("unknown subcommand: exit %d, want %d", got, exitCannot)
	}
}
