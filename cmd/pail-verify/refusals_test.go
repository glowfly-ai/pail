// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// Negative controls for the refusals main.go implements but main_test.go never
// drives. Measured 2026-08-31 by removing each guard in turn and re-running the
// shipped suite: of 39 guards, 23 could be deleted with the suite still green.
// A guard no test can make fire is indistinguishable, in a summary, from a guard
// that is working — which is the defect this whole tool exists to refuse.
//
// Every test here is named in GUARDS.tsv against the guard it covers, and the
// runner in spec/tools re-derives that mapping rather than trusting it.
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
	"testing"
)

// --- helpers ----------------------------------------------------------------

// mintTrust returns a trust root whose private half this process holds. The
// frozen key's private half was never written to disk (spec/trust-roots.tsv), so
// anything that has to be *validly signed* in order to reach the rule under test
// has to be signed with a key we make here.
func mintTrust(t *testing.T, name, origin string) (*trust, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(append(append([]byte(name), 0x0A, 0x01), pub...))
	return &trust{name: name, origin: origin, hint: sum[:4], pub: pub}, priv
}

// vkeyLine writes a key line whose hint is correct for the algorithm byte given.
// The hint has to be right so that a test about the algorithm byte is about the
// algorithm byte and not about the hint.
func vkeyLine(name string, algo byte, pub []byte) string {
	sum := sha256.Sum256(append(append([]byte(name), 0x0A, algo), pub...))
	return name + "+" + hex.EncodeToString(sum[:4]) + "+" +
		base64.StdEncoding.EncodeToString(append([]byte{algo}, pub...))
}

func tempFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func signedNote(tr *trust, priv ed25519.PrivateKey, body string) []byte {
	blob := append(append([]byte{}, tr.hint...), ed25519.Sign(priv, []byte(body))...)
	return []byte(body + "\n" + emDash + tr.name + " " +
		base64.StdEncoding.EncodeToString(blob) + "\n")
}

// --- the verifier key -------------------------------------------------------

func TestVkeyFileMustNotBeEmpty(t *testing.T) {
	if _, err := loadTrust(tempFile(t, "empty.vkey", "\n"), "any-log"); err == nil {
		t.Fatal("an empty key file was accepted — an empty verifier list is a refusal")
	}
}

func TestVkeyNeedsThreeFields(t *testing.T) {
	for _, line := range []string{"onlyname", "name+0a0b0c0d"} {
		if _, err := loadTrust(tempFile(t, "short.vkey", line), "any-log"); err == nil {
			t.Errorf("%q was accepted as a key line", line)
		}
	}
}

func TestVkeyHintIsFourHexBytes(t *testing.T) {
	_, priv := mintTrust(t, "l", "l")
	pub := priv.Public().(ed25519.PublicKey)
	body := base64.StdEncoding.EncodeToString(append([]byte{0x01}, pub...))
	for _, hint := range []string{"zzzzzzzz", "0a0b", "0a0b0c0d0e"} {
		if _, err := loadTrust(tempFile(t, "hint.vkey", "l+"+hint+"+"+body), "l"); err == nil {
			t.Errorf("hint %q was accepted", hint)
		}
	}
}

func TestVkeyBodyMustBeBase64(t *testing.T) {
	if _, err := loadTrust(tempFile(t, "b64.vkey", "l+0a0b0c0d+not!base64"), "l"); err == nil {
		t.Fatal("a key body that is not base64 was accepted")
	}
}

// The body is one algorithm byte followed by the key. A body of the wrong width
// is refused rather than sliced: without the width check `blob[0]` on an empty
// body is a panic, and a panic is not a verdict.
func TestVkeyBodyIsAlgorithmPlusKey(t *testing.T) {
	for _, n := range []int{0, 1, 16, 40} {
		body := base64.StdEncoding.EncodeToString(make([]byte, n))
		if _, err := loadTrust(tempFile(t, "width.vkey", "l+0a0b0c0d+"+body), "l"); err == nil {
			t.Errorf("a %d-byte key body was accepted", n)
		}
	}
}

// A key that is well-formed, self-consistent and not ed25519. The hint here is
// derived over algorithm 0x02, so every other rule in loadTrust is satisfied and
// only the algorithm check stands between this file and a trust root whose bytes
// would then be handed to ed25519.Verify.
func TestVkeyAlgorithmIdIsEd25519Only(t *testing.T) {
	_, priv := mintTrust(t, "l", "l")
	pub := priv.Public().(ed25519.PublicKey)
	line := vkeyLine("l", 0x02, pub)
	if _, err := loadTrust(tempFile(t, "algo.vkey", line), "l"); err == nil {
		t.Fatal("algorithm 0x02 was accepted as ed25519")
	}
	// The same construction with 0x01 must load, or the test above proves only
	// that something in the line was wrong.
	if _, err := loadTrust(tempFile(t, "ok.vkey", vkeyLine("l", 0x01, pub)), "l"); err != nil {
		t.Fatalf("the 0x01 twin must load, else the case above is untargeted: %v", err)
	}
}

// --- note authentication ----------------------------------------------------

// A note with no blank line has no body and no signature section. That is
// "cannot verify"; reporting it as an unsigned note would be a finding about the
// log, and the log did not necessarily do anything.
func TestNoteWithoutBlankLineCannotBeVerified(t *testing.T) {
	tr, priv := mintTrust(t, "l", "l")
	note := signedNote(tr, priv, "l\n4\n"+base64.StdEncoding.EncodeToString(make([]byte, 32))+"\n")
	flat := bytes.Replace(note, []byte("\n\n"), []byte("\n"), 1)
	_, err := authenticate(flat, tr)
	if !errors.Is(err, errMalformed) {
		t.Fatalf("want errMalformed (cannot verify), got %v", err)
	}
}

// The signature line names its signer. Without that check any line carrying our
// hint and a signature our key made is accepted no matter whose name it claims —
// so a note a sibling log published under its own name would authenticate here.
func TestSignatureLineMustNameTheTrustedSigner(t *testing.T) {
	tr, priv := mintTrust(t, "l", "l")
	body := "l\n4\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"
	blob := append(append([]byte{}, tr.hint...), ed25519.Sign(priv, []byte(body))...)
	note := body + "\n" + emDash + "someone-else " +
		base64.StdEncoding.EncodeToString(blob) + "\n"
	if _, err := authenticate([]byte(note), tr); !errors.Is(err, errSignature) {
		t.Fatalf("want errSignature, got %v", err)
	}
}

// A signature blob narrower than hint+signature is refused, not sliced.
func TestShortSignatureBlobIsRefusedNotPanicked(t *testing.T) {
	tr, priv := mintTrust(t, "l", "l")
	_ = priv
	body := "l\n4\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"
	note := body + "\n" + emDash + tr.name + " " +
		base64.StdEncoding.EncodeToString([]byte{0x01, 0x02, 0x03}) + "\n"
	if _, err := authenticate([]byte(note), tr); !errors.Is(err, errSignature) {
		t.Fatalf("want errSignature, got %v", err)
	}
}

// The four hint bytes in front of the signature select which key to try. A line
// whose hint is not ours is not ours to verify, even when the signature under it
// would check out.
func TestSignatureHintMustMatchTheTrustRoot(t *testing.T) {
	tr, priv := mintTrust(t, "l", "l")
	body := "l\n4\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"
	blob := append([]byte{0xDE, 0xAD, 0xBE, 0xEF}, ed25519.Sign(priv, []byte(body))...)
	note := body + "\n" + emDash + tr.name + " " +
		base64.StdEncoding.EncodeToString(blob) + "\n"
	if _, err := authenticate([]byte(note), tr); !errors.Is(err, errSignature) {
		t.Fatalf("want errSignature, got %v", err)
	}
}

// The signed span ends at the blank line, so bytes after the signature block are
// outside it. A positive control: appending unsigned trailing bytes must not
// disturb authentication. Widen the span to the whole file and this is the note
// that stops verifying.
//
// TestSignedSpanIsBodyOnly reads as the test for this, but it recomputes the cut
// itself and never calls authenticate — it pins a property of the frozen vector,
// not of the code. A test that re-implements the computation it claims to check
// cannot see that computation change (실측 2026-08-31: `body := data[:cut+1]` 을
// `body := data` 로 바꾸면 18건이 붉는데 그 이름은 거기 없다).
func TestBytesAfterTheSignatureAreOutsideTheSignedSpan(t *testing.T) {
	tr, priv := mintTrust(t, "l", "l")
	body := "l\n4\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"
	note := append(signedNote(tr, priv, body), []byte("unsigned trailing commentary\n")...)
	if _, err := authenticate(note, tr); err != nil {
		t.Fatalf("trailing bytes broke authentication — the signed span is not the body alone: %v", err)
	}
}

// A body of fewer than three lines is refused before it is indexed.
func TestBodyShorterThanThreeLinesIsMalformed(t *testing.T) {
	tr, priv := mintTrust(t, "l", "l")
	if _, err := authenticate(signedNote(tr, priv, "l\n"), tr); !errors.Is(err, errMalformed) {
		t.Fatalf("want errMalformed, got %v", err)
	}
}

// The tree size is decimal. Without the parse check a note whose size line is
// prose travels onward as size 0, and every later comparison against it is a
// comparison against a number the log never wrote.
func TestTreeSizeMustBeDecimal(t *testing.T) {
	tr, priv := mintTrust(t, "l", "l")
	body := "l\nfour\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"
	cp, err := authenticate(signedNote(tr, priv, body), tr)
	if !errors.Is(err, errMalformed) {
		t.Fatalf("want errMalformed, got %v", err)
	}
	if cp != nil {
		t.Error("a checkpoint travelled onward alongside the error")
	}
}

func TestRootMustBeBase64(t *testing.T) {
	tr, priv := mintTrust(t, "l", "l")
	if _, err := authenticate(signedNote(tr, priv, "l\n4\nnot!base64\n"), tr); !errors.Is(err, errMalformed) {
		t.Fatalf("want errMalformed, got %v", err)
	}
}

// --- RFC 6962 refusals ------------------------------------------------------

// size4 returns a four-leaf tree: the four leaf hashes, the root, and the
// inclusion proof for leaf 0. Built here rather than read from the corpus so
// that the perturbations below are obviously the only thing wrong.
func size4(t *testing.T) (leaves [][]byte, root []byte, proof0 [][]byte) {
	t.Helper()
	for i := 0; i < 4; i++ {
		leaves = append(leaves, leafHash([]byte{byte(i)}))
	}
	n01 := nodeHash(leaves[0], leaves[1])
	n23 := nodeHash(leaves[2], leaves[3])
	return leaves, nodeHash(n01, n23), [][]byte{leaves[1], n23}
}

func TestInclusionIndexMustBeInsideTheTree(t *testing.T) {
	leaves, root, proof := size4(t)
	if got, err := verifyInclusion(0, 4, leaves[0], proof); err != nil || !bytes.Equal(got, root) {
		t.Fatalf("the honest twin must verify, else the cases below are untargeted: %v", err)
	}
	for _, tc := range []struct{ index, size uint64 }{{4, 4}, {9, 4}, {0, 0}} {
		if _, err := verifyInclusion(tc.index, tc.size, leaves[0], proof); err == nil {
			t.Errorf("leaf %d of a tree of size %d was accepted", tc.index, tc.size)
		}
	}
}

func TestInclusionProofDeeperThanTheTree(t *testing.T) {
	leaves, _, proof := size4(t)
	long := append(append([][]byte{}, proof...), leaves[2])
	if _, err := verifyInclusion(0, 4, leaves[0], long); err == nil {
		t.Fatal("a proof longer than the tree is deep was accepted")
	}
}

func TestInclusionProofShallowerThanTheTree(t *testing.T) {
	leaves, _, proof := size4(t)
	if _, err := verifyInclusion(0, 4, leaves[0], proof[:1]); err == nil {
		t.Fatal("a proof shorter than the tree is deep was accepted")
	}
}

// A range that runs backwards, with the two roots equal and no proof, satisfies
// every later comparison. Only the range check refuses it — and "the log did not
// go backwards" is the whole claim a consistency proof makes.
func TestConsistencyRangeMustBeForwardAndNonEmpty(t *testing.T) {
	r := sha256.Sum256([]byte("a root"))
	for _, tc := range []struct{ from, to uint64 }{{2, 1}, {0, 4}, {4, 0}} {
		if err := verifyConsistency(tc.from, tc.to, r[:], r[:], nil); err == nil {
			t.Errorf("range %d..%d was accepted", tc.from, tc.to)
		}
	}
}

func TestSelfConsistencyCarriesNoHashes(t *testing.T) {
	r := sha256.Sum256([]byte("a root"))
	junk := sha256.Sum256([]byte("a hash"))
	if err := verifyConsistency(4, 4, r[:], r[:], [][]byte{junk[:]}); err == nil {
		t.Fatal("a self-consistency proof carrying hashes was accepted")
	}
	if err := verifyConsistency(4, 4, r[:], r[:], nil); err != nil {
		t.Fatalf("the honest twin must verify, else the case above is untargeted: %v", err)
	}
}

func TestSelfConsistencySameSizeMustAgreeOnTheRoot(t *testing.T) {
	a := sha256.Sum256([]byte("root a"))
	b := sha256.Sum256([]byte("root b"))
	if err := verifyConsistency(4, 4, a[:], b[:], nil); err == nil {
		t.Fatal("two different roots at the same size were called consistent")
	}
}

// Proof hashes are SHA-256 wide. A narrower one is not a hash that failed to
// match; it is material this algorithm cannot fold, and folding it anyway
// produces a root that is wrong for a reason nobody reports.
func TestProofHashesMustBeSHA256Wide(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33} {
		in := []string{base64.StdEncoding.EncodeToString(make([]byte, n))}
		if _, err := decodeAll(in, "proof_b64"); err == nil {
			t.Errorf("a %d-byte proof hash was accepted", n)
		}
	}
}

// --- subcommand plumbing ----------------------------------------------------

// The proof names the range it covers. If that range is not the range the two
// authenticated notes stand at, there is nothing to check it against — and that
// is "cannot verify", not a finding about the log.
func TestConsistencyRangeMustMatchTheAuthenticatedNotes(t *testing.T) {
	tr, priv := mintTrust(t, "l", "l")
	dir := t.TempDir()
	note := func(name string, size string) string {
		root := sha256.Sum256([]byte(name))
		p := filepath.Join(dir, name)
		body := "l\n" + size + "\n" + base64.StdEncoding.EncodeToString(root[:]) + "\n"
		if err := os.WriteFile(p, signedNote(tr, priv, body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	from2, to4 := note("from.note", "2"), note("to.note", "4")
	cp, err := authenticate(mustRead(t, to4), tr)
	if err != nil {
		t.Fatal(err)
	}
	proof := filepath.Join(dir, "proof.json")
	blob, err := json.Marshal(consistencyResp{From: 1, To: 4})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(proof, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := cmdConsistency(cp, from2, tr, proof); got != exitCannot {
		t.Errorf("exit %d, want %d (cannot verify)", got, exitCannot)
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// bundleCase builds a checkpoint plus a bundle envelope around the frozen
// inclusion vector, so the bundle tests below differ from each other in exactly
// one field.
func bundleCase(t *testing.T, size uint64, index uint64, proof []string) (*checkpoint, string, string) {
	t.Helper()
	pv := vectors(t, "proof")
	cp, err := authenticate(frozenNote(t), frozenTrust(t, "glowfly-anchor-log"))
	if err != nil {
		t.Fatal(err)
	}
	var r inclusionResp
	if err := readJSON(filepath.Join(pv, "inclusion_size4_idx0.json"), &r); err != nil {
		t.Fatal(err)
	}
	if proof == nil {
		proof = r.ProofB64
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
	blob, err := json.Marshal(map[string]any{
		"inclusion_proofs": []map[string]any{{
			"leaf_index": index, "sth_tree_size": size, "proof_base64": proof,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	return cp, bundlePath, leafPath
}

// The bundle carries proof hashes but not the leaf they prove. Without the leaf
// there is nothing to hash, and hashing nothing produces a leaf hash all the
// same — one that belongs to no record.
func TestBundleLeafIsRequired(t *testing.T) {
	cp, bundle, _ := bundleCase(t, 4, 0, nil)
	if got := cmdBundle(cp, bundle, "", 0); got != exitCannot {
		t.Errorf("no -leaf: exit %d, want %d", got, exitCannot)
	}
}

func TestBundleLeafMustBeReadable(t *testing.T) {
	cp, bundle, leaf := bundleCase(t, 4, 0, nil)
	if got := cmdBundle(cp, bundle, leaf+".missing", 0); got != exitCannot {
		t.Errorf("unreadable -leaf: exit %d, want %d", got, exitCannot)
	}
	if got := cmdBundle(cp, bundle, leaf, 0); got != exitVerified {
		t.Errorf("the honest twin must verify, else the case above is untargeted: exit %d", got)
	}
}

// An entry at a different tree size has no root here to be checked against.
func TestBundleEntrySizeMustMatchTheCheckpoint(t *testing.T) {
	cp, bundle, leaf := bundleCase(t, 999, 0, nil)
	if got := cmdBundle(cp, bundle, leaf, 0); got != exitCannot {
		t.Errorf("exit %d, want %d (cannot verify)", got, exitCannot)
	}
}

// A bundle with no proof for the leaf asked about proves nothing about it.
// Absent evidence must not be reported as evidence of presence.
func TestBundleWithoutAProofForTheLeafCannotVerify(t *testing.T) {
	cp, bundle, leaf := bundleCase(t, 4, 0, nil)
	if got := cmdBundle(cp, bundle, leaf, 3); got != exitCannot {
		t.Errorf("exit %d, want %d (cannot verify)", got, exitCannot)
	}
}
