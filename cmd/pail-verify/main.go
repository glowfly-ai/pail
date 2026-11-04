// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// Command pail-verify audits a PAIL anchor log from files, offline.
//
// It is a separate Go module with no dependencies outside the standard library,
// and that is a design constraint rather than an accident. A verifier that has
// to build the audited party's services in order to run is not an independent
// verifier; a verifier that shares the audited party's Merkle library agrees
// with it by identity rather than by evidence. Every rule implemented here is
// read from spec/VERIFICATION_INPUTS.md and spec/MERKLE_VECTORS.md.
//
// Three exit states, deliberately not two:
//
//	0  verified
//	1  the log's own bytes contradict the trust root — a finding
//	2  cannot verify — no trust anchor, unreadable input, mismatched sizes
//
// The third one exists because "we never checked" must not reach a caller
// wearing the same face as "we checked and it was fine".
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	exitVerified = 0
	exitFinding  = 1
	exitCannot   = 2
)

// emDash prefixes every signature line. U+2014, not a hyphen: an implementation
// that splits on "- " finds no signature and reports the note as unsigned
// (VERIFICATION_INPUTS §2.1).
const emDash = "— "

var (
	errSignature = errors.New("gate 1: signature not from the configured trust root")
	errOrigin    = errors.New("gate 2: a trusted key signed this, about a different log")
	errMalformed = errors.New("note is malformed")
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func usage() int {
	fmt.Fprint(os.Stderr, `pail-verify — offline audit of a PAIL anchor log

  pail-verify checkpoint  -vkey F -origin S -note F
  pail-verify inclusion   -vkey F -origin S -note F -proof F
  pail-verify consistency -vkey F -origin S -note F -from-note F -proof F
  pail-verify bundle      -vkey F -origin S -note F -bundle F -leaf F -leaf-index N

-vkey and -origin are the trust root. Both must reach this tool out of band.
Reading either out of the material being audited asks the subject to grade its
own paper, so neither has a default and neither can be omitted.

exit 0 verified · 1 finding · 2 cannot verify
`)
	return exitCannot
}

func run(args []string) int {
	if len(args) == 0 {
		return usage()
	}
	cmd, rest := args[0], args[1:]

	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	vkey := fs.String("vkey", "", "file holding the log's verifier key line")
	origin := fs.String("origin", "", "expected log origin")
	note := fs.String("note", "", "signed checkpoint note")
	fromNote := fs.String("from-note", "", "signed checkpoint note at the `from` size")
	proof := fs.String("proof", "", "proof-plane JSON response")
	bundlePath := fs.String("bundle", "", "verdict bundle JSON")
	leaf := fs.String("leaf", "", "file holding the exact leaf bytes the log committed")
	leafIndex := fs.Uint64("leaf-index", 0, "which inclusion_proofs entry to check")
	if err := fs.Parse(rest); err != nil {
		return exitCannot
	}
	if fs.NArg() > 0 {
		// An argument this tool does not understand is not a no-op. Ignoring it
		// would let `pail-verify inclusion -prof x.json` run as if no proof had
		// been named and report on whatever it did check.
		fmt.Fprintf(os.Stderr, "CANNOT-VERIFY: unrecognised argument %q\n", fs.Arg(0))
		return exitCannot
	}

	switch cmd {
	case "checkpoint", "inclusion", "consistency", "bundle":
	default:
		return usage()
	}

	tr, err := loadTrust(*vkey, *origin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "CANNOT-VERIFY: %v\n", err)
		return exitCannot
	}
	fmt.Printf("trust root : %s origin=%s hint=%s\n", tr.name, tr.origin, hex.EncodeToString(tr.hint))

	cp, code := authenticateFile(*note, tr, "checkpoint")
	if code != exitVerified {
		return code
	}

	switch cmd {
	case "checkpoint":
		return exitVerified
	case "inclusion":
		return cmdInclusion(cp, *proof)
	case "consistency":
		return cmdConsistency(cp, *fromNote, tr, *proof)
	case "bundle":
		return cmdBundle(cp, *bundlePath, *leaf, *leafIndex)
	}
	return usage()
}

// --- trust root -------------------------------------------------------------

type trust struct {
	name   string
	origin string
	hint   []byte
	pub    ed25519.PublicKey
}

// loadTrust parses the verifier key per VERIFICATION_INPUTS §2.4 and re-derives
// the key file's own hint. The hint selects which key to try and decides
// nothing: two keys can collide on four bytes. Re-deriving it here catches a
// key file whose two halves disagree, which is a different failure from a note
// that does not verify.
func loadTrust(vkeyPath, origin string) (*trust, error) {
	if vkeyPath == "" || origin == "" {
		return nil, errors.New("no trust anchor configured: -vkey and -origin are " +
			"both required. An empty verifier list is a refusal, not a verifier " +
			"that accepts everything")
	}
	raw, err := os.ReadFile(vkeyPath)
	if err != nil {
		return nil, fmt.Errorf("verifier key: %w", err)
	}
	line := strings.TrimSpace(string(raw))
	if line == "" {
		return nil, errors.New("verifier key file is empty — that is a refusal, not a wildcard")
	}
	// Cut twice, not everywhere: base64 emits `+`, so the body carries the
	// separator inside itself and a full split reports four or more fields for
	// most legitimate keys. Go's own sumdb/note parser cuts twice for the same
	// reason.
	parts := strings.SplitN(line, "+", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("verifier key: want name+hint+key, got %d fields", len(parts))
	}
	name, hintHex, keyB64 := parts[0], parts[1], parts[2]
	hint, err := hex.DecodeString(hintHex)
	if err != nil || len(hint) != 4 {
		return nil, fmt.Errorf("verifier key: hint is not 4 hex bytes: %q", hintHex)
	}
	blob, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("verifier key: %w", err)
	}
	if len(blob) != 1+ed25519.PublicKeySize {
		return nil, fmt.Errorf("verifier key: body is %d bytes, want %d",
			len(blob), 1+ed25519.PublicKeySize)
	}
	if blob[0] != 0x01 {
		return nil, fmt.Errorf("verifier key: algorithm id 0x%02x, this tool only "+
			"implements 0x01 (ed25519)", blob[0])
	}
	pub := ed25519.PublicKey(blob[1:])

	sum := sha256.Sum256(append(append([]byte(name), 0x0A, blob[0]), pub...))
	if !bytes.Equal(sum[:4], hint) {
		return nil, fmt.Errorf("verifier key: declared hint %s but the key derives %s "+
			"— the file disagrees with itself", hintHex, hex.EncodeToString(sum[:4]))
	}
	return &trust{name: name, origin: origin, hint: hint, pub: pub}, nil
}

// --- checkpoint -------------------------------------------------------------

type checkpoint struct {
	origin string
	size   uint64
	root   []byte
}

func authenticateFile(path string, tr *trust, label string) (*checkpoint, int) {
	if path == "" {
		fmt.Fprintf(os.Stderr, "CANNOT-VERIFY: no %s note given\n", label)
		return nil, exitCannot
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "CANNOT-VERIFY: %s: %v\n", label, err)
		return nil, exitCannot
	}
	cp, err := authenticate(data, tr)
	if err != nil {
		if errors.Is(err, errMalformed) {
			fmt.Fprintf(os.Stderr, "CANNOT-VERIFY: %s: %v\n", label, err)
			return nil, exitCannot
		}
		fmt.Printf("%-11s FAIL %v\n", label, err)
		return nil, exitFinding
	}
	fmt.Printf("%-11s OK   gate1=signature gate2=origin size=%d root=%s\n",
		label, cp.size, base64.StdEncoding.EncodeToString(cp.root))
	return cp, exitVerified
}

// authenticate runs §2.2's two gates in order and never parses an unauthenticated
// byte. The signature is checked over the body alone — lines 0-2 with their
// trailing newline — not over the whole file (§2.4, sig_message).
func authenticate(data []byte, tr *trust) (*checkpoint, error) {
	cut := bytes.Index(data, []byte("\n\n"))
	if cut < 0 {
		return nil, fmt.Errorf("%w: no blank line separating body from signatures", errMalformed)
	}
	body := data[:cut+1]

	verified := false
	for _, line := range strings.Split(string(data[cut+2:]), "\n") {
		if !strings.HasPrefix(line, emDash) {
			continue
		}
		f := strings.Fields(line[len(emDash):])
		if len(f) != 2 || f[0] != tr.name {
			continue
		}
		blob, err := base64.StdEncoding.DecodeString(f[1])
		if err != nil || len(blob) != 4+ed25519.SignatureSize {
			continue
		}
		if !bytes.Equal(blob[:4], tr.hint) {
			continue
		}
		if ed25519.Verify(tr.pub, body, blob[4:]) {
			verified = true
			break
		}
	}
	if !verified {
		return nil, errSignature
	}

	lines := strings.Split(string(body), "\n")
	if len(lines) < 4 {
		return nil, fmt.Errorf("%w: body has %d lines, want 3", errMalformed, len(lines)-1)
	}
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: tree size %q", errMalformed, lines[1])
	}
	root, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil {
		return nil, fmt.Errorf("%w: root: %v", errMalformed, err)
	}
	// Checked here rather than at the call site: a truncated note splits into
	// three fields whose last is empty, and base64 decodes "" without complaint.
	// Without this, no root travels onward as a root (§2.3).
	if len(root) != sha256.Size {
		return nil, fmt.Errorf("%w: root is %d bytes, want %d", errMalformed, len(root), sha256.Size)
	}
	if lines[0] != tr.origin {
		return nil, fmt.Errorf("%w: note says %q, trust root says %q", errOrigin, lines[0], tr.origin)
	}
	return &checkpoint{origin: lines[0], size: size, root: root}, nil
}

// --- RFC 6962 ---------------------------------------------------------------

func leafHash(b []byte) []byte {
	h := sha256.Sum256(append([]byte{0x00}, b...))
	return h[:]
}

func nodeHash(l, r []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}

// verifyInclusion is RFC 6962 §2.1.1. It returns the derived root; deriving a
// root is not verifying a root, so the comparison is the caller's and is made
// against a root the caller authenticated (§1).
func verifyInclusion(index, size uint64, lh []byte, proof [][]byte) ([]byte, error) {
	if size == 0 || index >= size {
		return nil, fmt.Errorf("leaf index %d is not inside a tree of size %d", index, size)
	}
	fn, sn := index, size-1
	r := lh
	for _, p := range proof {
		if sn == 0 {
			return nil, errors.New("proof is longer than the tree is deep")
		}
		if fn%2 == 1 || fn == sn {
			r = nodeHash(p, r)
			for fn%2 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = nodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return nil, errors.New("proof is shorter than the tree is deep")
	}
	return r, nil
}

// verifyConsistency is RFC 6962 §2.1.2. When `from` is an exact power of two the
// left tree's root is not carried in the proof and is prepended as an input —
// supply the wrong one and the derivation still completes and still yields 32
// bytes (§5.2). Both roots come from checkpoints the caller authenticated.
func verifyConsistency(from, to uint64, rootFrom, rootTo []byte, proof [][]byte) error {
	if from == 0 || from > to {
		return fmt.Errorf("range %d..%d is not a forward, non-empty range", from, to)
	}
	if from == to {
		if len(proof) != 0 {
			return errors.New("a self-consistency proof carries no hashes")
		}
		if !bytes.Equal(rootFrom, rootTo) {
			return errors.New("same size, different roots")
		}
		return nil
	}
	c := proof
	if from&(from-1) == 0 {
		c = append([][]byte{rootFrom}, proof...)
	}
	if len(c) == 0 {
		return errors.New("proof is empty")
	}
	fn, sn := from-1, to-1
	for fn%2 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := c[0], c[0]
	for _, p := range c[1:] {
		if sn == 0 {
			return errors.New("proof is longer than the tree is deep")
		}
		if fn%2 == 1 || fn == sn {
			fr = nodeHash(p, fr)
			sr = nodeHash(p, sr)
			for fn%2 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = nodeHash(sr, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return errors.New("proof is shorter than the tree is deep")
	}
	if !bytes.Equal(fr, rootFrom) {
		return fmt.Errorf("derived root@%d %s does not match the authenticated one %s",
			from, b64(fr), b64(rootFrom))
	}
	if !bytes.Equal(sr, rootTo) {
		return fmt.Errorf("derived root@%d %s does not match the authenticated one %s",
			to, b64(sr), b64(rootTo))
	}
	return nil
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func decodeAll(in []string, what string) ([][]byte, error) {
	out := make([][]byte, 0, len(in))
	for i, s := range in {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: %w", what, i, err)
		}
		if len(b) != sha256.Size {
			return nil, fmt.Errorf("%s[%d] is %d bytes, want %d", what, i, len(b), sha256.Size)
		}
		out = append(out, b)
	}
	return out, nil
}

func readJSON(path string, v any) error {
	if path == "" {
		return errors.New("no file given")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

// --- subcommands ------------------------------------------------------------

type inclusionResp struct {
	Status    string   `json:"status"`
	LeafIndex uint64   `json:"leaf_index"`
	TreeSize  uint64   `json:"tree_size"`
	RootB64   string   `json:"root_b64"`
	LeafB64   string   `json:"leaf_b64"`
	ProofB64  []string `json:"proof_b64"`
}

func cmdInclusion(cp *checkpoint, path string) int {
	var r inclusionResp
	if err := readJSON(path, &r); err != nil {
		fmt.Fprintf(os.Stderr, "CANNOT-VERIFY: inclusion proof: %v\n", err)
		return exitCannot
	}
	if r.TreeSize != cp.size {
		fmt.Fprintf(os.Stderr, "CANNOT-VERIFY: proof is at tree size %d, the "+
			"authenticated checkpoint is at %d — there is no root to check against\n",
			r.TreeSize, cp.size)
		return exitCannot
	}
	leaf, err := base64.StdEncoding.DecodeString(r.LeafB64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "CANNOT-VERIFY: leaf_b64: %v\n", err)
		return exitCannot
	}
	proof, err := decodeAll(r.ProofB64, "proof_b64")
	if err != nil {
		fmt.Fprintf(os.Stderr, "CANNOT-VERIFY: %v\n", err)
		return exitCannot
	}
	// §5.1: an empty root_b64 is the server correctly declining to assert a root
	// it has not signed. It is not an error and never substitutes for ours.
	if r.RootB64 == "" {
		fmt.Println("echoed root: absent (historical size) — using the authenticated one")
	} else if r.RootB64 != b64(cp.root) {
		fmt.Printf("inclusion   FAIL echoed root %s contradicts the authenticated %s\n",
			r.RootB64, b64(cp.root))
		return exitFinding
	} else {
		fmt.Println("echoed root: agrees with the authenticated checkpoint")
	}

	derived, err := verifyInclusion(r.LeafIndex, r.TreeSize, leafHash(leaf), proof)
	if err != nil {
		fmt.Printf("inclusion   FAIL %v\n", err)
		return exitFinding
	}
	if !bytes.Equal(derived, cp.root) {
		fmt.Printf("inclusion   FAIL derived %s, authenticated %s\n", b64(derived), b64(cp.root))
		return exitFinding
	}
	fmt.Printf("inclusion   OK   leaf %d of %d is in the authenticated root\n",
		r.LeafIndex, r.TreeSize)
	return exitVerified
}

type consistencyResp struct {
	Status   string   `json:"status"`
	From     uint64   `json:"from"`
	To       uint64   `json:"to"`
	ProofB64 []string `json:"proof_b64"`
}

func cmdConsistency(cp *checkpoint, fromNote string, tr *trust, path string) int {
	var r consistencyResp
	if err := readJSON(path, &r); err != nil {
		fmt.Fprintf(os.Stderr, "CANNOT-VERIFY: consistency proof: %v\n", err)
		return exitCannot
	}
	from, code := authenticateFile(fromNote, tr, "from-note")
	if code != exitVerified {
		return code
	}
	if from.size != r.From || cp.size != r.To {
		fmt.Fprintf(os.Stderr, "CANNOT-VERIFY: proof covers %d..%d, the authenticated "+
			"checkpoints are at %d and %d\n", r.From, r.To, from.size, cp.size)
		return exitCannot
	}
	proof, err := decodeAll(r.ProofB64, "proof_b64")
	if err != nil {
		fmt.Fprintf(os.Stderr, "CANNOT-VERIFY: %v\n", err)
		return exitCannot
	}
	if err := verifyConsistency(r.From, r.To, from.root, cp.root, proof); err != nil {
		fmt.Printf("consistency FAIL %v\n", err)
		return exitFinding
	}
	fmt.Printf("consistency OK   %d..%d is append-only between two authenticated roots\n",
		r.From, r.To)
	return exitVerified
}

// verdictBundle names only the fields §8 permits a verifier to read. `verdict`
// and `log_consistency` are absent on purpose: they are the audited party's
// summary of its own audit, and reading them reproduces §1's defect one layer up.
type verdictBundle struct {
	InclusionProofs []struct {
		LeafIndex   uint64   `json:"leaf_index"`
		STHTreeSize uint64   `json:"sth_tree_size"`
		ProofBase64 []string `json:"proof_base64"`
	} `json:"inclusion_proofs"`
}

func cmdBundle(cp *checkpoint, path, leafPath string, index uint64) int {
	var b verdictBundle
	if err := readJSON(path, &b); err != nil {
		fmt.Fprintf(os.Stderr, "CANNOT-VERIFY: bundle: %v\n", err)
		return exitCannot
	}
	if leafPath == "" {
		fmt.Fprintln(os.Stderr, "CANNOT-VERIFY: -leaf is required. The bundle carries "+
			"proof hashes but not the leaf they prove; the verifier must already hold it")
		return exitCannot
	}
	leaf, err := os.ReadFile(leafPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "CANNOT-VERIFY: leaf: %v\n", err)
		return exitCannot
	}
	fmt.Println("bundle     : read proof_base64 + sth_tree_size only; verdict and " +
		"log_consistency are the audited party's claim and are not read (§8)")

	for _, e := range b.InclusionProofs {
		if e.LeafIndex != index {
			continue
		}
		if e.STHTreeSize != cp.size {
			fmt.Fprintf(os.Stderr, "CANNOT-VERIFY: entry is at tree size %d, the "+
				"authenticated checkpoint is at %d\n", e.STHTreeSize, cp.size)
			return exitCannot
		}
		// §5.3: the same concept, spelled `proof_base64` here and `proof_b64`
		// on the proof plane.
		proof, err := decodeAll(e.ProofBase64, "proof_base64")
		if err != nil {
			fmt.Fprintf(os.Stderr, "CANNOT-VERIFY: %v\n", err)
			return exitCannot
		}
		derived, err := verifyInclusion(e.LeafIndex, e.STHTreeSize, leafHash(leaf), proof)
		if err != nil {
			fmt.Printf("bundle      FAIL %v\n", err)
			return exitFinding
		}
		if !bytes.Equal(derived, cp.root) {
			fmt.Printf("bundle      FAIL derived %s, authenticated %s\n", b64(derived), b64(cp.root))
			return exitFinding
		}
		fmt.Printf("bundle      OK   leaf %d of %d is in the authenticated root\n",
			e.LeafIndex, e.STHTreeSize)
		return exitVerified
	}
	fmt.Fprintf(os.Stderr, "CANNOT-VERIFY: the bundle carries no inclusion proof for "+
		"leaf %d — absent evidence is not evidence of presence\n", index)
	return exitCannot
}
