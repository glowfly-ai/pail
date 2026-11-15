// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// pail_verify is the standard-library-only verifier that ships inside the
// evaluation bundle (design PAIL-p42 §1, PAIL-p43 §3): archive + manifest
// checksums, the manifest's Ed25519 signature, the extracted tree against the
// manifest, a verification receipt, and the doctor vector. Its stdout is
// byte-identical to oss/distribution/verify_evaluation.py except for the
// backend word after VERIFIED and the VERIFIER: line.
//
//	pail_verify --zip Z --manifest M --expected-release R [--public-key P] [--expected-fingerprint H]
//	            [--allow-unsigned] [--bundle-root DIR] [--tree-root DIR | --no-tree-check]
//	            [--receipt-dir D | --no-receipt]
//	pail_verify --sig-only --manifest M [--public-key P] [--expected-fingerprint H] [--bundle-root DIR]
//	pail_verify --vector FILE
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/glowfly/pail/services/pkg/releaseverify"
)

const (
	defaultKeyName = "RELEASE-SIGNING-KEY.pub"
	receiptDirEnv  = "PAIL_VERIFICATION_RECEIPT_DIR"
	toolName       = "pail_verify"
	// verifierNote is the VERIFIER: line and the receipt's verifier_note: this
	// program is the bundled verifier itself, so there is no "used / not used".
	verifierNote    = "this is the bundled verifier (pail_verify)"
	treeNotCompared = "not compared (no images.lock.json beside the tree root; run from the extracted pail-evaluation/ directory to compare)"
)

// treeResult is what the TREE: line and the receipt's tree fields are built from.
type treeResult struct {
	skipped    bool // --no-tree-check
	compared   bool
	matched    bool
	files      int                      // keys in TreeKeys(manifest.files_sha256)
	digest     string                   // TreeDigest of those keys, always from the manifest
	mismatches []releaseverify.Mismatch // the full sorted list; the receipt takes CapMismatches of it
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(toolName, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		zipPath    = fs.String("zip", "", "evaluation ZIP")
		manifest   = fs.String("manifest", "", "delivery manifest (JSON) obtained separately from the ZIP")
		release    = fs.String("expected-release", "", "release_id the manifest must carry")
		publicKey  = fs.String("public-key", "", "publisher public key (PEM); default <bundle-root>/"+defaultKeyName)
		expectedFP = fs.String("expected-fingerprint", "", "sha256 of the raw public key, obtained outside this archive; a key that differs is refused")
		allowUns   = fs.Bool("allow-unsigned", false, "accept the archive on checksums only when no .sig is beside the manifest (the default refuses)")
		bundleRoot = fs.String("bundle-root", ".", "directory holding "+defaultKeyName)
		treeRoot   = fs.String("tree-root", "", "extracted pail-evaluation/ directory compared with the manifest (default --bundle-root); compared only when it holds images.lock.json")
		noTree     = fs.Bool("no-tree-check", false, "do not compare the extracted tree with the manifest")
		receiptDir = fs.String("receipt-dir", "", "receipt directory (default $"+receiptDirEnv+" or ~/.pail-evaluation/verification)")
		noReceipt  = fs.Bool("no-receipt", false, "do not write a verification receipt")
		sigOnly    = fs.Bool("sig-only", false, "check only the manifest signature; exit 0 verified / 1 bad / 2 not verified")
		vector     = fs.String("vector", "", "doctor capability vector JSON; exit 0 only when the good signature verifies and the corrupted one is rejected")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	usage := func(msg string) int {
		fmt.Fprintln(stderr, toolName+": "+msg)
		return 2
	}
	if fs.NArg() != 0 {
		return usage("unexpected argument: " + fs.Arg(0))
	}
	if *vector != "" {
		return runVector(*vector, stdout)
	}
	if *manifest == "" {
		return usage("--manifest is required")
	}
	keyPath := *publicKey
	if keyPath == "" {
		keyPath = filepath.Join(*bundleRoot, defaultKeyName)
	}
	if *sigOnly {
		rc, msg, err := releaseverify.VerifySignature(*manifest, keyPath, *expectedFP)
		if err != nil {
			fmt.Fprintln(stdout, "SIGNATURE: "+err.Error())
			return 2
		}
		fmt.Fprintln(stdout, "SIGNATURE: "+msg)
		return rc
	}
	if *zipPath == "" || *release == "" {
		return usage("--zip, --manifest and --expected-release are required")
	}
	if *receiptDir != "" && *noReceipt {
		return usage("--receipt-dir and --no-receipt are exclusive")
	}
	m, err := releaseverify.LoadManifest(*manifest)
	if err != nil {
		fmt.Fprintln(stdout, "EVALUATION_VERIFY: FAIL "+err.Error())
		return 1
	}
	count, err := releaseverify.VerifyArchive(*zipPath, m, *release)
	if err != nil {
		fmt.Fprintln(stdout, "EVALUATION_VERIFY: FAIL "+err.Error())
		return 1
	}
	// P22-L1 / P23-M1: a signed release must not degrade to "checksums only" when
	// the .sig is removed in transit; only the recipient can waive it, explicitly.
	required := !*allowUns
	rc, msg, err := releaseverify.VerifySignature(*manifest, keyPath, *expectedFP)
	if err != nil {
		rc, msg = releaseverify.SigBad, err.Error()
	}
	if rc == releaseverify.SigBad || (rc == releaseverify.SigNotVerified && required) {
		fmt.Fprintf(stdout, "EVALUATION_VERIFY: FAIL (signature) files=%d\n", count)
		suffix := ""
		if rc == releaseverify.SigNotVerified {
			suffix = "; a signature is required (pass --allow-unsigned to accept checksums only)"
		}
		fmt.Fprintln(stdout, "SIGNATURE: "+msg+suffix)
		fmt.Fprintln(stdout, "VERIFIER: "+verifierNote) // P42-L2: the verifier's state is reported on a signature FAIL too
		return 1
	}
	fmt.Fprintf(stdout, "EVALUATION_VERIFY: PASS files=%d\n", count)
	fmt.Fprintln(stdout, "SIGNATURE: "+msg)
	if rc == releaseverify.SigNotVerified {
		fmt.Fprintln(stdout, "Checksums only; the publisher was not authenticated by this run.")
	}
	fmt.Fprintln(stdout, "VERIFIER: "+verifierNote)
	if rc != releaseverify.SigVerified {
		fmt.Fprintln(stdout, "PUBLISHER_KEY: NOT_AUTHENTICATED — signature not verified")
	} else if *expectedFP != "" {
		fmt.Fprintln(stdout, "PUBLISHER_KEY: MATCHED_SUPPLIED_FINGERPRINT — the recipient must establish its independent provenance")
	} else {
		fmt.Fprintln(stdout, "PUBLISHER_KEY: NOT_COMPARED — signature self-consistency only; obtain the fingerprint independently and pass --expected-fingerprint")
	}
	// The tree comparison never changes the exit code: the ZIP is verified; the
	// state of the extracted tree is for the receipt and the launcher (design §3).
	root := *treeRoot
	if root == "" {
		root = *bundleRoot
	}
	tree, err := compareTree(root, *noTree, m)
	if err != nil {
		fmt.Fprintln(stdout, "TREE: not compared ("+err.Error()+")")
	} else {
		fmt.Fprintln(stdout, "TREE: "+treeLine(tree))
	}
	if !*noReceipt {
		// The receipt never changes the exit code. A receipt inside the delivery tree would itself be an extra file.
		// P021-M1: judge the directory the receipt would actually go to (flag, PAIL_VERIFICATION_RECEIPT_DIR or the default).
		if dir, derr := receiptDirectory(*receiptDir); derr == nil && !*noTree && insideTree(dir, root) {
			fmt.Fprintln(stdout, "RECEIPT: not written (receipt directory is inside the delivery tree; keep receipts outside)")
			return 0
		}
		writeReceipt(stdout, *receiptDir, *manifest, keyPath, *expectedFP != "", m, count, rc, tree)
	}
	return 0
}

// insideTree reports whether dir equals root or lies under it (both made
// absolute, symlinks resolved where the path exists).
func insideTree(dir, root string) bool {
	d, r := canonPath(dir), canonPath(root)
	return d == r || strings.HasPrefix(d, r+string(filepath.Separator))
}

// canonPath makes p absolute, resolves symlinks in its nearest existing ancestor
// and re-joins the rest. P021-M1: a receipt directory usually does not exist
// yet; resolving only existing paths left /tmp/<tree>/receipts unresolved while
// the tree resolved to /private/tmp/<tree> on macOS, and the receipt landed
// inside the tree.
func canonPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	p = filepath.Clean(p)
	rest := ""
	for cur := p; ; {
		if resolved, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Join(resolved, rest)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

// compareTree compares root with the manifest when the check is not skipped
// and root holds images.lock.json; the manifest-side digest and count are
// filled either way.
func compareTree(root string, skipped bool, m releaseverify.Manifest) (treeResult, error) {
	expected := releaseverify.TreeKeys(m.FilesSHA256)
	tree := treeResult{skipped: skipped, files: len(expected), digest: releaseverify.TreeDigest(expected), mismatches: []releaseverify.Mismatch{}}
	if skipped || !releaseverify.HasLock(root) {
		return tree, nil
	}
	matched, _, _, mismatches, compared, err := releaseverify.CompareTree(root, expected)
	if err != nil {
		return tree, err
	}
	tree.compared, tree.matched, tree.files, tree.mismatches = true, matched, compared, mismatches
	return tree, nil
}

func treeLine(tree treeResult) string {
	if tree.skipped {
		return "skipped (--no-tree-check)"
	}
	if !tree.compared {
		return treeNotCompared
	}
	if tree.matched {
		return fmt.Sprintf("MATCHES manifest (%d files compared; images/ archives are verified by load)", tree.files)
	}
	// Totals over the full list; only the first five paths are printed.
	var changed, missing, extra int
	var first []string
	for i, mm := range tree.mismatches {
		switch mm.Kind {
		case "changed":
			changed++
		case "missing":
			missing++
		default: // extra, symlink, irregular, unreadable
			extra++
		}
		if i < 5 {
			first = append(first, mm.Path+"("+mm.Kind+")")
		}
	}
	return fmt.Sprintf("MODIFIED — %d changed, %d missing, %d extra: %s", changed, missing, extra, strings.Join(first, ", "))
}

func receiptDirectory(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if env := os.Getenv(receiptDirEnv); env != "" {
		return env, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".pail-evaluation", "verification"), nil
}

func writeReceipt(stdout io.Writer, dirFlag, manifestPath, keyPath string, fpGiven bool, m releaseverify.Manifest, count, rc int, tree treeResult) {
	lock, ok := m.FilesSHA256["images.lock.json"]
	if !ok {
		fmt.Fprintln(stdout, "RECEIPT: not written (no images.lock.json in the manifest)")
		return
	}
	dir, err := receiptDirectory(dirFlag)
	if err != nil {
		fmt.Fprintln(stdout, "RECEIPT: not written ("+err.Error()+")")
		return
	}
	manifestSum, err := releaseverify.FileSHA256(manifestPath)
	if err != nil {
		fmt.Fprintln(stdout, "RECEIPT: not written ("+err.Error()+")")
		return
	}
	r := releaseverify.Receipt{
		SchemaVersion:            releaseverify.ReceiptSchemaVersion,
		ReleaseID:                m.ReleaseID,
		Artifact:                 m.Artifact,
		ZipSHA256:                m.SHA256,
		ManifestSHA256:           manifestSum,
		LockSHA256:               lock,
		Signature:                "CHECKSUMS_ONLY", // key_fingerprint and backend stay null: nothing was verified
		ExpectedFingerprintGiven: fpGiven,
		VerifierNote:             verifierNote,
		Tool:                     toolName,
		Files:                    count,
		TreeScope:                releaseverify.TreeScope,
		TreeFiles:                tree.files,
		TreeSHA256:               tree.digest,
		TreeMismatches:           releaseverify.CapMismatches(tree.mismatches), // first 20; tree_matched stays null when not compared
		At:                       time.Now().UTC().Format(releaseverify.ReceiptTimeLayout),
	}
	if tree.compared {
		r.TreeMatched = releaseverify.Bool(tree.matched)
	}
	if rc == releaseverify.SigVerified {
		r.Signature = "VERIFIED"
		r.Backend = releaseverify.String(releaseverify.Backend)
		if fp, err := releaseverify.KeyFingerprint(keyPath); err == nil {
			r.KeyFingerprint = releaseverify.String(fp)
		}
	}
	path, err := releaseverify.WriteReceipt(dir, r)
	if releaseverify.IsReceiptKept(err) {
		fmt.Fprintln(stdout, "RECEIPT: kept "+path+" ("+err.Error()+")")
		return
	}
	if err != nil {
		fmt.Fprintln(stdout, "RECEIPT: not written ("+err.Error()+")")
		return
	}
	fmt.Fprintln(stdout, "RECEIPT: "+path)
}

func runVector(path string, stdout io.Writer) int {
	pos, neg, err := releaseverify.VerifyVector(path)
	if err != nil {
		fmt.Fprintln(stdout, "VECTOR: error "+err.Error())
		return 2
	}
	word := func(rc int) string {
		if rc == releaseverify.SigVerified {
			return "VERIFIED"
		}
		return "BAD_SIGNATURE"
	}
	fmt.Fprintf(stdout, "VECTOR: positive=%s negative=%s backend=%s\n", word(pos), word(neg), releaseverify.Backend)
	if pos == releaseverify.SigVerified && neg == releaseverify.SigBad {
		return 0
	}
	return 1
}
