// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

// P021-M1 (0.2.1 evaluation): a verification receipt must never be written
// inside the delivery tree — it would itself be a tree change. Two holes:
// a not-yet-existing receipt directory under a symlinked parent (macOS /tmp is
// /private/tmp) was compared unresolved, and a directory chosen through
// PAIL_VERIFICATION_RECEIPT_DIR was not checked at all.

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// m1Tree copies the tree-match fixture into a fresh real directory and returns
// (real parent, symlinked alias of it). The fixture itself is never touched.
func m1Tree(t *testing.T) (string, string) {
	t.Helper()
	root, _ := loadFixture(t)
	real := t.TempDir()
	src := filepath.Join(root, "tree-match", "tree")
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		dst := filepath.Join(real, "tree", rel)
		if d.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	return real, alias
}

func m1Args(t *testing.T, treeRoot string, extra ...string) []string {
	root, f := loadFixture(t)
	good := filepath.Join(root, "good", f.Artifact)
	return append([]string{"--zip", good, "--manifest", good + ".manifest.json", "--expected-release", f.ReleaseID,
		"--public-key", filepath.Join(root, "TEST-SIGNING-KEY.pub"), "--tree-root", treeRoot}, extra...)
}

const m1Refusal = "RECEIPT: not written (receipt directory is inside the delivery tree"

func TestM1T01InsideTreeThroughASymlinkedParent(t *testing.T) {
	real, alias := m1Tree(t)
	if !insideTree(filepath.Join(alias, "tree", "receipts"), filepath.Join(real, "tree")) {
		t.Error("a not-yet-existing receipts dir under the symlinked tree was judged outside the tree")
	}
	if !insideTree(filepath.Join(real, "tree", "receipts"), filepath.Join(alias, "tree")) {
		t.Error("a receipts dir under the real tree was judged outside the symlinked tree root")
	}
	if insideTree(filepath.Join(real, "other"), filepath.Join(alias, "tree")) {
		t.Error("a sibling of the tree was judged inside it")
	}
}

func TestM1T02NoReceiptInTheTreeThroughASymlinkedRoot(t *testing.T) {
	real, alias := m1Tree(t)
	out, _, _ := runBinary(t, nil, m1Args(t, filepath.Join(alias, "tree"), "--receipt-dir", filepath.Join(alias, "tree", "receipts"))...)
	if !strings.Contains(out, m1Refusal) {
		t.Errorf("receipt line:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(real, "tree", "receipts")); err == nil {
		t.Error("a receipts directory was created inside the delivery tree")
	}
}

func TestM1T03NoReceiptInTheTreeThroughTheEnvironment(t *testing.T) {
	real, _ := m1Tree(t)
	out, _, _ := runBinary(t, []string{receiptDirEnv + "=" + filepath.Join(real, "tree", "receipts")}, m1Args(t, filepath.Join(real, "tree"))...)
	if !strings.Contains(out, m1Refusal) {
		t.Errorf("receipt line:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(real, "tree", "receipts")); err == nil {
		t.Error("PAIL_VERIFICATION_RECEIPT_DIR put a receipt inside the delivery tree")
	}
}

func TestM1T04AReceiptOutsideTheTreeIsStillWritten(t *testing.T) {
	real, _ := m1Tree(t)
	outside := filepath.Join(t.TempDir(), "receipts")
	out, _, rc := runBinary(t, []string{receiptDirEnv + "=" + outside}, m1Args(t, filepath.Join(real, "tree"))...)
	if rc != 0 || !strings.Contains(out, "RECEIPT: "+outside) {
		t.Errorf("rc %d, receipt line:\n%s", rc, out)
	}
}
