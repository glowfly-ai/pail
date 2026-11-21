// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// P024-H1 (0.2.4 recipient evaluation): `--expected-fingerprint ""` exited 0 with PUBLISHER_KEY: NOT_COMPARED. The
// flag's default is the empty string, so "given empty" was indistinguishable from "absent" — the same defect the
// Python verifier had. The fixture parity test cannot hold this alone (its golden output is whatever the Python tool
// prints), so the refusal is a literal here: exit 2, one line on stdout, nothing on stderr, no receipt.
const emptyFingerprintLine = "--expected-fingerprint was given but is empty; pass the fingerprint obtained from the publisher outside " +
	"this archive, or omit the flag to record PUBLISHER_KEY: NOT_COMPARED\n"

func TestEmptyExpectedFingerprintIsRefused(t *testing.T) {
	root, f := loadFixture(t)
	zip := filepath.Join(root, "good", f.Artifact)
	base := []string{"--zip", zip, "--manifest", zip + ".manifest.json", "--expected-release", f.ReleaseID,
		"--public-key", filepath.Join(root, "TEST-SIGNING-KEY.pub")}
	for _, value := range []string{"", " ", "\t", " \n"} {
		receipts := t.TempDir()
		args := append(append([]string{}, base...), "--receipt-dir", receipts, "--no-tree-check", "--expected-fingerprint", value)
		out, errOut, rc := runBinary(t, []string{"HOME=" + t.TempDir()}, args...)
		if rc != 2 || out != "EVALUATION_VERIFY: FAIL "+emptyFingerprintLine || errOut != "" {
			t.Errorf("value %q: rc %d stdout %q stderr %q", value, rc, out, errOut)
		}
		if entries, _ := os.ReadDir(receipts); len(entries) != 0 {
			t.Errorf("value %q: a refused call left a receipt: %v", value, entries)
		}
	}
	// --sig-only answers in its own vocabulary (the Python verifier reads the SIGNATURE: prefix).
	out, errOut, rc := runBinary(t, nil, "--sig-only", "--manifest", zip+".manifest.json",
		"--public-key", filepath.Join(root, "TEST-SIGNING-KEY.pub"), "--expected-fingerprint", "")
	if rc != 2 || out != "SIGNATURE: "+emptyFingerprintLine || errOut != "" {
		t.Errorf("sig-only: rc %d stdout %q stderr %q", rc, out, errOut)
	}
	// The absent flag keeps its outcome: exit 0 and NOT_COMPARED (the recipient's choice, recorded as such).
	out, _, rc = runBinary(t, nil, append(append([]string{}, base...), "--no-receipt")...)
	if rc != 0 || !strings.Contains(out, "PUBLISHER_KEY: NOT_COMPARED") {
		t.Errorf("absent flag: rc %d stdout %q", rc, out)
	}
}
