// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

//go:build red_lldd

// RED harness for implementation contract (RD-9), keyring rollback floor.
//
// Run:
//
//	go test -count=1 -tags red_lldd -run TestRedD9 ./internal/crypto/
//
// The authoritative pass/fail record is the runner (tests/tools/red_lldd.py).
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

// RD-9 (X22/G-DEL-04): the rollback floor lives in a plain file with no
// integrity protection, and readBundleState treats "file missing" as floor 0
// (keyring_bundle.go:249-256, the Go twin of keyring_bundle.cpp:98-111).
// An attacker with local write access therefore does not need to forge or edit
// anything — deleting the file is enough, and a retired bundle loads again.
//
// A garbled file is fail-closed, as designed. Absence is not: it is
// indistinguishable from a legitimate first boot, and no process-local check
// can tell them apart. That is why X22 is a delegation (only filesystem
// permissions can draw the line) — but a delegation is only honest once the
// consequence is written down, so this probe exists to keep the documented
// sentence tied to observed behaviour.
//
// This test's GREEN condition is NOT "the load is refused". It is D §4's
// unusual one: the fact is stated exactly in TRUST_BOUNDARY.md G-DEL-04, and
// this reproduction still matches that statement. The runner owns that half.
func TestRedD9_DeletingStateFileResetsRollbackFloor(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")

	newPath := filepath.Join(dir, "v8.json")
	newB, err := BuildBundle(rootPriv, "root-1", makePayload(t, 8, futureUnix()))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, newPath, newB)
	if _, err := LoadKeyringBundle(newPath, rootPub, statePath, testBundlePolicy); err != nil {
		t.Fatalf("fixture broken: v8 must load: %v", err)
	}
	floor, err := readBundleState(statePath)
	if err != nil || floor != 8 {
		t.Fatalf("fixture broken: floor after v8 = %d (err %v), want 8", floor, err)
	}
	t.Logf("floor recorded: last_version=%d at %s", floor, statePath)

	// v6 is a retired bundle. With the floor in place it is refused.
	oldPath := filepath.Join(dir, "v6.json")
	oldB, err := BuildBundle(rootPriv, "root-1", makePayload(t, 6, futureUnix()))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, oldPath, oldB)

	// Control: the defence works while the file exists.
	if _, err := LoadKeyringBundle(oldPath, rootPub, statePath, testBundlePolicy); err == nil {
		t.Fatalf("control broken: v6 loaded while the floor was 8 — rollback rejection is not in effect")
	} else {
		t.Logf("RD9_CONTROL=refused (%v)", err)
	}

	// Attack: no forgery, no edit. Remove the file.
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	t.Logf("attack: removed %s (the cheapest possible action)", statePath)

	_, err = LoadKeyringBundle(oldPath, rootPub, statePath, testBundlePolicy)
	after, stErr := readBundleState(statePath)
	t.Logf("observed: retired v6 load err=%v; floor now %d (err %v)", err, after, stErr)

	// A bare "--- FAIL" cannot carry this: a broken fixture fails the same way.
	// The marker is only printed once the attack has actually been observed.
	if err == nil {
		t.Logf("RD9_REPRODUCED=yes")
		t.Errorf("retired bundle v6 was accepted after the state file was deleted — the rollback floor reset to 0 with no forgery")
	} else {
		t.Logf("RD9_REPRODUCED=no")
	}
}
