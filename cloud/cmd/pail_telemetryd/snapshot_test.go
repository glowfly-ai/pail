// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

// AL-4: the snapshot zone resolver reads only kept snapshots by hash, through
// the issuer's own compiler; anything else is "cannot resolve".

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

const snapSite = `site: s
schema: v3
zones:
  - id: z7
    type: work_area
robots:
  - id: robot-1
    capabilities: [move]
    schema: v3
    home: z7
objects:
  - id: "880123"
    at: z7
  - id: loose
`

func TestAL4_SnapshotZoneResolver(t *testing.T) {
	dir := t.TempDir()
	sum := sha256.Sum256([]byte(snapSite))
	h := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(dir, h+".yaml"), []byte(snapSite), 0o600); err != nil {
		t.Fatal(err)
	}
	r := snapshotZoneResolver(dir)
	if z, ok := r(h, "880123"); !ok || z != "z7" {
		t.Fatalf("declared object: %q %v", z, ok)
	}
	if _, ok := r(h, "loose"); ok {
		t.Fatal("object without `at` has no zone")
	}
	if _, ok := r(h, "ghost"); ok {
		t.Fatal("undeclared object must not resolve")
	}
	other := hex.EncodeToString(sha256.New().Sum(nil))
	if _, ok := r(other, "880123"); ok {
		t.Fatal("a hash with no snapshot must not resolve — not even to today's model")
	}
	if _, ok := r("not-a-hash", "880123"); ok {
		t.Fatal("malformed hash must not touch the filesystem")
	}
	// an unreadable snapshot (bad YAML) is "cannot resolve", cached as such
	bsum := sha256.Sum256([]byte("bad"))
	bad := hex.EncodeToString(bsum[:])
	_ = os.WriteFile(filepath.Join(dir, bad+".yaml"), []byte("site: [\n"), 0o600)
	if _, ok := r(bad, "880123"); ok {
		t.Fatal("uncompilable snapshot must not resolve")
	}
}

const snapSiteOther = `site: s
schema: v3
zones:
  - id: z8
    type: work_area
robots:
  - id: robot-1
    capabilities: [move]
    schema: v3
    home: z8
objects:
  - id: "880123"
    at: z8
`

// Review item 17 (PAIL-P43-SNAPSHOT-TEST-LLD-001 T-A): a snapshot whose bytes do not hash to its own name is not
// the model of that day — it is a file somebody put there. The resolver must re-hash what it reads.
func TestAL4_SnapshotContentMustMatchItsName(t *testing.T) {
	dir := t.TempDir()
	sum := sha256.Sum256([]byte(snapSite))
	h := hex.EncodeToString(sum[:])
	// the name of the real model, the bytes of another valid, compilable model
	if err := os.WriteFile(filepath.Join(dir, h+".yaml"), []byte(snapSiteOther), 0o600); err != nil {
		t.Fatal(err)
	}
	if z, ok := snapshotZoneResolver(dir)(h, "880123"); ok {
		t.Fatalf("a snapshot whose content does not hash to its name was used (zone %q)", z)
	}
	// the genuine bytes under their own name still resolve (a fresh resolver: the first cached the mismatch)
	if err := os.WriteFile(filepath.Join(dir, h+".yaml"), []byte(snapSite), 0o600); err != nil {
		t.Fatal(err)
	}
	if z, ok := snapshotZoneResolver(dir)(h, "880123"); !ok || z != "z7" {
		t.Fatalf("genuine snapshot: %q %v", z, ok)
	}
}
