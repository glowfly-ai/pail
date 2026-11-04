// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package contract

// AL-2 (implementation contract D5) — the pass-through digests are pinned by
// tests/golden/contract/ledger_v2.vec: prefix constants (internal/canon) and
// the algorithm (sha256 over prefix ‖ body) against one-shot outputs. The
// vector is never regenerated here — a regenerated vector is a copy, not a
// comparison. Owner of the canon side of G-LED-05.

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/glowfly/pail/services/internal/testlayout"
	"os"
	"strings"
	"testing"

	"github.com/glowfly/pail/services/internal/canon"
)

func TestGLED05_LedgerV2DigestsFrozen(t *testing.T) {
	raw, err := os.ReadFile(testlayout.Path(t, "tests/golden/contract/ledger_v2.vec"))
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{canon.CtxV1: true, canon.ConstraintsV1: true, canon.ParamsV1: true}
	n := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) != 5 || cols[0] != "hash" {
			t.Fatalf("malformed row: %q", line)
		}
		id, prefix, body, want := cols[1], cols[2], cols[3], cols[4]
		if !known[prefix] {
			t.Fatalf("%s: prefix %q is not a canon constant — the vector names a domain the code does not have", id, prefix)
		}
		if body == "(empty)" {
			body = ""
		}
		sum := sha256.Sum256([]byte(prefix + body))
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("%s: sha256(%q ‖ %q) = %s, vector says %s", id, prefix, body, got, want)
		}
		n++
	}
	if n != 7 {
		t.Fatalf("ledger_v2.vec rows %d — 7 expected (3 ctx · 2 constraints · 2 params)", n)
	}
	// the three prefixes must be pairwise distinct so the same bytes never
	// collide across domains (the point of prefixing)
	if canon.CtxV1 == canon.ConstraintsV1 || canon.CtxV1 == canon.ParamsV1 || canon.ConstraintsV1 == canon.ParamsV1 {
		t.Fatal("pass-through prefixes must be distinct")
	}
}
