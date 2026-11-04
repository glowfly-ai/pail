// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestPublisherKeyComparisonDisclosure(t *testing.T) {
	root, f := loadFixture(t)
	good := filepath.Join(root, "good", f.Artifact)
	for _, compare := range []bool{false, true} {
		args := []string{"--zip", good, "--manifest", good + ".manifest.json", "--expected-release", f.ReleaseID, "--public-key", filepath.Join(root, "TEST-SIGNING-KEY.pub"), "--no-receipt"}
		want := "PUBLISHER_KEY: NOT_COMPARED"
		if compare {
			args = append(args, "--expected-fingerprint", f.TestKeyFingerprint)
			want = "PUBLISHER_KEY: MATCHED_SUPPLIED_FINGERPRINT"
		}
		out, err, rc := runBinary(t, nil, args...)
		if rc != 0 || !strings.Contains(out, want) {
			t.Errorf("compare=%v rc=%d stdout=%s stderr=%s", compare, rc, out, err)
		}
	}
}
