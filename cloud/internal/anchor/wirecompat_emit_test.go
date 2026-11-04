// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package anchor

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/glowfly/pail/services/internal/signer"
)

// TestEmitRealRecord produces an AnchorRecord with the REAL robot code path
// (BuildRecord + real issuer key) and writes it to PAIL_WIRECOMPAT_OUT. The
// Anchor SaaS side then re-verifies this exact JSON, proving the SaaS canon is
// byte-identical to what the shipping robot signs. No-op unless the env var is
// set, so it never runs in normal CI.
func TestEmitRealRecord(t *testing.T) {
	out := os.Getenv("PAIL_WIRECOMPAT_OUT")
	if out == "" {
		t.Skip("set PAIL_WIRECOMPAT_OUT to emit")
	}
	keyfile := os.Getenv("PAIL_ISSUER_KEYFILE")
	if keyfile == "" {
		t.Fatal("PAIL_ISSUER_KEYFILE required")
	}
	sg, err := signer.FromEnv(keyfile, "dev-key-1")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	var head [32]byte
	for i := range head {
		head[i] = 0xA0
	}
	rec, err := BuildRecord(sg, "robot-1", head, 0, 7, 1700000000000)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// Self-check with the robot's own verifier before handing off.
	if !VerifyRecord(sg.Public(), rec) {
		t.Fatal("robot self-verify failed")
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	var pretty bytes.Buffer
	_ = json.Indent(&pretty, raw, "", "  ")
	if err := os.WriteFile(out, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("emitted robot record -> %s\n%s", out, pretty.String())
}
