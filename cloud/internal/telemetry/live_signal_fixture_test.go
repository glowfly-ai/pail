// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package telemetry

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/glowfly/pail/services/internal/burst"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Optional fixture exporter: PUBLIC keys and signed test packets only. Private
// random signing keys stay in memory. The mirror prefix comes from its actual
// Python producer, not a second hand-maintained wire encoder.
func TestExportPublicSignalFixture(t *testing.T) {
	dest := os.Getenv("AC5_PUBLIC_SIGNAL_FIXTURE")
	if dest == "" {
		t.Skip("explicit public fixture destination required")
	}
	bp, bk, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	mp, mk, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(dest, 0700); e != nil {
		t.Fatal(e)
	}
	keys := map[string]interface{}{"keys": []map[string]string{{"key_id": "test-burst", "role": "burst", "ed25519_public_key_base64": base64.StdEncoding.EncodeToString(bp)}, {"key_id": "test-mirror", "role": "mirror", "ed25519_public_key_base64": base64.StdEncoding.EncodeToString(mp)}}}
	write := func(name string, v interface{}) {
		b, e := json.MarshalIndent(v, "", "  ")
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dest, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	write("public-keyring.json", keys)
	packets := map[string]map[string]string{}
	for _, robot := range []string{"robot-01", "robot-added-02"} {
		rows := map[string]string{}
		for seq := uint32(1); seq <= 4; seq++ {
			b := burst.BuildPacketV2(bk, burst.EventCheckpoint, 0, uint64(time.Now().UnixMilli()), robot, [16]byte{}, seq)
			rows[fmt.Sprintf("burst%d", seq)] = hex.EncodeToString(b)
			prefix := pythonPrefix(t, "robot="+robot, "effective_mode=enforce", "tick_ms=500", "permit_age_ms=0", "deadman_window_ms=200", "permit_seq=1", fmt.Sprintf("mirror_seq=%d", seq), fmt.Sprintf("unix_ms=%d", time.Now().UnixMilli()))
			mirror := append(append([]byte{}, prefix...), ed25519.Sign(mk, prefix)...)
			rows[fmt.Sprintf("mirror%d", seq)] = hex.EncodeToString(mirror)
		}
		b, _ := hex.DecodeString(rows["mirror2"])
		b[len(b)-1] ^= 1
		rows["bad_mirror"] = hex.EncodeToString(b)
		packets[robot] = rows
	}
	write("packets.json", map[string]interface{}{"test_only": true, "packets": packets})
}
