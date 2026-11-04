// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

// Review items 15/21 (PAIL-P43-LEDGER-LIVE-TEST-LLD-001 §3): the collector's verification cycle, run against a
// REAL ledger that is being appended to, must end in one pass. Fail-first on the preview.42 tree: every cycle
// exhausts its three passes with SOURCE_UNSTABLE (the evaluator's "3 passes consumed per cycle").

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glowfly/pail/services/internal/blackbox"
	devcrypto "github.com/glowfly/pail/services/internal/crypto"
	"github.com/glowfly/pail/services/internal/ledgerq"
	"github.com/glowfly/pail/services/internal/signer"
)

func liveSigner(t *testing.T) signer.Signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return signer.NewLocal(&devcrypto.Keypair{Public: pub, Private: priv, KeyID: "dev-key-live"})
}

func TestOpsviewLedgerCycleUnderLiveAppend(t *testing.T) {
	bb := filepath.Join(t.TempDir(), "bb")
	tel := filepath.Join(t.TempDir(), "tel")
	for _, p := range []string{bb, tel} {
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cfg := blackbox.Config{Signer: liveSigner(t), IdleFlushAfter: -1, CheckpointEveryRecords: 50}
	w, err := blackbox.OpenDir(bb, cfg)
	if err != nil {
		t.Fatal(err)
	}
	base := uint64(1_800_000_000_000)
	payload := func(i int64) []byte {
		b, _ := json.Marshal(map[string]any{"kind": "plan_accepted", "unix_ms": base + uint64(i), "robot_id": "robot-1",
			"plan_id": fmt.Sprintf("plan-cycle-%06d", i), "chain_id": "chain-cycle", "policy_hash_hex": "ab", "key_id": "dev-key-live"})
		return b
	}
	for i := int64(1); i <= 3; i++ {
		if err := w.Append(blackbox.RecordPlanAccepted, base+uint64(i), payload(i)); err != nil {
			t.Fatal(err)
		}
	}
	d, err := ledgerq.Open(filepath.Join(t.TempDir(), "ledger.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if _, _, err := d.Ingest(bb, tel, time.UnixMilli(int64(base)+10_000)); err != nil {
		t.Fatal(err)
	}
	var count atomic.Int64
	count.Store(3)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			n := count.Load() + 1
			if err := w.Append(blackbox.RecordPlanAccepted, base+uint64(n), payload(n)); err != nil {
				t.Error(err)
				return
			}
			count.Store(n)
			time.Sleep(3 * time.Millisecond)
		}
	}()
	prev := int64(0)
	for cycle := 0; cycle < 5; cycle++ {
		before := count.Load()
		for count.Load() <= before+10 { // the cycle must start with growth under way
			time.Sleep(2 * time.Millisecond)
		}
		cs, passes, err := verifyLedger(d, bb, time.Now, time.Sleep)
		if err != nil {
			t.Fatal(err)
		}
		if cs.State != "ok" || passes != 1 {
			t.Fatalf("cycle %d: state=%s error=%s passes=%d — a ledger being appended to must verify in one pass (review 21: three passes consumed per cycle)", cycle, cs.State, cs.Error, passes)
		}
		if cs.CheckedToSeq < prev {
			t.Fatalf("cycle %d: verified position went back %d -> %d", cycle, prev, cs.CheckedToSeq)
		}
		prev = cs.CheckedToSeq
	}
	close(stop)
	<-done
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if prev <= 3 {
		t.Fatalf("the verified position never advanced past the initial records: %d", prev)
	}
}
