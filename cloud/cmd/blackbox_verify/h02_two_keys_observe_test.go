// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

// SEC-H02 — an observation, not a judgement (test LLD T25).
//
// After a revocation the issuer continues under a new key, so its journal holds
// checkpoints of two keys. The offline verifier takes one public key (the residual of
// SEC-H07). This test produces such a journal and records what the verifier says for each
// key; it fails only if the journal cannot be produced or the tool cannot be run. The
// output goes to the test log, and to the file named by H02_OBSERVE_OUT when set.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/glowfly/pail/services/internal/blackbox"
	devcrypto "github.com/glowfly/pail/services/internal/crypto"
	"github.com/glowfly/pail/services/internal/signer"
)

func TestH02ObserveJournalAcrossTwoIssuerKeys(t *testing.T) {
	dir := t.TempDir()
	journal := filepath.Join(dir, "journal")
	var pubs [2]string
	var report strings.Builder
	for i, id := range []string{"h02-issuer-1", "h02-issuer-2"} {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pubs[i] = base64.StdEncoding.EncodeToString(pub)
		w, err := blackbox.OpenDir(journal, blackbox.Config{Signer: signer.NewLocal(&devcrypto.Keypair{Public: pub, Private: priv, KeyID: id}),
			CheckpointEveryRecords: 2, IdleFlushAfter: -1})
		if err != nil {
			fmt.Fprintf(&report, "open journal with %s: %v\n", id, err)
			if i == 0 {
				t.Fatalf("cannot produce the first half of the journal: %v", err)
			}
			break
		}
		for n := 0; n < 4; n++ {
			if err := w.Append(blackbox.RecordOperatorEvent, uint64(time.Now().UnixMilli()), []byte(fmt.Sprintf(`{"kind":"H02_OBSERVE","key":%q,"n":%d}`, id, n))); err != nil {
				t.Fatalf("append under %s: %v", id, err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close under %s: %v", id, err)
		}
		fmt.Fprintf(&report, "journal continued under %s: 4 records, closed\n", id)
	}

	bin := filepath.Join(dir, "blackbox_verify")
	if out, err := exec.Command("go", "build", "-tags", "pail_generated", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build verifier: %v\n%s", err, out)
	}
	for i, pub := range pubs {
		out, err := exec.Command(bin, "-check-chain", "-dir", journal, "-pubkey", pub).CombinedOutput()
		rc := 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			rc = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("run verifier: %v", err)
		}
		fmt.Fprintf(&report, "\nblackbox_verify -check-chain -pubkey <key %d of 2>: rc=%d\n%s", i+1, rc, strings.TrimSpace(string(out))+"\n")
	}
	t.Log("\n" + report.String())
	if path := os.Getenv("H02_OBSERVE_OUT"); path != "" {
		if err := os.WriteFile(path, []byte(report.String()), 0644); err != nil {
			t.Fatal(err)
		}
	}
}
