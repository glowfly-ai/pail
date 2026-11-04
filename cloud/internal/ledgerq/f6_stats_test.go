// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package ledgerq

import (
	"path/filepath"
	"testing"
	"time"
)

// The offline -reindex verified the chain itself
// ("chain": ok) and then printed stats saying "unverified /
// VERIFICATION_UNAVAILABLE", because Stats describes a serving collector whose
// live verifier is not running. The offline command reads the recorded state;
// the live Stats keeps its override.
func TestF6OfflineStatsReportTheRecordedChainState(t *testing.T) {
	bb, tel := fixture(t)
	path := filepath.Join(t.TempDir(), "ledger.sqlite")
	d, cs, _, err := Rebuild(path, bb, tel, time.UnixMilli(tBurst+10_000))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if cs.State != "ok" {
		t.Fatalf("fixture chain state %q, want ok — nothing to measure", cs.State)
	}
	offline, err := d.StatsAsRecorded()
	if err != nil {
		t.Fatal(err)
	}
	if offline.ChainState != "ok" || offline.ChainError != "" {
		t.Fatalf("offline stats chain_state=%q chain_error=%q, want ok and empty", offline.ChainState, offline.ChainError)
	}
	live, err := d.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if live.ChainState != "unverified" || live.ChainError != "VERIFICATION_UNAVAILABLE" {
		t.Fatalf("live stats without a running verifier = %q/%q, want unverified/VERIFICATION_UNAVAILABLE", live.ChainState, live.ChainError)
	}
}
