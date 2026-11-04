// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package ledgerq

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/glowfly/pail/services/internal/blackbox"
)

// Each case is a shape that exactly one verification guard decides. The broader
// corruption tests accept any refusal, so an adjacent guard can stand in for a
// removed one; these cases name the deciding guard by its published code.
func TestMOBSFrontierEachGuardAlone(t *testing.T) {
	t.Run("walk-without-prior-trust", func(t *testing.T) {
		bb, _ := fixture(t)
		seg := filepath.Join(bb, "pail_blackbox.00000001.seg")
		b, err := os.ReadFile(seg)
		if err != nil {
			t.Fatal(err)
		}
		b[len(b)-100] ^= 0xff
		if err = os.WriteFile(seg, b, 0600); err != nil {
			t.Fatal(err)
		}
		// A new index has no trusted frontier or segment record to fall back on.
		d, err := Open(filepath.Join(t.TempDir(), "index.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		cs, err := d.IngestChain(bb, time.UnixMilli(tBurst+10000))
		if err != nil || cs.State != "chain_error" {
			t.Fatalf("corrupt first journal: %+v %v", cs, err)
		}
	})
	t.Run("regression-code", func(t *testing.T) {
		bb, tel := fixture(t)
		now := time.UnixMilli(tBurst + 10000)
		d := openIngested(t, bb, tel, now)
		seg := filepath.Join(bb, "pail_blackbox.00000001.seg")
		b, err := os.ReadFile(seg)
		if err != nil {
			t.Fatal(err)
		}
		var off int64
		if _, err = blackbox.WalkDir(bb, func(r blackbox.Record) error { off = r.Offset; return nil }); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(seg, b[:off], 0600); err != nil {
			t.Fatal(err)
		}
		cs, err := d.IngestChain(bb, now)
		if err != nil || cs.State != "chain_error" || cs.Error != "JOURNAL_REGRESSION" {
			t.Fatalf("shorter valid journal: %+v %v", cs, err)
		}
	})
	t.Run("identity-code-and-no-foreign-frontier", func(t *testing.T) {
		bb, tel := fixture(t)
		now := time.UnixMilli(tBurst + 10000)
		d := openIngested(t, bb, tel, now)
		other, _ := fixture(t)
		b, err := os.ReadFile(filepath.Join(other, "pail_blackbox.00000001.seg"))
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(bb, "pail_blackbox.00000001.seg"), b, 0600); err != nil {
			t.Fatal(err)
		}
		cs, err := d.IngestChain(bb, now)
		if err != nil || cs.State != "chain_error" || !strings.Contains(cs.Error, "JOURNAL_IDENTITY_CHANGED") {
			t.Fatalf("replaced valid journal: %+v %v", cs, err)
		}
		r, err := d.Query(Filter{}, time.Second, now)
		if err != nil || r.Verify.Diagnostic.VerifiedThrough != nil {
			t.Fatalf("foreign record published as verified frontier: %+v %v", r.Verify, err)
		}
	})
}
