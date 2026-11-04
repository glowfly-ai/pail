// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package ledgerq

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/glowfly/pail/services/internal/blackbox"
)

type heard struct {
	seqs    []int64
	kinds   []string
	bodies  []string
	verdict *ChainVerdict
	after   int // records handed over after the verdict
}

func (h *heard) Record(seq int64, rec blackbox.Record) {
	if h.verdict != nil {
		h.after++
	}
	h.seqs = append(h.seqs, seq)
	h.kinds = append(h.kinds, RecordName(rec.Type))
	h.bodies = append(h.bodies, string(rec.Payload))
}
func (h *heard) Done(v ChainVerdict) {
	if h.verdict != nil {
		h.after++
	}
	h.verdict = &v
}

// listen opens an index on the fixture ledger with a receiver per pass.
func listen(t *testing.T) (*DB, string, *[]*heard) {
	t.Helper()
	bb, _ := fixture(t)
	d, err := Open(filepath.Join(t.TempDir(), "ledger.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	passes := &[]*heard{}
	d.ChainWalker = func() ChainWalk {
		h := &heard{}
		*passes = append(*passes, h)
		return h
	}
	return d, bb, passes
}

// The plan and ledger columns are computed from the records of the
// verification walk itself: every verified record once, in order, then the
// verdict the index published.
func TestOpsviewChainWalkHearsTheVerifiedLedger(t *testing.T) {
	d, bb, passes := listen(t)
	now := time.UnixMilli(tBurst + 10000)
	for pass := 1; pass <= 2; pass++ {
		cs, err := d.IngestChain(bb, now)
		if err != nil || cs.State != "ok" {
			t.Fatal(cs, err)
		}
		if len(*passes) != pass {
			t.Fatal("receivers: ", len(*passes))
		}
		h := (*passes)[pass-1]
		// a later pass hears the whole ledger again, not only what is new to the index
		if len(h.seqs) != 3 || h.seqs[0] != 1 || h.seqs[1] != 2 || h.seqs[2] != 3 || h.kinds[0] != "PLAN_ACCEPTED" || h.kinds[1] != "TOKEN_ISSUED" || h.kinds[2] != "TYPE_999" || h.after != 0 {
			t.Fatalf("%+v", h)
		}
		if h.bodies[0] == "" || h.bodies[0][0] != '{' {
			t.Fatal(h.bodies[0])
		}
		v := h.verdict
		if v == nil || !v.Published || v.State != "ok" || v.Code != "" || v.VerifiedSeq != 3 || v.TipSeq == nil || *v.TipSeq != 3 || v.LagRecords == nil || *v.LagRecords != 0 || !v.At.Equal(now) {
			t.Fatalf("%+v", v)
		}
	}
}

func TestOpsviewChainWalkVerdicts(t *testing.T) {
	now := time.UnixMilli(tBurst + 10000)
	last := func(passes *[]*heard) *heard { return (*passes)[len(*passes)-1] }
	t.Run("damaged", func(t *testing.T) {
		d, bb, passes := listen(t)
		if _, err := d.IngestChain(bb, now); err != nil {
			t.Fatal(err)
		}
		seg := filepath.Join(bb, "pail_blackbox.00000001.seg")
		b, _ := os.ReadFile(seg)
		b[len(b)-100] ^= 0xff
		if err := os.WriteFile(seg, b, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := d.IngestChain(bb, now); err != nil {
			t.Fatal(err)
		}
		h := last(passes)
		if h.verdict == nil || !h.verdict.Published || h.verdict.State != "chain_error" || h.verdict.Code == "" || h.verdict.LagRecords != nil || h.verdict.TipSeq != nil {
			t.Fatalf("%+v", h.verdict)
		}
		// a closed code, not the text of an error
		if !regexp.MustCompile(`^[A-Z][A-Z_]+$`).MatchString(h.verdict.Code) {
			t.Fatal(h.verdict.Code)
		}
		// nothing beyond the verified position was handed over
		if int64(len(h.seqs)) != h.verdict.VerifiedSeq || len(h.seqs) >= 3 {
			t.Fatalf("heard %d records, verified %d", len(h.seqs), h.verdict.VerifiedSeq)
		}
	})
	t.Run("absent", func(t *testing.T) {
		d, bb, passes := listen(t)
		if _, err := d.IngestChain(filepath.Join(bb, "none"), now); err != nil {
			t.Fatal(err)
		}
		h := last(passes)
		if h.verdict == nil || !h.verdict.Published || h.verdict.State != "absent" || h.verdict.Code != "SOURCE_ABSENT" || h.verdict.VerifiedSeq != 0 || len(h.seqs) != 0 {
			t.Fatalf("%+v %v", h.verdict, h.seqs)
		}
	})
	t.Run("changed while read", func(t *testing.T) {
		d, bb, passes := listen(t)
		seg := filepath.Join(bb, "pail_blackbox.00000001.seg")
		original, _ := os.ReadFile(seg)
		d.snapshotCopied = func() {
			b := append([]byte{}, original...)
			b[len(b)-100] ^= 1
			if err := os.WriteFile(seg, b, 0600); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := d.IngestChain(bb, now); err != nil {
			t.Fatal(err)
		}
		h := last(passes)
		// the records were heard, and the verdict says none of them may be shown
		if h.verdict == nil || h.verdict.State != "unverified" || h.verdict.Code != "SOURCE_UNSTABLE" || h.verdict.VerifiedSeq != 0 || len(h.seqs) != 3 {
			t.Fatalf("%+v %v", h.verdict, h.seqs)
		}
	})
	t.Run("index cannot publish", func(t *testing.T) {
		d, bb, passes := listen(t)
		if _, err := d.IngestChain(bb, now); err != nil {
			t.Fatal(err)
		}
		if err := d.setMeta("chain_trusted_frontier", "broken JSON"); err != nil {
			t.Fatal(err)
		}
		if _, err := d.IngestChain(bb, now); err == nil {
			t.Fatal("invalid persisted identity was ignored")
		}
		h := last(passes)
		if len(*passes) != 2 || h.verdict == nil || h.verdict.Published {
			t.Fatalf("%+v", h.verdict)
		}
	})
	t.Run("no receiver", func(t *testing.T) {
		d, bb, passes := listen(t)
		d.ChainWalker = nil
		if cs, err := d.IngestChain(bb, now); err != nil || cs.State != "ok" || len(*passes) != 0 {
			t.Fatal(cs, err)
		}
	})
}
