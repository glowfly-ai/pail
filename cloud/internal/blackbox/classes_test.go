// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// G-EUC-03 (EC-3) — the embedded table and the four-valued lookup. The
// records.go ↔ TSV bidirectional check is tests/contract/test_intervention_classes.py.
package blackbox

import "testing"

func TestIC01_EveryKnownTypeHasARowAndAVocabularyClass(t *testing.T) {
	rows, err := InterventionClasses()
	if err != nil {
		t.Fatalf("table: %v", err)
	}
	if len(rows) < 20 {
		t.Fatalf("table has %d rows — the chain has 21 record types", len(rows))
	}
	for _, typ := range []uint32{RecordTokenIssued, RecordGateDecision, RecordCheckpointV2, RecordIdentityRefused, RecordLeaseRetracted} {
		c, ok := ClassOf(typ)
		if !ok || c.Kind == "" {
			t.Fatalf("type %d: no row (%+v ok=%v)", typ, c, ok)
		}
	}
}

func TestIC02_UnknownTypeIsNotSystem(t *testing.T) {
	// 99 is not a record type. Folding it into `system` would let a new,
	// unclassified record kind pass as bookkeeping in every class summary.
	c, ok := ClassOf(99)
	if ok || c.Class != "" {
		t.Fatalf("unknown type must be ok=false with no class, got %+v ok=%v", c, ok)
	}
}

func TestIC03_ByPayloadTypesNameTheDecidingField(t *testing.T) {
	for _, typ := range []uint32{RecordGateDecision, RecordOperatorEvent} {
		c, ok := ClassOf(typ)
		if !ok || c.Class != "by_payload" || c.Note == "" {
			t.Fatalf("type %d must be by_payload with a note naming the field: %+v", typ, c)
		}
	}
}
