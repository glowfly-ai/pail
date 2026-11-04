// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"encoding/json"
	"errors"

	"github.com/glowfly/pail/services/internal/blackbox"
	"github.com/glowfly/pail/services/internal/ledgerq"
	"github.com/glowfly/pail/services/internal/observability"
	"github.com/glowfly/pail/services/internal/telemetry"
)

var observationCollector *observability.Collector

// Extend the existing strict storage document with one optional source_map.
// Old documents keep precisely their prior no-delete behavior. The original
// storage parser still owns storage validation; nested duplicates are rejected.
func parseObservationConfig(b []byte) (telemetry.StorageConfig, *observability.Collector, error) {
	config := telemetry.DefaultStorageConfig()
	var fields map[string]json.RawMessage
	if e := observability.StrictJSON(b, &fields); e != nil {
		return config, nil, e
	}
	raw, ok := fields["source_map"]
	delete(fields, "source_map")
	storage, _ := json.Marshal(fields)
	var e error
	config, e = telemetry.ParseStorageConfig(storage)
	if e != nil {
		return config, nil, e
	}
	if !ok {
		return config, nil, nil
	}
	if string(raw) == "null" {
		return config, nil, errors.New("SOURCE_MAP_NULL")
	}
	mapping, e := observability.ParseSourceMap(raw)
	if e != nil {
		return config, nil, e
	}
	c, e := observability.New(mapping)
	return config, c, e
}

// ledgerWalk hands the records of one verification pass to the observation
// collector. The plan and ledger columns are computed here, at the end of the
// collector's own ledger cycle; a request reads the result from memory.
type ledgerWalk struct {
	collector *observability.Collector
	fold      *observability.LedgerFold
}

func (w *ledgerWalk) Record(seq int64, rec blackbox.Record) {
	w.fold.Record(observability.LedgerRecord{Seq: seq, Kind: ledgerq.RecordName(rec.Type), Ms: rec.UnixMs, Payload: rec.Payload})
}
func (w *ledgerWalk) Done(v ledgerq.ChainVerdict) {
	w.collector.PublishLedger(w.fold, observability.LedgerVerdict{State: v.State, Code: v.Code, VerifiedSeq: v.VerifiedSeq, TipSeq: v.TipSeq, LagRecords: v.LagRecords, Published: v.Published})
}

// connectLedger binds the ledger source of the source map, when it declares
// one, to the index. Without an index the source says INDEX_UNAVAILABLE.
func connectLedger(idx *ledgerq.DB, c *observability.Collector) {
	if c == nil || !c.HasLedgerSource() {
		return
	}
	if idx == nil {
		c.PublishLedger(nil, observability.LedgerVerdict{})
		return
	}
	c.LedgerVerifying()
	idx.ChainWalker = func() ledgerq.ChainWalk {
		return &ledgerWalk{collector: c, fold: c.NewLedgerFold()}
	}
}
