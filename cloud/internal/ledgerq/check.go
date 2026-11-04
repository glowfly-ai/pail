// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package ledgerq

import (
	"database/sql"
	"fmt"
	"os"
	"time"

	"github.com/glowfly/pail/services/internal/blackbox"
)

// CheckReport is the outcome of CheckOrigins.
type CheckReport struct {
	Checked    int64    `json:"checked"`
	Mismatches []string `json:"mismatches"`
	Missing    []string `json:"missing"` // index rows whose origin no longer exists in the walk
	Extra      int64    `json:"extra"`   // chain records not in the index (ingest lag, not a defect)
}

// OK is true when every index row reproduces from its origin.
func (r CheckReport) OK() bool { return len(r.Mismatches) == 0 && len(r.Missing) == 0 }

// CheckOrigins re-derives every chain row from its origin bytes — through the
// same reader and the same derivation that filled the index — and compares
// field by field. A row that differs is an index that says something the
// ledger does not (G-LED-02). This is the observation point a tampered or
// corrupted index reddens; the ledger itself is not touched.
func (d *DB) CheckOrigins(dir string) (CheckReport, error) {
	var rep CheckReport
	rep.Mismatches = []string{}
	rep.Missing = []string{}
	derived := map[string]Row{}
	var seq int64
	if _, err := blackbox.WalkDir(dir, func(rec blackbox.Record) error {
		seq++
		r := rowFromChain(rec, seq)
		derived[r.Seg+":"+fmt.Sprint(r.Off)] = r
		return nil
	}); err != nil {
		return rep, fmt.Errorf("check: walk: %w", err)
	}
	rows, err := d.sql.Query(`SELECT seg, off, chain_seq, ms, robot_hash, robot_id, kind, plan_id, step_id, token_id, token_hash,
	                                 target, outcome, chain_id, key_id, requester_kind, requester_id, reject_code,
	                                 action_class, action_name, registered, zone, site_model_hash FROM events WHERE src = 'chain'`)
	if err != nil {
		return rep, err
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var (
			stored                                      Row
			chainSeq                                    sql.NullInt64
			robotHash, robotID, planID, stepID, tokenID sql.NullString
			tokenHash, target, chainID, keyID           sql.NullString
			reqKind, reqID, rejectCode                  sql.NullString
			actionClass, registered                     sql.NullInt64
			actionName, zone, siteHash                  sql.NullString
		)
		if err := rows.Scan(&stored.Seg, &stored.Off, &chainSeq, &stored.Ms, &robotHash, &robotID, &stored.Kind, &planID,
			&stepID, &tokenID, &tokenHash, &target, &stored.Outcome, &chainID, &keyID, &reqKind, &reqID, &rejectCode,
			&actionClass, &actionName, &registered, &zone, &siteHash); err != nil {
			return rep, err
		}
		stored.Zone, stored.SiteModelHash = zone.String, siteHash.String
		stored.RequesterKind, stored.RequesterID, stored.RejectCode = reqKind.String, reqID.String, rejectCode.String
		stored.ActionClass, stored.ActionName = actionClass.Int64, actionName.String
		if registered.Valid {
			b := registered.Int64 != 0
			stored.Registered = &b
		}
		stored.Src = "chain"
		stored.ChainSeq = chainSeq.Int64
		stored.RobotHash, stored.RobotID, stored.PlanID, stored.StepID = robotHash.String, robotID.String, planID.String, stepID.String
		stored.TokenID, stored.TokenHash, stored.Target, stored.ChainID, stored.KeyID = tokenID.String, tokenHash.String, target.String, chainID.String, keyID.String
		key := stored.Seg + ":" + fmt.Sprint(stored.Off)
		want, ok := derived[key]
		if !ok {
			rep.Missing = append(rep.Missing, key)
			continue
		}
		seen++
		rep.Checked++
		if diff := diffRow(stored, want); diff != "" {
			rep.Mismatches = append(rep.Mismatches, key+": "+diff)
		}
	}
	if err := rows.Err(); err != nil {
		return rep, err
	}
	rep.Extra = int64(len(derived) - seen)
	return rep, nil
}

func boolStr(b *bool) string {
	if b == nil {
		return "null"
	}
	if *b {
		return "true"
	}
	return "false"
}

// diffRow names the first field that differs — the name is the evidence.
func diffRow(a, b Row) string {
	type f struct {
		name string
		x, y any
	}
	for _, c := range []f{
		{"chain_seq", a.ChainSeq, b.ChainSeq}, {"ms", a.Ms, b.Ms}, {"robot_hash", a.RobotHash, b.RobotHash},
		{"robot_id", a.RobotID, b.RobotID}, {"kind", a.Kind, b.Kind}, {"plan_id", a.PlanID, b.PlanID},
		{"step_id", a.StepID, b.StepID}, {"token_id", a.TokenID, b.TokenID}, {"token_hash", a.TokenHash, b.TokenHash},
		{"target", a.Target, b.Target}, {"outcome", a.Outcome, b.Outcome}, {"chain_id", a.ChainID, b.ChainID},
		{"key_id", a.KeyID, b.KeyID}, {"requester_kind", a.RequesterKind, b.RequesterKind},
		{"requester_id", a.RequesterID, b.RequesterID}, {"reject_code", a.RejectCode, b.RejectCode},
		{"action_class", a.ActionClass, b.ActionClass}, {"action_name", a.ActionName, b.ActionName},
		{"registered", boolStr(a.Registered), boolStr(b.Registered)},
		{"zone", a.Zone, b.Zone}, {"site_model_hash", a.SiteModelHash, b.SiteModelHash},
	} {
		if c.x != c.y {
			return fmt.Sprintf("%s index=%v origin=%v", c.name, c.x, c.y)
		}
	}
	return ""
}

// Rebuild uses a side-by-side index; only a complete, checked SQLite file is
// published. The previous index and its WAL files remain as rollback evidence.
// Callers must close their existing index handles before explicit rebuilding.
func Rebuild(path, blackboxDir, telemetryDir string, now time.Time) (*DB, ChainStatus, TelemetryStatus, error) {
	building := path + ".building"
	if _, err := os.Stat(building); !os.IsNotExist(err) {
		return nil, ChainStatus{}, TelemetryStatus{}, fmt.Errorf("INDEX_BUILDING_EXISTS: inspect previous build")
	}
	d, err := Open(building)
	if err != nil {
		return nil, ChainStatus{}, TelemetryStatus{}, err
	}
	cs, ts, err := d.Ingest(blackboxDir, telemetryDir, now)
	if err == nil {
		var result string
		err = d.sql.QueryRow("PRAGMA integrity_check").Scan(&result)
		if err == nil && result != "ok" {
			err = fmt.Errorf("index integrity: %s", result)
		}
	}
	if err == nil {
		_, err = d.sql.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	}
	closeErr := d.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, cs, ts, err
	}
	if err = publishIndex(path, building); err != nil {
		return nil, cs, ts, err
	}
	d, err = Open(path)
	if err == nil {
		d.observationReady.Store(true)
	}
	return d, cs, ts, err
}
