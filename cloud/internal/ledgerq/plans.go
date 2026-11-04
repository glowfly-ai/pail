// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package ledgerq

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type PlanSummary struct {
	PlanID   string `json:"plan_id"`
	Accepted int64  `json:"accepted"`
	Rejected int64  `json:"rejected"`
	Tokens   int64  `json:"tokens"`
	Events   int64  `json:"events"`
	LastMs   uint64 `json:"last_ms"`
	LastSeq  int64  `json:"last_seq,string"`
	LastKind string `json:"last_kind"`
}
type PlansResult struct {
	Plans      []PlanSummary `json:"plans"`
	Verify     Verify        `json:"verify"`
	Index      Stats         `json:"index"`
	NextCursor string        `json:"next_cursor"`
	Resolution string        `json:"resolution"`
}

// QueryPlans summarizes the selected indexed range, not the current event
// page. Counts describe matching events only; they are not lifecycle verdicts.
func (d *DB) QueryPlans(f Filter, now time.Time) (PlansResult, error) {
	res := PlansResult{Plans: []PlanSummary{}}
	if f.ToMs == 0 {
		f.ToMs = uint64(now.UnixMilli())
	}
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 200
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	tx, err := d.observationReader.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return res, err
	}
	defer tx.Rollback()
	where, args := eventWhere(f)
	where = append(where, "plan_id IS NOT NULL", "src='chain'")
	// A deterministic last event is selected by (ms,seq), including ties.
	q := `WITH selected AS (SELECT *, ROW_NUMBER() OVER (PARTITION BY plan_id ORDER BY ms DESC,seq DESC) AS rn FROM events WHERE ` + strings.Join(where, " AND ") + `), grouped AS (
 SELECT plan_id,SUM(outcome='PLAN_ACCEPTED') AS accepted,SUM(outcome='PLAN_REJECTED') AS rejected,SUM(outcome='TOKEN_ISSUED') AS tokens,COUNT(*) AS events,
 MAX(CASE WHEN rn=1 THEN ms END) AS last_ms,MAX(CASE WHEN rn=1 THEN seq END) AS last_seq,MAX(CASE WHEN rn=1 THEN kind END) AS last_kind FROM selected GROUP BY plan_id)
 SELECT * FROM grouped`
	if f.Cursor != "" {
		ms, seq, e := decodeCursor(f.Cursor)
		if e != nil {
			return res, e
		}
		q += " WHERE (last_ms<? OR (last_ms=? AND last_seq<?))"
		args = append(args, int64(ms), int64(ms), seq)
	}
	q += " ORDER BY last_ms DESC,last_seq DESC LIMIT ?"
	args = append(args, f.Limit+1)
	rows, err := tx.Query(q, args...)
	if err != nil {
		return res, err
	}
	pageBytes := 0
	for rows.Next() {
		var p PlanSummary
		if err = rows.Scan(&p.PlanID, &p.Accepted, &p.Rejected, &p.Tokens, &p.Events, &p.LastMs, &p.LastSeq, &p.LastKind); err != nil {
			rows.Close()
			return res, err
		}
		if len(p.PlanID) > 64<<10 {
			rows.Close()
			return res, fmt.Errorf("PLAN_ID_OVERSIZE")
		}
		encoded, _ := json.Marshal(p)
		if pageBytes+len(encoded)+1 > (1<<20)-(16<<10) {
			last := res.Plans[len(res.Plans)-1]
			res.NextCursor = encodeCursor(last.LastMs, last.LastSeq)
			break
		}
		pageBytes += len(encoded) + 1
		res.Plans = append(res.Plans, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return res, err
	}
	if len(res.Plans) > f.Limit {
		res.Plans = res.Plans[:f.Limit]
		p := res.Plans[len(res.Plans)-1]
		res.NextCursor = encodeCursor(p.LastMs, p.LastSeq)
	}
	st, err := d.stats(tx, true)
	if err != nil {
		return res, err
	}
	res.Index = st
	res.Verify = verifyState(st, st.CheckedToSeq, now)
	return res, nil
}
