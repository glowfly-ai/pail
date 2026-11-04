// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package ledgerq

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/glowfly/pail/services/internal/telemetry"
)

// MaxLimit caps one page (implementation contract D6).
const MaxLimit = 5000

// Filter is the AL-1 axis set. Robot is a hash (the caller resolves names —
// the index does not read the registry). TokenID matches chain rows by id and
// telemetry rows by hash16 of the same id, so one token can be followed across
// both sources with one parameter.
type Filter struct {
	FromMs, ToMs uint64
	RobotHash    string
	PlanID       string
	StepID       string
	TokenID      string
	Target       string
	Outcome      string
	Src          string
	// AL-3 axes: ActionClass is a mask (rows whose action_class AND mask != 0),
	// ActionName exact, Registered filters on the recorded flag (nil = any).
	ActionClass uint32
	ActionName  string
	Registered  *bool
	// Zone (AL-4) matches the zone recorded at issuance (TOKEN_ISSUED
	// journal_v ≥ 7). Rows whose zone was never recorded do not match — the
	// filter does not guess from a later model.
	Zone string
	// Requester (AL-5): "kind:id" or "id" — matches PLAN_ACCEPTED/PLAN_REJECTED
	// rows' recorded requester. Tokens/bursts carry none and do not match.
	Requester string
	Limit     int
	Cursor    string
}

// ZoneResolver answers "in the site model with this hash, which zone held
// this object?" from a kept snapshot. ok=false = no snapshot (or the object is
// not in it). Set by the host process (telemetryd reads the snapshot dir);
// nil means nothing can be resolved after the fact.
type ZoneResolver func(siteModelHash, target string) (zone string, ok bool)

// Verify says whether the chain rows in this response were behind a verified
// walk. `chain_ok` is hash-chain linkage verified by the reader up to
// checked_to_seq (the walk that filled the index); `chain_error` is a walk that
// hit a break (error kept); `unverified` is everything else — including a
// stale walk. `anchored` is reserved and never claimed by this version.
type Verify struct {
	Diagnostic   ChainDiagnostic `json:"diagnostic"`
	State        string          `json:"state"`
	CheckedToSeq int64           `json:"checked_to_seq"`
	CheckedToMs  uint64          `json:"checked_to_ms"`
	WalkMs       uint64          `json:"walk_ms"`
	Error        string          `json:"error,omitempty"`
	AnchorSeq    *int64          `json:"anchor_seq"`
}

// Resolution names how identifiers in the response were resolved. Zone is
// always `unresolved` until AL-4 stores site-model snapshots — saying so is
// the point (H-B2).
type Resolution struct {
	Robot string `json:"robot"` // registry | hash_only | unresolved | none
	// Zone: "snapshot" = every row that names a target got its zone either
	// from the issuance record or from that model's kept snapshot;
	// "unresolved" = at least one such row could not (no snapshot, object not
	// in it, or no site model at issuance); "none" = no row names a target.
	// "current_model" is reserved: this surface never answers from a model
	// other than the one of that day.
	Zone string `json:"zone"`
}

// Origin points back to the bytes a row was derived from.
type Origin struct {
	Seg string `json:"seg"`
	Off int64  `json:"off"`
}

// OutRow is the wire shape of one event.
type OutRow struct {
	Seq         int64   `json:"seq"`
	Ms          uint64  `json:"ms"`
	Src         string  `json:"src"`
	RobotID     string  `json:"robot_id"`
	RobotHash   string  `json:"robot_hash"`
	Kind        string  `json:"kind"`
	PlanID      string  `json:"plan_id"`
	StepID      string  `json:"step_id"`
	TokenID     string  `json:"token_id"`
	TokenHash   string  `json:"token_hash"`
	Target      string  `json:"target"`
	Zone        string  `json:"zone"`
	ActionClass int64   `json:"action_class"`
	ActionName  string  `json:"action_name"`
	Registered  *bool   `json:"registered"`
	Outcome     string  `json:"outcome"`
	ReasonValue int64   `json:"reason_value"`
	Requester   *Req    `json:"requester"`
	Origin      *Origin `json:"origin"`
	Sig         string  `json:"sig"`
	Resolved    bool    `json:"robot_resolved"`
	RejectCode  string  `json:"reject_code"`
	// TargetUnverified: true = issued against an undeclared target under
	// policy allow; false = declared (or no target); null = record predates AL-3.
	TargetUnverified *bool `json:"target_unverified"`
	// SiteModelHash names the model of that issuance (snapshot file key).
	SiteModelHash string `json:"site_model_hash"`
	// ZoneResolution per row: recorded | snapshot | unresolved | none(no target).
	ZoneResolution string `json:"zone_resolution"`
}

// Req is the requester identity (AL-2 fills it; nil until then).
type Req struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// Result is the response body of GET /v1/ledger/events.
type Result struct {
	Rows       []OutRow           `json:"rows"`
	Coverage   telemetry.Coverage `json:"coverage"`
	Verify     Verify             `json:"verify"`
	Resolution Resolution         `json:"resolution"`
	Index      Stats              `json:"index"`
	NextCursor string             `json:"next_cursor"`
}

// StaleWalk is how old a chain walk may be before its verdict stops covering
// an open window: rows appended after the walk are simply not in the index,
// but the *absence* of rows in the tail of the window is then unverified.
const StaleWalk = 60 * time.Second

func encodeCursor(ms uint64, seq int64) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatUint(ms, 10) + ":" + strconv.FormatInt(seq, 10)))
}

func decodeCursor(c string) (uint64, int64, error) {
	b, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return 0, 0, fmt.Errorf("cursor: %w", err)
	}
	parts := strings.SplitN(string(b), ":", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("cursor: malformed")
	}
	ms, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("cursor: %w", err)
	}
	seq, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("cursor: %w", err)
	}
	return ms, seq, nil
}

// Query answers one page. Rows are newest first (ms desc, seq desc); the
// cursor continues past the last row. `now` is the request time: open windows
// end there and the walk age is judged against it.
func (d *DB) Query(f Filter, maxGap time.Duration, now time.Time) (Result, error) {
	var res Result
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	tx, err := d.observationReader.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return res, err
	}
	defer tx.Rollback()
	res.Rows = []OutRow{}
	if f.ToMs == 0 {
		f.ToMs = uint64(now.UnixMilli())
	}
	if f.Limit <= 0 || f.Limit > MaxLimit {
		f.Limit = MaxLimit
	}
	where, args := eventWhere(f)
	if f.Cursor != "" {
		cms, cseq, err := decodeCursor(f.Cursor)
		if err != nil {
			return res, err
		}
		where = append(where, "(ms < ? OR (ms = ? AND seq < ?))")
		args = append(args, int64(cms), int64(cms), cseq)
	}
	q := `SELECT seq, ms, src, seg, off, chain_seq, robot_hash, robot_id, kind, plan_id, step_id, token_id, token_hash,
	             target, zone, action_class, action_name, registered, outcome, reason, requester_kind, requester_id, sig, reject_code, target_unverified, site_model_hash
	      FROM events WHERE ` + strings.Join(where, " AND ") + ` ORDER BY ms DESC, seq DESC LIMIT ?`
	args = append(args, f.Limit+1)
	rows, err := tx.Query(q, args...)
	if err != nil {
		return res, err
	}
	defer rows.Close()
	var maxChainSeq int64
	for rows.Next() {
		var (
			o                                                 OutRow
			seg                                               string
			off                                               int64
			chainSeq, actionClass, registered, reason         sql.NullInt64
			robotHash, robotID, planID, stepID, tokenID, th   sql.NullString
			target, zone, actionName, reqKind, reqID, sigCell sql.NullString
			rejectCode                                        sql.NullString
			targetUnv                                         sql.NullInt64
			siteHash                                          sql.NullString
		)
		if err := rows.Scan(&o.Seq, &o.Ms, &o.Src, &seg, &off, &chainSeq, &robotHash, &robotID, &o.Kind, &planID, &stepID,
			&tokenID, &th, &target, &zone, &actionClass, &actionName, &registered, &o.Outcome, &reason, &reqKind, &reqID, &sigCell, &rejectCode, &targetUnv, &siteHash); err != nil {
			return res, err
		}
		o.SiteModelHash = siteHash.String
		o.RejectCode = rejectCode.String
		if targetUnv.Valid {
			b := targetUnv.Int64 != 0
			o.TargetUnverified = &b
		}
		o.RobotHash, o.RobotID, o.PlanID, o.StepID = robotHash.String, robotID.String, planID.String, stepID.String
		o.TokenID, o.TokenHash, o.Target, o.Zone, o.ActionName = tokenID.String, th.String, target.String, zone.String, actionName.String
		o.ActionClass, o.ReasonValue, o.Sig = actionClass.Int64, reason.Int64, sigCell.String
		if registered.Valid {
			b := registered.Int64 != 0
			o.Registered = &b
		}
		if reqKind.Valid || reqID.Valid {
			o.Requester = &Req{Kind: reqKind.String, ID: reqID.String}
		}
		o.Origin = &Origin{Seg: seg, Off: off}
		o.Resolved = o.RobotID != ""
		if chainSeq.Valid && chainSeq.Int64 > maxChainSeq {
			maxChainSeq = chainSeq.Int64
		}
		res.Rows = append(res.Rows, o)
	}
	if err := rows.Err(); err != nil {
		return res, err
	}
	if len(res.Rows) > f.Limit {
		res.Rows = res.Rows[:f.Limit]
		last := res.Rows[len(res.Rows)-1]
		res.NextCursor = encodeCursor(last.Ms, last.Seq)
	}
	// AL-4: zones. Recorded at issuance → "recorded"; otherwise ask the kept
	// snapshot of that row's model; otherwise say so. The model of that day,
	// never the model of today.
	zoneSummary := "none"
	for i := range res.Rows {
		o := &res.Rows[i]
		switch {
		case o.Target == "":
			o.ZoneResolution = "none"
			continue
		case o.Zone != "":
			o.ZoneResolution = "recorded"
		case d.ZoneResolver != nil && o.SiteModelHash != "":
			if z, ok := d.ZoneResolver(o.SiteModelHash, o.Target); ok {
				o.Zone, o.ZoneResolution = z, "snapshot"
			} else {
				o.ZoneResolution = "unresolved"
			}
		default:
			o.ZoneResolution = "unresolved"
		}
		if o.ZoneResolution == "unresolved" {
			zoneSummary = "unresolved"
		} else if zoneSummary == "none" {
			zoneSummary = "snapshot"
		}
	}

	// Coverage from the ticks table — the same judgement as /liveness, fed
	// from the index instead of a full JSONL load.
	trows, err := tx.Query(`SELECT ms FROM ticks WHERE ms >= ? AND ms <= ? ORDER BY ms`,
		int64(f.FromMs)-int64(maxGap/time.Millisecond)*2, int64(f.ToMs))
	if err != nil {
		return res, err
	}
	var ticks []telemetry.Record
	for trows.Next() {
		var ms int64
		if err := trows.Scan(&ms); err != nil {
			trows.Close()
			return res, err
		}
		ticks = append(ticks, telemetry.Record{Kind: telemetry.KindTick, Ms: uint64(ms)})
	}
	trows.Close()
	res.Coverage = telemetry.CoverageOf(ticks, f.FromMs, f.ToMs, maxGap)

	st, err := d.stats(tx, true)
	if err != nil {
		return res, err
	}
	res.Index = st
	res.Verify = verifyState(st, maxChainSeq, now)
	res.Resolution = Resolution{Robot: "none", Zone: zoneSummary}
	return res, nil
}

// verifyState turns the index bookkeeping into the response's verify block.
// chain_ok requires: the last walk ended without a chain error, every chain
// row in the page sits at or below the walked position, and the walk is not
// stale. Anything less is unverified — never a guess.
func verifyState(st Stats, maxChainSeq int64, now time.Time) Verify {
	v := Verify{State: "unverified", CheckedToSeq: st.CheckedToSeq, CheckedToMs: st.CheckedToMs, WalkMs: st.ChainWalkMs}
	_ = json.Unmarshal([]byte(st.FrontierJSON), &v.Diagnostic)
	if st.ChainError != "" {
		v.Diagnostic.Error = chainFault(st.ChainError)
	}
	v.Diagnostic.ChainState = strings.ToUpper(st.ChainState)
	if st.ChainState == "never" {
		v.Diagnostic.ChainState = "UNVERIFIED"
	}
	if st.ChainWalkMs > 0 {
		v.Diagnostic.IndexLag.AgeMs = now.UnixMilli() - int64(st.ChainWalkMs)
	}
	switch st.ChainState {
	case "chain_error":
		v.State = "chain_error"
		v.Error = st.ChainError
	case "ok":
		age := time.Duration(now.UnixMilli()-int64(st.ChainWalkMs)) * time.Millisecond
		if maxChainSeq <= st.CheckedToSeq && age <= StaleWalk && age >= 0 {
			v.State = "chain_ok"
		}
	}
	if v.State == "unverified" && st.ChainState == "ok" {
		v.Diagnostic.ChainState = "UNVERIFIED"
		v.Diagnostic.Error = &ChainFault{Code: "STALE_VERIFICATION"}
	}
	return v
}

func eventWhere(f Filter) ([]string, []any) {
	where := []string{"ms >= ?", "ms <= ?"}
	args := []any{int64(f.FromMs), int64(f.ToMs)}
	add := func(cond string, v any) {
		where = append(where, cond)
		args = append(args, v)
	}
	if f.RobotHash != "" {
		add("robot_hash = ?", strings.ToLower(f.RobotHash))
	}
	if f.PlanID != "" {
		add("plan_id = ?", f.PlanID)
	}
	if f.StepID != "" {
		add("step_id = ?", f.StepID)
	}
	if f.TokenID != "" {
		where = append(where, "(token_id = ? OR token_hash = ?)")
		args = append(args, f.TokenID, TokenHash16(f.TokenID))
	}
	if f.Target != "" {
		add("target = ?", f.Target)
	}
	if f.Outcome != "" {
		add("outcome = ?", f.Outcome)
	}
	if f.Src != "" {
		add("src = ?", f.Src)
	}
	if f.ActionClass != 0 {
		add("(action_class & ?) != 0", int64(f.ActionClass))
	}
	if f.ActionName != "" {
		add("action_name = ?", f.ActionName)
	}
	if f.Registered != nil {
		if *f.Registered {
			add("registered = ?", int64(1))
		} else {
			add("registered = ?", int64(0))
		}
	}
	if f.Zone != "" {
		add("zone = ?", f.Zone)
	}
	if f.Requester != "" {
		if k, id, ok := strings.Cut(f.Requester, ":"); ok {
			add("requester_kind = ?", k)
			add("requester_id = ?", id)
		} else {
			add("requester_id = ?", f.Requester)
		}
	}

	return where, args
}
