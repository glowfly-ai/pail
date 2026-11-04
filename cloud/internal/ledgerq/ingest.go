// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package ledgerq

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/glowfly/pail/services/internal/blackbox"
	"github.com/glowfly/pail/services/internal/telemetry"
	"github.com/glowfly/pail/services/pkg/robotid"
)

// Row is one index row as derived from its origin. The same derivation is
// used to fill the index and to check it (CheckOrigins) — a second derivation
// would let both drift and still agree.
type Row struct {
	Src           string `json:"src"`
	Seg           string `json:"seg"`
	Off           int64  `json:"off"`
	ChainSeq      int64  `json:"chain_seq,omitempty"`
	Ms            uint64 `json:"ms"`
	RobotHash     string `json:"robot_hash"`
	RobotID       string `json:"robot_id"`
	Kind          string `json:"kind"`
	PlanID        string `json:"plan_id"`
	StepID        string `json:"step_id"`
	TokenID       string `json:"token_id"`
	TokenHash     string `json:"token_hash"`
	Target        string `json:"target"`
	Zone          string `json:"zone"`
	ActionClass   int64  `json:"action_class"`
	ActionName    string `json:"action_name"`
	Registered    *bool  `json:"registered"`
	Outcome       string `json:"outcome"`
	Reason        int64  `json:"reason_value"`
	RequesterKind string `json:"requester_kind"`
	RequesterID   string `json:"requester_id"`
	Sig           string `json:"sig"`
	ChainID       string `json:"chain_id"`
	KeyID         string `json:"key_id"`
	RejectCode    string `json:"reject_code"`
	// AL-3 TOKEN_ISSUED journal_v 6: nil = record predates the field (v1/v5),
	// never "verified" by default.
	TargetUnverified *bool `json:"target_unverified"`
	// SiteModelHash (AL-4): sha256 of the site-model bytes the issuer served
	// against — the snapshot file name a past query resolves zones from.
	SiteModelHash string `json:"site_model_hash"`
}

// recordName maps blackbox record types to the outcome vocabulary. Unknown
// types are not dropped: they arrive as TYPE_<n> so a new record kind is
// visible in the index the day it first appears, not the day someone adds it.
func recordName(t uint32) string {
	switch t {
	case blackbox.RecordTokenIssued:
		return "TOKEN_ISSUED"
	case blackbox.RecordPlanAccepted:
		return "PLAN_ACCEPTED"
	case blackbox.RecordContextSealed:
		return "CONTEXT_SEALED"
	case blackbox.RecordPlanRejected:
		return "PLAN_REJECTED"
	case blackbox.RecordGateDecision:
		return "GATE_DECISION"
	case blackbox.RecordChainRevoked:
		return "CHAIN_REVOKED"
	case blackbox.RecordCheckpoint, blackbox.RecordCheckpointV2:
		return "CHECKPOINT"
	case blackbox.RecordRecoveryTruncate:
		return "RECOVERY_TRUNCATE"
	case blackbox.RecordSafeStop:
		return "SAFE_STOP"
	case blackbox.RecordOperatorEvent:
		return "OPERATOR_EVENT"
	case blackbox.RecordGraphMutation:
		return "GRAPH_MUTATION"
	case blackbox.RecordContextProvenance:
		return "CONTEXT_PROVENANCE"
	case blackbox.RecordAttestation:
		return "ATTESTATION"
	case blackbox.RecordConfigSealed:
		return "CONFIG_SEALED"
	case blackbox.RecordLeaseGranted:
		return "LEASE_GRANTED"
	case blackbox.RecordLeaseReconciled:
		return "LEASE_RECONCILED"
	case blackbox.RecordFleetCensus:
		return "FLEET_CENSUS"
	case blackbox.RecordLeaseRetracted:
		return "LEASE_RETRACTED"
	case blackbox.RecordHaMembership:
		return "HA_MEMBERSHIP"
	case blackbox.RecordIdentityRefused:
		return "IDENTITY_REFUSED"
	// C1 basic communication contract receipts (spec/CORE_COMM.md §E; preview.38 RV09). Data indexed by an
	// older mirror carries these as TYPE_100 / TYPE_101: a re-index maps them to the names below.
	case blackbox.RecordCoreOperation:
		return "CORE_OPERATION"
	case blackbox.RecordCoreReport:
		return "CORE_REPORT"
	}
	return fmt.Sprintf("TYPE_%d", t)
}

// RobotHash16 is the burst v2 robot field: hex(sha256(robot_id)[:16]).
func RobotHash16(id string) string { return robotid.Hash16(id) }

// TokenHash16 is the burst v2 token field: hex(sha256(token_id)[:16]).
func TokenHash16(tokenID string) string {
	h := sha256.Sum256([]byte(tokenID))
	return hex.EncodeToString(h[:16])
}

func segmentName(seq uint64) string { return fmt.Sprintf("pail_blackbox.%08d.seg", seq) }

// rowFromChain derives one row from a chain record. JSON payloads yield their
// plaintext identifiers; binary payloads (checkpoints, recovery) yield only the
// outcome and time. Fields absent from the payload stay empty — the index does
// not guess.
func rowFromChain(rec blackbox.Record, chainSeq int64) Row {
	r := Row{
		Src:      "chain",
		Seg:      segmentName(rec.SegmentSeq),
		Off:      rec.Offset,
		ChainSeq: chainSeq,
		Ms:       rec.UnixMs,
		Kind:     recordName(rec.Type),
		Outcome:  recordName(rec.Type),
	}
	if len(rec.Payload) > 0 && rec.Payload[0] == '{' {
		var m map[string]any
		if json.Unmarshal(rec.Payload, &m) == nil {
			str := func(k string) string {
				if v, ok := m[k].(string); ok {
					return v
				}
				return ""
			}
			r.RobotID = str("robot_id")
			if r.RobotID != "" {
				r.RobotHash = RobotHash16(r.RobotID)
			}
			r.PlanID = str("plan_id")
			r.StepID = str("step_id")
			r.TokenID = str("token_id")
			if r.TokenID != "" {
				r.TokenHash = TokenHash16(r.TokenID)
			}
			r.Target = str("target_object_id")
			r.ChainID = str("chain_id")
			r.KeyID = str("key_id")
			// v2 (AL-2): requester rides PLAN_ACCEPTED / PLAN_REJECTED as an object.
			// v1 records have none — the column stays NULL and the response says
			// nil, never a guessed "system".
			if rq, ok := m["requester"].(map[string]any); ok {
				if k, ok := rq["kind"].(string); ok {
					r.RequesterKind = k
				}
				if id, ok := rq["id"].(string); ok {
					r.RequesterID = id
				}
			}
			r.RejectCode = str("reject_code")
			// AL-3 (journal_v 6): action resolution on TOKEN_ISSUED.
			if v, ok := m["action_class"].(float64); ok {
				r.ActionClass = int64(v)
			}
			r.ActionName = str("action_name")
			if v, ok := m["registered"].(bool); ok {
				b := v
				r.Registered = &b
			}
			r.Zone = str("zone_id")
			r.SiteModelHash = str("site_model_hash_hex")
			if v, ok := m["target_unverified"].(bool); ok {
				b := v
				r.TargetUnverified = &b
			}
		}
	}
	return r
}

// rowFromBurst derives one row from a telemetry burst record (JSONL line).
func rowFromBurst(rec telemetry.Record, file string, line int64) Row {
	return Row{
		Src:       "telemetry",
		Seg:       file,
		Off:       line,
		Ms:        rec.Ms,
		RobotHash: strings.ToLower(rec.Robot),
		Kind:      "burst",
		TokenHash: strings.ToLower(rec.Token),
		Outcome:   rec.Event,
		Reason:    int64(rec.ReasonValue),
		Sig:       rec.Sig,
	}
}

const insertSQL = `INSERT OR IGNORE INTO events
 (src, seg, off, chain_seq, ms, robot_hash, robot_id, kind, plan_id, step_id, token_id, token_hash,
  target, zone, action_class, action_name, registered, outcome, reason, requester_kind, requester_id, sig, chain_id, key_id, reject_code, target_unverified, site_model_hash)
 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullI(n int64, present bool) any {
	if !present {
		return nil
	}
	return n
}

func insertRow(tx *sql.Tx, r Row) error {
	var reg, tu any
	if r.Registered != nil {
		if *r.Registered {
			reg = int64(1)
		} else {
			reg = int64(0)
		}
	}
	if r.TargetUnverified != nil {
		if *r.TargetUnverified {
			tu = int64(1)
		} else {
			tu = int64(0)
		}
	}
	_, err := tx.Exec(insertSQL,
		r.Src, r.Seg, r.Off, nullI(r.ChainSeq, r.Src == "chain"), int64(r.Ms), nullStr(r.RobotHash), nullStr(r.RobotID),
		r.Kind, nullStr(r.PlanID), nullStr(r.StepID), nullStr(r.TokenID), nullStr(r.TokenHash),
		nullStr(r.Target), nullStr(r.Zone), nullI(r.ActionClass, r.ActionClass != 0), nullStr(r.ActionName), reg,
		r.Outcome, nullI(r.Reason, r.Src == "telemetry"), nullStr(r.RequesterKind), nullStr(r.RequesterID),
		nullStr(r.Sig), nullStr(r.ChainID), nullStr(r.KeyID), nullStr(r.RejectCode), tu, nullStr(r.SiteModelHash))
	return err
}

// ChainStatus is the outcome of one chain walk.
type ChainStatus struct {
	State        string // ok | chain_error | absent | unverified
	Error        string
	Records      int64 // records seen in this walk (all, not only new)
	Inserted     int64
	CheckedToSeq int64
	CheckedToMs  uint64
	TornTail     bool
}

// TelemetryStatus is the outcome of one JSONL tail pass.
type TelemetryStatus struct {
	Files    int
	Bursts   int64
	Ticks    int64
	BadLines int64
}

// IngestTelemetry tails every decisions-*.jsonl in dir from the byte offset
// remembered per file. Bursts become events; liveness ticks go to the ticks
// table (coverage material); permit mirror ticks are not events and stay on
// the v1 /permits surface. A partial last line (writer mid-append) is left
// for the next pass — it is not an unparseable line.
func (d *DB) IngestTelemetry(dir string, now time.Time) (TelemetryStatus, error) {
	return d.ingestObservations(dir, now)
}

// Ingest runs both passes. Chain first: a chain failure is the more important
// fact and must be recorded even when the JSONL pass then errors.
func (d *DB) Ingest(blackboxDir, telemetryDir string, now time.Time) (ChainStatus, TelemetryStatus, error) {
	cs, err := d.IngestChain(blackboxDir, now)
	if err != nil {
		return cs, TelemetryStatus{}, err
	}
	ts, err := d.IngestTelemetry(telemetryDir, now)
	return cs, ts, err
}
