// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package corecomm

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/glowfly/pail/services/internal/blackbox"
	pb "github.com/glowfly/pail/services/proto/pailv1"
	"google.golang.org/protobuf/proto"
	"sync"
	"time"
)

var ErrConflict = errors.New("CORE_OPERATION_CONFLICT")
var ErrCapacity = errors.New("CORE_OPERATION_CAPACITY")

const DefaultMaxEntries = 4096
const DefaultMaxBytes = 64 << 20

// Entry is a receipt/tombstone in the existing authenticated blackbox chain.
// A prepared entry with no final record is UNKNOWN after a crash, never absent.
type Entry struct {
	ResolvedBy string `json:"resolved_by,omitempty"`
	Chain      string `json:"chain,omitempty"`
	Payload    []byte `json:"payload,omitempty"`
	Version    int    `json:"v"`
	Key        string `json:"key"`
	Scope      string `json:"scope"`
	Robot      string `json:"robot"`
	Plan       string `json:"plan,omitempty"`
	Kind       string `json:"kind"`
	ID         string `json:"id"`
	Digest     []byte `json:"digest"`
	Phase      string `json:"phase"`
	Response   []byte `json:"response,omitempty"`
	Critical   bool   `json:"critical,omitempty"`
	AtMS       int64  `json:"at_ms"`
	Recovered  bool   `json:"-"`
}
type Journal struct {
	mu                   sync.Mutex
	writer               *blackbox.Writer
	entries              map[string]Entry
	legacyPlans          map[string]bool
	blocked              map[string]int
	bytes                int
	maxEntries, maxBytes int
}

func Key(scope, robot, kind, id string) string {
	b, _ := json.Marshal([]string{scope, robot, kind, id})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func clone(e Entry) Entry {
	e.Digest = append([]byte(nil), e.Digest...)
	e.Response = append([]byte(nil), e.Response...)
	e.Payload = append([]byte(nil), e.Payload...)
	return e
}
func OpenJournal(w *blackbox.Writer) (*Journal, error) {
	if w == nil {
		return nil, errors.New("CORE_JOURNAL_UNAVAILABLE")
	}
	j := &Journal{writer: w, entries: map[string]Entry{}, legacyPlans: map[string]bool{}, maxEntries: DefaultMaxEntries, maxBytes: DefaultMaxBytes}
	_, err := blackbox.WalkDir(w.Dir(), func(r blackbox.Record) error {
		if r.Type == blackbox.RecordPlanAccepted {
			var plan struct {
				Robot string `json:"robot_id"`
				Plan  string `json:"plan_id"`
			}
			if err := json.Unmarshal(r.Payload, &plan); err != nil {
				return err
			}
			// A legacy plan ID is not a new operation just because its receipt
			// predates this protocol. A later matching core entry supersedes this guard.
			if plan.Robot != "" && plan.Plan != "" {
				j.legacyPlans[Key("", plan.Robot, "PLAN", plan.Plan)] = true
			}
		}
		if r.Type != blackbox.RecordCoreOperation && r.Type != blackbox.RecordCoreReport {
			return nil
		}
		var e Entry
		if err := json.Unmarshal(r.Payload, &e); err != nil {
			return err
		}
		if e.Version != 1 || e.Key != Key(e.Scope, e.Robot, e.Kind, e.ID) || len(e.Digest) != 32 {
			return errors.New("invalid core-comm journal record")
		}
		old, ok := j.entries[e.Key]
		if ok && (!bytes.Equal(old.Digest, e.Digest) || old.Robot != e.Robot) {
			return ErrConflict
		}
		if ok && old.Phase != "IN_PROGRESS" && old.Phase != "OUTCOME_UNKNOWN" {
			return errors.New("core receipt rewritten after terminal result")
		}
		if e.Phase != "IN_PROGRESS" && e.Phase != "COMMITTED" && e.Phase != "REJECTED" && e.Phase != "OUTCOME_UNKNOWN" {
			return errors.New("unknown core receipt phase")
		}
		if e.ResolvedBy != "" {
			proof, ok := j.entries[e.ResolvedBy]
			var response pb.CancelPlanResponse
			if !ok || proof.Kind != "CANCEL" || proof.Phase != "COMMITTED" || proof.Robot != e.Robot || proof.Plan != e.Plan || (e.Kind == "REPORT" && proof.Chain != e.Chain) || proto.Unmarshal(proof.Response, &response) != nil || !response.Cancelled {
				return errors.New("invalid withdrawal resolution")
			}
		}
		e.Recovered = true
		j.put(e)
		j.bytes += len(r.Payload)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return j, nil
}
func (j *Journal) append(e Entry) error {
	e.Version = 1
	e.AtMS = time.Now().UnixMilli()
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	typ := blackbox.RecordCoreOperation
	if e.Kind == "REPORT" {
		typ = blackbox.RecordCoreReport
	}
	if err = j.writer.AppendDurable(typ, uint64(e.AtMS), b); err != nil {
		return err
	}
	j.bytes += len(b)
	return nil
}
func (j *Journal) Begin(e Entry) (Entry, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	e.Key = Key(e.Scope, e.Robot, e.Kind, e.ID)
	if old, ok := j.entries[e.Key]; ok {
		if !bytes.Equal(old.Digest, e.Digest) {
			return Entry{}, false, ErrConflict
		}
		return clone(old), false, nil
	}
	// A different operation ID cannot issue another incarnation of the same plan.
	if e.Kind == "SUBMIT" {
		for _, old := range j.entries {
			if old.Robot == e.Robot && old.Plan == e.Plan && old.Kind == "SUBMIT" {
				if old.Scope != e.Scope || old.ID != e.ID || !bytes.Equal(old.Digest, e.Digest) {
					return Entry{}, false, ErrConflict
				}
				return clone(old), false, nil
			}
		}
	}
	if e.Kind == "SUBMIT" && j.legacyPlans[Key("", e.Robot, "PLAN", e.Plan)] {
		return Entry{}, false, errors.New("LEGACY_PLAN_RECONCILIATION_REQUIRED")
	}
	if len(j.entries) >= j.maxEntries || j.bytes+2*MaxCanonicalBytes+4096 > j.maxBytes {
		return Entry{}, false, ErrCapacity
	}
	if e.ID == "" || e.Robot == "" || len(e.Digest) != 32 {
		return Entry{}, false, errors.New("invalid operation identity")
	}
	e.Version = 1
	e.Phase = "IN_PROGRESS"
	e.Recovered = false
	if err := j.append(e); err != nil {
		return Entry{}, false, err
	}
	j.put(clone(e))
	return e, true, nil
}
func (j *Journal) Finish(e Entry, phase string, response []byte) (Entry, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	old, ok := j.entries[e.Key]
	if !ok || old.Phase != "IN_PROGRESS" || !bytes.Equal(old.Digest, e.Digest) {
		return Entry{}, ErrConflict
	}
	old.Chain = e.Chain
	e = old
	if len(response) > MaxCanonicalBytes {
		return Entry{}, errors.New("receipt too large")
	}
	e.Phase = phase
	e.Response = append([]byte(nil), response...)
	if phase != "COMMITTED" && phase != "REJECTED" && phase != "OUTCOME_UNKNOWN" {
		return Entry{}, errors.New("invalid terminal phase")
	}
	if err := j.append(e); err != nil {
		old.Phase = "OUTCOME_UNKNOWN"
		j.put(old)
		return Entry{}, err
	}
	j.put(clone(e))
	return e, nil
}
func (j *Journal) Lookup(scope, plan, kind, id string) (Entry, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, e := range j.entries {
		if e.Scope == scope && e.Plan == plan && e.Kind == kind && (id == "" || e.ID == id) {
			return clone(e), true
		}
	}
	return Entry{}, false
}
func isBlocking(e Entry) bool {
	return e.ResolvedBy == "" && (e.Kind == "SUBMIT" || e.Critical) && (e.Phase == "IN_PROGRESS" || e.Phase == "OUTCOME_UNKNOWN")
}

// Called under the journal mutex (or during single-threaded startup).
// Token reads never walk the growing receipt history.
func (j *Journal) put(e Entry) {
	if j.blocked == nil {
		j.blocked = map[string]int{}
	}
	if old, ok := j.entries[e.Key]; ok && isBlocking(old) {
		j.blocked[old.Robot]--
	}
	j.entries[e.Key] = e
	if isBlocking(e) {
		j.blocked[e.Robot]++
	}
}
func (j *Journal) Blocked(robot string) bool { return j.BlockedExcept(robot, "") }
func (j *Journal) BlockedExcept(robot, except string) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	n := j.blocked[robot]
	if e, ok := j.entries[except]; ok && e.Robot == robot && isBlocking(e) {
		n--
	}
	return n > 0
}
func (e Entry) Reference() string { return fmt.Sprintf("core-comm:v1:%s", e.Key) }

// ResolveWithdrawn clears only the *admission hold* of an uncertain submission.
// It never labels the original request a success or permits its replay. The
// proof is a durable, authorized cancellation receipt of the same robot/plan.
func (j *Journal) ResolveWithdrawn(cancel Entry) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	proof, ok := j.entries[cancel.Key]
	if !ok || proof.Kind != "CANCEL" || proof.Phase != "COMMITTED" {
		return errors.New("durable cancellation proof required")
	}
	var result pb.CancelPlanResponse
	if proto.Unmarshal(proof.Response, &result) != nil || !result.Cancelled {
		return errors.New("cancellation effect not confirmed")
	}
	for _, e := range j.entries {
		if (e.Kind != "SUBMIT" && !(e.Kind == "REPORT" && e.Critical && e.Chain == proof.Chain)) || e.Robot != proof.Robot || e.Plan != proof.Plan || e.ResolvedBy != "" || (e.Phase != "IN_PROGRESS" && e.Phase != "OUTCOME_UNKNOWN") {
			continue
		}
		e.Phase = "OUTCOME_UNKNOWN"
		e.ResolvedBy = proof.Key
		if err := j.append(e); err != nil {
			return err
		}
		j.put(e)
	}
	return nil
}

func (j *Journal) UncertainPlan(plan string) (Entry, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, e := range j.entries {
		if e.Plan == plan && (e.Phase == "IN_PROGRESS" || e.Phase == "OUTCOME_UNKNOWN") {
			return clone(e), true
		}
	}
	return Entry{}, false
}
