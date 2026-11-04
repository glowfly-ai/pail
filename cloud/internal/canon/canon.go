// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// Package canon is the single source of the canon domain prefixes used by the
// robot-side Go services (implementation contract 상수 일원화, rule F7).
//
// Every byte string that is signed or circulated as a hash input starts with
// "pail-<domain>:v<N>:" (rule F1). Those prefixes are frozen format, so they
// must have exactly one definition per service.
//
// This package is deliberately NOT shared with the Anchor SaaS module, which
// keeps its own copy: the anchor canon is a wire contract across a closed
// IP boundary, and the two implementations verify each other. Sharing the
// constant would turn a cross-check into a tautology. The golden vectors
// (§4.3) are what keeps the two copies honest.
//
// Callers must not spell the literal themselves — CI check 1 (§6.2) greps for
// `pail-[a-z0-9-]+:v[0-9]` and compares the set against the F1 registry.
package canon

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/text/unicode/norm"
)

const (
	// AnchorV1 prefixes the anchor record canon uploaded to the anchor service.
	// Must stay byte-identical to the SaaS-side model.AnchorCanon.
	AnchorV1 = "pail-anchor:v1:"

	// UnlockV1 prefixes the operator Unlock canon (M9 SAFE_STOP -> NORMAL).
	// Generation ended at OB1; parsing stays forever (F8, implementation contract).
	UnlockV1 = "pail-unlock:v1:"

	// UnlockV2 is the same command with the signer's own key id inside the
	// signed bytes . Under v1 the operator_key_id travelled
	// beside the signature rather than under it, so a v1 record can never say
	// who signed it — the archive keeps the envelope's claim, not the signer's.
	UnlockV2 = "pail-unlock:v2:"

	// RevokeIssuerV1 prefixes the operator RevokeIssuerKey canon (-> LOCKDOWN).
	// Generation ended at OB1; parsing stays forever (F8).
	RevokeIssuerV1 = "pail-revoke-issuer:v1:"

	// RevokeIssuerV2 carries the same addition as UnlockV2. The two editions
	// move together on purpose : they are the same defect in
	// two places, and raising one alone leaves the other silently unraised.
	RevokeIssuerV2 = "pail-revoke-issuer:v2:"

	// ContextV1 prefixes the type-51 context provenance payload (A §3.6, FB-1).
	ContextV1 = "pail-context:v1:"

	// CtxBodyV1 prefixes the hash input for the context event body itself
	// (A §3.6, FB-2). Without it the payload carries a hash nobody else can
	// recompute, which is a claim rather than evidence.
	CtxBodyV1 = "pail-ctxbody:v1:"

	// TokenKeyV1 prefixes the consumption key: the single-use identity of a
	// token derived from the verified bytes only (A §3.5, X12②).
	TokenKeyV1 = "pail-tokenkey:v1:"

	// PlanHashV1 prefixes the retry-floor plan identity hash. Unlike the others
	// this value is never signed nor circulated (NF5): it is an internal
	// identity key, and its separator after the version is "\n", not ":".
	// It is listed here so that the literal has one home, not because it is
	// part of the interoperability profile PAIL-CORE-2026.1.
	PlanHashV1 = "pail-planhash:v1\n"

	// PlanHashV2 (AL-2, implementation contract D1) extends the plan identity with the
	// length-prefixed pass-through fields (context_json, constraints_json,
	// per-step action spec + params_json). Same internal-only status as v1
	// (NF5): never signed, never circulated. v1 is kept as a constant for the
	// registry's sake; nothing generates it any more.
	PlanHashV2 = "pail-planhash:v2\n"

	// CtxV1 / ConstraintsV1 / ParamsV1 (AL-2/AL-3, implementation contract D5) prefix the
	// sha256 inputs of the three pass-through byte fields. The hashes ride the
	// chain (CONTEXT_SEALED / PLAN_ACCEPTED v2 / TOKEN_ISSUED v2); the prefixes
	// separate the three domains so a context body can never be replayed as a
	// constraints body under the same digest. Like the other hash-input
	// prefixes they do not appear in canon values, so they are registered in
	// UNPINNED.tsv rather than pinned by a vector.
	CtxV1         = "pail-ctx:v1:"
	ConstraintsV1 = "pail-constraints:v1:"
	ParamsV1      = "pail-params:v1:"
)

// Rule R-A (§3, F3): identifier fields are concatenated into a canon without
// escaping, so a ':' inside one of them silently moves a field boundary and two
// different scopes sign the same bytes (X23). The defense belongs at the
// assembly point, not at the network boundary — a boundary check protects only
// the paths that happen to run through it.
//
// R-A rejects; callers fail closed rather than substituting a placeholder. An
// empty identifier is rejected for the same reason: it collapses two adjacent
// separators. This is an intentional independent copy of the Anchor SaaS rule
// (§6.1 item 2) — the golden vectors keep the two honest.
var (
	ErrIdentifierSeparator = errors.New("separator ':' in identifier")
	ErrIdentifierEmpty     = errors.New("empty identifier")
)

// RA validates one identifier field destined for a canon string.
func RA(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s: %w", field, ErrIdentifierEmpty)
	}
	if strings.Contains(value, ":") {
		return fmt.Errorf("%s: %w", field, ErrIdentifierSeparator)
	}
	return nil
}

// Rule R-B (§3): free text is length-prefixed instead of escaped, so a ':' in
// the value cannot move a field boundary. u32BE length over NFC bytes.
func writeLP(b *bytes.Buffer, s string) {
	nb := norm.NFC.Bytes([]byte(s))
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(nb)))
	b.Write(l[:])
	b.Write(nb)
}

// CallerKinds is the frozen vocabulary of caller_kind (FB-1, rule F6). A value
// outside the set is rejected rather than passed through: "unknown" already
// means "we could not tell", so an unrecognised kind is a producer defect and
// must not be minted into the journal as if it were a fourth answer.
var CallerKinds = [...]string{"mtls", "uds", "unknown"}

// ErrCallerKind reports a caller_kind outside the frozen set.
var ErrCallerKind = errors.New("caller_kind not in {mtls,uds,unknown}")

// ContextBodyHashHex returns event_body_hash_hex for a context event (A §3.6).
// The claimed timestamp is the one the caller asserted, not our clock — the
// record must hash what was said, not what we would have said.
func ContextBodyHashHex(nodeID, kindName, arg string, claimedUnixMs uint64) string {
	var b bytes.Buffer
	b.WriteString(CtxBodyV1)
	writeLP(&b, nodeID)
	writeLP(&b, kindName)
	writeLP(&b, arg)
	var t [8]byte
	binary.BigEndian.PutUint64(t[:], claimedUnixMs)
	b.Write(t[:])
	sum := sha256.Sum256(b.Bytes())
	return hex.EncodeToString(sum[:])
}

// ContextProvenancePayload assembles the type-51 record payload (A §3.6).
// callerID may be empty: an unknown caller has no identity, and the empty LP is
// what distinguishes "we could not tell" from "there was nothing to tell".
func ContextProvenancePayload(eventKind, callerKind, callerID string,
	contextVerified bool, eventBodyHashHex string) ([]byte, error) {
	ok := false
	for _, k := range CallerKinds {
		if callerKind == k {
			ok = true
			break
		}
	}
	if !ok {
		return nil, fmt.Errorf("%q: %w", callerKind, ErrCallerKind)
	}
	var b bytes.Buffer
	b.WriteString(ContextV1)
	writeLP(&b, eventKind)
	writeLP(&b, callerKind)
	writeLP(&b, callerID)
	if contextVerified {
		b.WriteByte(1)
	} else {
		b.WriteByte(0)
	}
	writeLP(&b, eventBodyHashHex)
	return b.Bytes(), nil
}

// ConsumptionKeyHex derives the single-use identity of a token from the
// verified bytes (A §3.5). The input is the signed action_token_bytes as they
// arrived — re-serialising them would key the cache on our own re-encoding
// rather than on what was actually signed.
func ConsumptionKeyHex(actionTokenBytes []byte) string {
	h := sha256.New()
	h.Write([]byte(TokenKeyV1))
	h.Write(actionTokenBytes)
	return hex.EncodeToString(h.Sum(nil))
}
