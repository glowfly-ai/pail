// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package robotops

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	jcs "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"regexp"
	"sort"
)

// Management documents (plans, prepared bundles, approvals, adoption records
// and the trust store) share one RFC 8785 JCS codec with purpose-separated
// prefixes. These domains are distinct from InspectionDigest domains and from
// every existing token, unlock or ledger canon. A digest alone is never an
// authorization: VerifyApproval also requires a trusted key, role, scope,
// validity window, current trust epoch and exact binding.
const (
	DomainPlan     = "plan"
	DomainPrepare  = "prepare"
	DomainApproval = "approval"
	DomainAdoption = "adoption"
	DomainTrust    = "trust"
	// DomainQuiescence binds the executor's WAIT_QUIESCENCE evidence document.
	DomainQuiescence = "quiescence"
	// DomainRecovery binds a RecoveryPlan (§3.1/§14.4).
	DomainRecovery = "recovery"

	// ApprovalMaxValidityMS is the design maximum (60 minutes). A profile may be
	// shorter; verification never extends an expired approval.
	ApprovalMaxValidityMS = int64(60 * 60 * 1000)
)

var (
	managementDomains = map[string]bool{DomainPlan: true, DomainPrepare: true, DomainApproval: true, DomainAdoption: true, DomainTrust: true, DomainQuiescence: true, DomainRecovery: true, DomainPolicy: true}
	keyName           = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	principalName     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$`)
	hexDigest         = regexp.MustCompile(`^[0-9a-f]{64}$`)
	uuidName          = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	b64url            = base64.RawURLEncoding.Strict()
)

// Roles a management key may hold. Adoption of an externally owned installation
// baseline is bound to approve_apply because it changes what later plans may
// rewrite; no separate weaker role exists for it.
var roleForAction = map[string]string{
	"prepare": "prepare",
	"adopt":   "approve_apply",
	"apply":   "approve_apply",
	"resume":  "resume",
	"recover": "recover",
	// AS-4: a policy change is its own privileged act; the role is never
	// implied by approve_apply.
	"policy_change": "policy_change",
	// M8: a robot-side observation document (quiescence / verification) is
	// attested by an observer key; the attestation is an Approval whose action
	// is observe, bound to the execution id and the document digest. Observe
	// grants no approval, hold, resume or recovery authority.
	"observe": "observe",
}
var knownRoles = map[string]bool{"prepare": true, "approve_apply": true, "resume": true, "recover": true, "observe": true, "policy_change": true}

// ManagementCanonical returns prefix + JCS bytes of value after removing the
// listed top-level keys. The trailing newline of the prefix is part of the
// signed/hashed input. No unknown or debug fields are ever dropped implicitly.
func ManagementCanonical(kind string, value interface{}, exclude ...string) ([]byte, error) {
	if !managementDomains[kind] {
		return nil, fmt.Errorf("RO_SCHEMA: unsupported management domain")
	}
	b, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("RO_SCHEMA: encoding failed")
	}
	var m map[string]interface{}
	if err := StrictDecode(b, &m, nil); err != nil {
		return nil, err
	}
	for _, k := range exclude {
		delete(m, k)
	}
	b, err = json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("RO_SCHEMA: encoding failed")
	}
	canonical, err := jcs.Transform(b)
	if err != nil {
		return nil, fmt.Errorf("RO_SCHEMA: canonical encoding refused")
	}
	return append([]byte("pail.robotops."+kind+"/v1\n"), canonical...), nil
}

// ManagementDigest hashes the document without its top-level digest field.
func ManagementDigest(kind string, value interface{}) (string, error) {
	c, err := ManagementCanonical(kind, value, "digest")
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c)
	return hex.EncodeToString(sum[:]), nil
}

// TrustStore is the administrator-provisioned ops_trust.json. It holds public
// keys only. Retention of the highest received trust_epoch is the caller's
// durable-store responsibility; this decoder validates one document.
type TrustStore struct {
	SchemaVersion       int        `json:"schema_version"`
	TrustEpoch          uint64     `json:"trust_epoch"`
	DeploymentID        string     `json:"deployment_id"`
	Keys                []TrustKey `json:"keys"`
	TrustedExecutorUIDs []uint32   `json:"trusted_executor_uids"`
}
type TrustKey struct {
	KeyID           string   `json:"key_id"`
	PublicKey       string   `json:"public_key"`
	PrincipalID     string   `json:"principal_id"`
	Roles           []string `json:"roles"`
	DeploymentScope string   `json:"deployment_scope"`
	TargetScope     []string `json:"target_scope"`
	NotBeforeMS     int64    `json:"not_before_ms"`
	NotAfterMS      int64    `json:"not_after_ms"`
	Revoked         bool     `json:"revoked"`
}

func DecodeTrustStore(raw []byte) (TrustStore, error) {
	var s TrustStore
	if err := StrictDecode(raw, &s, []string{"schema_version", "trust_epoch", "deployment_id", "keys", "trusted_executor_uids"}); err != nil {
		return s, err
	}
	return s, s.Validate()
}
func (s TrustStore) Validate() error {
	if s.SchemaVersion != 1 || !deploymentName.MatchString(s.DeploymentID) || s.TrustEpoch == 0 || s.TrustEpoch > uint64(MaxSafeInteger) {
		return fmt.Errorf("RO_TRUST: unsupported schema, deployment or epoch")
	}
	if len(s.Keys) == 0 || len(s.Keys) > 256 || len(s.TrustedExecutorUIDs) > 64 {
		return fmt.Errorf("RO_TRUST: keys must contain 1..256 entries")
	}
	ids, pubs := map[string]bool{}, map[string]bool{}
	for i, k := range s.Keys {
		if !keyName.MatchString(k.KeyID) || ids[k.KeyID] {
			return fmt.Errorf("RO_TRUST: invalid or repeated key id at row %d", i)
		}
		ids[k.KeyID] = true
		pk, err := b64url.DecodeString(k.PublicKey)
		if err != nil || len(pk) != ed25519.PublicKeySize || pubs[k.PublicKey] {
			return fmt.Errorf("RO_TRUST: public key must be a unique 32-byte base64url value at row %d", i)
		}
		pubs[k.PublicKey] = true
		if !principalName.MatchString(k.PrincipalID) || k.DeploymentScope != s.DeploymentID {
			return fmt.Errorf("RO_TRUST: invalid principal or deployment scope at row %d", i)
		}
		if len(k.Roles) == 0 || len(k.Roles) > len(knownRoles) {
			return fmt.Errorf("RO_TRUST: roles required at row %d", i)
		}
		seen := map[string]bool{}
		for _, r := range k.Roles {
			if !knownRoles[r] || seen[r] {
				return fmt.Errorf("RO_TRUST: unknown or repeated role at row %d", i)
			}
			seen[r] = true
		}
		if len(k.TargetScope) == 0 || len(k.TargetScope) > 10000 {
			return fmt.Errorf("RO_TRUST: target scope required at row %d", i)
		}
		for _, t := range k.TargetScope {
			if t != "*" && !refName.MatchString(t) {
				return fmt.Errorf("RO_TRUST: invalid target scope at row %d", i)
			}
		}
		if k.NotBeforeMS < 0 || k.NotAfterMS <= k.NotBeforeMS || k.NotAfterMS > MaxSafeInteger {
			return fmt.Errorf("RO_TRUST: invalid validity window at row %d", i)
		}
	}
	return nil
}
func (s TrustStore) key(id string) (TrustKey, bool) {
	for _, k := range s.Keys {
		if k.KeyID == id {
			return k, true
		}
	}
	return TrustKey{}, false
}

// Approval is one signed management decision bound to exactly one document
// digest, action and execution/prepare id.
type Approval struct {
	SchemaVersion        int    `json:"schema_version"`
	DocumentKind         string `json:"document_kind"`
	DeploymentID         string `json:"deployment_id"`
	DocumentID           string `json:"document_id"`
	CreatedAtMS          int64  `json:"created_at_ms"`
	ToolBuild            string `json:"tool_build"`
	ApprovalID           string `json:"approval_id"`
	Action               string `json:"action"`
	ExecutionOrPrepareID string `json:"execution_or_prepare_id"`
	PlanDigest           string `json:"plan_digest"`
	PrincipalID          string `json:"principal_id"`
	KeyID                string `json:"key_id"`
	TrustEpoch           uint64 `json:"trust_epoch"`
	IssuedAtMS           int64  `json:"issued_at_ms"`
	ExpiresAtMS          int64  `json:"expires_at_ms"`
	Nonce                string `json:"nonce"`
	Signature            string `json:"signature"`
}

var approvalFields = []string{"schema_version", "document_kind", "deployment_id", "document_id", "created_at_ms", "tool_build", "approval_id", "action", "execution_or_prepare_id", "plan_digest", "principal_id", "key_id", "trust_epoch", "issued_at_ms", "expires_at_ms", "nonce", "signature"}

func DecodeApproval(raw []byte) (Approval, error) {
	var a Approval
	if err := StrictDecode(raw, &a, approvalFields); err != nil {
		return a, err
	}
	return a, a.ValidateShape()
}

// ValidateShape checks encoding and format only. It does not consult trust.
func (a Approval) ValidateShape() error {
	if a.SchemaVersion != 1 || a.DocumentKind != "Approval" || !deploymentName.MatchString(a.DeploymentID) || !uuidName.MatchString(a.DocumentID) || !uuidName.MatchString(a.ApprovalID) || a.ApprovalID == a.DocumentID {
		return fmt.Errorf("RO_APPROVAL: unsupported schema or identifiers")
	}
	if a.ToolBuild == "" || len(a.ToolBuild) > 128 || a.CreatedAtMS <= 0 || a.CreatedAtMS > MaxSafeInteger {
		return fmt.Errorf("RO_APPROVAL: invalid tool build or creation time")
	}
	if _, ok := roleForAction[a.Action]; !ok {
		return fmt.Errorf("RO_APPROVAL: unknown action")
	}
	if !uuidName.MatchString(a.ExecutionOrPrepareID) || !hexDigest.MatchString(a.PlanDigest) || !principalName.MatchString(a.PrincipalID) || !keyName.MatchString(a.KeyID) {
		return fmt.Errorf("RO_APPROVAL: invalid binding fields")
	}
	if a.TrustEpoch == 0 || a.TrustEpoch > uint64(MaxSafeInteger) || a.IssuedAtMS <= 0 || a.ExpiresAtMS <= a.IssuedAtMS || a.ExpiresAtMS-a.IssuedAtMS > ApprovalMaxValidityMS || a.ExpiresAtMS > MaxSafeInteger {
		return fmt.Errorf("RO_APPROVAL: invalid epoch or validity window")
	}
	n, err := b64url.DecodeString(a.Nonce)
	if err != nil || len(n) < 16 || len(n) > 32 {
		return fmt.Errorf("RO_APPROVAL: nonce must be 16..32 bytes base64url without padding")
	}
	s, err := b64url.DecodeString(a.Signature)
	if err != nil || len(s) != ed25519.SignatureSize {
		return fmt.Errorf("RO_APPROVAL: signature must be 64 bytes base64url without padding")
	}
	return nil
}

// SigningInput is the approval prefix plus canonical bytes without signature.
func (a Approval) SigningInput() ([]byte, error) {
	return ManagementCanonical(DomainApproval, a, "signature")
}

// SignApproval fills Signature using an Ed25519 seed held by the caller's key
// provider. The seed is never part of any document. Development file
// providers are a private-tool policy, not part of this package.
func SignApproval(seed []byte, a Approval) (Approval, error) {
	if len(seed) != ed25519.SeedSize {
		return a, fmt.Errorf("RO_APPROVAL: seed must be 32 bytes")
	}
	a.Signature = b64url.EncodeToString(make([]byte, ed25519.SignatureSize))
	if err := a.ValidateShape(); err != nil {
		return a, err
	}
	in, err := a.SigningInput()
	if err != nil {
		return a, err
	}
	a.Signature = b64url.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(seed), in))
	return a, nil
}

// PublicKeyForSeed returns the base64url public key for a seed so a
// development trust store can be assembled without exposing the seed.
func PublicKeyForSeed(seed []byte) (string, error) {
	if len(seed) != ed25519.SeedSize {
		return "", fmt.Errorf("RO_APPROVAL: seed must be 32 bytes")
	}
	return b64url.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)), nil
}

// ApprovalBinding is what the caller expects the approval to authorize.
type ApprovalBinding struct {
	Action       string
	DeploymentID string
	TargetID     string   // execution_id or prepare_id of the bound document
	PlanDigest   string   // management digest of the bound document
	Resources    []string // resource/component ids the key's target_scope must cover
}

// VerifyApproval performs §7.2 steps 1-3: trusted key, role, scope, signature,
// exact binding, format, validity window and current trust epoch. It does NOT
// record consumption or enforce approval_id uniqueness; a durable store must
// do that before the first effect. Any error means the approval is not valid
// for this binding.
func VerifyApproval(store TrustStore, a Approval, want ApprovalBinding, nowMS int64) (TrustKey, error) {
	if err := a.ValidateShape(); err != nil {
		return TrustKey{}, err
	}
	if err := store.Validate(); err != nil {
		return TrustKey{}, err
	}
	if a.DeploymentID != store.DeploymentID || a.DeploymentID != want.DeploymentID {
		return TrustKey{}, fmt.Errorf("RO_APPROVAL: deployment mismatch")
	}
	k, ok := store.key(a.KeyID)
	if !ok || k.Revoked {
		return TrustKey{}, fmt.Errorf("RO_APPROVAL: key unknown or revoked")
	}
	if k.PrincipalID != a.PrincipalID {
		return TrustKey{}, fmt.Errorf("RO_APPROVAL: principal does not match key")
	}
	role := roleForAction[a.Action]
	if a.Action != want.Action || !contains(k.Roles, role) {
		return TrustKey{}, fmt.Errorf("RO_APPROVAL: action not permitted for key role")
	}
	if !coversScope(k.TargetScope, want.Resources) {
		return TrustKey{}, fmt.Errorf("RO_APPROVAL: target outside key scope")
	}
	if nowMS < k.NotBeforeMS || nowMS >= k.NotAfterMS {
		return TrustKey{}, fmt.Errorf("RO_APPROVAL: key outside validity window")
	}
	if a.TrustEpoch != store.TrustEpoch {
		return TrustKey{}, fmt.Errorf("RO_APPROVAL: trust epoch is not current")
	}
	if nowMS < a.IssuedAtMS || nowMS >= a.ExpiresAtMS {
		return TrustKey{}, fmt.Errorf("RO_APPROVAL: approval outside validity window")
	}
	if a.ExecutionOrPrepareID != want.TargetID || a.PlanDigest != want.PlanDigest || !hexDigest.MatchString(want.PlanDigest) || !uuidName.MatchString(want.TargetID) {
		return TrustKey{}, fmt.Errorf("RO_APPROVAL: binding mismatch")
	}
	pk, _ := b64url.DecodeString(k.PublicKey)
	sig, _ := b64url.DecodeString(a.Signature)
	in, err := a.SigningInput()
	if err != nil {
		return TrustKey{}, err
	}
	if !ed25519.Verify(ed25519.PublicKey(pk), in, sig) {
		return TrustKey{}, fmt.Errorf("RO_APPROVAL: signature invalid")
	}
	return k, nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
func coversScope(scope, resources []string) bool {
	if contains(scope, "*") {
		return true
	}
	if len(resources) == 0 {
		return false
	}
	sorted := append([]string(nil), resources...)
	sort.Strings(sorted)
	for _, r := range sorted {
		if !contains(scope, r) {
			return false
		}
	}
	return true
}

// DigestDocument strictly decodes one management document and returns its
// digest in the given domain (top-level "digest" excluded) together with the
// decoded object. Callers that must bind RPC arguments to a signed plan read
// fields from the returned object, never from separate request arguments.
func DigestDocument(kind string, raw []byte) (string, map[string]interface{}, error) {
	var m map[string]interface{}
	if err := StrictDecode(raw, &m, []string{"schema_version", "document_kind", "deployment_id", "document_id", "digest"}); err != nil {
		return "", nil, err
	}
	d, err := ManagementDigest(kind, m)
	if err != nil {
		return "", nil, err
	}
	return d, m, nil
}

// StringField / StringList read typed fields from a decoded document.
func StringField(m map[string]interface{}, key string) string {
	s, _ := m[key].(string)
	return s
}
func StringList(m map[string]interface{}, key string) []string {
	out := []string{}
	list, _ := m[key].([]interface{})
	for _, v := range list {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
