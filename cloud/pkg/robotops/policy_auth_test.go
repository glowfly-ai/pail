// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package robotops

import (
	"encoding/json"
	"strings"
	"testing"
)

func mustJSON(v interface{}) string { b, _ := json.Marshal(v); return string(b) }

func policyTrust(t *testing.T) (TrustStore, map[string][]byte) {
	t.Helper()
	seeds := map[string][]byte{"pol-1": seedOf("pol-1"), "pol-2": seedOf("pol-2"), "pol-1b": seedOf("pol-1b"), "app-1": seedOf("app-1")}
	pk := func(k string) string { p, _ := PublicKeyForSeed(seeds[k]); return p }
	return TrustStore{SchemaVersion: 1, TrustEpoch: 3, DeploymentID: testDeployment, TrustedExecutorUIDs: []uint32{}, Keys: []TrustKey{
		{KeyID: "pol-1", PublicKey: pk("pol-1"), PrincipalID: "ops.alice", Roles: []string{"policy_change"}, DeploymentScope: testDeployment, TargetScope: []string{"*"}, NotBeforeMS: 1000, NotAfterMS: 9_000_000_000_000},
		{KeyID: "pol-2", PublicKey: pk("pol-2"), PrincipalID: "ops.bob", Roles: []string{"policy_change"}, DeploymentScope: testDeployment, TargetScope: []string{"res:policy"}, NotBeforeMS: 1000, NotAfterMS: 9_000_000_000_000},
		// a second key of alice: distinct key, same principal
		{KeyID: "pol-1b", PublicKey: pk("pol-1b"), PrincipalID: "ops.alice", Roles: []string{"policy_change"}, DeploymentScope: testDeployment, TargetScope: []string{"*"}, NotBeforeMS: 1000, NotAfterMS: 9_000_000_000_000},
		{KeyID: "app-1", PublicKey: pk("app-1"), PrincipalID: "ops.admin", Roles: []string{"approve_apply"}, DeploymentScope: testDeployment, TargetScope: []string{"*"}, NotBeforeMS: 1000, NotAfterMS: 9_000_000_000_000},
	}}, seeds
}

func policyChangeFixture(t *testing.T, policy []byte) PolicyChange {
	t.Helper()
	c := PolicyChange{SchemaVersion: 1, DocumentKind: "PolicyChange", DocumentID: "0b6e5c58-6d9c-4d0d-9f57-6d1c5d7f0a22", DeploymentID: testDeployment, CreatedAtMS: 1_700_000_000_000, ToolBuild: "test", Subject: SubjectPolicy, ContentSHA256: PolicyBytesSHA256(policy), PreviousContentSHA256: strings.Repeat("00", 32), Note: "raise speed cap"}
	d, err := PolicyChangeDigest(c)
	if err != nil {
		t.Fatal(err)
	}
	c.Digest = d
	return c
}

func policyApproval(t *testing.T, seeds map[string][]byte, keyID, principal, action string, c PolicyChange, approvalID string) Approval {
	t.Helper()
	a := Approval{SchemaVersion: 1, DocumentKind: "Approval", DeploymentID: testDeployment, DocumentID: "0b6e5c58-6d9c-4d0d-9f57-6d1c5d7f0a11", CreatedAtMS: 1_700_000_000_000, ToolBuild: "test", ApprovalID: approvalID, Action: action, ExecutionOrPrepareID: c.DocumentID, PlanDigest: c.Digest, PrincipalID: principal, KeyID: keyID, TrustEpoch: 3, IssuedAtMS: 1_700_000_000_000, ExpiresAtMS: 1_700_000_000_000 + 15*60*1000, Nonce: "AAECAwQFBgcICQoLDA0ODw"}
	signed, err := SignApproval(seeds[keyID], a)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestPolicyAuthorizationTwoPersonRule(t *testing.T) {
	store, seeds := policyTrust(t)
	policy := []byte("version: 1\nmax_linear_speed_mps: 0.5\n")
	c := policyChangeFixture(t, policy)
	now := int64(1_700_000_000_000 + 60_000)
	alice := policyApproval(t, seeds, "pol-1", "ops.alice", "policy_change", c, "6f3b2a10-1b2c-4d3e-8f90-123456789a01")
	bob := policyApproval(t, seeds, "pol-2", "ops.bob", "policy_change", c, "6f3b2a10-1b2c-4d3e-8f90-123456789a02")
	aliceAgain := policyApproval(t, seeds, "pol-1b", "ops.alice", "policy_change", c, "6f3b2a10-1b2c-4d3e-8f90-123456789a03")

	good := PolicyAuthorization{SchemaVersion: 1, DocumentKind: "PolicyAuthorization", Change: c, Approvals: []Approval{alice, bob}}
	keys, err := VerifyPolicyAuthorization(store, good, policy, SubjectPolicy, 2, now)
	if err != nil || len(keys) != 2 {
		t.Fatal(keys, err)
	}
	// One approval is not two persons; the same principal twice is not either.
	if _, err = VerifyPolicyAuthorization(store, PolicyAuthorization{SchemaVersion: 1, DocumentKind: "PolicyAuthorization", Change: c, Approvals: []Approval{alice}}, policy, SubjectPolicy, 2, now); err == nil || !strings.Contains(err.Error(), "1 distinct") {
		t.Fatal("single approval accepted", err)
	}
	if _, err = VerifyPolicyAuthorization(store, PolicyAuthorization{SchemaVersion: 1, DocumentKind: "PolicyAuthorization", Change: c, Approvals: []Approval{alice, alice}}, policy, SubjectPolicy, 2, now); err == nil || !strings.Contains(err.Error(), "repeats") {
		t.Fatal("same approval twice accepted", err)
	}
	if _, err = VerifyPolicyAuthorization(store, PolicyAuthorization{SchemaVersion: 1, DocumentKind: "PolicyAuthorization", Change: c, Approvals: []Approval{alice, aliceAgain}}, policy, SubjectPolicy, 2, now); err == nil || !strings.Contains(err.Error(), "repeats") {
		t.Fatal("two keys of one principal accepted", err)
	}
	// Single-operator declaration: min 1 accepts one approval.
	if _, err = VerifyPolicyAuthorization(store, PolicyAuthorization{SchemaVersion: 1, DocumentKind: "PolicyAuthorization", Change: c, Approvals: []Approval{bob}}, policy, SubjectPolicy, 1, now); err != nil {
		t.Fatal("min 1 refused a valid single approval", err)
	}
	// The bytes must be the authorized bytes.
	if _, err = VerifyPolicyAuthorization(store, good, append(policy, '\n'), SubjectPolicy, 2, now); err == nil || !strings.Contains(err.Error(), "bytes differ") {
		t.Fatal("tampered policy accepted", err)
	}
	// approve_apply is not policy_change; an apply-action approval is refused.
	apply := policyApproval(t, seeds, "app-1", "ops.admin", "apply", c, "6f3b2a10-1b2c-4d3e-8f90-123456789a04")
	if _, err = VerifyPolicyAuthorization(store, PolicyAuthorization{SchemaVersion: 1, DocumentKind: "PolicyAuthorization", Change: c, Approvals: []Approval{alice, apply}}, policy, SubjectPolicy, 2, now); err == nil {
		t.Fatal("apply-role approval counted for a policy change")
	}
	// Tampered change body → digest mismatch; expired approval → refused.
	bent := good
	bent.Change.Note = "different"
	if _, err = VerifyPolicyAuthorization(store, bent, policy, SubjectPolicy, 2, now); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatal("tampered change accepted", err)
	}
	if _, err = VerifyPolicyAuthorization(store, good, policy, SubjectPolicy, 2, now+16*60*1000); err == nil {
		t.Fatal("expired approvals accepted")
	}
	if _, err = VerifyPolicyAuthorization(store, good, policy, SubjectPolicy, 0, now); err == nil {
		t.Fatal("min 0 accepted")
	}
}

func TestPolicyAuthorizationDecodeShape(t *testing.T) {
	store, seeds := policyTrust(t)
	policy := []byte("version: 1\n")
	c := policyChangeFixture(t, policy)
	a := policyApproval(t, seeds, "pol-1", "ops.alice", "policy_change", c, "6f3b2a10-1b2c-4d3e-8f90-123456789a05")
	raw := []byte(`{"schema_version":1,"document_kind":"PolicyAuthorization","change":` + mustJSON(c) + `,"approvals":[` + mustJSON(a) + `]}`)
	if _, err := DecodePolicyAuthorization(raw); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]string{
		"extra field":  `{"schema_version":1,"document_kind":"PolicyAuthorization","change":` + mustJSON(c) + `,"approvals":[` + mustJSON(a) + `],"x":1}`,
		"no approvals": `{"schema_version":1,"document_kind":"PolicyAuthorization","change":` + mustJSON(c) + `,"approvals":[]}`,
		"wrong kind":   `{"schema_version":1,"document_kind":"Approval","change":` + mustJSON(c) + `,"approvals":[` + mustJSON(a) + `]}`,
	} {
		if _, err := DecodePolicyAuthorization([]byte(bad)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	same := c
	same.PreviousContentSHA256 = same.ContentSHA256
	same.Digest, _ = PolicyChangeDigest(same)
	if err := same.validate(); err == nil {
		t.Fatal("identical previous/new accepted")
	}
	_ = store
}

// A site model change is the same discipline under its own subject: the
// bundle must name the subject the issuer is loading, and the approving key's
// target_scope must cover res:site_model (bob, scoped to res:policy only,
// cannot approve it).
func TestPolicyAuthorizationSubjectBinding(t *testing.T) {
	store, seeds := policyTrust(t)
	model := []byte("schema: site_model/v1\nsite: demo\n")
	c := policyChangeFixture(t, model)
	c.Subject = SubjectSiteModel
	c.Digest, _ = PolicyChangeDigest(c)
	now := int64(1_700_000_000_000 + 60_000)
	alice := policyApproval(t, seeds, "pol-1", "ops.alice", "policy_change", c, "6f3b2a10-1b2c-4d3e-8f90-123456789b01")
	bob := policyApproval(t, seeds, "pol-2", "ops.bob", "policy_change", c, "6f3b2a10-1b2c-4d3e-8f90-123456789b02")
	aliceAgain := policyApproval(t, seeds, "pol-1b", "ops.alice", "policy_change", c, "6f3b2a10-1b2c-4d3e-8f90-123456789b03")
	bundle := func(ap ...Approval) PolicyAuthorization {
		return PolicyAuthorization{SchemaVersion: 1, DocumentKind: "PolicyAuthorization", Change: c, Approvals: ap}
	}
	if _, err := VerifyPolicyAuthorization(store, bundle(alice, bob), model, SubjectSiteModel, 2, now); err == nil || !strings.Contains(err.Error(), "outside key scope") {
		t.Fatal("res:policy-scoped key approved a site model change", err)
	}
	// alice's two keys are distinct keys but one principal; still not two persons.
	if _, err := VerifyPolicyAuthorization(store, bundle(alice, aliceAgain), model, SubjectSiteModel, 2, now); err == nil || !strings.Contains(err.Error(), "repeats") {
		t.Fatal("one principal counted twice for a site model change", err)
	}
	if keys, err := VerifyPolicyAuthorization(store, bundle(alice), model, SubjectSiteModel, 1, now); err != nil || len(keys) != 1 {
		t.Fatal("valid single site model approval refused at min 1", err)
	}
	// The issuer names the subject it loads: a site model bundle does not
	// authorize policy bytes, even when the bytes are the same.
	if _, err := VerifyPolicyAuthorization(store, bundle(alice), model, SubjectPolicy, 1, now); err == nil || !strings.Contains(err.Error(), "subject") {
		t.Fatal("site model bundle accepted for the policy subject", err)
	}
	if _, err := VerifyPolicyAuthorization(store, bundle(alice), model, "keyring", 1, now); err == nil {
		t.Fatal("unknown subject accepted")
	}
	// A change with no subject or an unknown subject is not a valid document.
	bad := c
	bad.Subject = ""
	bad.Digest, _ = PolicyChangeDigest(bad)
	if err := bad.validate(); err == nil {
		t.Fatal("subject-less change accepted")
	}
	if r, err := ResourceForSubject(SubjectSiteModel); err != nil || r != SiteModelResource {
		t.Fatal(r, err)
	}
}
