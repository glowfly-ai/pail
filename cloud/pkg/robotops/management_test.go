// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package robotops

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

const testDeployment = "5e8b24a0-2319-4a53-b5cf-a03afc977301"

func seedOf(label string) []byte { s := sha256.Sum256([]byte("test-seed:" + label)); return s[:] }

func trustFixture(t *testing.T) (TrustStore, []byte) {
	seed := seedOf("approver")
	pk, err := PublicKeyForSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := PublicKeyForSeed(seedOf("observer"))
	return TrustStore{SchemaVersion: 1, TrustEpoch: 3, DeploymentID: testDeployment, TrustedExecutorUIDs: []uint32{}, Keys: []TrustKey{
		{KeyID: "mgmt-1", PublicKey: pk, PrincipalID: "ops.admin", Roles: []string{"prepare", "approve_apply"}, DeploymentScope: testDeployment, TargetScope: []string{"res:registry", "cred:c1"}, NotBeforeMS: 1000, NotAfterMS: 9_000_000_000_000},
		{KeyID: "obs-1", PublicKey: other, PrincipalID: "ops.viewer", Roles: []string{"observe"}, DeploymentScope: testDeployment, TargetScope: []string{"*"}, NotBeforeMS: 1000, NotAfterMS: 9_000_000_000_000},
	}}, seed
}
func approvalFixture() Approval {
	return Approval{SchemaVersion: 1, DocumentKind: "Approval", DeploymentID: testDeployment, DocumentID: "0b6e5c58-6d9c-4d0d-9f57-6d1c5d7f0a11", CreatedAtMS: 1_700_000_000_000, ToolBuild: "test", ApprovalID: "6f3b2a10-1b2c-4d3e-8f90-123456789abc", Action: "apply", ExecutionOrPrepareID: "9a1f2e3d-4c5b-4a69-8877-665544332211", PlanDigest: strings.Repeat("ab", 32), PrincipalID: "ops.admin", KeyID: "mgmt-1", TrustEpoch: 3, IssuedAtMS: 1_700_000_000_000, ExpiresAtMS: 1_700_000_000_000 + 15*60*1000, Nonce: "AAECAwQFBgcICQoLDA0ODw"}
}
func bindingFixture() ApprovalBinding {
	return ApprovalBinding{Action: "apply", DeploymentID: testDeployment, TargetID: "9a1f2e3d-4c5b-4a69-8877-665544332211", PlanDigest: strings.Repeat("ab", 32), Resources: []string{"res:registry", "cred:c1"}}
}

func TestManagementCanonicalIsOrderIndependentAndPrefixed(t *testing.T) {
	a := map[string]interface{}{"z": 1, "a": map[string]interface{}{"y": "é", "b": []interface{}{1.0, "x"}}, "digest": "drop"}
	b := map[string]interface{}{"digest": "other", "a": map[string]interface{}{"b": []interface{}{1, "x"}, "y": "é"}, "z": 1}
	ca, err := ManagementCanonical(DomainPlan, a, "digest")
	if err != nil {
		t.Fatal(err)
	}
	cb, _ := ManagementCanonical(DomainPlan, b, "digest")
	if !bytes.HasPrefix(ca, []byte("pail.robotops.plan/v1\n")) || string(ca[len("pail.robotops.plan/v1\n"):]) != `{"a":{"b":[1,"x"],"y":"é"},"z":1}` {
		t.Fatalf("canonical form %q", ca)
	}
	// NFC is not applied by the codec: distinct code point sequences differ.
	if bytes.Equal(ca, cb) {
		t.Fatal("codec must not silently normalize Unicode")
	}
	if _, err = ManagementCanonical("inventory", a); err == nil {
		t.Fatal("inspection domain accepted as management domain")
	}
	if _, err = ManagementCanonical(DomainPlan, []int{1}); err == nil {
		t.Fatal("non-object accepted")
	}
	d1, _ := ManagementDigest(DomainPrepare, a)
	d2, _ := ManagementDigest(DomainPlan, a)
	if d1 == d2 || len(d1) != 64 {
		t.Fatal("domains must separate digests")
	}
	sum := sha256.Sum256(ca)
	if d, _ := ManagementDigest(DomainPlan, a); d != hex.EncodeToString(sum[:]) {
		t.Fatal("digest is not sha256 of canonical bytes")
	}
}

func TestTrustStoreRejectsMalformedRows(t *testing.T) {
	good, _ := trustFixture(t)
	raw, _ := json.Marshal(good)
	if _, err := DecodeTrustStore(raw); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*TrustStore){
		"epoch zero":        func(s *TrustStore) { s.TrustEpoch = 0 },
		"other deployment":  func(s *TrustStore) { s.Keys[0].DeploymentScope = "5e8b24a0-2319-4a53-b5cf-a03afc977302" },
		"short key":         func(s *TrustStore) { s.Keys[0].PublicKey = "AAAA" },
		"padded key":        func(s *TrustStore) { s.Keys[0].PublicKey = s.Keys[0].PublicKey + "=" },
		"duplicate key id":  func(s *TrustStore) { s.Keys[1].KeyID = s.Keys[0].KeyID },
		"duplicate pubkey":  func(s *TrustStore) { s.Keys[1].PublicKey = s.Keys[0].PublicKey },
		"unknown role":      func(s *TrustStore) { s.Keys[0].Roles = []string{"root"} },
		"no roles":          func(s *TrustStore) { s.Keys[0].Roles = nil },
		"empty scope":       func(s *TrustStore) { s.Keys[0].TargetScope = nil },
		"bad scope":         func(s *TrustStore) { s.Keys[0].TargetScope = []string{"/etc/pail"} },
		"inverted validity": func(s *TrustStore) { s.Keys[0].NotAfterMS = s.Keys[0].NotBeforeMS },
		"no keys":           func(s *TrustStore) { s.Keys = nil },
	}
	for name, mutate := range cases {
		s := good
		s.Keys = append([]TrustKey(nil), good.Keys...)
		mutate(&s)
		if err := s.Validate(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if _, err := DecodeTrustStore([]byte(`{"schema_version":1,"trust_epoch":1,"deployment_id":"` + testDeployment + `","keys":[],"trusted_executor_uids":[],"private_key":"x"}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestApprovalSignVerifyAndRejections(t *testing.T) {
	store, seed := trustFixture(t)
	a, err := SignApproval(seed, approvalFixture())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(a)
	decoded, err := DecodeApproval(raw)
	if err != nil {
		t.Fatal(err)
	}
	now := int64(1_700_000_000_000 + 60*1000)
	k, err := VerifyApproval(store, decoded, bindingFixture(), now)
	if err != nil || k.KeyID != "mgmt-1" {
		t.Fatal("valid approval rejected", err)
	}
	if _, err = VerifyApproval(store, decoded, ApprovalBinding{Action: "apply", DeploymentID: testDeployment, TargetID: decoded.ExecutionOrPrepareID, PlanDigest: decoded.PlanDigest, Resources: []string{"res:registry"}}, now); err != nil {
		t.Fatal("subset of scope rejected", err)
	}
	type variant struct {
		mutate  func(*Approval)
		binding func(*ApprovalBinding)
		now     int64
		store   func(*TrustStore)
	}
	cases := map[string]variant{
		"tampered digest field":  {mutate: func(x *Approval) { x.PlanDigest = strings.Repeat("cd", 32) }, binding: func(b *ApprovalBinding) { b.PlanDigest = strings.Repeat("cd", 32) }},
		"tampered action":        {mutate: func(x *Approval) { x.Action = "prepare" }, binding: func(b *ApprovalBinding) { b.Action = "prepare" }},
		"tampered nonce":         {mutate: func(x *Approval) { x.Nonce = "AAECAwQFBgcICQoLDA0OEA" }},
		"tampered expiry":        {mutate: func(x *Approval) { x.ExpiresAtMS += 1000 }},
		"binding digest differs": {binding: func(b *ApprovalBinding) { b.PlanDigest = strings.Repeat("cd", 32) }},
		"binding target differs": {binding: func(b *ApprovalBinding) { b.TargetID = "9a1f2e3d-4c5b-4a69-8877-665544332212" }},
		"binding action differs": {binding: func(b *ApprovalBinding) { b.Action = "resume" }},
		"resource outside scope": {binding: func(b *ApprovalBinding) { b.Resources = []string{"res:registry", "res:site"} }},
		"empty resources":        {binding: func(b *ApprovalBinding) { b.Resources = nil }},
		"other deployment":       {binding: func(b *ApprovalBinding) { b.DeploymentID = "5e8b24a0-2319-4a53-b5cf-a03afc977302" }},
		"before issue":           {now: 1_700_000_000_000 - 1},
		"at expiry":              {now: 1_700_000_000_000 + 15*60*1000},
		"key revoked":            {store: func(s *TrustStore) { s.Keys[0].Revoked = true }},
		"key expired":            {store: func(s *TrustStore) { s.Keys[0].NotAfterMS = 1_700_000_000_000 }},
		"epoch advanced":         {store: func(s *TrustStore) { s.TrustEpoch = 4 }},
		"role removed":           {store: func(s *TrustStore) { s.Keys[0].Roles = []string{"prepare"} }},
		"principal renamed":      {store: func(s *TrustStore) { s.Keys[0].PrincipalID = "someone.else" }},
		"scope narrowed":         {store: func(s *TrustStore) { s.Keys[0].TargetScope = []string{"res:registry"} }},
	}
	for name, v := range cases {
		t.Run(name, func(t *testing.T) {
			x := decoded
			s := store
			s.Keys = append([]TrustKey(nil), store.Keys...)
			b := bindingFixture()
			n := now
			if v.mutate != nil {
				v.mutate(&x)
			}
			if v.binding != nil {
				v.binding(&b)
			}
			if v.store != nil {
				v.store(&s)
			}
			if v.now != 0 {
				n = v.now
			}
			if _, err := VerifyApproval(s, x, b, n); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	// A signature by an untrusted key over an otherwise perfect document.
	forged, _ := SignApproval(seedOf("observer"), approvalFixture())
	if _, err := VerifyApproval(store, forged, bindingFixture(), now); err == nil {
		t.Fatal("foreign signature accepted")
	}
	obs := approvalFixture()
	obs.KeyID, obs.PrincipalID = "obs-1", "ops.viewer"
	obs, _ = SignApproval(seedOf("observer"), obs)
	if _, err := VerifyApproval(store, obs, bindingFixture(), now); err == nil {
		t.Fatal("observe role approved apply")
	}
	long := approvalFixture()
	long.ExpiresAtMS = long.IssuedAtMS + ApprovalMaxValidityMS + 1
	if _, err := SignApproval(seed, long); err == nil {
		t.Fatal("validity above maximum accepted")
	}
	if _, err := SignApproval(seed[:16], approvalFixture()); err == nil {
		t.Fatal("short seed accepted")
	}
}
