// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"math"
	"path/filepath"
	"strings"
	"testing"
)

func TestTrustRenewalExpiredBaseAndAuthenticatedCandidate(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	raw := makePayload(t, 7, 1000)
	base, e := BuildBundle(priv, "root", raw)
	if e != nil {
		t.Fatal(e)
	}
	consumers := []RenewalConsumer{renewalConsumer(t, base, pub, 10)}
	p, e := PrepareTrustRenewal(base, pub, consumers, 2000, 2099)
	if e != nil {
		t.Fatal(e)
	}
	var next BundlePayload
	if e = json.Unmarshal(p.Payload, &next); e != nil {
		t.Fatal(e)
	}
	if next.BundleVersion != 11 || p.MotionAction != "NONE" || p.BaseSHA256 != trustHash(base) {
		t.Fatal("proposal identity")
	}
	signed, e := BuildBundle(priv, "root", p.Payload)
	if e != nil {
		t.Fatal(e)
	}
	if e = ValidateTrustRenewal(base, signed, pub, consumers); e != nil {
		t.Fatal(e)
	}
	// Later observations are fresh input, not silently inherited approval.
	changed := append([]RenewalConsumer(nil), consumers...)
	changed[0].RollbackFloor = 11
	if e = ValidateTrustRenewal(base, signed, pub, changed); e == nil {
		t.Fatal("new floor accepted")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*BundlePayload)
	}{
		{"role", func(p *BundlePayload) { p.Keys[0].Role = "operator" }},
		{"key-id", func(p *BundlePayload) { p.Keys[0].KeyID = "replacement" }},
		{"version", func(p *BundlePayload) { p.BundleVersion++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var v BundlePayload
			json.Unmarshal(p.Payload, &v)
			tc.mutate(&v)
			b, _ := json.Marshal(v)
			s, e := BuildBundle(priv, "root", b)
			if e != nil {
				t.Fatal(e)
			}
			if ValidateTrustRenewal(base, s, pub, consumers) == nil {
				t.Fatal("immutable change accepted")
			}
		})
	}
	renamed, _ := BuildBundle(priv, "other-label", p.Payload)
	if ValidateTrustRenewal(base, renamed, pub, consumers) == nil {
		t.Fatal("label changed")
	}
	_, wrong, _ := ed25519.GenerateKey(rand.Reader)
	other, _ := BuildBundle(wrong, "root", p.Payload)
	if ValidateTrustRenewal(base, other, pub, consumers) == nil {
		t.Fatal("root changed")
	}
}

func TestTrustRenewalRejectsUnknownAndOverflow(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	base, _ := BuildBundle(priv, "root", makePayload(t, 7, 1000))
	good := renewalConsumer(t, base, pub, 10)
	for _, tc := range []struct {
		name            string
		cons            []RenewalConsumer
		issued, expires int64
	}{
		{"no-consumer", nil, 2000, 2099},
		{"unknown", []RenewalConsumer{{ID: "gate"}}, 2000, 2099},
		{"duplicate", []RenewalConsumer{good, good}, 2000, 2099},
		{"overflow", []RenewalConsumer{renewalConsumer(t, base, pub, math.MaxUint64)}, 2000, 2099},
		{"cap", []RenewalConsumer{good}, 2000, 2101},
		{"clock-uncertainty", []RenewalConsumer{good}, 2000, 2002},
		{"future-issue", []RenewalConsumer{good}, 2001, 2099},
		{"negative", []RenewalConsumer{good}, -1, 2099},
		{"far-expiry", []RenewalConsumer{good}, 2000, math.MaxInt64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, e := PrepareTrustRenewal(base, pub, tc.cons, tc.issued, tc.expires); e == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestTrustRenewalRejectsAmbiguousJSON(t *testing.T) {
	for _, s := range []string{`{"x":1,"x":2}`, `{"x":{"a":1,"\u0061":2}}`, `[] []`, `{"a":[{"x":1,"x":2}]}`, strings.Repeat("[", 18) + strings.Repeat("]", 18)} {
		if uniqueJSON([]byte(s)) == nil {
			t.Fatalf("accepted %s", s)
		}
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	raw := makePayload(t, 7, 1000)
	// Existing signature kernel accepts duplicate JSON. The administrative
	// renewal boundary must refuse it rather than silently normalizing it.
	raw = append([]byte(`{"bundle_version":1,`), raw[1:]...)
	base, e := BuildBundle(priv, "root", raw)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = VerifyBundle(base, pub); e != nil {
		t.Fatal(e)
	}
	if _, e = PrepareTrustRenewal(base, pub, []RenewalConsumer{renewalConsumer(t, base, pub, 7)}, 2000, 2099); e == nil {
		t.Fatal("duplicate signed payload normalized")
	}
}

func TestLoadedTrustSnapshotBoundToAcceptedBytes(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.json")
	raw := makePayload(t, 7, futureUnix())
	bundle, e := BuildBundle(priv, "root", raw)
	if e != nil {
		t.Fatal(e)
	}
	writeFile(t, path, bundle)
	kr, e := LoadKeyringBundle(path, pub, filepath.Join(dir, "state.json"), testBundlePolicy)
	if e != nil {
		t.Fatal(e)
	}
	var m map[string]any
	if e = json.Unmarshal([]byte(kr.LoadedTrustJSON()), &m); e != nil {
		t.Fatal(e)
	}
	if m["bundle_sha256"] != trustHash(bundle) || m["bundle_version"] != float64(7) || m["load_verdict"] != "LOADED" {
		t.Fatalf("wrong loaded snapshot: %v", m)
	}
	before := kr.LoadedTrustJSON()
	writeFile(t, path, []byte("replaced after successful load"))
	if kr.LoadedTrustJSON() != before {
		t.Fatal("file observation replaced actual loaded state")
	}
	if (&Keyring{}).LoadedTrustJSON() == before {
		t.Fatal("unloaded ring claimed accepted metadata")
	}
}

func TestRenewalCannotAssumeLoadedMaterialFromOnlyVersionFloor(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	base, e := BuildBundle(priv, "root", makePayload(t, 7, 1000))
	if e != nil {
		t.Fatal(e)
	}
	// Version 10 may have revoked a key still present in this old version-7 file.
	// Knowing only the floor and process generation cannot prove key equivalence.
	observations := []RenewalConsumer{{ID: "gate", LoadedGeneration: "loaded-version-10", Observed: true, RollbackFloor: 10, NowMinUnix: 2000, NowMaxUnix: 2002, MaxRemainingSeconds: 100}}
	if _, e = PrepareTrustRenewal(base, pub, observations, 2000, 2099); e == nil {
		t.Fatal("unobserved loaded key/revocation material accepted for renewal")
	}
}

func renewalConsumer(t *testing.T, base []byte, root ed25519.PublicKey, floor uint64) RenewalConsumer {
	t.Helper()
	p, _, e := VerifyBundle(base, root)
	if e != nil {
		t.Fatal(e)
	}
	material, e := TrustMaterialDigest(p)
	if e != nil {
		t.Fatal(e)
	}
	return RenewalConsumer{MaxBundleVersion: math.MaxUint64, ID: "gate", LoadedGeneration: "proc-4", Observed: true, RollbackFloor: floor,
		NowMinUnix: 2000, NowMaxUnix: 2002, MaxRemainingSeconds: 100, RootFingerprint: trustHash(root), MaterialDigest: material}
}

func TestRenewalRejectsDifferentLoadedKeysOrRoot(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	base, _ := BuildBundle(priv, "root", makePayload(t, 7, 1000))
	for _, which := range []string{"root", "revocation-material"} {
		c := renewalConsumer(t, base, pub, 10)
		if which == "root" {
			c.RootFingerprint = strings.Repeat("0", 64)
		} else {
			c.MaterialDigest = strings.Repeat("0", 64)
		}
		if _, e := PrepareTrustRenewal(base, pub, []RenewalConsumer{c}, 2000, 2099); e == nil {
			t.Fatalf("accepted different %s", which)
		}
	}
}

func TestTrustMaterialDigestMatchesCrossLanguageGolden(t *testing.T) {
	p := &BundlePayload{Keys: []KeyringEntry{
		{KeyID: "i", Role: "issuer", PublicKeyB64: base64.StdEncoding.EncodeToString(make([]byte, 32))},
		{KeyID: "o", Role: "operator", PublicKeyB64: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))},
	}, RevokedKeys: []KeyringEntry{{KeyID: "r", Role: "issuer", PublicKeyB64: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))}}}
	got, e := TrustMaterialDigest(p)
	if e != nil || got != "d7df5df418103d3096dd7be7210f735842ca20bcbbab432971abeb635f8dfc6d" {
		t.Fatalf("%s %v", got, e)
	}
	p.RevokedKeys = nil
	changed, e := TrustMaterialDigest(p)
	if e != nil || changed == got {
		t.Fatal("revocation material disappeared without changing digest")
	}
}

func TestRenewalHonorsConsumersIntegerVersionRange(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	base, _ := BuildBundle(priv, "root", makePayload(t, 7, 1000))
	c := renewalConsumer(t, base, pub, 10)
	c.MaxBundleVersion = 10
	if _, e := PrepareTrustRenewal(base, pub, []RenewalConsumer{c}, 2000, 2099); e == nil {
		t.Fatal("candidate exceeds consumer version range")
	}
}
