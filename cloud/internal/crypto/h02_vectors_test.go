// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package crypto

// SEC-H02 — keyring bundle parity vectors, Go loader side (test LLD §3.3, T15–T17).
// tests/golden/keyring_bundle/vectors.json is read by this runner and by the C++ gate
// loader's runner (libpail_gate/test/test_trust_vectors.cpp); each vector must get the
// same verdict from both. Wording is not compared.

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/glowfly/pail/services/internal/testlayout"
)

type h02Vector struct {
	Name           string `json:"name"`
	Note           string `json:"note"`
	BundleB64      string `json:"bundle_b64"`
	RootPubB64     string `json:"root_pub_b64"`
	State          string `json:"state"`
	Profile        string `json:"profile"`
	MaxLifetimeSec string `json:"max_lifetime_sec"`
	Want           struct {
		Loaded     bool     `json:"loaded"`
		Class      string   `json:"class"`
		IssuerIDs  []string `json:"issuer_ids"`
		RevokedIDs []string `json:"revoked_ids"`
	} `json:"want"`
}

func h02Vectors(t *testing.T) map[string]h02Vector {
	t.Helper()
	// The development tree keeps the file under tests/golden; a delivered Core carries it as
	// spec/vectors/keyring_bundle/vectors.json. testlayout resolves either.
	path := testlayout.Path(t, "tests/golden/keyring_bundle/vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("vectors: %v", err)
	}
	var doc struct {
		Vectors []h02Vector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("vectors: %v", err)
	}
	if len(doc.Vectors) < 14 {
		t.Fatalf("vectors: %d in %s, 14 expected at least", len(doc.Vectors), path)
	}
	out := map[string]h02Vector{}
	for _, v := range doc.Vectors {
		out[v.Name] = v
	}
	return out
}

func h02RunVector(t *testing.T, v h02Vector) {
	t.Helper()
	bundle, err := base64.StdEncoding.DecodeString(v.BundleB64)
	if err != nil {
		t.Fatalf("%s: bundle_b64: %v", v.Name, err)
	}
	got := h02LoadGo(t, bundle, v.RootPubB64, v.State, v.Profile, v.MaxLifetimeSec)
	if got.Loaded != v.Want.Loaded || got.Class != v.Want.Class ||
		!reflect.DeepEqual(got.IssuerIDs, v.Want.IssuerIDs) || !reflect.DeepEqual(got.RevokedIDs, v.Want.RevokedIDs) {
		t.Errorf("%s (%s): got loaded=%v class=%q issuers=%v revoked=%v err=%v ; want loaded=%v class=%q issuers=%v revoked=%v",
			v.Name, v.Note, got.Loaded, got.Class, got.IssuerIDs, got.RevokedIDs, got.Err,
			v.Want.Loaded, v.Want.Class, v.Want.IssuerIDs, v.Want.RevokedIDs)
	}
}

// T15: the twelve vectors of the load rules.
func TestH02Vectors(t *testing.T) {
	vs := h02Vectors(t)
	for _, name := range []string{"V01", "V02", "V03", "V04", "V05", "V06", "V07", "V08", "V09", "V10", "V11", "V12"} {
		v, ok := vs[name]
		if !ok {
			t.Fatalf("vector %s is missing", name)
		}
		t.Run(name, func(t *testing.T) { h02RunVector(t, v) })
	}
}

// T16: reserved and unknown roles are loaded and trusted for nothing.
func TestH02VectorsRoles(t *testing.T) {
	vs := h02Vectors(t)
	for _, name := range []string{"V13", "V14"} {
		v, ok := vs[name]
		if !ok {
			t.Fatalf("vector %s is missing", name)
		}
		t.Run(name, func(t *testing.T) { h02RunVector(t, v) })
	}
}

// T17: the state-file rule on the Go loader — absent in production is not a first load,
// a garbled file is refused, an initialised file loads.
func TestH02StateRule(t *testing.T) {
	vs := h02Vectors(t)
	base := vs["V01"]
	bundle, err := base64.StdEncoding.DecodeString(base.BundleB64)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("production_absent_is_refused", func(t *testing.T) {
		got := h02LoadGo(t, bundle, base.RootPubB64, "absent", "production", base.MaxLifetimeSec)
		if got.Loaded || got.Class != "STATE" {
			t.Errorf("got loaded=%v class=%q err=%v ; want a STATE refusal", got.Loaded, got.Class, got.Err)
		}
	})
	t.Run("garbled_is_refused", func(t *testing.T) {
		got := h02LoadGo(t, bundle, base.RootPubB64, "garbled", "production", base.MaxLifetimeSec)
		if got.Loaded || got.Class != "STATE" {
			t.Errorf("got loaded=%v class=%q err=%v ; want a STATE refusal", got.Loaded, got.Class, got.Err)
		}
	})
	t.Run("initialised_loads", func(t *testing.T) {
		got := h02LoadGo(t, bundle, base.RootPubB64, "floor:1", "production", base.MaxLifetimeSec)
		if !got.Loaded {
			t.Errorf("got class=%q err=%v ; want loaded", got.Class, got.Err)
		}
	})
	t.Run("dev_absent_is_a_first_load", func(t *testing.T) {
		got := h02LoadGo(t, bundle, base.RootPubB64, "absent", "dev", base.MaxLifetimeSec)
		if !got.Loaded {
			t.Errorf("got class=%q err=%v ; want loaded (dev keeps the first-load behaviour)", got.Class, got.Err)
		}
	})
}
