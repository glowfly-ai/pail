// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// G-EUC-02 (EC-2) — the identification string. `pail-build:v1:` is a display
// prefix, not a hash input; this test is its GOTEST_NOVEC pin in UNPINNED.tsv.
package buildinfo

import (
	"strings"
	"testing"
)

const sha64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestBI01_RoundTripKeepsEveryField(t *testing.T) {
	in := Info{Component: "pep_gate", Version: "0.3.1+eu", GitSHA: "4a3a441",
		ImageDigest: "sha256:" + sha64, SBOMSHA256: sha64}
	s := Format(in)
	if !strings.HasPrefix(s, "pail-build:v1:pep_gate:0.3.1+eu:4a3a441:sha256%3A") {
		t.Fatalf("format: %s", s)
	}
	out, err := Parse(s)
	if err != nil || out != in {
		t.Fatalf("round trip: %+v err=%v", out, err)
	}
}

func TestBI02_UnknownSlotsAreDashNotEmpty(t *testing.T) {
	s := Format(Info{Component: "issuer"})
	if s != "pail-build:v1:issuer:-:-:-:-" {
		t.Fatalf("empty slots must print as `-`: %s", s)
	}
	if _, err := Parse(s); err != nil {
		t.Fatalf("all-unknown is well-formed: %v", err)
	}
	if _, err := Parse("pail-build:v1:issuer::-:-:-"); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("an empty token must be rejected by name: %v", err)
	}
}

func TestBI03_EachRuleRejectsByName(t *testing.T) {
	// 부정 픽스처의 접두어는 런타임 조립 — 리터럴로 두면 canon 동결 검사기가
	// 그것을 레지스트리 밖 접두어의 실제 출현으로 센다(스캐너는 의도를 못 본다).
	cases := map[string]string{
		"missing prefix":    "pail-" + "attest:v1:issuer:-:-:-:-",
		"tokens, want 7":    "pail-build:v1:issuer:-:-:-",
		"unknown component": "pail-build:v1:planner:-:-:-:-",
		"version":           "pail-build:v1:issuer:has space:-:-:-",
		"git_sha":           "pail-build:v1:issuer:-:ZZZZZZZ:-:-",
		"image_digest":      "pail-build:v1:issuer:-:-:sha256%3Anothex:-",
		"sbom_sha256":       "pail-build:v1:issuer:-:-:-:abc",
	}
	for want, s := range cases {
		_, err := Parse(s)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%q: want error naming %q, got %v", s, want, err)
		}
	}
}

func TestBI04_StringUsesLinkTimeValues(t *testing.T) {
	Version, GitSHA, ImageDigest, SBOMSHA256 = "t", "abcdef0", "", sha64
	t.Cleanup(func() { Version, GitSHA, ImageDigest, SBOMSHA256 = "", "", "", "" })
	got, err := Parse(String("telemetryd"))
	if err != nil || got.Version != "t" || got.GitSHA != "abcdef0" || got.ImageDigest != "" || got.SBOMSHA256 != sha64 {
		t.Fatalf("%+v err=%v", got, err)
	}
}
