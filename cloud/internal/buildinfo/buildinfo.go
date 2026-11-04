// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// Package buildinfo is the installed-software identification string (EC-2,
// EUC D2): what exactly is running, said in one line that the chain keeps.
//
//	pail-build:v1:<component>:<version>:<git_sha>:<image_digest>:<sbom_sha256>
//
// Seven colon-separated tokens, fixed. An unknown value is `-`, never empty —
// an empty token would make "unknown" and "malformed" the same bytes. A colon
// inside a value is `%3A` (image digests carry one: `sha256:…`).
//
// This is a DISPLAY value: it is journaled verbatim in ATTESTATION and
// CONFIG_SEALED records and shown by the collector; it is not a hash input
// and no golden vector pins it (registered as such in
// tests/golden/canon/UNPINNED.tsv).
//
// The four fields come from the build (`-ldflags -X`); a binary built without
// them says `-` in every slot and that is visible, not hidden — production
// refuses a gate whose attest_build_info is empty or malformed (S26), it does
// not refuse `-` slots, because a slot that honestly says "unknown" is a fact
// an auditor can act on and an empty string is not.
package buildinfo

import (
	"fmt"
	"regexp"
	"strings"
)

// Set at link time: -X github.com/glowfly/pail/services/internal/buildinfo.Version=…
var (
	Version     string
	GitSHA      string
	ImageDigest string
	SBOMSHA256  string
)

const Prefix = "pail-build:v1:"

// Components is the closed vocabulary of the <component> token. Adding one is
// a spec change (this file and EXPORT_SCHEMA_v1.md §2.8 together).
var Components = []string{"pep_gate", "issuer", "robot_agent", "telemetryd", "permit_mirror"}

type Info struct {
	Component   string
	Version     string
	GitSHA      string
	ImageDigest string
	SBOMSHA256  string
}

var (
	gitShaRe  = regexp.MustCompile(`^[0-9a-f]{7,40}$`)
	sha256Re  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	digestRe  = regexp.MustCompile(`^sha256%3A[0-9a-f]{64}$`)
	versionRe = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}$`)
)

func esc(s string) string {
	if s == "" {
		return "-"
	}
	return strings.ReplaceAll(s, ":", "%3A")
}

// Unesc reverses the token escaping. `-` becomes "".
func Unesc(s string) string {
	if s == "-" {
		return ""
	}
	return strings.ReplaceAll(s, "%3A", ":")
}

// Format renders the seven-token string. It does not validate: a caller that
// wants to know whether what it built is well-formed calls Parse on it.
func Format(i Info) string {
	return Prefix + strings.Join([]string{
		esc(i.Component), esc(i.Version), esc(i.GitSHA), esc(i.ImageDigest), esc(i.SBOMSHA256),
	}, ":")
}

// String is this binary's own identification for `component`.
func String(component string) string {
	return Format(Info{Component: component, Version: Version, GitSHA: GitSHA,
		ImageDigest: ImageDigest, SBOMSHA256: SBOMSHA256})
}

func knownComponent(c string) bool {
	for _, k := range Components {
		if k == c {
			return true
		}
	}
	return false
}

// Parse accepts exactly the strings Format produces from a well-formed Info.
// Every rule is its own error text so a rejected string says which slot lied.
func Parse(s string) (Info, error) {
	if !strings.HasPrefix(s, Prefix) {
		return Info{}, fmt.Errorf("build_info: missing prefix %q", Prefix)
	}
	toks := strings.Split(s, ":")
	if len(toks) != 7 {
		return Info{}, fmt.Errorf("build_info: %d tokens, want 7", len(toks))
	}
	for i, t := range toks[2:] {
		if t == "" {
			return Info{}, fmt.Errorf("build_info: token %d is empty — unknown is `-`, not nothing", i+3)
		}
	}
	i := Info{Component: toks[2], Version: Unesc(toks[3]), GitSHA: Unesc(toks[4]),
		ImageDigest: Unesc(toks[5]), SBOMSHA256: Unesc(toks[6])}
	if !knownComponent(i.Component) {
		return Info{}, fmt.Errorf("build_info: unknown component %q (want one of %s)", i.Component, strings.Join(Components, "|"))
	}
	if toks[3] != "-" && !versionRe.MatchString(toks[3]) {
		return Info{}, fmt.Errorf("build_info: version %q is not [A-Za-z0-9._+-]{1,64}", toks[3])
	}
	if toks[4] != "-" && !gitShaRe.MatchString(toks[4]) {
		return Info{}, fmt.Errorf("build_info: git_sha %q is not 7..40 lowercase hex", toks[4])
	}
	if toks[5] != "-" && !digestRe.MatchString(toks[5]) {
		return Info{}, fmt.Errorf("build_info: image_digest %q is not sha256%%3A<64 hex>", toks[5])
	}
	if toks[6] != "-" && !sha256Re.MatchString(toks[6]) {
		return Info{}, fmt.Errorf("build_info: sbom_sha256 %q is not 64 lowercase hex", toks[6])
	}
	return i, nil
}
