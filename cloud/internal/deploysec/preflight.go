// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// Package deploysec implements the BG boot-time deployment-security gate
// (PAIL-BG-LLD-v1 §4). PAIL refuses to start with its protections disabled
// unless PAIL_PROFILE=dev is set explicitly.
//
// This is operational discipline, not a cryptographic guarantee: an attacker
// who can set the process environment has already taken the host. Its purpose
// is to stop configuration drift and "debugged with security off, shipped that
// way" from reaching a robot silently.
package deploysec

import (
	"fmt"
	"os"
	"strings"
)

// ExitConfig is sysexits.h EX_CONFIG: the configuration, not the code, is wrong.
const ExitConfig = 78

type Finding struct {
	ID  string
	Msg string
}

type Result struct {
	Profile string
	Fail    []Finding
	Warn    []Finding
	// Checked lists the rules that ran, so the OK line names what was
	// verified rather than implying everything was.
	Checked []string
}

func (r Result) ids(f []Finding) string {
	out := make([]string, 0, len(f))
	for _, x := range f {
		out = append(out, x.ID)
	}
	return strings.Join(out, ",")
}

// ReplayOff reports whether the development switch that skips the issuer's
// journal replay is set. One predicate serves both the issuer and rule S41:
// two readings of the variable could drift apart and leave a value that skips
// the replay without being refused.
func ReplayOff(get func(string) string) bool { return get("PAIL_REPLAY") == "off" }

// Evaluate is pure: it reads only through get and never exits. It does not vary
// its Fail list by profile — what counts as a violation and whether to refuse
// are separate decisions, so the dev banner can list exactly what production
// would have refused.
func Evaluate(get func(string) string) Result {
	profile := get("PAIL_PROFILE")
	if profile == "" {
		profile = "production"
	}
	r := Result{Profile: profile, Checked: []string{"S4", "S5", "S41"}}

	if profile != "production" && profile != "dev" {
		r.Fail = append(r.Fail, Finding{"S0", fmt.Sprintf("PAIL_PROFILE=%s (want production|dev)", profile)})
		// The profile decides how everything else is judged. If we cannot trust
		// it, reporting further findings would only add noise.
		r.Checked = nil
		return r
	}

	// [SEC-H05] No Unix-socket exception. A socket set with PAIL_GRPC_UDS_PATH is
	// an ADDITIONAL listener: pail_cloud, pail_services and pail_robot_agent all
	// open their TCP port regardless (pail_cloud has no such socket at all), and
	// with TLS off that port is plaintext. The earlier rule let "TLS off + any
	// socket path" start in production with that port open.
	if get("PAIL_GRPC_TLS") == "off" {
		r.Fail = append(r.Fail, Finding{"S4",
			"PAIL_GRPC_TLS=off — the TCP listener is plaintext, with or without PAIL_GRPC_UDS_PATH: the control plane accepts unauthenticated ReportDecision/Unlock from any local process"})
	}
	if get("PAIL_KEYRING_MODE") == "unsigned-dev" {
		r.Fail = append(r.Fail, Finding{"S5",
			"PAIL_KEYRING_MODE=unsigned-dev — unsigned keyring trust path (KM2 W2: a swapped keyring makes forged tokens verify)"})
	}
	// [SEC-H08A] The issuer restores its state by replaying its journal at
	// start-up, and that replay is also where the journal's checkpoint
	// signatures are verified. The switch skips all of it; it was honoured in
	// every profile with one warning line.
	if ReplayOff(get) {
		r.Fail = append(r.Fail, Finding{"S41",
			"PAIL_REPLAY=off — the issuer would start without replaying its journal: the lockdown, the consumed tokens and the issuance history are not restored and no checkpoint signature is verified"})
	}
	if m := get("PAIL_ATTESTATION"); m == "" || m == "off" {
		r.Warn = append(r.Warn, Finding{"S6",
			"PEP attestation disabled — binary substitution on the robot is not detected (AS-2)"})
	}
	return r
}

// EvaluateDeployment adds the rules that must look at the deployment itself,
// not just at the environment: S8 (key fingerprints, PAIL-SD2-LLD-v1 §2) and
// S9 (evidence path volatility, §3).
func EvaluateDeployment(component string, p Probe) Result {
	r := Evaluate(p.Get)
	if r.Checked == nil {
		return r // S0: the profile is not trustworthy, judge nothing else.
	}
	if !ComponentRegistered(component) {
		// Not "no committed key found" — nothing was looked for. A process that
		// joins the deployment without being registered used to get an OK line
		// naming S8, which is the worst shape a check can take: it reports on a
		// question it never asked.
		r.Fail = append(r.Fail, Finding{"S8", fmt.Sprintf(
			"component %q is not in the S8 key-material registry — its signing keys and trust anchors were never scanned; add it to componentKeyRegistry (deploysec/keymaterial.go)",
			component)})
	}
	r.Fail = append(r.Fail, EvaluateKeyMaterial(collectKeyMaterial(component, p))...)
	r.Checked = append(r.Checked, "S8")

	// Only the components that hold the evidence chain. The robot agent writes
	// no blackbox, so refusing it for a tmpfs it never uses would be noise.
	if component == "pail_cloud" || component == "pail_services" {
		fail, warn := evaluatePaths(p)
		r.Fail = append(r.Fail, fail...)
		r.Warn = append(r.Warn, warn...)
		r.Checked = append(r.Checked, "S9")
	}
	// Only the issuer binary that verifies change authorizations (AS-4 is
	// wired in pail_cloud). Demanding a bundle from a process that would never
	// read it would be a refusal without a protection behind it.
	if component == "pail_cloud" {
		r.Fail = append(r.Fail, EvaluateChangeAuthorization(p.Get)...)
		r.Checked = append(r.Checked, "S40")
	}
	return r
}

// EvaluateChangeAuthorization is S40 (AS-4 / O-4): the issuer's standing
// inputs are loaded only under a change authorization from distinct trusted
// principals. S40 = no PolicyAuthorization for the policy file
// (PAIL_POLICY_AUTH); S40b = a site model is configured (PAIL_SITE_MODEL)
// without its authorization (PAIL_SITE_MODEL_AUTH). Like S4/S5 these are
// "a protection is off": production refuses, PAIL_PROFILE=dev is the
// operator's declaration to run without it and gets the INSECURE banner.
// The bundle's validity is not judged here — the issuer verifies the bytes
// it actually loads; this only says whether a bundle was offered at all.
func EvaluateChangeAuthorization(get func(string) string) []Finding {
	var out []Finding
	if get("PAIL_POLICY_AUTH") == "" {
		out = append(out, Finding{"S40", "PAIL_POLICY_AUTH unset — the policy file is loaded without a policy-change authorization from distinct trusted principals (AS-4)"})
	}
	if get("PAIL_SITE_MODEL") != "" && get("PAIL_SITE_MODEL_AUTH") == "" {
		out = append(out, Finding{"S40b", "PAIL_SITE_MODEL set without PAIL_SITE_MODEL_AUTH — the site model is loaded without a change authorization from distinct trusted principals (AS-4)"})
	}
	return out
}

// Preflight evaluates the process environment and enforces the verdict.
// component names the binary in the log line. It must run before the process
// takes a listening port, so a refused process never holds one.
func Preflight(component string) {
	// `L10` 관측점 (`U-E3`, implementation contract). 없는 것은 격리가 아니라 **격리의
	// 기록**이다 — 컨테이너는 이미 비특권으로 돌지만 root 로 올린 배치가 아무
	// 줄도 내지 않았다. 이 줄은 판정하지 않는다: uid 0 을 거부하지 않고 적기만
	// 한다. 거부는 배치 정책이고 여기서 정하면 위임이 아니게 된다.
	//
	// **평가보다 앞이어야 한다.** 아래 세 갈래는 전부 일찍 빠져나가고(OK 반환 ·
	// dev 반환 · `os.Exit`), 그중 마지막이 정확히 "잘못 올린 배치"다. 뒤에 두면
	// 가장 알고 싶은 경우에만 줄이 안 나온다.
	EmitProcessIdentity(component)
	r := EvaluateDeployment(component, SystemProbe())
	for _, w := range r.Warn {
		fmt.Fprintf(os.Stderr, "PAIL PREFLIGHT WARN: %s %s [component=%s]\n", w.ID, w.Msg, component)
	}
	if len(r.Fail) == 0 {
		fmt.Fprintf(os.Stderr, "PAIL PREFLIGHT: profile=%s OK (%s) component=%s\n",
			r.Profile, strings.Join(r.Checked, ","), component)
		return
	}
	if r.Profile == "dev" {
		fmt.Fprintf(os.Stderr, "PAIL PREFLIGHT: profile=dev INSECURE(%s) component=%s — NOT FOR PRODUCTION\n", r.ids(r.Fail), component)
		for _, f := range r.Fail {
			fmt.Fprintf(os.Stderr, "PAIL PREFLIGHT:   %s %s\n", f.ID, f.Msg)
		}
		return
	}
	for _, f := range r.Fail {
		fmt.Fprintf(os.Stderr, "PAIL PREFLIGHT FAIL: %s %s [profile=%s component=%s]\n", f.ID, f.Msg, r.Profile, component)
	}
	fmt.Fprintf(os.Stderr, "PAIL PREFLIGHT FAIL: refusing to start. Set PAIL_PROFILE=dev to run without these protections (DEV ONLY).\n")
	os.Exit(ExitConfig)
}
