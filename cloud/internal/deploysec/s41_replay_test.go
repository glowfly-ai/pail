// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package deploysec

// SEC-H08A: the development switch PAIL_REPLAY=off is refused in the
// production profile (rule S41).
//
// The issuer restores its state — the lockdown, the consumed tokens, the
// issuance history — by replaying its journal at start-up, and since SEC-H08
// that replay also verifies the journal's checkpoint signatures. The switch
// skips the replay altogether. It was honoured in every profile with one
// warning line.

import (
	"strings"
	"testing"
)

func h08aS41(r Result) (Finding, bool) {
	for _, f := range r.Fail {
		if f.ID == "S41" {
			return f, true
		}
	}
	return Finding{}, false
}

func TestH08AT01ReplayOffAloneFailsTheProductionProfile(t *testing.T) {
	r := Evaluate(h05Env(map[string]string{"PAIL_REPLAY": "off"}))
	if r.Profile != "production" {
		t.Fatalf("profile=%q", r.Profile)
	}
	if len(r.Fail) != 1 || r.Fail[0].ID != "S41" {
		t.Fatalf("production + PAIL_REPLAY=off: fail list %v, want exactly [S41] — this setting alone must turn a passing environment into a refused one", r.Fail)
	}
}

func TestH08AT02OnlyTheExactValueOffIsTheSwitch(t *testing.T) {
	for _, v := range []string{"", "on", "OFF", " off", "off ", "0", "false", "Off"} {
		env := map[string]string{}
		if v != "" {
			env["PAIL_REPLAY"] = v
		}
		if f, ok := h08aS41(Evaluate(h05Env(env))); ok {
			t.Errorf("PAIL_REPLAY=%q: S41 raised (%s) although the issuer replays for every value but \"off\"", v, f.Msg)
		}
	}
}

func TestH08AT03TheFindingDoesNotDependOnTheProfile(t *testing.T) {
	r := Evaluate(h05Env(map[string]string{"PAIL_PROFILE": "dev", "PAIL_REPLAY": "off"}))
	if r.Profile != "dev" {
		t.Fatalf("profile=%q", r.Profile)
	}
	if _, ok := h08aS41(r); !ok {
		t.Fatal("the dev banner would not list S41: what production refuses must be named in dev")
	}
}

func TestH08AT04TheMessageSaysWhatIsLost(t *testing.T) {
	f, ok := h08aS41(Evaluate(h05Env(map[string]string{"PAIL_REPLAY": "off"})))
	if !ok {
		t.Fatal("no S41 to read")
	}
	for _, want := range []string{"PAIL_REPLAY=off", "journal"} {
		if !strings.Contains(f.Msg, want) {
			t.Errorf("S41 message lacks %q: %q", want, f.Msg)
		}
	}
}

func TestH08AT05TheOKLineNamesS41AsChecked(t *testing.T) {
	r := Evaluate(h05Env(map[string]string{}))
	for _, id := range r.Checked {
		if id == "S41" {
			return
		}
	}
	t.Fatalf("checked rules %v do not include S41: the OK line would not say this rule ran", r.Checked)
}

// T06: the executables. In the production profile with this one setting the
// exit code is 78 before and after the change (other rules refuse a bare
// environment too), so the exit code is not the evidence — the S41 line is.
func TestH08AT06ExecutablesRefuseTheSwitchInProduction(t *testing.T) {
	for _, name := range []string{"pail_cloud", "pail_robot_agent"} {
		name := name
		t.Run(name, func(t *testing.T) {
			rc, out := h05Start(t, h05Build(t, name), map[string]string{"PAIL_REPLAY": "off"})
			if rc != ExitConfig {
				t.Errorf("%s: exit code %d, want %d\n%s", name, rc, ExitConfig, out)
			}
			if !strings.Contains(out, "PAIL PREFLIGHT FAIL: S41 ") {
				t.Errorf("%s: no S41 refusal line\n%s", name, out)
			}
			if strings.Contains(strings.ToLower(out), "listening") {
				t.Errorf("%s: a listener was opened before the refusal\n%s", name, out)
			}
		})
	}
}
