// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package deploysec

import (
	"strings"
	"testing"
)

func envOf(kv map[string]string) func(string) string {
	return func(k string) string { return kv[k] }
}

func ids(f []Finding) string {
	s := ""
	for i, x := range f {
		if i > 0 {
			s += ","
		}
		s += x.ID
	}
	return s
}

func TestEvaluate(t *testing.T) {
	cases := []struct {
		name     string
		env      map[string]string
		profile  string
		wantFail string
		wantWarn string
	}{
		{"empty env defaults to production", map[string]string{}, "production", "", "S6"},
		{"plaintext grpc", map[string]string{"PAIL_GRPC_TLS": "off", "PAIL_ATTESTATION": "required"}, "production", "S4", ""},
		{"plaintext grpc over uds is allowed", map[string]string{
			"PAIL_GRPC_TLS": "off", "PAIL_GRPC_UDS_PATH": "/var/run/pail/cloud.sock", "PAIL_ATTESTATION": "required",
		}, "production", "", ""},
		{"unsigned keyring", map[string]string{"PAIL_KEYRING_MODE": "unsigned-dev", "PAIL_ATTESTATION": "log"}, "production", "S5", ""},
		{"both, order fixed", map[string]string{
			"PAIL_GRPC_TLS": "off", "PAIL_KEYRING_MODE": "unsigned-dev", "PAIL_ATTESTATION": "required",
		}, "production", "S4,S5", ""},
		{"dev keeps the same findings", map[string]string{
			"PAIL_PROFILE": "dev", "PAIL_GRPC_TLS": "off", "PAIL_KEYRING_MODE": "unsigned-dev", "PAIL_ATTESTATION": "required",
		}, "dev", "S4,S5", ""},
		{"unknown profile is refused alone", map[string]string{
			"PAIL_PROFILE": "develop", "PAIL_GRPC_TLS": "off", "PAIL_KEYRING_MODE": "unsigned-dev",
		}, "develop", "S0", ""},
		{"attestation on clears the warning", map[string]string{
			"PAIL_ATTESTATION": "required", "PAIL_KEYRING_MODE": "bundle",
		}, "production", "", ""},
		{"attestation off warns", map[string]string{"PAIL_ATTESTATION": "off"}, "production", "", "S6"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Evaluate(envOf(c.env))
			if r.Profile != c.profile {
				t.Errorf("profile = %q, want %q", r.Profile, c.profile)
			}
			if got := ids(r.Fail); got != c.wantFail {
				t.Errorf("fail = %q, want %q", got, c.wantFail)
			}
			if got := ids(r.Warn); got != c.wantWarn {
				t.Errorf("warn = %q, want %q", got, c.wantWarn)
			}
		})
	}
}

// An unknown profile must not be reported alongside other findings: the operator
// has to fix the profile first, and anything judged under a profile we do not
// understand is unreliable.
func TestUnknownProfileSuppressesOtherFindings(t *testing.T) {
	r := Evaluate(envOf(map[string]string{
		"PAIL_PROFILE": "Production", "PAIL_GRPC_TLS": "off", "PAIL_KEYRING_MODE": "unsigned-dev",
	}))
	if len(r.Fail) != 1 || r.Fail[0].ID != "S0" {
		t.Fatalf("fail = %v, want exactly S0", r.Fail)
	}
	if len(r.Warn) != 0 {
		t.Fatalf("warn = %v, want none", r.Warn)
	}
}

// S40/S40b: the change-authorization rule is judged only from what was
// offered, per subject, and only for the binary that verifies it.
func TestChangeAuthorizationRule(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"nothing offered", map[string]string{}, "S40"},
		{"policy bundle offered, no site model", map[string]string{"PAIL_POLICY_AUTH": "/etc/pail/policy-auth.json"}, ""},
		{"site model without its bundle", map[string]string{"PAIL_POLICY_AUTH": "/etc/pail/policy-auth.json", "PAIL_SITE_MODEL": "/etc/pail/site_model.yaml"}, "S40b"},
		{"both offered", map[string]string{"PAIL_POLICY_AUTH": "/etc/pail/policy-auth.json", "PAIL_SITE_MODEL": "/etc/pail/site_model.yaml", "PAIL_SITE_MODEL_AUTH": "/etc/pail/site-auth.json"}, ""},
		{"site model bundle alone does not cover the policy", map[string]string{"PAIL_SITE_MODEL": "/etc/pail/site_model.yaml", "PAIL_SITE_MODEL_AUTH": "/etc/pail/site-auth.json"}, "S40"},
		{"neither, site model set", map[string]string{"PAIL_SITE_MODEL": "/etc/pail/site_model.yaml"}, "S40,S40b"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ids(EvaluateChangeAuthorization(envOf(c.env))); got != c.want {
				t.Errorf("fail = %q, want %q", got, c.want)
			}
		})
	}
	// Component scoping: the rule is part of pail_cloud's deployment verdict
	// and absent from the agent's, which never reads a bundle.
	probe := SystemProbe()
	probe.Get = envOf(map[string]string{"PAIL_ATTESTATION": "required", "PAIL_KEYRING_MODE": "bundle"})
	if got := ids(EvaluateDeployment("pail_cloud", probe).Fail); !contains(got, "S40") {
		t.Errorf("pail_cloud verdict lacks S40: %q", got)
	}
	if got := ids(EvaluateDeployment("pail_robot_agent", probe).Fail); contains(got, "S40") {
		t.Errorf("agent verdict carries S40: %q", got)
	}
}

func contains(csv, id string) bool {
	for _, x := range strings.Split(csv, ",") {
		if x == id {
			return true
		}
	}
	return false
}
