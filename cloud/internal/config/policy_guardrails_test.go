// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package config

// SK-1 : the guardrails envelope table — G-POL-10 (zone values
// only tighten, S34) and G-POL-12 (motion alias agrees, S34b). Each refusal is
// planted alone and the RULE ID is read, not just the refusal (H-B9).

import (
	"strings"
	"testing"

	"github.com/glowfly/pail/services/internal/deploysec"
)

const guardrailsOK = `
guardrails:
  common:
    sls.linear_mps: 1.0
    sls.angular_rps: 1.0
    step.max_duration_s: 30
  zones:
    z1:
      sls.linear_mps: 0.3
`

func TestGuardrails_AbsentDerivesFromMotion(t *testing.T) {
	p, err := loadFrom(t, validPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if p.Guardrails.Declared {
		t.Fatal("no section, yet Declared")
	}
	env, missing := p.Guardrails.Envelope([]string{GuardrailLinear, GuardrailAngular, GuardrailDuration}, "z1")
	if env[GuardrailLinear] != 1.0 || env[GuardrailAngular] != 1.0 {
		t.Fatalf("derived: %v", env)
	}
	if len(missing) != 1 || missing[0] != GuardrailDuration {
		t.Fatalf("missing: %v — a name without a common value must be reported, not defaulted", missing)
	}
}

func TestGuardrails_DeclaredAndZoneTightens(t *testing.T) {
	p, err := loadFrom(t, validPolicy+guardrailsOK)
	if err != nil {
		t.Fatal(err)
	}
	env, missing := p.Guardrails.Envelope([]string{GuardrailLinear, GuardrailAngular, GuardrailDuration}, "z1")
	if len(missing) != 0 || env[GuardrailLinear] != 0.3 || env[GuardrailAngular] != 1.0 || env[GuardrailDuration] != 30 {
		t.Fatalf("env=%v missing=%v", env, missing)
	}
	env, _ = p.Guardrails.Envelope([]string{GuardrailLinear}, "z9")
	if env[GuardrailLinear] != 1.0 {
		t.Fatalf("unknown zone must fall back to common: %v", env)
	}
}

// PAIL-CASE: guardrails_zone_above_common_refused
func TestGuardrails_ZoneAboveCommonRefused_S34(t *testing.T) {
	c := strings.Replace(validPolicy+guardrailsOK, "sls.linear_mps: 0.3", "sls.linear_mps: 1.5", 1)
	_, err := loadFrom(t, c)
	if deploysec.RuleID(err) != "S34" {
		t.Fatalf("G-POL-10: want S34, got %v", err)
	}
}

// PAIL-CASE: guardrails_alias_mismatch_refused
func TestGuardrails_MotionAliasMismatchRefused_S34b(t *testing.T) {
	c := strings.Replace(validPolicy+guardrailsOK, "    sls.angular_rps: 1.0\n", "    sls.angular_rps: 0.7\n", 1)
	_, err := loadFrom(t, c)
	if deploysec.RuleID(err) != "S34b" {
		t.Fatalf("G-POL-12: want S34b, got %v", err)
	}
}

func TestGuardrails_OtherRefusals(t *testing.T) {
	cases := map[string]struct{ src, rule string }{
		"zone names unknown common": {strings.Replace(validPolicy+guardrailsOK, "      sls.linear_mps: 0.3", "      sfc.contact_n: 5", 1), "S16g"},
		"non-positive common":       {strings.Replace(validPolicy+guardrailsOK, "step.max_duration_s: 30", "step.max_duration_s: 0", 1), "S16i"},
		"non-positive zone":         {strings.Replace(validPolicy+guardrailsOK, "sls.linear_mps: 0.3", "sls.linear_mps: -1", 1), "S16i"},
		"alias missing":             {strings.Replace(validPolicy+guardrailsOK, "    sls.angular_rps: 1.0\n", "", 1), "S16e"},
		"empty common":              {validPolicy + "\nguardrails:\n  common: {}\n", "S16e"},
	}
	for name, c := range cases {
		_, err := loadFrom(t, c.src)
		if got := deploysec.RuleID(err); got != c.rule {
			t.Errorf("%s: want %s, got %v", name, c.rule, err)
		}
	}
}
