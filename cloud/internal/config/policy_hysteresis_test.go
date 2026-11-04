// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package config

import "testing"

// AS-5: `revocation_hysteresis` is optional as a section (absent = no
// damping, Declared=false); present, it must be whole (S16e) and sane (S16i).
func TestS16RevocationHysteresisSection(t *testing.T) {
	section := func(body string) string { return validPolicy + "revocation_hysteresis:\n" + body }
	p, err := loadContent(t, validPolicy)
	if err != nil || p.RevocationHysteresis.Declared {
		t.Fatalf("absent section must load undeclared: %v %+v", err, p.RevocationHysteresis)
	}
	p, err = loadContent(t, section("  flap_window_ms: 10000\n  flap_threshold: 3\n  settle_ms: 5000\n"))
	if err != nil || !p.RevocationHysteresis.Declared || p.RevocationHysteresis.FlapWindowMS != 10000 || p.RevocationHysteresis.FlapThreshold != 3 || p.RevocationHysteresis.SettleMS != 5000 {
		t.Fatalf("declared section: %v %+v", err, p.RevocationHysteresis)
	}
	for name, body := range map[string]string{
		"missing window":    "  flap_threshold: 3\n  settle_ms: 5000\n",
		"missing threshold": "  flap_window_ms: 10000\n  settle_ms: 5000\n",
		"missing settle":    "  flap_window_ms: 10000\n  flap_threshold: 3\n",
		"empty section":     "  {}\n",
	} {
		t.Run(name, func(t *testing.T) { wantRule(t, "S16e", section(body)) })
	}
	for name, body := range map[string]string{
		"zero window":     "  flap_window_ms: 0\n  flap_threshold: 3\n  settle_ms: 5000\n",
		"threshold 1":     "  flap_window_ms: 10000\n  flap_threshold: 1\n  settle_ms: 5000\n",
		"negative settle": "  flap_window_ms: 10000\n  flap_threshold: 3\n  settle_ms: -1\n",
	} {
		t.Run(name, func(t *testing.T) { wantRule(t, "S16i", section(body)) })
	}
	t.Run("unknown key", func(t *testing.T) {
		wantRule(t, "S16b", section("  flap_window_ms: 10000\n  flap_threshold: 3\n  settle_ms: 5000\n  cooldown_ms: 1\n"))
	})
}
