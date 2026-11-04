// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package skills

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const good = `version: 1
robot_class: diff_drive_amr
skills:
  - name: twist
    classes: [MOVE]
    evidence: {when: before, trust: identity_bearing}
    envelope: [sls.linear_mps, sls.angular_rps, step.max_duration_s]
    feeds: [safety_feed]
    complete: {signal: duration}
    safe_state: stop_zero_twist
  - name: pick
    classes: [MANIPULATE]
    evidence: {when: none}
    envelope: []
    feeds: []
    complete: {signal: robot_report}
    safe_state: stop_zero_twist
`

func TestParse_Good(t *testing.T) {
	r, err := Parse([]byte(good), "diff_drive_amr")
	if err != nil {
		t.Fatal(err)
	}
	tw, ok := r.Lookup("twist")
	if !ok || tw.Mask != 1 || tw.Slot != "main" || !tw.RequiresTarget() || len(tw.Envelope) != 3 {
		t.Fatalf("twist row: %+v ok=%v", tw, ok)
	}
	pk, _ := r.Lookup("pick")
	if pk.RequiresTarget() || pk.Mask != 2 {
		t.Fatalf("pick row: %+v", pk)
	}
	if len(r.SHA256Hex) != 64 {
		t.Fatalf("sha: %q", r.SHA256Hex)
	}
}

// Each refusal is planted alone so a rule that dies is seen as its own green,
// not hidden under a neighbour (H-B9).
func TestParse_Refusals(t *testing.T) {
	cases := map[string]string{
		"unknown key":      strings.Replace(good, "    slot: main\n", "", 1) + "    bogus: 1\n",
		"wildcard":         strings.Replace(good, "  - name: pick", "  - name: \"*\"", 1),
		"bad class":        strings.Replace(good, "classes: [MANIPULATE]", "classes: [FLY]", 1),
		"bad when":         strings.Replace(good, "{when: none}", "{when: during}", 1),
		"when needs trust": strings.Replace(good, "{when: none}", "{when: before}", 1),
		"bad signal":       strings.Replace(good, "signal: robot_report", "signal: telepathy", 1),
		"no safe_state":    strings.Replace(good, "    safe_state: stop_zero_twist\n  - name: pick", "  - name: pick", 1),
		"duplicate":        strings.Replace(good, "  - name: pick", "  - name: twist", 1),
		"empty":            "version: 1\nrobot_class: x\nskills: []\n",
		"version":          strings.Replace(good, "version: 1", "version: 2", 1),
		"class mismatch":   good, // wantClass below differs
		"params_schema":    strings.Replace(good, "    safe_state: stop_zero_twist\n  - name: pick", "    safe_state: stop_zero_twist\n    params_schema: \"{}\"\n  - name: pick", 1),
		"missing feeds":    strings.Replace(good, "    feeds: []\n", "", 1),
	}
	for name, src := range cases {
		want := "diff_drive_amr"
		if name == "class mismatch" {
			want = "humanoid"
		}
		if name == "unknown key" {
			src = good + "    bogus: 1\n"
		}
		if _, err := Parse([]byte(src), want); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "skills.diff_drive_amr.yaml"), []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if set.Len() != 1 || set.Classes()[0] != "diff_drive_amr" {
		t.Fatalf("set: %+v", set.Classes())
	}
	if _, ok := set.ForClass("humanoid"); ok {
		t.Fatal("humanoid should be absent")
	}
	// a misnamed file is a misplaced registry, not a different robot
	if err := os.WriteFile(filepath.Join(dir, "skills.humanoid.yaml"), []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDir(dir); err == nil {
		t.Fatal("file named humanoid declaring diff_drive_amr was accepted")
	}
	empty, err := LoadDir(t.TempDir())
	if err != nil || empty.Len() != 0 {
		t.Fatalf("empty dir: %v %d", err, empty.Len())
	}
}

// PAIL-CASE: unknown_feeds
// SK-5 (G-ISS-21): a row naming a feed outside the live-checked preconditions
// is listed by class/skill:feed; the shipped vocabulary clears the good registry.
func TestUnknownFeeds(t *testing.T) {
	dir := t.TempDir()
	withFleet := strings.Replace(good, "feeds: [safety_feed]", "feeds: [safety_feed, fleet_feed]", 1)
	if withFleet == good {
		t.Fatal("fixture: the good registry no longer carries `feeds: [safety_feed]`")
	}
	if err := os.WriteFile(filepath.Join(dir, "skills.diff_drive_amr.yaml"), []byte(withFleet), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	unk := set.UnknownFeeds([]string{"safety_feed", "evidence_claim"})
	if len(unk) != 1 || !strings.HasSuffix(unk[0], ":fleet_feed") || !strings.HasPrefix(unk[0], "diff_drive_amr/") {
		t.Fatalf("unknown feeds = %v", unk)
	}
	if got := set.UnknownFeeds([]string{"safety_feed", "evidence_claim", "fleet_feed"}); len(got) != 0 {
		t.Fatalf("declared feed still unknown: %v", got)
	}
	if got := set.UnknownFeeds(nil); len(got) < 2 {
		t.Fatalf("no vocabulary must leave every feed unknown, got %v", got)
	}
}
