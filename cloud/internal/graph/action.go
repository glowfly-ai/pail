// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package graph

// AL-3 (implementation contract D3): action = enforcement class set × name.
//
// The four classes are the specification; the mask below is what a schema
// version 4 token carries in `action_type` and what the gate tests bit-wise
// (`(action_type & ClassMove) == 0` → ERR_ACTION_MISMATCH on /cmd_vel).
//
// NONE is bit 8, not 0: the design text wrote NONE=0, but 0 is the enum's
// UNSPECIFIED, which every verifier already refuses fail-closed. A CUSTOM step
// with no physical class must still yield a parseable, signed token — so NONE
// needs a bit of its own. Stated in implementation contract as a deviation.
const (
	ClassMove       uint32 = 1
	ClassManipulate uint32 = 2
	ClassActuate    uint32 = 4
	ClassNone       uint32 = 8
	ClassMaskAll    uint32 = ClassMove | ClassManipulate | ClassActuate | ClassNone
)

// ClassNames maps the YAML/registry vocabulary to bits.
var ClassNames = map[string]uint32{
	"MOVE":       ClassMove,
	"MANIPULATE": ClassManipulate,
	"ACTUATE":    ClassActuate,
	"NONE":       ClassNone,
}

// ClassMaskNames renders a mask as sorted names (evidence for the journal).
func ClassMaskNames(mask uint32) []string {
	var out []string
	for _, n := range []string{"MOVE", "MANIPULATE", "ACTUATE", "NONE"} {
		if mask&ClassNames[n] != 0 {
			out = append(out, n)
		}
	}
	return out
}

// ActionDef is one `actions:` registry entry of the site model.
type ActionDef struct {
	Name        string
	Mask        uint32
	Description string
}

// Policy is the site model's `policy:` block.
type Policy struct {
	// UnverifiedTargets: "refuse" (default) — a step whose target_object_id is
	// not a declared object is refused (ERR_TARGET_UNKNOWN); "allow" — issued
	// with target_unverified=true on the TOKEN_ISSUED record.
	UnverifiedTargets string
}

// AllowsUnverifiedTargets is the one place the policy string is read.
func (p Policy) AllowsUnverifiedTargets() bool { return p.UnverifiedTargets == "allow" }
