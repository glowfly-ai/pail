// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package burst

// BeaconAddresses reports whether a relay event tagged with robot id target
// concerns the robot self. It is the one rule both ends of the relay apply:
// the issuer's relay filters the stream it sends to a subscribing agent, and
// the agent refuses to act on anything that slipped through (an older relay
// forwards every event to every subscriber).
//
// The rule:
//
//   - CHECKPOINT is a ledger marker, not a statement about any robot. The
//     issuer tags it with its own configured robot id (a single-robot default
//     that predates fleets), so the tag carries no scope: every agent takes it
//     and re-broadcasts it for its local observers.
//   - An empty target is fleet-wide: an emitter that names no robot addresses
//     all of them.
//   - Otherwise the event concerns exactly the robot it names.
//
// Measured 2026-10-01 (OI-02): without this rule one robot's CHAIN_REVOKED or
// ESTOP made every other agent in the fleet drop its delegated window and
// declare a census, and every agent re-signed the foreign event as its own
// burst. Fail-closed, but each foreign revoke cost the other robots a window,
// a LEASE_RETRACTED record and one gate recheck answered from nothing.
func BeaconAddresses(event byte, target, self string) bool {
	if event == EventCheckpoint {
		return true
	}
	return target == "" || target == self
}
