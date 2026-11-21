// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "pail_gate/strict_verify.hpp"

namespace pail_pep_gate {

// KM2-1 (KM LLD §6.3): signed keyring bundle loader, C++ gate side.
// Semantics mirror the Go loader (internal/crypto/keyring_bundle.go):
//   1) root ed25519 signature over the EXACT payload bytes carried in
//      payload_b64 (no re-serialization),
//   2) bundle_version not below the persisted floor (rollback defense —
//      equal-version reload is a normal restart, only smaller is rejected),
//   3) expiry and remaining-validity ceiling (PAIL_KEYRING_MAX_LIFETIME_SEC;
//      C++ default 86400 seconds, explicit malformed/nonpositive values refuse).
// Every failure means "no keyring from this bundle" — the gate then has no
// trust anchor and stays fail-closed at token verification.
//
// SEC-H02: a running gate takes up a newer bundle by itself (ApplyPlacedBundle
// below, through the same checks as a start) and stops judging with a bundle whose
// expiry has passed. A restart still loads whatever is placed, as before.
//
// Format rules of the bundle path (parity with the Go loader, pinned by the shared
// vectors tests/golden/keyring_bundle/vectors.json):
//   - envelope, payload and entries are read by shape, not by text search: a member
//     the format does not define, a member name given twice, or content after the
//     envelope object refuses the bundle;
//   - an entry without a role refuses the bundle (it used to become an issuer key);
//     the same key_id twice in one list refuses the bundle;
//   - a token trust anchor is an entry whose role is exactly "issuer". Any other
//     role — operator, burst, the reserved journal and anchor, a role this reader
//     does not know — is loaded and trusted for nothing.

// Reads a bare-base64 root public key file (surrounding whitespace tolerated).
// Returns false and fills reason on failure.
bool ReadRootPubFile(const std::string &path,
                     std::vector<unsigned char> *out,
                     std::string *reason);

// Verify + rollback + expiry + persist accepted version, then return the
// issuer keyring (only role=="issuer" or role-absent entries become token
// trust anchors, same rule as LoadKeyringJSON).
// state_path stores {"last_version":N}; a missing file means no floor yet.
Keyring LoadKeyringBundle(const std::string &bundle_path,
                          const std::vector<unsigned char> &root_pub,
                          const std::string &state_path,
                          std::string *reason);

// SEC-H02 — taking up a placed bundle while the gate runs.
//
// Reads the bundle at current->source.bundle_path and puts it through the load
// checks (root signature, format, version floor, expiry, validity ceiling, the
// production rules recorded in the source):
//   Refused    a check failed; *current is untouched and `reason` names the check
//              (a version below the floor is ERR_BUNDLE_ROLLBACK)
//   Unchanged  the placed version is the version in force — also when its content
//              differs; nothing to do, as for a restart on an unchanged bundle
//   Applied    the placed version is higher: the floor is written first, then
//              *current is replaced as a whole. A bundle that carries no issuer key
//              is applied too: revoking the last issuer key means "refuse everything".
// A keyring that did not come from a bundle (unsigned-dev) is always Unchanged.
enum class TrustApply { Unchanged, Applied, Refused };
struct TrustApplyResult {
  TrustApply outcome{TrustApply::Unchanged};
  std::string reason;
  uint64_t version{0};          // version in force after the call
  long long expires_at_unix{0}; // expiry in force after the call
};
TrustApplyResult ApplyPlacedBundle(Keyring *current);

// Trust-path selector (parity with Go LoadTrustedKeyringFromEnv):
//   PAIL_KEYRING_MODE      "" | "bundle"  (default: signed bundle required)
//                          "unsigned-dev" (legacy unsigned keyring, dev only)
//   PAIL_KEYRING_BUNDLE    bundle path (default: dir(legacy)/keyring_bundle.json)
//   PAIL_ROOT_PUBKEY_FILE  base64 root public key file (required in bundle mode)
//   PAIL_KEYRING_STATE     version-floor state file
//                          (default: dir(bundle)/keyring_bundle.state.json;
//                          deployments must point this at a persistent
//                          writable path or the rollback floor resets with
//                          the container)
// mode is always filled so the caller can log which trust path was taken.
//
// SEC-H02 — this selector reads the profile (PAIL_PROFILE; anything but "dev" is
// production) and applies two production rules that the path-taking
// LoadKeyringBundle above does not:
//   - a missing state file is refused (ERR_BUNDLE_STATE:missing) and none is
//     created: a first install writes the floor explicitly
//     (`pail-keyring-sign init-floor`), so that a lost state file cannot bring a
//     bundle from before a revocation back;
//   - an undeclared PAIL_KEYRING_MAX_LIFETIME_SEC is refused (ERR_BUNDLE_POLICY).
// The dev profile keeps the first-load behaviour and the 86400 s default.
Keyring LoadTrustedKeyring(const std::string &legacy_path,
                           std::string *mode,
                           std::string *reason);

// DC-10 / C3-C7 : cross-restart wall-clock rewind floor.
// The monotonic baseline dies with the process, so a reboot with a rewound
// clock would start a fresh baseline and never notice. The last known wall
// time is persisted in the SAME state file as the bundle version floor —
// a second state file would repeat the F-KEY-07 permission work per file.
// The floor rides the bundle trust path's lifecycle (bundle mode only):
// unsigned-dev has no version floor either.

// Resolves the state-file path exactly as LoadTrustedKeyring does
// (PAIL_KEYRING_STATE, else dir(PAIL_KEYRING_BUNDLE or dir(legacy)/
// keyring_bundle.json)/keyring_bundle.state.json). Factored out so the node's
// wall-floor check reads the same file the version floor writes.
std::string KeyringStatePathFromEnv(const std::string &legacy_path);

// 4-valued on purpose (H-B2): "no floor yet" and "could not read the floor"
// must not collapse into one answer. A pre-DC10 state file carries only
// last_version — that is NoFloor, not an error. Unreadable/garbled/negative
// is StateError: a rewind cannot be ruled out, so the caller must refuse.
enum class WallFloor { NoFloor, Ok, Rewind, StateError };

WallFloor CheckWallFloor(const std::string &state_path, int64_t boot_wall_ms);

// Merged write: preserves last_version (and any parseable floor already
// present). Returns false on any read/parse/write failure — a floor that
// cannot be persisted must refuse startup, or the NEXT boot inherits an
// open rewind window.
bool PersistWallFloor(const std::string &state_path, int64_t wall_ms);

}  // namespace pail_pep_gate
