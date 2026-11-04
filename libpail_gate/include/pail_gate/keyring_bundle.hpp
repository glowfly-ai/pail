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
// trust anchor and stays fail-closed at token verification. A new bundle is
// applied by restarting the gate (§6.3 decision: restart-based application).

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
