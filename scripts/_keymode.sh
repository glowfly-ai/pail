# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

# shellcheck shell=bash
# Detect private key material by content, not filename. Creation-time narrowing
# complements runtime S19 checks: imported or already-existing files may bypass
# generators. The same predicate is used for narrowing and verification.

pail_is_private_key() {
  LC_ALL=C grep -qa -e '-----BEGIN .*PRIVATE KEY-----' \
    -e 'ed25519_private_key_base64' "$1"
}

# pail_private_keys <dir...> emits NUL-separated paths to private key material.
pail_private_keys() {
  local f
  while IFS= read -r -d '' f; do
    if pail_is_private_key "$f"; then printf '%s\0' "$f"; fi
  done < <(find "$@" -type f -print0 2>/dev/null)
}

# BSD and GNU stat use different flags. Failure must return nonzero, not an
# empty mode that a caller could interpret as restrictive permissions. Return
# status to the parent rather than exiting only a command-substitution subshell.

pail_mode_of() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null || return 1
}

# True if any non-owner permission bit is set; special bits are outside this predicate.
pail_mode_too_wide() {
  local m="$1"
  while [ "${#m}" -lt 3 ]; do m="0${m}"; done
  m="${m: -3}"
  [ "${m:1:1}" != "0" ] || [ "${m:2:1}" != "0" ]
}

# pail_narrow_private_keys <dir...> is called by generators and deployment scripts.
pail_narrow_private_keys() {
  local f
  while IFS= read -r -d '' f; do chmod 600 "$f"; done < <(pail_private_keys "$@")
}

# Verify permissions without silently narrowing the inspected inputs. Callers
# also pass existing source material so the rejection path is actually testable.

pail_assert_private_key_modes() {
  local prefix="$1"
  shift
  local f mode
  local -a wide=()
  while IFS= read -r -d '' f; do
    if ! mode="$(pail_mode_of "$f")" || [ -z "$mode" ]; then
      # Unreadable modes are failures too; missing stat must not disable this guard.
      wide+=("$(printf '%s  %s' '????' "${f#"${prefix}"}")")
      continue
    fi
    if pail_mode_too_wide "$mode"; then
      wide+=("$(printf '%s  %s' "$mode" "${f#"${prefix}"}")")
    fi
  done < <(pail_private_keys "$@")
  if [ "${#wide[@]}" -eq 0 ]; then
    return 0
  fi
  echo "FATAL: private key material readable beyond its owner (want 0600):" >&2
  printf '  %s\n' "${wide[@]}" >&2
  echo "  fix: chmod 600 <path>  — runtime enforcement is S19" >&2
  return 1
}
