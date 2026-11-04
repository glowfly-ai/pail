#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
#
# MD-3 path check without systemd (LLD §12 MD-3: "컨테이너에서 systemd 없이 경로만 검증").
#
#   check.sh --binary <pail-duckd> --lib <libpail_gate.so> --updater-toml <upstream deploy/updater.toml>
#
# Installs into a fresh staging root with install.sh --root, then verifies:
#   C1  every Exec*= path the two units name exists in the tree (adapter binary; robotd's
#       path is upstream's and is reported, not asserted — the board has it, the tree does not)
#   C2  the drop-in resets ExecStart (empty line) before overriding it, sets Group=pail and
#       RuntimeDirectoryMode=0750, and names the raw socket the adapter's --raw names
#   C3  the adapter unit's --public/--raw/--policy/--keyring/--skills/--evidence and
#       EnvironmentFile/LD_LIBRARY_PATH paths agree with the files the installer placed
#       (policy/keyring are provisioned separately — reported as "provisioned elsewhere")
#   C4  updater.toml robot_socket == the raw socket, and a second install leaves it alone
#   C5  `pail-duckd --help` from the staged binary lists every flag the unit uses
#   C6  `systemd-analyze verify` when available (Ubuntu images have it without a running
#       systemd); reported as "not available" otherwise — never as passed
# Exit 1 on any failed check. Output is one line per check, PASS/FAIL/INFO.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
BINARY=""; LIB=""; UPD=""; WORK=""
while [ $# -gt 0 ]; do
    case "$1" in
        --workdir) WORK="$2"; shift 2 ;;
        --binary) BINARY="$2"; shift 2 ;;
        --lib) LIB="$2"; shift 2 ;;
        --updater-toml) UPD="$2"; shift 2 ;;
        *) echo "check.sh: unknown argument $1" >&2; exit 2 ;;
    esac
done
[ -n "$BINARY" ] && [ -n "$LIB" ] && [ -n "$UPD" ] || { echo "check.sh: --binary, --lib, --updater-toml are required" >&2; exit 2; }

if [ -n "$WORK" ]; then
    if [ -e "$WORK" ] || [ -L "$WORK" ]; then echo "check.sh: use a new workdir; prior evidence is preserved" >&2; exit 2; fi
    mkdir -m 0700 "$WORK" || exit 2
    STAGE=$(cd "$WORK" && pwd)
else
    STAGE=$(mktemp -d /tmp/pail-md3.XXXXXX)
fi
printf 'STAGE=%s\n' "$STAGE"
fails=0
notrun=0
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; fails=$((fails + 1)); }
info() { printf 'INFO  %s\n' "$*"; }
not_run() { notrun=$((notrun + 1)); printf 'NOT_RUN  %s\n' "$*"; }

mkdir -p "$STAGE/etc/robot"
cp "$UPD" "$STAGE/etc/robot/updater.toml"
if ! sh "$HERE/install.sh" --root "$STAGE" --binary "$BINARY" --lib "$LIB" > "$STAGE/install.log" 2>&1; then
    cat "$STAGE/install.log"; fail "install.sh --root failed"; echo "checks failed: $fails"; exit 1
fi

UNIT="$STAGE/etc/systemd/system/pail-duckd.service"
DROP="$STAGE/etc/systemd/system/robotd.service.d/pail.conf"

# ---- C1: Exec paths ---------------------------------------------------------------------
exec_line() { # file → the logical ExecStart value (continuation lines joined)
    awk '/^ExecStart=/{v=$0; sub(/^ExecStart=/,"",v); while (v ~ /\\$/) { sub(/\\$/,"",v); getline; v=v $0 } print v}' "$1"
}
adapter_exec=$(exec_line "$UNIT")
adapter_bin=$(printf '%s' "$adapter_exec" | awk '{print $1}')
if [ -x "$STAGE$adapter_bin" ]; then pass "C1 adapter ExecStart binary staged: $adapter_bin"; else fail "C1 adapter ExecStart binary missing in tree: $adapter_bin"; fi
robotd_exec=$(exec_line "$DROP" | tail -1)
info "C1 robotd ExecStart (upstream's path, provided by the board): $robotd_exec"

# ---- C2: drop-in shape ------------------------------------------------------------------
if grep -qx 'ExecStart=' "$DROP"; then pass "C2 drop-in resets ExecStart before overriding"; else fail "C2 drop-in has no empty ExecStart= reset line (systemd would append, not replace)"; fi
if grep -qx 'Group=pail' "$DROP"; then pass "C2 drop-in Group=pail"; else fail "C2 drop-in lacks Group=pail"; fi
if grep -qx 'RuntimeDirectoryMode=0750' "$DROP"; then pass "C2 drop-in RuntimeDirectoryMode=0750"; else fail "C2 drop-in lacks RuntimeDirectoryMode=0750"; fi
raw_from_drop=$(printf '%s' "$robotd_exec" | sed -n 's/.*--socket[[:space:]]\{1,\}\([^[:space:]]*\).*/\1/p')
raw_from_unit=$(printf '%s' "$adapter_exec" | sed -n 's/.*--raw[[:space:]]\{1,\}\([^[:space:]]*\).*/\1/p')
if [ -n "$raw_from_drop" ] && [ "$raw_from_drop" = "$raw_from_unit" ]; then pass "C2 raw socket agrees: drop-in --socket == unit --raw ($raw_from_drop)"; else fail "C2 raw socket disagrees: drop-in '$raw_from_drop' vs unit '$raw_from_unit'"; fi
case "$raw_from_drop" in /run/robotd/*) pass "C2 raw socket lives inside RuntimeDirectory=robotd (/run/robotd)";; *) fail "C2 raw socket is outside /run/robotd — the 0750 directory would not protect it";; esac

# ---- C3: unit paths vs installed files -----------------------------------------------------
flag() { printf '%s' "$adapter_exec" | sed -n "s/.*$1[[:space:]]\{1,\}\([^[:space:]]*\).*/\1/p"; }
for f in --policy --keyring; do
    p=$(flag "$f"); [ -n "$p" ] && info "C3 $f $p — provisioned elsewhere (sealed configuration), not asserted here"
done
p=$(flag --skills); if [ -n "$p" ] && [ -f "$STAGE$p" ]; then pass "C3 --skills table staged: $p"; else fail "C3 --skills path not staged: '$p'"; fi
p=$(flag --public); case "$p" in /run/robotd.sock) pass "C3 --public is the path clients already dial ($p)";; *) fail "C3 --public is not /run/robotd.sock: '$p'";; esac
p=$(flag --evidence); case "$p" in /run/pail/*) pass "C3 --evidence lives in RuntimeDirectory=pail ($p)";; *) fail "C3 --evidence outside /run/pail: '$p'";; esac
envf=$(sed -n 's/^EnvironmentFile=-\{0,1\}//p' "$UNIT"); if [ -n "$envf" ] && [ -f "$STAGE$envf" ]; then pass "C3 EnvironmentFile staged: $envf"; else fail "C3 EnvironmentFile not staged: '$envf'"; fi
ld=$(sed -n 's/^Environment=LD_LIBRARY_PATH=//p' "$UNIT"); if [ -n "$ld" ] && [ -f "$STAGE$ld/libpail_gate.so" ]; then pass "C3 libpail_gate.so staged under LD_LIBRARY_PATH: $ld"; else fail "C3 libpail_gate.so not under LD_LIBRARY_PATH '$ld'"; fi
if grep -q '^RuntimeDirectory=pail$' "$UNIT"; then pass "C3 RuntimeDirectory=pail declared"; else fail "C3 RuntimeDirectory=pail missing"; fi
if grep -q '^Group=pail$' "$UNIT" && grep -q '^SupplementaryGroups=robot$' "$UNIT"; then pass "C3 Group=pail + SupplementaryGroups=robot"; else fail "C3 unit groups are not pail + robot"; fi
if grep -q '^\(ExecStart=\|[[:space:]]\).*--public-group robot' "$UNIT"; then pass "C3 public socket handed to group by NAME (--public-group robot)"; else fail "C3 unit does not hand the public socket to the robot group by name"; fi

# ---- C4: updater.toml -------------------------------------------------------------------
if grep -Eq '^[[:space:]]*robot_socket[[:space:]]*=[[:space:]]*"/run/robotd/raw.sock"' "$STAGE/etc/robot/updater.toml"; then pass "C4 updater.toml robot_socket -> raw socket"; else fail "C4 updater.toml robot_socket not patched"; fi
before=$(cksum "$STAGE/etc/robot/updater.toml"); sh "$HERE/patch_updater_toml.sh" "$STAGE/etc/robot/updater.toml" > /dev/null; after=$(cksum "$STAGE/etc/robot/updater.toml")
if [ "$before" = "$after" ]; then pass "C4 second patch is a no-op (idempotent)"; else fail "C4 second patch changed the file"; fi
grep -v '^[[:space:]]*robot_socket' "$UPD" > "$STAGE/upd.a"; grep -v '^[[:space:]]*robot_socket' "$STAGE/etc/robot/updater.toml" > "$STAGE/upd.b"
if cmp -s "$STAGE/upd.a" "$STAGE/upd.b"; then pass "C4 nothing but robot_socket changed in updater.toml"; else fail "C4 updater.toml changed outside robot_socket"; fi

# ---- C5: staged executable and loader -----------------------------------------------------
if command -v python3 >/dev/null 2>&1; then
    python3 "$HERE/check_runtime.py" --binary "$STAGE$adapter_bin" \
        --libdir "$STAGE/opt/pail/lib" --unit "$UNIT" --report "$STAGE/C5.json" > "$STAGE/C5.log" 2>&1
    rc=$?
    cat "$STAGE/C5.log"
    case "$rc" in
        0) pass "C5 staged loader and unit flags verified" ;;
        2) not_run "C5 unsupported host/architecture; see C5.json (not a loader-success claim)" ;;
        *) fail "C5 staged executable/loader failed; see C5.json and C5.log" ;;
    esac
else
    not_run "C5 python3 unavailable; staged ELF/loader/flags not verified"
fi

# ---- C6: real vendor targets/slices, without a running systemd -----------------------------
if command -v python3 >/dev/null 2>&1; then
    python3 "$HERE/check_systemd.py" --stage "$STAGE" --report "$STAGE/C6.json" > "$STAGE/C6.log" 2>&1
    rc=$?
    cat "$STAGE/C6.log"
    case "$rc" in
        0) pass "C6 unchanged adapter unit verified with real distribution target/slice definitions" ;;
        2) not_run "C6 systemd tool/distribution definitions unavailable; see C6.json" ;;
        *) fail "C6 adapter unit or verification environment failed; see C6.json and C6.log" ;;
    esac
else
    not_run "C6 python3 unavailable; adapter unit static verification not run"
fi
info "C6 does not verify upstream robotd unit, board enablement/generators, or live service startup/update behavior"

# Keep the exact staged files and diagnostics, including failures, for inspection.
status=PASS; rc=0
if [ "$fails" != 0 ]; then status=FAIL; rc=1
elif [ "$notrun" != 0 ]; then status=PASS_WITH_LIMITATIONS
fi
printf '{"schema_version":1,"status":"%s","failed":%s,"not_run":%s,"scope":"board_free_paths_and_adapter_unit_static","unverified":["upstream robotd unit and board enablement","live service startup, drop-in application and updates","physical hardware"]}\n' "$status" "$fails" "$notrun" > "$STAGE/result.json"
printf 'MD3_RESULT='; cat "$STAGE/result.json"
printf 'Evidence retained: %s\n' "$STAGE"
exit "$rc"
