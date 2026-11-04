#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
#
# Install pail-duckd on a Microduck board (LLD §9 / MD-3). Idempotent; run as root.
#
#   install.sh --binary <pail-duckd> --lib <libpail_gate.so> [--root <dir>] [--no-systemd]
#
# Puts in place, under --root (default /):
#   /opt/pail/bin/pail-duckd                         the adapter
#   /opt/pail/lib/libpail_gate.so                     the decision library (AD-1)
#   /opt/pail/share/doc/INSTALL.md                    this procedure
#   /etc/systemd/system/pail-duckd.service            the adapter's unit
#   /etc/systemd/system/robotd.service.d/pail.conf    moves robotd behind the adapter
#   /usr/lib/sysusers.d/pail.conf                     the `pail` group
#   /etc/pail/pail-duckd.env                          environment (kept if present)
#   /etc/pail/duck_skills.yaml                        skill table (kept if present)
#   /etc/robot/updater.toml                           robot_socket patched to the raw socket
# and, unless --no-systemd or no systemd is running:
#   systemd-sysusers · systemctl daemon-reload · enable pail-duckd · restart robotd (moves
#   its socket) · start pail-duckd.
#
# What it does NOT do: write policy.yaml or the keyring (sealed configuration, provisioned
# by the PAIL issuer side), and it never touches upstream's robotd.service file itself —
# the drop-in is the whole change (R1, INSTALL.md §4).
#
# --root <dir> installs into a staging tree with no systemd calls — the container check
# (deploy/check.sh) runs the same script this way and then verifies every path the units
# name exists in the tree.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=""
BINARY=""
LIB=""
NO_SYSTEMD=0
SKILLS=""
while [ $# -gt 0 ]; do
    case "$1" in
        --root) ROOT="$2"; shift 2 ;;
        --skills) SKILLS="$2"; shift 2 ;;
        --binary) BINARY="$2"; shift 2 ;;
        --lib) LIB="$2"; shift 2 ;;
        --no-systemd) NO_SYSTEMD=1; shift ;;
        -h|--help) sed -n '5,30p' "$0"; exit 0 ;;
        *) echo "install.sh: unknown argument $1 (the tree was not touched)" >&2; exit 2 ;;
    esac
done
[ -n "$BINARY" ] || { echo "install.sh: --binary <pail-duckd> is required" >&2; exit 2; }
[ -n "$LIB" ] || { echo "install.sh: --lib <libpail_gate.so> is required" >&2; exit 2; }
[ -f "$BINARY" ] || { echo "install.sh: $BINARY is not a file" >&2; exit 2; }
if [ -z "$SKILLS" ]; then
    if [ -f "$HERE/duck_skills.yaml" ]; then SKILLS="$HERE/duck_skills.yaml"; else SKILLS="$HERE/../../../config/duck_skills.yaml"; fi
fi
[ -f "$SKILLS" ] || { echo "install.sh: --skills must name an available skill table" >&2; exit 2; }
[ -f "$LIB" ] || { echo "install.sh: $LIB is not a file" >&2; exit 2; }
if [ -n "$ROOT" ]; then NO_SYSTEMD=1; fi
if [ ! -d "$ROOT/run/systemd/system" ]; then NO_SYSTEMD=1; fi
case "$ROOT" in *'|'*) echo "install.sh: invalid staging path" >&2; exit 2;; esac
if [ "$(printf '%s' "$ROOT" | wc -l | tr -d ' ')" != 0 ]; then echo "install.sh: newline in staging path" >&2; exit 2; fi
say() { printf '==> %s\n' "$*"; }

inst() { # mode src dst
    mkdir -p "$(dirname "$3")"
    if [ -L "$3" ]; then echo "Refusing to overwrite symlink: $3" >&2; exit 2; fi
    if [ -f "$3" ]; then
        BACKUP="$ROOT/var/lib/pail/install-backups/$STAMP$3"
        mkdir -p "$(dirname "$BACKUP")"
        cp -p "$3" "$BACKUP"
        printf 'old|%s|%s\n' "$3" "$BACKUP" >> "$LEDGER"
    else
        printf 'new|%s|\n' "$3" >> "$LEDGER"
    fi
    cp "$2" "$3.tmp.$$" && chmod "$1" "$3.tmp.$$" && mv "$3.tmp.$$" "$3"
}
keep_or_install() { # mode src dst — never overwrite operator-edited configuration
    if [ -f "$3" ]; then say "keeping existing $3"; else inst "$1" "$2" "$3"; fi
}

STAMP=$(date -u +%Y%m%dT%H%M%SZ)-$$
TXN="$ROOT/var/lib/pail/install-backups/$STAMP"
mkdir -p "$TXN"
LEDGER="$TXN/files.tsv"
: > "$LEDGER"
rollback() {
    rc=$1
    if [ "$rc" -ne 0 ]; then
        say "installation failed; restoring the files changed by this transaction"
        while IFS='|' read -r kind target backup; do
            if [ "$kind" = old ]; then cp -p "$backup" "$target" || true
            elif [ "$kind" = new ]; then rm -f "$target" || true
            fi
        done < "$LEDGER"
        say "rollback files recorded in $LEDGER; inspect service state before resuming hardware"
    fi
}
trap 'rollback $?' 0
say "binary and library"
inst 0755 "$BINARY" "$ROOT/opt/pail/bin/pail-duckd"
inst 0644 "$LIB" "$ROOT/opt/pail/lib/libpail_gate.so"
inst 0644 "$LIB" "$ROOT/opt/pail/lib/libpail_gate.so.1"
inst 0644 "$HERE/INSTALL.md" "$ROOT/opt/pail/share/doc/INSTALL.md"

say "units"
inst 0644 "$HERE/systemd/pail-duckd.service" "$ROOT/etc/systemd/system/pail-duckd.service"
inst 0644 "$HERE/systemd/robotd.service.d/pail.conf" "$ROOT/etc/systemd/system/robotd.service.d/pail.conf"
inst 0644 "$HERE/sysusers.d/pail.conf" "$ROOT/usr/lib/sysusers.d/pail.conf"

say "configuration (kept if present)"
mkdir -p "$ROOT/etc/pail"
keep_or_install 0640 "$HERE/pail-duckd.env" "$ROOT/etc/pail/pail-duckd.env"
keep_or_install 0644 "$SKILLS" "$ROOT/etc/pail/duck_skills.yaml"

say "updater.toml → raw socket"
if [ -f "$ROOT/etc/robot/updater.toml" ]; then
    BACKUP="$ROOT/var/lib/pail/install-backups/$STAMP/updater.toml"
    mkdir -p "$(dirname "$BACKUP")"; cp -p "$ROOT/etc/robot/updater.toml" "$BACKUP"
    printf 'old|%s|%s\n' "$ROOT/etc/robot/updater.toml" "$BACKUP" >> "$LEDGER"
fi
sh "$HERE/patch_updater_toml.sh" "$ROOT/etc/robot/updater.toml"

if [ "$NO_SYSTEMD" = 1 ]; then
    say "no systemd calls (staging root or not under systemd) — files are in place"
    exit 0
fi

say "systemd"
systemd-sysusers
systemctl daemon-reload
systemctl enable pail-duckd.service
# robotd must move first: the adapter's S27 check reads the raw socket's mode/gid, and the
# public path must be free before the adapter binds it.
systemctl restart robotd.service
systemctl start pail-duckd.service
say "done — check: systemctl status pail-duckd; journalctl -u pail-duckd | grep -E 'S27|S28|S29|serving'"
