#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""CB-1 (contract I-1) for the socket transport: a requester principal must NOT be able to
connect to robotd's raw socket behind the adapter. Drops to an unprivileged uid (the shape of
`padd`/`btd`: a member of the client group, never of the adapter's group) and tries to
connect to the RAW socket. PASS = EACCES/EPERM. Connecting successfully is the bypass — FAIL.
A missing socket is neither (exit 2): "could not probe" must not read as "probe passed".

The probe changes nothing: it opens no listener, writes nothing, and the uid drop is on the
probe's own process only.
"""
import errno
import os
import socket
import sys

RAW = os.environ.get("PAIL_DUCK_RAW", "/run/duck/robotd.sock")
PUBLIC = os.environ.get("PAIL_DUCK_PUBLIC", "/run/duck/pail.sock")
UID = int(os.environ.get("PAIL_CB1_UID", "12345"))
GID = int(os.environ.get("PAIL_CB1_GID", "12345"))

if not os.path.exists(RAW):
    print(f"CB-1: raw socket {RAW} not present — cannot probe"); sys.exit(2)

# Control: the PUBLIC socket must be reachable by root before we drop (rig sanity).
try:
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); c.connect(PUBLIC); c.close()
except OSError as e:
    print(f"CB-1: public socket {PUBLIC} not reachable even as root ({e}) — rig broken"); sys.exit(2)

os.setgroups([])
os.setgid(GID)
os.setuid(UID)
# Positive control under the SAME principal. An inaccessible parent must not make
# both sockets unreachable and turn an unusable deployment into a green bypass check.
try:
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); c.connect(PUBLIC); c.close()
except OSError as e:
    print(f"CB-1: inconclusive — uid {UID} cannot reach public ingress: {e}"); sys.exit(2)
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(RAW)
    s.close()
    print(f"CB-1: FAIL — uid {UID} connected to the raw ingress {RAW} (bypass possible)")
    sys.exit(1)
except OSError as e:
    if e.errno in (errno.EACCES, errno.EPERM):
        print(f"CB-1: PASS — uid {UID} refused at {RAW} ({errno.errorcode[e.errno]})")
        sys.exit(0)
    print(f"CB-1: inconclusive — {e}"); sys.exit(2)
