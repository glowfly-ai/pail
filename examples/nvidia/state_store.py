# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Durable local state, serialized ownership, and explicit evidence boundaries."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import tempfile
import uuid
from contextlib import contextmanager


def atomic(path, value, mode=0o600):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("symlink state")
    fd, name = tempfile.mkstemp(prefix=".next-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w") as f:
            json.dump(value, f, sort_keys=True, allow_nan=False); f.write("\n"); f.flush(); os.fsync(f.fileno())
        os.replace(name, path)
        parent = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(parent)
        finally: os.close(parent)
    finally:
        if os.path.exists(name): os.unlink(name)


def read(path):
    p = Path(path)
    if p.is_symlink(): raise ValueError("symlink state")
    return json.loads(p.read_text())


@contextmanager
def exclusive(state):
    fd = os.open(Path(state)/"controller.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def journal(state, event, data=None):
    path = Path(state)/"events.jsonl"
    rows = read_journal(state)
    entry = {"seq": len(rows)+1, "event": event, "data": data or {}}
    fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(entry, sort_keys=True, allow_nan=False)+"\n"); f.flush(); os.fsync(f.fileno())
    return entry


def read_journal(state):
    p = Path(state)/"events.jsonl"
    if not p.exists(): return []
    if p.is_symlink(): raise ValueError("symlink journal")
    text = p.read_text()
    if text and not text.endswith("\n"): raise ValueError("torn journal")
    rows = [json.loads(line) for line in text.splitlines()]
    if any(r.get("seq") != i+1 for i, r in enumerate(rows)): raise ValueError("journal sequence")
    return rows


def source_hashes(path):
    return {str(p.relative_to(path)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(Path(path).rglob('*')) if p.is_file() and '__pycache__' not in p.parts}
