#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Private operator state on a Linux host: trusted declaration files and durable, atomically written records.

Shared by the trust-renewal CLI (`trust_admin.py`) and the publisher's internal management helpers. A declaration is
read only when it is a regular file owned by root or the caller, not group/world writable, not behind a symlink and
within a size bound; a state record is written through a temp file, fsync'd and renamed (or hard-linked when the
record must be created exactly once), and the directory entry is fsync'd too. Nothing here starts, stops or
authorizes anything.
"""
import json
import os
import stat
import tempfile
from pathlib import Path

class OpsStateError(RuntimeError):
    """A refusal by code. `field` names the declaration or the command argument the refusal is about — never a path:
    operational private paths are not diagnostic text, and the name is enough to find the place (P024-M2)."""
    def __init__(self,code,field=None):
        super().__init__(code);self.code=code;self.field=field

def load_private(path,max_bytes=65536,field=None):
    p=Path(path)
    # P024T-L3: a declaration named on a command line is an absolute path, like the other inputs of the trust tools
    # (the guide says so, and a relative --profile used to be accepted). Callers that name no item are unchanged.
    if field is not None and not p.is_absolute():raise OpsStateError('ABSOLUTE_PATH_REQUIRED',field)
    for part in (p,*p.parents):
        if part.is_symlink():raise OpsStateError('SYMLINK_DECLARATION',field)
    st=p.stat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid not in (0,os.geteuid()) or st.st_mode&0o022:
        raise OpsStateError('UNTRUSTED_DECLARATION_OWNER',field)
    if st.st_size>max_bytes:raise OpsStateError('DECLARATION_TOO_LARGE',field)
    return json.loads(p.read_text())

def fsync_dir(p):
    fd=os.open(str(p),os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)

def write_state(path,data,exclusive=False):
    raw=(json.dumps(data,sort_keys=True)+'\n').encode()
    if len(raw)>1<<20:raise OpsStateError('STATE_TOO_LARGE')
    fd,temp=tempfile.mkstemp(prefix='.state-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
        if exclusive:os.link(temp,path)
        else:os.replace(temp,path)
        fsync_dir(path.parent)
    finally:
        if os.path.exists(temp):os.unlink(temp)

def location(root,op,field=None):
    """The record path of operation `op` under the private state directory `root` (created 0700, owned by the caller)."""
    if not isinstance(op,str) or not 1<=len(op)<=128 or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_' for c in op):raise OpsStateError('OPERATION_ID')
    root=Path(root)
    if field is not None and not root.is_absolute():raise OpsStateError('ABSOLUTE_PATH_REQUIRED',field)
    for part in (root,*root.parents):
        if part.is_symlink():raise OpsStateError('SYMLINK_STATE',field)
    root.mkdir(mode=0o700,parents=True,exist_ok=True)
    st=root.stat()
    if root.is_symlink() or st.st_uid!=os.geteuid() or st.st_mode&0o077:raise OpsStateError('PRIVATE_STATE_REQUIRED',field)
    return root/(op+'.json')
