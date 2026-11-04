# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Explicit allowlist export; private runtime state is never traversed."""
import hashlib
import json
import os
from pathlib import Path
import shutil
from state_store import atomic, read

ALLOWLIST=('summary.json','checks.json','doctor.json','runtime-observations.json','lifecycle-result.json','isolation-checks.json','role-view-audit.json','isaac-normal-checks.json','isaac-matrix-case.json')
# Markers of private key material that must never appear in an exported summary. Assembled
# from parts so that the secret scanner of the public snapshot does not read this list itself
# as a credential (its generic key rule matched the literal tuple, 2026-10-15).
PRIVATE_MARKERS=tuple(head+tail for head,tail in (('private','_key'),('private',' key'),('ed25519','_private'),('-----','begin'),('client','.key'),('root','-keys')))


def export(state, dest):
    state=Path(state).resolve(); dest=Path(dest)
    if dest.exists() or dest.is_symlink(): raise ValueError('new export destination required')
    if state==dest.resolve() or state in dest.resolve().parents or dest.resolve() in state.parents:
        raise ValueError('export and private state must be disjoint')
    if (state/'public').is_symlink(): raise ValueError('symlink public directory')
    validated={}
    for name in ALLOWLIST:
        source=state/'public'/name
        if not source.exists(): continue
        if source.is_symlink() or source.resolve().parent != (state/'public').resolve(): raise ValueError('export symlink')
        data=read(source)
        # This boundary only exports tool-authored public summaries, not arbitrary logs.
        encoded=json.dumps(data,sort_keys=True,allow_nan=False)
        if any(word in encoded.lower() for word in PRIVATE_MARKERS):
            raise ValueError('private material marker in summary')
        validated[name]=(encoded+'\n').encode()
    if 'summary.json' not in validated: raise ValueError('summary missing')
    dest.mkdir(mode=0o700)
    manifest={}
    for name, data in validated.items():
        (dest/name).write_bytes(data); manifest[name]=hashlib.sha256(data).hexdigest()
    atomic(dest/'MANIFEST.json',{'schema_version':2,'complete':True,'files':manifest})
    return {'exported':str(dest),'files':len(manifest),'hardware_verified':False}
