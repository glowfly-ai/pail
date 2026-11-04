# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Read-only identity digest probe inside the owned prepare container; no key output."""
import hashlib
import json
from pathlib import Path

state=Path('/fleet');meta=json.loads((state/'fleet-run.json').read_text());out={}
for row in meta['robots']:
    base=state/'robots'/row['key']/'private'
    values={}
    for name in ('config','agent-key'):
        for p in sorted((base/name).rglob('*')):
            if p.is_symlink():raise RuntimeError('PRIVATE_IDENTITY_SYMLINK')
            if p.is_file():values[str(p.relative_to(base))]=hashlib.sha256(p.read_bytes()).hexdigest()
    if not values:raise RuntimeError('PRIVATE_IDENTITY_MISSING')
    out[row['robot_id']]=values
print(json.dumps(out,sort_keys=True))
