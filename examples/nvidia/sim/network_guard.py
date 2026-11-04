# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Reject unexpected TCP management listeners in the private reference namespace.

Not a complete UDP/SDK extension inventory or defense against host administrators.
Only existing mTLS agent/Issuer listeners and Docker's 127.0.0.11 DNS are allowed.
"""
from pathlib import Path


def unexpected_tcp(tables):
    unexpected=[]
    for family,text in tables.items():
        for line in text.splitlines()[1:]:
            fields=line.split()
            if not fields:continue
            if len(fields)<4:raise ValueError('unparseable TCP inventory')
            if fields[3]!='0A':continue
            address,port=fields[1].rsplit(':',1);port=int(port,16)
            if family=='tcp' and address=='0B00007F':continue  # Docker embedded DNS only
            if port not in (50051,50061):unexpected.append({'family':family,'address':address,'port':port})
    return unexpected


def listeners(tables):
    """Every listening TCP socket in the namespace (evidence inventory, not a verdict)."""
    found=[]
    for family,text in tables.items():
        for line in text.splitlines()[1:]:
            fields=line.split()
            if len(fields)>=4 and fields[3]=='0A':
                address,port=fields[1].rsplit(':',1);found.append({'family':family,'address':address,'port':int(port,16)})
    return found


def require_no_management_listener():
    tables={family:Path('/proc/net',family).read_text() for family in ('tcp','tcp6')}
    bad=unexpected_tcp(tables)
    if bad:raise ValueError('Unexpected SDK/namespace TCP listener: '+repr(bad))
