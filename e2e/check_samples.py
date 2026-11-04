#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Compare stable README sample fields with a completed full bundle E2E verdict log."""
import argparse
from pathlib import Path
import re


def fields(text, verdict_log=False):
    out={}
    for key,pattern in [('issuer_keys',r'keyring trust path: mode=bundle keys=(\d+)'),('seal_version',r'config seal v(\d+)')]:
        material=text
        if verdict_log and key=='issuer_keys':
            material='\n'.join(line for line in text.splitlines() if 'issuer trusts a root-signed keyring bundle' in line)
        values=set(re.findall(pattern,material))
        if len(values)!=1:raise ValueError('expected one '+key+' value, found '+str(sorted(values)))
        out[key]=int(next(iter(values)))
    return out


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--log',required=True,type=Path);ap.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1]);a=ap.parse_args()
    try:
        observed=fields(a.log.read_text(), verdict_log=True)
        for name in ['README.md','README.ko.md']:
            documented=fields((a.root/name).read_text())
            if documented!=observed:print('DOC_SAMPLES: FAIL',name,'documented',documented,'observed',observed);return 1
    except (OSError,ValueError) as exc:print('DOC_SAMPLES: CANNOT_CHECK:',exc, 'Use a completed full --keyring bundle run log (not --a-only); if already using one, inspect missing/truncated verdicts and README fields.');return 2
    print('DOC_SAMPLES: PASS',observed);return 0

if __name__=='__main__':raise SystemExit(main())
