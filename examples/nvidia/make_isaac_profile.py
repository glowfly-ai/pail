# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Generate a strict candidate profile from explicit local SDK/assets. No download/run."""
import argparse
import json
import sys
from pathlib import Path
from isaac_runtime import assets_digest,missing_wheel_joints
from nvidia_profile import validate,read_json


def main():
    try:
        return generate()
    except ValueError as exc:
        # P16-L2: a refusal is one line on stderr, not a traceback.
        sys.stderr.write('make_isaac_profile: refused: %s\n'%exc)
        return 1


def generate():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--image',required=True,help='Already-loaded immutable local SDK image ID')
    p.add_argument('--version',required=True,choices=('6.0.0','6.0.1'))
    p.add_argument('--asset-dir',required=True,type=Path);p.add_argument('--usd',required=True)
    p.add_argument('--wheel-joints',required=True,nargs=2)
    p.add_argument('--wheel-radius-um',required=True,type=int);p.add_argument('--wheel-base-um',required=True,type=int)
    p.add_argument('--accept-sdk-eula',action='store_true',help='Acknowledge applicable NVIDIA SDK terms; no privacy opt-in is set')
    p.add_argument('--output',required=True,type=Path);a=p.parse_args()
    if not a.accept_sdk_eula:raise ValueError('Acknowledge SDK terms explicitly before generating a runnable profile')
    root=a.asset_dir.resolve()
    usd=Path(a.usd)
    if usd.is_absolute() or '..' in usd.parts or not (root/usd).is_file():raise ValueError('relative existing USD required')
    missing=missing_wheel_joints(root,a.usd,a.wheel_joints)
    if missing:raise ValueError('wheel joints not defined in the converted asset tree (overlay excluded): %s — see sim/assets/ASSETS.md (xacro expansion, P15-M1)'%', '.join(missing))
    data={'schema_version':4,'profile_id':'isaac-humble-headless-v4','target':'isaac-sim',
          'platform':{'arch':'x86_64','board':'none','l4t_major':0,'ros':'humble'},
          'runtime':{'mode':'isaac-headless','gpu':True},'transport':'isolated-local-dds',
          'endpoint':{'kind':'isaac-sdk','model_timeout_ms':250},'security':{'enabled':True,'strategy':'Enforce'},
          'evidence':{'hardware_verified':False,'support_status':'UNVERIFIED'},
          'resources':{'min_state_free_bytes':200*1024**3,'min_host_available_memory_bytes':32*1024**3,'basis':'estimated'},
          'sim':{'image':a.image,'version':a.version,'asset_dir':str(root),'assets_sha256':assets_digest(root),'usd':a.usd,'wheel_joints':a.wheel_joints,'wheel_radius_um':a.wheel_radius_um,'wheel_base_um':a.wheel_base_um,'eula_accepted':True}}
    validate(data,read_json(Path(__file__).parent/'profiles/schema-v4.json'))
    with a.output.open('x') as f:json.dump(data,f,indent=2);f.write('\n')
    print('Candidate profile created; actual SDK/ROS security remains UNVERIFIED')
    return 0

if __name__=='__main__':sys.exit(main())
