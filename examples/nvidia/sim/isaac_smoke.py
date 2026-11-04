# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
# API sequence follows NVIDIA Isaac Sim's Apache-2.0 add_cubes example.
# Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
"""Candidate real-SDK smoke; run with the pinned Isaac Sim python.sh, NOT mock Python.

Uses the 6.0.1 source tree's deprecated isaacsim.core.api path. Actual GPU/version
compatibility is unverified until this script is run in the selected image.
This is physics/API smoke, not PAIL authorization, ROS, video or SROS2 proof.
"""
import argparse
import json
import math
from pathlib import Path
import time


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    # Exclusive creation also protects an existing failure record.
    with args.output.open('x') as out:
        json.dump({'status':'RUNNING','started':time.time(),'support_status':'UNVERIFIED'},out)
    app=None
    result={'status':'FAIL','authority_source':'ISAAC_SDK','support_status':'UNVERIFIED',
            'coverage':{'physics_pose':False,'render_step_requested':False,'rendered_pixels':False,
                        'pail_authorization':False,'ros':False,'security':False,'physical_motion':False}}
    try:
        from isaacsim import SimulationApp
        app=SimulationApp({'headless':True})
        import numpy as np
        from isaacsim.core.api import World
        from isaacsim.core.api.objects import DynamicCuboid
        world=World(stage_units_in_meters=1.0)
        # Local plane: add_default_ground_plane fetches a remote asset and stalls in an offline container
        # (observed 2026-10-16: no result file, exit 0). Same plane the v4 endpoint uses.
        world.scene.add_ground_plane(size=10.,static_friction=.5,dynamic_friction=.5,restitution=0.)
        cube=world.scene.add(DynamicCuboid(prim_path='/PAILSmokeCube',name='pail_smoke_cube',position=np.array([0.,0.,2.]),size=.25))
        world.reset()
        initial=cube.get_world_pose()[0].tolist()
        for _ in range(120):world.step(render=True)
        final=cube.get_world_pose()[0].tolist()
        if not all(math.isfinite(v) for v in initial+final) or not final[2]<initial[2]-.1:
            raise RuntimeError('Actual physics pose change not observed')
        result.update(status='PASS',initial_pose=initial,final_pose=final,steps=120)
        result['coverage'].update(physics_pose=True,render_step_requested=True)
    except Exception as exc:
        result['error']=type(exc).__name__+': '+str(exc)
    finally:
        # Persist the verdict BEFORE closing Kit: its fast shutdown can end the process first, which
        # left the RUNNING placeholder on disk with exit 0 (2026-10-16). The close result is appended after.
        result['finished']=time.time()
        args.output.write_text(json.dumps(result,indent=2)+'\n')
        if app is not None:
            try:app.close()
            except Exception as exc:result.update(status='FAIL',cleanup_error=str(exc))
            result['closed']=time.time();args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result));return 0 if result['status']=='PASS' else 2

if __name__=='__main__':raise SystemExit(main())
