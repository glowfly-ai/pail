# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Sim-only test fixture inside the trusted SDK endpoint process.

Loaded only when the coordinator prepared the state with --fixture (meta
fixture_allowed). It exists to prove negative controls (BS-06/07 timeline pause,
play and physics reset) and the BP-11 positive control (wheel injection that
bypasses the exercise latch so the judge must detect unauthorized motion).
Such runs are marked fixture_run and never count toward a support claim.
"""
import json
import math


class Fixture:
    def __init__(self,path,meta,record):
        self.path=path;self.meta=meta;self.record=record;self.seq=0;self.inject=None

    def poll(self,world,timeline):
        try:row=json.loads(self.path.read_text())
        except (OSError,ValueError):return None
        if not isinstance(row,dict) or row.get('fixture') is not True or row.get('run_id')!=self.meta['run_id'] or row.get('generation')!=self.meta['generation']:return None
        if type(row.get('seq')) is not int or row['seq']<=self.seq:return None
        self.seq=row['seq'];action=row.get('action')
        if action=='timeline_pause':timeline.pause()
        elif action=='timeline_play':timeline.play()
        elif action=='physics_reset':world.reset()
        elif action=='inject_wheels':
            wheels=[float(w) for w in row['wheels']];ticks=int(row['ticks'])
            if len(wheels)!=2 or any(not math.isfinite(w) or abs(w)>5 for w in wheels) or not 1<=ticks<=300:raise ValueError('fixture wheel injection out of range')
            self.inject=[wheels,ticks]
        else:raise ValueError('unknown fixture action')
        self.record('FIXTURE_APPLIED',seq=self.seq,action=action,fixture=True)
        return action

    def override(self,action,ArticulationAction,np):
        """Replace the latch-derived wheel action while an injection is pending."""
        if not self.inject or self.inject[1]<=0:return action
        self.inject[1]-=1
        return ArticulationAction(joint_velocities=np.array(self.inject[0]))
