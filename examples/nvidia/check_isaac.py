# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Actual SDK normal/cancel proof on an already READY owned v4 rig. No mock fallback.

Not the complete BP bypass or lifecycle acceptance suite. Does not stop/recreate
the rig automatically; invoke session stop after collecting this result.

A zero after the cancel request counts only when the exercise was still ACTIVE at
that request and the endpoint latch ended because of the cancel (EXERCISE_ENDED).
A fault such as CONTROL_STALE also produces a physical zero; that is the control
case, not cancel evidence (Brev i10, 2026-10-15).
"""
import argparse
import json
import math
from pathlib import Path
from session import request,Rig
from check_managed import await_value
from state_store import read,atomic
from isaac_runtime import observed_zero

FAULT_FREE_END='EXERCISE_ENDED'


def moved(start,row):
    if row.get('authority_source')!='ISAAC_SDK' or row.get('state')!='ACTIVE' or row.get('epoch')!=start.get('epoch') or row.get('physics_tick',-1)<=start.get('physics_tick',-1):return False
    a=start.get('pose');b=row.get('pose');v=row.get('linear_velocity')
    if any(not isinstance(x,list) or len(x)!=3 or any(type(y) not in (int,float) or not math.isfinite(y) for y in x) for x in (a,b,v)):return False
    distance=math.hypot(b[0]-a[0],b[1]-a[1])
    return distance>=.001 and math.hypot(v[0],v[1])>=.005 and row.get('applied_linear_x',0)>0


def cancel_stop(before_cancel,row):
    """True only for a cancel-driven zero: ACTIVE at the request, later record, latch ended by cancel."""
    if not isinstance(before_cancel,dict) or before_cancel.get('state')!='ACTIVE':return False
    if type(row.get('seq')) is not int or type(before_cancel.get('seq')) is not int or row['seq']<=before_cancel['seq']:return False
    if row.get('epoch')!=before_cancel.get('epoch') or not observed_zero(row):return False
    return row.get('state')=='FAULT_LOCKED' and row.get('reason')==FAULT_FREE_END


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--state',type=Path,required=True);a=p.parse_args();state=a.state.resolve()
    if read(state/'prepared.json')['profile']['schema_version']!=4:raise ValueError('actual SDK v4 required')
    rig=Rig(state);rig.owned();start=rig.snapshot()
    if not observed_zero(start):raise ValueError('actual initial zero missing')
    result={'test_verdict':'FAIL','scope':'actual SDK normal/cancel only','bypass_suite':'NOT_RUN','hardware_verified':False}
    try:
        r=request(state,'exercise')
        if not r.get('request_accepted'):raise ValueError('exercise rejected')
        await_value(lambda:moved(start,rig.snapshot()),'actual horizontal pose and velocity change',6)
        result['motion_observed']=True
        before=rig.snapshot()
        result['state_at_cancel_request']=before.get('state');result['reason_at_cancel_request']=before.get('reason')
        if before.get('state')!='ACTIVE':raise ValueError('exercise ended before the cancel request: '+str(before.get('reason')))
        r=request(state,'idle')
        if not r.get('request_accepted'):raise ValueError('cancel rejected')
        await_value(lambda:cancel_stop(before,rig.snapshot()),'actual post-cancel body/wheel zero with latch reason '+FAULT_FREE_END,5)
        final=rig.snapshot();result['terminal_reason']=final.get('reason')
        result['max_horizontal_displacement_m']=math.hypot(final['pose'][0]-start['pose'][0],final['pose'][1]-start['pose'][1])
        result.update(test_verdict='PASS',stop_observed=True)
    except Exception as exc:
        result['error']=str(exc)
        try:result['terminal_reason']=rig.snapshot().get('reason')
        except Exception:pass
        try:request(state,'idle')
        except Exception:pass
    atomic(state/'public/isaac-normal-checks.json',result)
    print(json.dumps(result));return 0 if result['test_verdict']=='PASS' else 2

if __name__=='__main__':raise SystemExit(main())
