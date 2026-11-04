#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""CA-17: test-only pickup injection; clearing input must NOT resurrect a plan.

Requires a fresh software rig and an explicit state seam. This is not an IMU
measurement and never claims that autonomous daemon motions are gated.
"""
import argparse,json,os,socket,time,types
from pathlib import Path
import grpc
import pail_pb2 as pb
import pail_pb2_grpc as rpc
import operator_service_pb2_grpc as op_rpc
from runner.adapters.microduck_backend import _FarSide,_MovePublisher,_GateLogTail,MicroduckBackend
from runner.mocks.mock_ai import load_issuer_signing_key
from runner.verifiers import keys,segment_chain
from core_operation_wire import submit_outcome


def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',default='/state/evidence/ca17.json');a=ap.parse_args()
 output=Path(a.output)
 if output.exists():raise RuntimeError('new output required')
 checks=[];publisher=None;phase='PRECONDITIONS';chains=[]
 far=_FarSide(os.environ.get('PAIL_DUCK_RAW','/run/duck/raw/robotd.sock'));far.start()
 tail=_GateLogTail('/run/duck/gate.ndjson');tail.start()
 public='/run/duck/pail.sock';ctl='/run/duck/state.ctl'
 def wait(pred,timeout=12):
  end=time.monotonic()+timeout
  while time.monotonic()<end:
   if pred():return
   time.sleep(.05)
  raise RuntimeError('OBSERVATION_DEADLINE:'+phase)
 def command(on):
  with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
   sock.settimeout(3);sock.connect(ctl);sock.sendall(json.dumps(dict(op='picked_up',on=on)).encode()+b'\n')
   response=json.loads(sock.makefile('rb').readline())
  if response.get('ok') is not True or response.get('picked_up')!=on:raise RuntimeError('INJECTION_NOT_CONFIRMED')
  return response
 def outcomes(start):return [e for e in tail.since(start) if e.get('kind')=='outcome']
 channel=grpc.insecure_channel(os.environ.get('PAIL_DUCK_ISSUER','issuer:50051'));stub=rpc.PailNorthboundStub(channel)
 def plan():
  p=pb.ActionPlan(plan_id='ca17-'+str(time.time_ns()));s=p.steps.add(step_id='move-1',type=pb.STEP_TWIST);s.twist.linear_x=.12;s.twist.duration_sec=25
  request=pb.SubmitActionPlanRequest(session_id='ca17',robot_id='robot-1',plan=p)
  request.operation_id=p.plan_id   # one contract: every submit carries its operation id
  r=stub.SubmitActionPlan(request,timeout=5)
  if submit_outcome(request,r)!='AUTHORIZED':raise RuntimeError('AUTHORIZATION_NOT_CONFIRMED')
  if r.status!=pb.ACCEPTED or not r.chain_id:raise RuntimeError('PLAN_NOT_ACCEPTED:'+r.rejected_reason)
  chains.append(r.chain_id);return r.chain_id
 try:
  command(False);wait(lambda:len(far.history)>2)
  old=plan();start=time.time();publisher=_MovePublisher(public,.12,0.,20.,60.);publisher.start()
  wait(lambda:any(e.get('state')=='PERMIT' and e.get('chain_id')==old for e in outcomes(start)))
  wait(lambda:any(abs(x.linear_x-.12)<1e-6 for x in far.requested_history))
  checks.append(dict(id='baseline',status='PASS',chain=old));phase='PICKUP'
  start=time.time();command(True)
  wait(lambda:any(e.get('fatal') and 'SAFETY' in e.get('reason','') for e in outcomes(start)))
  checks.append(dict(id='pickup_fatal',status='PASS'))
  phase='OLD_CHAIN_AFTER_CLEAR';command(False);time.sleep(.5);start=time.time();time.sleep(1)
  rows=outcomes(start)
  if not any(e.get('state') in ('BLOCK','ESTOP') for e in rows) or any(e.get('state')=='PERMIT' for e in rows):raise RuntimeError('OLD_CHAIN_NOT_STILL_BLOCKED')
  checks.append(dict(id='clear_does_not_resurrect',status='PASS'))
  phase='NEW_AUTHORIZATION';publisher.stop();publisher=None
  operator=types.SimpleNamespace(_last_op_nonce=None,_op_sign=load_issuer_signing_key(os.environ['PVS_OPERATOR_KEY']),_op_stub=op_rpc.OperatorServiceStub(channel))
  unlock=MicroduckBackend.operator_unlock(operator,{})
  if unlock.startswith('error:'):raise RuntimeError('OPERATOR_UNREACHABLE')
  new=plan()
  if new==old:raise RuntimeError('CHAIN_REUSED')
  start=time.time();publisher=_MovePublisher(public,.12,0.,20.,15.);publisher.start()
  wait(lambda:any(e.get('state')=='PERMIT' and e.get('chain_id')==new for e in outcomes(start)))
  checks.append(dict(id='new_authorized_chain',status='PASS',chain=new))
  publisher.stop();publisher=None;phase='JOURNAL_DETAIL';time.sleep(.5)
  ring=keys.load_keyring(os.environ['PVS_KEYRING']);verified=segment_chain.verify(os.environ['PAIL_DUCK_BLACKBOX'],keys.issuer_pubs(ring))
  if not verified.ok:raise RuntimeError('JOURNAL_NOT_VERIFIED')
  records=[]
  for r in verified.all_records:
   try:row=json.loads(r.payload)
   except (ValueError,UnicodeDecodeError):continue
   if isinstance(row,dict) and row.get('chain_id')==old and row.get('fatal') and 'picked_up' in row.get('detail',''):records.append(row)
  if not records:raise RuntimeError('PICKUP_DETAIL_NOT_JOURNALLED')
  checks.append(dict(id='journal_pickup_detail',status='PASS',count=len(records)))
  result=dict(id='CA-17',status='PASS',checks=checks,chains=chains,scope='software seam pickup injection; not physical IMU validation')
 except Exception as e:
  result=dict(id='CA-17',status='INCONCLUSIVE' if phase=='PRECONDITIONS' else 'FAIL',phase=phase,error=str(e),checks=checks,chains=chains)
 finally:
  if publisher:publisher.stop()
  try:
   result['injection_clear_receipt']=command(False)
   if phase!='PRECONDITIONS' and result['injection_clear_receipt'].get('injected',0)<1:
    result['status']='INCONCLUSIVE';result['error']='NO_INJECTED_FRAME_OBSERVED'
  except Exception:
   result['status']='INCONCLUSIVE';result['cleanup']='INJECTION_CLEAR_UNCONFIRMED'
  channel.close()
 with output.open('x') as f:json.dump(result,f,indent=2);f.write('\n')
 print(json.dumps(result),flush=True)
 return 0 if result['status']=='PASS' else 1

if __name__=='__main__':raise SystemExit(main())
