#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Issuer-side helper for the live demo, run with `docker compose exec issuer python …`.
Prints one JSON line. The default preview uses isolated plaintext; the fleet mTLS
profile loads its own client leaf and verifies the server. The host console never
receives private keys or reaches the issuer directly.

  submit  --steps '[{"linear":0.1,"angular":0,"duration":10}]' [--target box-12]
  skill   --name wave [--classes NONE] [--duration 3]
  cancel  --plan ID
  unlock                       (OperatorService.Unlock signed with the operator key)
  verify                       (blackbox_verify over the issuer's journal)
  status
"""
import argparse, base64, json, os, subprocess, sys, time, uuid
import grpc
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'common'))
# The image provides common helpers; mounted fleet references also carry a local copy.
sys.path.insert(0, '/opt/pail/common')
from diagnostics import transport
from core_operation_wire import check_no_contract_setting,submit_outcome,cancel_outcome
import pail_pb2 as pb
import pail_pb2_grpc as rpc

ISSUER = os.environ.get('PAIL_DEMO_ISSUER', '127.0.0.1:50051')
ROBOT = os.environ.get('PAIL_ROBOT_ID', 'robot-1')
CLASSES = {'MOVE': pb.ACTION_CLASS_MOVE, 'MANIPULATE': pb.ACTION_CLASS_MANIPULATE, 'ACTUATE': pb.ACTION_CLASS_ACTUATE, 'NONE': pb.ACTION_CLASS_NONE}


def channel():
    if os.environ.get('PAIL_GRPC_TLS', 'off') == 'off':
        return grpc.insecure_channel(ISSUER)
    from pathlib import Path
    ca = Path(os.environ.get('PAIL_GRPC_CA', '/etc/pail/grpc_certs/ca.crt')).read_bytes()
    cert = Path(os.environ.get('PAIL_GRPC_CLIENT_CERT', '/etc/pail/grpc_certs/client.crt')).read_bytes()
    key = Path(os.environ.get('PAIL_GRPC_CLIENT_KEY', '/etc/pail/grpc_certs/client.key')).read_bytes()
    return grpc.secure_channel(ISSUER, grpc.ssl_channel_credentials(ca, key, cert))


def denial(d):
    return {'code': d.reason_code, 'detail': d.detail, 'disposition': pb.Disposition.Name(d.disposition) if d.disposition else '',
            'exceeded': [{'name': e.name, 'requested': e.requested, 'max': e.max} for e in d.exceeded]}


def token_view(t):
    if not t.action_token_bytes:raise ValueError("SIGNED_TOKEN_BYTES_MISSING")
    a = pb.ActionToken.FromString(t.action_token_bytes)
    g = [{'name': x.name, 'max': x.max} for x in a.constraints.guardrails] if a.HasField('constraints') else []
    return {'id': a.token_id, 'robot_id': a.robot_id, 'plan_id': a.plan_id, 'chain': a.chain_id, 'skill': a.skill, 'schema_version': a.schema_version,
            'constraints': {'guardrails': g}, 'target': a.target_object_id}


def submit_plan(plan):
    stub = rpc.PailNorthboundStub(channel())
    req=pb.SubmitActionPlanRequest(session_id='demo-console',robot_id=ROBOT,plan=plan)
    check_no_contract_setting();req.operation_id=plan.plan_id
    r=stub.SubmitActionPlan(req,timeout=10)
    outcome=submit_outcome(req,r)
    out = {'plan': plan.plan_id, 'status': pb.SubmitStatus.Name(r.status), 'chain': r.chain_id, 'rejected': r.rejected_reason,
           'tokens': [token_view(t) for t in r.tokens], 'operation_outcome':outcome, 'dispatch_allowed':outcome=='AUTHORIZED', 'operation_id':req.operation_id or plan.plan_id}
    if r.HasField('denial'):
        out['denial'] = denial(r.denial)
    return out


def submit(a):
    plan = pb.ActionPlan(plan_id=a.plan_id or 'demo-' + uuid.uuid4().hex[:12])
    a.plan_id=plan.plan_id
    for i, s in enumerate(json.loads(a.steps)):
        st = plan.steps.add(step_id='s%d' % (i + 1), type=pb.STEP_TWIST)
        st.twist.linear_x = float(s.get('linear', 0))
        st.twist.angular_z = float(s.get('angular', 0))
        st.twist.duration_sec = float(s['duration'])
        if a.target:
            st.target_object_id = a.target
    return submit_plan(plan)


def skill(a):
    plan = pb.ActionPlan(plan_id=a.plan_id or 'demo-' + uuid.uuid4().hex[:12])
    a.plan_id=plan.plan_id
    st = plan.steps.add(step_id='s1', type=pb.STEP_CUSTOM)
    st.action.name = a.name
    st.action.classes.extend(CLASSES[c] for c in a.classes.split(',') if c)
    st.action.params_json = b'{}'
    st.twist.duration_sec = float(a.duration)
    if a.target:
        st.target_object_id = a.target
    return submit_plan(plan)


def cancel(a):
    stub = rpc.PailNorthboundStub(channel())
    req=pb.CancelPlanRequest(plan_id=a.plan)
    check_no_contract_setting();req.operation_id=a.plan
    r=stub.CancelPlan(req,timeout=10)
    outcome=cancel_outcome(req,r,ROBOT)
    return {'plan':r.plan_id,'cancelled':outcome=='WITHDRAWAL_RECORDED','operation_outcome':outcome,'physical_stop':'NOT_OBSERVED'}


def plan_status(a):
    stub = rpc.PailNorthboundStub(channel())
    r = stub.GetPlanStatus(pb.GetPlanStatusRequest(plan_id=a.plan), timeout=10)
    return {'plan': r.plan_id, 'state': pb.PlanState.Name(r.state), 'detail': r.detail}


def unlock(a):
    import nacl.signing
    from google.protobuf import json_format  # noqa: F401  (grpc stubs already imported the runtime)
    import operator_service_pb2 as op_pb
    import operator_service_pb2_grpc as op_rpc
    key = json.loads(open(os.environ.get('PAIL_DEMO_OPERATOR_KEY', '/etc/pail/keys/operator_ed25519.json')).read())
    seed = base64.b64decode(key.get('ed25519_private_key_base64') or key.get('private_key_base64'))
    signer = nacl.signing.SigningKey(seed[:32])
    key_id = key.get('key_id', 'op-key-1')
    nonce = os.urandom(16)
    now_ms = int(time.time() * 1000)
    canon = ('pail-unlock:v2:%s:%d:%s:%s' % (ROBOT, now_ms, base64.b64encode(nonce).decode(), key_id)).encode()
    sig = signer.sign(canon).signature
    stub = op_rpc.OperatorServiceStub(channel())
    r = stub.Unlock(op_pb.UnlockRequest(robot_id=ROBOT, unix_ms=now_ms, nonce=nonce, operator_sig=sig, operator_key_id=key_id), timeout=10)
    return {'accepted': bool(r.accepted), 'detail': getattr(r, 'detail', '') or getattr(r, 'reason', '')}


def verify(a):
    # Exit 7 means the newest records are not yet under a signed checkpoint. The Issuer covers them once its writes
    # pause for about a second, so wait for that instead of accepting records outside every signature.
    for attempt in range(6):
        p = subprocess.run(['blackbox_verify', '-check-chain', '-dir', '/var/log/pail_blackbox', '-keyfile', '/etc/pail/keys/issuer_ed25519.json'],
                           capture_output=True, text=True, timeout=60)
        if p.returncode != 7 or attempt == 5:
            break
        time.sleep(1.5)
    out = (p.stdout + p.stderr).strip()
    return {'ok': p.returncode == 0 and 'OK: chain verified' in out, 'rc': p.returncode, 'output': out[-1500:]}


def status(a):
    # Read-only end-to-end probe; never GetActiveToken (which can consume a lease).
    stub=rpc.PailNorthboundStub(channel())
    started=time.monotonic()
    stub.GetPlanStatus(pb.GetPlanStatusRequest(plan_id='health-'+uuid.uuid4().hex),timeout=3)
    return {'issuer':'OK','basis':'read_only_rpc_response','authorization_proven':False,'rpc_duration_ms':(time.monotonic()-started)*1000}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest='mode', required=True)
    s = sub.add_parser('submit'); s.add_argument('--plan-id'); s.add_argument('--steps', required=True); s.add_argument('--target', default='')
    s = sub.add_parser('skill'); s.add_argument('--plan-id'); s.add_argument('--name', required=True); s.add_argument('--classes', default='NONE'); s.add_argument('--duration', default='3'); s.add_argument('--target', default='')
    s = sub.add_parser('cancel'); s.add_argument('--plan', required=True)
    s = sub.add_parser('plan_status'); s.add_argument('--plan', required=True)
    sub.add_parser('unlock'); sub.add_parser('verify'); sub.add_parser('status')
    a = ap.parse_args()
    try:
        out = globals()[a.mode](a)
    except grpc.RpcError as ex:
        out = {'error':'rpc','code':str(ex.code()),'diagnostic':transport(ex.code(),ex.details())}
        out['diagnostic'].update(plan_id=getattr(a,'plan_id',None) or getattr(a,'plan',None),operation_outcome='UNKNOWN')
    except ValueError as ex:
        out={'error':'operation_receipt','diagnostic':dict(transport(basis='receipt_validation_failed'),reason=str(ex),operation_outcome='UNKNOWN',plan_id=getattr(a,'plan_id',None) or getattr(a,'plan',None))}
    print(json.dumps(out))
    return 0 if 'error' not in out else 1


if __name__ == '__main__':
    sys.exit(main())
