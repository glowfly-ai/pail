#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Software-only C ABI integration example. NDJSON stdin; decisions/STOP stdout, NO motors.
Production adapters must replace synthetic feeds and wire an independent stop/deadman path.
"""
import argparse,ctypes as C,json,os,queue,sys,threading,time,uuid
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"common"))
from core_report_wire import prepare_report,accepted_report
import grpc
import pail_gate_abi_pb2 as abi
import token_service_pb2 as tp
import token_service_pb2_grpc as rpc


def execution_token(client, robot_id, execution_id):
    response, call = client.GetActiveToken.with_call(
        tp.GetActiveTokenRequest(robot_id=robot_id), timeout=.3,
        metadata=(("pail-execution-instance", execution_id),))
    echoed = [v for k, v in call.initial_metadata() if k == "pail-execution-instance"]
    if echoed != [execution_id]:
        # Old/mismatched gateways cannot acknowledge this execution boundary.
        return tp.GetActiveTokenResponse(status=tp.ERROR)
    return response


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',default='/opt/pail/lib/libpail_gate.so')
    ap.add_argument('--gateway',default='127.0.0.1:50051')
    ap.add_argument('--robot-id',default='robot-1');ap.add_argument('--robot-class',default='microduck')
    ap.add_argument('--policy',default='/etc/pail/policy.yaml');ap.add_argument('--keyring',default='/etc/pail/keys/keyring.json')
    ap.add_argument('--skills',default='/etc/pail/skills.microduck.yaml')
    ap.add_argument('--synthetic-inputs',action='store_true',help='explicit software-only OK safety + box-12 evidence')
    ap.add_argument('--interactive-inputs',action='store_true',help='software test only: enable synthetic inputs per NDJSON command')
    if 'PAIL_CORE_COMM_CONTRACT' in os.environ:raise ValueError('CORE_COMM_CONTRACT_SETTING_REMOVED: PAIL_CORE_COMM_CONTRACT has no meaning (there is one communication contract); unset it')
    a=ap.parse_args();lib=C.CDLL(a.library);pointer=C.c_void_p;size=C.c_size_t
    lib.pail_gate_abi_version.restype=C.c_uint32
    if lib.pail_gate_abi_version()!=1:raise ValueError('ABI_VERSION_MISMATCH')
    lib.pail_gate_new.argtypes=[C.c_char_p,size,C.POINTER(pointer)];lib.pail_gate_new.restype=pointer
    lib.pail_gate_free.argtypes=[pointer];lib.pail_gate_free_buf.argtypes=[pointer]
    for name in ('pail_gate_set_token','pail_gate_observe_evidence'):
        getattr(lib,name).argtypes=[pointer,C.c_char_p,size];getattr(lib,name).restype=C.c_int
    for name in ('pail_gate_command','pail_gate_tick','pail_gate_observe_safety'):
        getattr(lib,name).argtypes=[pointer,C.c_char_p,size,C.POINTER(pointer),C.POINTER(size)];getattr(lib,name).restype=C.c_int
    config=abi.Config(robot_id=a.robot_id,robot_class=a.robot_class,policy_path=a.policy,keyring_path=a.keyring,skills_file=a.skills)
    data=config.SerializeToString();err=pointer();handle=lib.pail_gate_new(data,len(data),C.byref(err))
    if not handle:
        message=C.string_at(err).decode() if err else 'gate refused configuration'
        if err:lib.pail_gate_free_buf(err)
        raise ValueError(message)
    # Say on stderr what trust anchor the gate actually loaded. The library reads PAIL_KEYRING_MODE from the
    # environment: unset means "signed bundle required", so an unsigned development keyring.json yields zero keys
    # and every token is refused with ERR_UNKNOWN_KEY_ID — which reads like a key-id problem when it is a mode
    # problem — exactly what a host-side run without the variable looks like.
    lib.pail_gate_info.argtypes=[pointer,C.POINTER(pointer),C.POINTER(size)];lib.pail_gate_info.restype=C.c_int
    buf=pointer();length=size()
    if lib.pail_gate_info(handle,C.byref(buf),C.byref(length))==0:
        try:info=abi.Info.FromString(C.string_at(buf,length.value))
        finally:lib.pail_gate_free_buf(buf)
        startup={'keyring_mode':info.keyring_mode,'keys':info.keys,'keyring_error':info.keyring_error,'gate_mode':info.gate_mode,
                 'env_PAIL_KEYRING_MODE':os.environ.get('PAIL_KEYRING_MODE','(unset: a signed bundle is required)')}
        if info.keyring_error or not info.keys:
            startup['hint']=('no trust anchor loaded: every token will be refused with ERR_UNKNOWN_KEY_ID. For the software rig\'s unsigned '
                             'development keyring set PAIL_KEYRING_MODE=unsigned-dev in this process\'s environment (development only; a '
                             'deployment uses a signed bundle).')
        print(json.dumps({'startup':startup}),file=sys.stderr,flush=True)
    channel=grpc.insecure_channel(a.gateway);client=rpc.TokenServiceStub(channel)
    execution_id=uuid.uuid4().hex  # stable for this process; never reused on restart
    def call(name,message,output=None):
        raw=message.SerializeToString()
        if output is None:
            rc=getattr(lib,name)(handle,raw,len(raw))
            if rc:raise ValueError('ABI_ERROR '+name+' '+str(rc))
            return
        buf=pointer();length=size();rc=getattr(lib,name)(handle,raw,len(raw),C.byref(buf),C.byref(length))
        try:
            if rc:raise ValueError('ABI_ERROR '+name+' '+str(rc))
            return output.FromString(C.string_at(buf,length.value))
        finally:
            if buf:lib.pail_gate_free_buf(buf)
    def publish(outcome,request_id=None):
        delivered=not outcome.report
        if outcome.report:
            decision={'PERMIT':tp.PERMIT,'BLOCK':tp.BLOCK,'ESTOP':tp.ESTOP}.get(outcome.state,tp.BLOCK)
            try:
                report=tp.ReportDecisionRequest(robot_id=a.robot_id,chain_id=outcome.report_chain_id,
                    token_id=outcome.report_token_id,decision=decision,reason_code=outcome.reason,step_complete=outcome.step_complete,fatal=outcome.fatal,
                    detail=outcome.detail,effective_mode=outcome.effective_mode)
                prepare_report(report)   # one contract: every report carries the C1 identity/digest fields
                delivered=accepted_report(report,client.ReportDecision(report,timeout=.5))
            except grpc.RpcError:delivered=False
        print(json.dumps({'state':outcome.state,'reason':outcome.reason,'detail':outcome.detail,
                          'forward':bool(outcome.forward and delivered),'report_accepted':delivered,'physical_execution':False,'request_id':request_id}),flush=True)
    inbox=queue.Queue(maxsize=128)
    def read():
        try:
            for line in sys.stdin:
                if len(line)>65536:raise ValueError('COMMAND_SIZE')
                inbox.put(json.loads(line))
        except Exception as exc:inbox.put({'input_error':str(exc)})
        finally:inbox.put(None)
    threading.Thread(target=read,daemon=True).start()
    rejected=None
    ready=False;ready_deadline=time.monotonic()+30
    synthetic=a.synthetic_inputs
    try:
        while True:
            started=time.monotonic()
            try:
                response=execution_token(client,a.robot_id,execution_id)
                call('pail_gate_set_token',abi.TokenInput(reachable=True,response=response))
                rejected=None
                if not ready and response.status!=tp.ERROR:
                    ready=True
                    print(json.dumps({'ready':True,'physical_execution':False}),flush=True)
            except grpc.RpcError as exc:
                # Fail-closed either way: the gate sees "no answer" and blocks with ERR_ISSUER_UNREACHABLE. But a
                # gateway that ANSWERED with a refusal (a robot id this rig does not bind, no registry row) is not
                # a network problem; say so once on stderr so a porter does not debug the wrong layer. The reason
                # code on stdout stays the gate's own. (The gateway binds the robot id; the robot class is not
                # part of that check.)
                call('pail_gate_set_token',abi.TokenInput(reachable=False))
                code=exc.code() if hasattr(exc,'code') else None
                if code not in (None,grpc.StatusCode.UNAVAILABLE,grpc.StatusCode.DEADLINE_EXCEEDED) and rejected!=code:
                    rejected=code
                    print(json.dumps({'diagnostic':'GATEWAY_REFUSED_TOKEN_REQUEST','grpc_status':code.name,'detail':(exc.details() or '')[:200],
                                      'hint':'the gateway answered but refused robot_id='+a.robot_id+'; use the robot id the rig was started with (--robot-id). Not a connectivity failure.'}),file=sys.stderr,flush=True)
            if not ready:
                if time.monotonic()>=ready_deadline:raise ValueError('EXECUTION_HANDSHAKE_NOT_READY')
                time.sleep(.1)
                continue
            if synthetic:
                call('pail_gate_observe_safety',abi.SafetyInput(level='OK',source='software-only'),abi.Outcome)
                call('pail_gate_observe_evidence',abi.EvidenceInput(object_id='box-12',confidence=1,source='RFID'))
            tick=call('pail_gate_tick',abi.TickInput(),abi.TickOutcome)
            for outcome in (tick.recheck,tick.step):
                if outcome.state:publish(outcome)
            try:command=inbox.get(timeout=max(.001,.1-(time.monotonic()-started)))
            except queue.Empty:continue
            if command is None:break
            if 'input_error' in command:raise ValueError(command['input_error'])
            if 'synthetic_inputs' in command:
                if not a.interactive_inputs or not isinstance(command['synthetic_inputs'],bool):
                    raise ValueError('synthetic_inputs requires --interactive-inputs and a boolean')
                synthetic=command['synthetic_inputs']
                if synthetic:
                    call('pail_gate_observe_safety',abi.SafetyInput(level='OK',source='software-only'),abi.Outcome)
                    call('pail_gate_observe_evidence',abi.EvidenceInput(object_id='box-12',confidence=1,source='RFID'))
            # A command can arrive after the idle poll. Refresh at this command
            # boundary instead of judging against a pre-read token view.
            try:
                response=execution_token(client,a.robot_id,execution_id)
                call('pail_gate_set_token',abi.TokenInput(reachable=True,response=response))
            except grpc.RpcError:
                call('pail_gate_set_token',abi.TokenInput(reachable=False))
            linear,angular=abs(float(command.get('linear',0))),abs(float(command.get('angular',0)))
            outcome=call('pail_gate_command',abi.CommandInput(linear_norm=linear,angular_norm=angular,requested_class=1,
                skill=command.get('skill','twist'),measured={'sls.linear_mps':linear,'sls.angular_rps':angular,
                'step.max_duration_s':float(command.get('duration',1))}),abi.Outcome)
            publish(outcome,command.get('request_id'))
    finally:
        print('{"state":"STOP","forward":false,"physical_execution":false}',flush=True)
        lib.pail_gate_free(handle);channel.close()

if __name__=='__main__':
    try:main()
    except (ValueError,OSError,KeyboardInterrupt) as exc:
        print(json.dumps({'state':'STOP','forward':False,'error':str(exc),'physical_execution':False}),flush=True)
        raise SystemExit(2)
