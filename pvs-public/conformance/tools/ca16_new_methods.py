#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""CA-16: no-token new methods over a real adapter and recording robotd proxy."""
import argparse,base64,json,socket,time,uuid
from pathlib import Path

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',default='/state/evidence/ca16.json');a=ap.parse_args();output=Path(a.output)
 if output.exists():raise RuntimeError('fresh result required')
 checks=[];run_id=uuid.uuid4().hex
 def rows(path):
  try:return [json.loads(x) for x in Path(path).read_text().splitlines() if x]
  except FileNotFoundError:return []
 def recorded(identifier,side):return [base64.b64decode(r['raw_b64']) for r in rows('/run/duck/ca16-tap.jsonl') if r['id']==identifier and r['side']==side]
 try:
  with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
   sock.settimeout(4);sock.connect('/run/duck/pail.sock');stream=sock.makefile('rb')
   def call(identifier,method,params):
    raw=(json.dumps(dict(jsonrpc='2.0',id=identifier,method=method,params=params),separators=(', ',': '))+'\n').encode();sock.sendall(raw)
    response=stream.readline(1024*1024+1)
    if len(response)>1024*1024 or not response.endswith(b'\n'):raise RuntimeError('invalid response frame')
    if json.loads(response).get('id')!=identifier:raise RuntimeError('response identity mismatch')
    return raw,response
   _,hello=call('hello','hello',dict(api_version=44))
   if json.loads(hello).get('result',{}).get('api_version')!=44:raise RuntimeError('API44 not ready')
   methods=[('robot.model',{}),('robot.vetbook',{}),('robot.vetbookTally',dict(tallies={},highs={},lows={})),('robot.vetbookNote',dict(text='ca16 synthetic note'))]
   for index,(method,params) in enumerate(methods):
    identifier='ca16-'+run_id+'-pass-'+str(index);before=sum(r.get('kind')=='note' for r in rows('/run/duck/gate.ndjson'))
    sent,response=call(identifier,method,params)
    deadline=time.monotonic()+2
    while not recorded(identifier,'response') and time.monotonic()<deadline:time.sleep(.01)
    ok=recorded(identifier,'request')==[sent] and recorded(identifier,'response')==[response]
    if method=='robot.vetbookNote':
     notes=[r for r in rows('/run/duck/gate.ndjson') if r.get('kind')=='note']
     ok=ok and len(notes)==before+1 and notes[-1].get('scope')=='adapter_local_audit_not_blackbox' and 'ca16 synthetic note' not in json.dumps(notes[-1])
    checks.append(dict(method=method,status='PASS' if ok else 'FAIL',comparison='far-side bytes and original upstream response'))
   for index,(method,params) in enumerate([('robot.flashlight',dict(on=True)),('robot.rest',{}),('robot.rebootMotors',dict(ids=[]))]):
    identifier='ca16-'+run_id+'-block-'+str(index);sent,response=call(identifier,method,params);time.sleep(.15)
    error=json.loads(response).get('error',{})
    ok=error.get('code')==-32001 and error.get('message')=='PAIL_COMMAND_BLOCKED' and not recorded(identifier,'request')
    checks.append(dict(method=method,status='PASS' if ok else 'FAIL',error=error,far_side_count=len(recorded(identifier,'request'))))
  result=dict(id='CA-16',status='PASS' if all(r['status']=='PASS' for r in checks) else 'FAIL',checks=checks,hardware_tested=False)
 except Exception as e:result=dict(id='CA-16',status='FAIL',error=str(e),checks=checks,hardware_tested=False)
 with output.open('x') as f:json.dump(result,f,indent=2);f.write('\n')
 print(json.dumps(result),flush=True);return 0 if result['status']=='PASS' else 1
if __name__=='__main__':raise SystemExit(main())
