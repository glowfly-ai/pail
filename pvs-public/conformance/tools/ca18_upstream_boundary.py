#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""CA-18: real raw robotd vs adapter support boundary, read-only requests.

head_imu.stream is served BEFORE upstream dispatch; adapter v2 deliberately
excludes it. The four other methods belong to other daemons and both reject.
"""
import argparse,json,os,socket
from pathlib import Path

def query(path,method,params):
 with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
  sock.settimeout(3);sock.connect(path);stream=sock.makefile('rb')
  def call(identifier,name,arguments):
   sock.sendall(json.dumps(dict(jsonrpc='2.0',id=identifier,method=name,params=arguments)).encode()+b'\n')
   raw=stream.readline(65537)
   if len(raw)>65536 or not raw.endswith(b'\n'):raise RuntimeError('INVALID_FRAME')
   response=json.loads(raw)
   if response.get('id')!=identifier:raise RuntimeError('RESPONSE_ID_MISMATCH')
   return response
  hello=call('hello','hello',dict(api_version=44))
  if hello.get('result',{}).get('api_version')!=44:raise RuntimeError('API44_PRECONDITION')
  return call('ca18',method,params)

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',default='/state/evidence/ca18.json');a=ap.parse_args()
 output=Path(a.output)
 if output.exists():raise RuntimeError('new output required')
 rows=[]
 try:
  for method,params in [('head_imu.stream',{}),('detector.check',{}),('detector.install',{}),('system.logs',dict(unit='robotd',lines=1,boot=0)),('vetbook.share',{})]:
   raw=query(os.environ.get('PAIL_DUCK_RAW','/run/duck/raw/robotd.sock'),method,params)
   adapted=query(os.environ.get('PAIL_DUCK_PUBLIC','/run/duck/pail.sock'),method,params)
   upstream_code=raw.get('error',{}).get('code');adapter_code=adapted.get('error',{}).get('code')
   if method=='head_imu.stream':
    ok='result' in raw and adapter_code==-32601 and 'not supported by this PAIL adapter' in adapted.get('error',{}).get('message','')
    expected='upstream supported; adapter-v2 explicitly unsupported'
   else:ok=upstream_code==adapter_code==-32601;expected='other service; both reject'
   rows.append(dict(method=method,status='PASS' if ok else 'FAIL',upstream_code=upstream_code,adapter_code=adapter_code,expected=expected))
  result=dict(id='CA-18',status='PASS' if all(r['status']=='PASS' for r in rows) else 'FAIL',checks=rows,hardware_tested=False)
 except Exception as e:result=dict(id='CA-18',status='INCONCLUSIVE',error=str(e),checks=rows,hardware_tested=False)
 with output.open('x') as f:json.dump(result,f,indent=2);f.write('\n')
 print(json.dumps(result),flush=True);return 0 if result['status']=='PASS' else 1
if __name__=='__main__':raise SystemExit(main())
