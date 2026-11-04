#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Test-only transparent raw-socket tap. Records only explicit ca16-* requests.

The real robotd still supplies all answers. No permit or robot state is invented.
"""
import argparse,asyncio,base64,json,os
from pathlib import Path

async def main():
 ap=argparse.ArgumentParser();ap.add_argument('--listen',required=True);ap.add_argument('--upstream',required=True);ap.add_argument('--log',required=True);a=ap.parse_args()
 if Path(a.listen).exists() or Path(a.log).exists():raise RuntimeError('fresh tap paths required')
 with open(a.log,'x') as f:f.write('')
 async def connection(reader,writer):
  upstream,upwriter=await asyncio.open_unix_connection(a.upstream,limit=1024*1024)
  async def pump(source,dest,side):
   while True:
    line=await source.readline()
    if not line:return
    dest.write(line);await dest.drain()
    try:msg=json.loads(line)
    except ValueError:continue
    identifier=msg.get('id') if isinstance(msg,dict) else None
    if isinstance(identifier,str) and identifier.startswith('ca16-'):
     with open(a.log,'a') as f:f.write(json.dumps(dict(side=side,id=identifier,raw_b64=base64.b64encode(line).decode()))+'\n')
  tasks=[asyncio.create_task(pump(reader,upwriter,'request')),asyncio.create_task(pump(upstream,writer,'response'))]
  try:await asyncio.wait(tasks,return_when=asyncio.FIRST_COMPLETED)
  finally:
   for t in tasks:t.cancel()
   await asyncio.gather(*tasks,return_exceptions=True)
   writer.close();upwriter.close()
   await asyncio.gather(writer.wait_closed(),upwriter.wait_closed(),return_exceptions=True)
 server=await asyncio.start_unix_server(connection,path=a.listen,limit=1024*1024);os.chmod(a.listen,0o660)
 async with server:await server.serve_forever()
if __name__=='__main__':asyncio.run(main())
