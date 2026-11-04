# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Narrow, task-scoped fault requests; no Docker socket inside the harness."""
import json,os,time,uuid
from pathlib import Path
class FileControl:
    def __init__(self,root):
        self.root=Path(root);self.run_id=json.loads((self.root.parent/'run.json').read_text())['run_id']
    def request(self,role,action,signal=None):
        ident=uuid.uuid4().hex
        req={'run_id':self.run_id,'request_id':ident,'target_role':role,'action':action,'signal':signal}
        temp=self.root/(ident+'.tmp');path=self.root/(ident+'.request.json');response=self.root/(ident+'.response.json')
        with temp.open('x') as f:json.dump(req,f);f.flush();os.fsync(f.fileno())
        temp.chmod(0o644);temp.replace(path)
        deadline=time.monotonic()+30
        while time.monotonic()<deadline:
            if response.exists():
                r=json.loads(response.read_text())
                if r.get('request_id')!=ident or r.get('run_id')!=self.run_id:raise RuntimeError('Fault response identity mismatch')
                if r.get('status')!='OK':raise RuntimeError('Fault request refused: '+str(r))
                return r.get('value')
            time.sleep(.05)
        raise RuntimeError('Fault control response deadline expired')
    def running(self,role):return bool(self.request(role,'running'))
    def start(self,role):self.request(role,'start')
    def kill(self,role,signal=9):self.request(role,'stop',signal)
