# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Per-run scene evidence: reserve output before any action and preserve progress on failure."""
import datetime
import json
import hashlib
import os
from pathlib import Path
import tempfile
import uuid


class RunRecord:
    def __init__(self, output, url, only):
        self.run_id = uuid.uuid4().hex
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        if output:
            self.path = Path(output)
        else:
            parent = Path(tempfile.gettempdir()) / 'pail-demo-results'
            parent.mkdir(exist_ok=True)
            self.path = parent / ('demo-scenes-'+stamp+'-'+self.run_id[:12]+'.json')
        self.events_path = Path(str(self.path) + '.events.jsonl')
        self.event_hash = hashlib.sha256()
        self.event_count = 0
        self.data = dict(schema_version=2, run_id=self.run_id, started_at_utc=stamp,
                         console_url=url, selected_scenes=only, status='RUNNING', completed=False,
                         passed=False, scope='initializing; no measurement claimed', scenes=[],
                         event_file=self.events_path.name, checkpoint_event_count=0, checkpoint_event_sha256=self.event_hash.hexdigest())
        # A pre-existing result is evidence, never a reusable scratch slot.
        with self.path.open('x') as f:
            json.dump(self.data,f,indent=2); f.write('\n'); f.flush(); os.fsync(f.fileno())
        try:
            with self.events_path.open('xb'):
                pass
        except OSError:
            self.path.unlink()  # only the new reservation made by this constructor
            raise

    def append_events(self, rows):
        if not rows:
            return
        with self.events_path.open('ab') as f:
            for row in rows:
                raw = (json.dumps(row, ensure_ascii=False, allow_nan=False) + '\n').encode()
                f.write(raw); self.event_hash.update(raw); self.event_count += 1
            f.flush(); os.fsync(f.fileno())
        self.save(self.data['scenes'])


    def save(self, scenes, *, scope=None, completed=False, error=None):
        self.data.update(scenes=list(scenes),completed=completed,
                         checkpoint_event_count=self.event_count, checkpoint_event_sha256=self.event_hash.hexdigest())
        if scope is not None:self.data['scope']=scope
        self.data['passed']=bool(completed and scenes and all(s['passed'] for s in scenes) and error is None)
        self.data['status']=('PASS' if self.data['passed'] else 'FAIL') if completed else 'RUNNING'
        if error is not None:self.data['error']=str(error)
        if completed:self.data['ended_at_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
        fd,name=tempfile.mkstemp(prefix='.'+self.path.name+'.',dir=str(self.path.parent))
        try:
            with os.fdopen(fd,'w') as f:
                json.dump(self.data,f,indent=2,ensure_ascii=False,allow_nan=False);f.write('\n');f.flush();os.fsync(f.fileno())
            os.replace(name,self.path)
        finally:
            if os.path.exists(name):os.unlink(name)
