# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Bounded local demo observation transport; never an execution authority."""
from collections import deque
import base64
import os
import hashlib
import json
import math
import sqlite3
import threading
import time
import urllib.parse
import uuid

from eventlog import (BoundedEventLog, BoundedJSONLines, EventLogError,
                      READ_CHUNK_BYTES, MAX_PAGE_BYTES, _json, _filters)


_PRIVATE_FIELDS = frozenset(('path', 'socket', 'files', 'raw', 'private_key',
    'secret', 'credential', 'authorization', 'action_token', 'action_token_bytes',
    'token_bytes', 'approval_bytes', 'secret_handle'))


def public_actor(value):
    """Drop local transport/credential material; preserve the untouched raw file."""
    if isinstance(value, dict):
        result = {k: public_actor(v) for k, v in value.items() if k.lower() not in _PRIVATE_FIELDS}
        # Gate route is a closed protocol enum, not a filesystem path. Preserve
        # only these literal values; arbitrary paths and nested credentials stay private.
        if value.get('event') == 'gate' and value.get('path') in ('command', 'recheck', 'step', 'safety'):
            result['path'] = value['path']
        return result
    if isinstance(value, list):
        return [public_actor(v) for v in value]
    if isinstance(value, str):
        # Error/detail strings can contain local paths even without a path key.
        import re
        return re.sub(r'(?<![A-Za-z0-9:])(?:/[A-Za-z0-9_.-]+){2,}[^\s]*', '[local path]', value)
    return value


class FutureObservations:
    """Bounded per-source deferral, never permission to use a future sample.

    Keep source order until the host clock reaches a producer stamp. Retention
    cannot exceed the existing two-second freshness horizon. Other sources are
    not blocked. Overflow is an explicit observation failure, not silent loss.
    """
    def __init__(self, max_rows=4096, max_bytes=4*1024*1024, horizon=2.0):
        self.queues={};self.rows=0;self.bytes=0
        self.max_rows=max_rows;self.max_bytes=max_bytes;self.horizon=horizon
    @staticmethod
    def future(row, now):
        stamp=row.get('t')
        return (not row.get('replayed') and type(stamp) in (int,float)
                and math.isfinite(stamp) and stamp>now)
    def ready(self, rows, now, mono_now):
        result=[]
        for row in rows:
            role=row['source']
            row.pop('observation_rejection_reason',None)
            if row.get('event')=='source_gap':
                for old,arrived,size in self.queues.pop(role,()):
                    old['observation_rejection_reason']='SOURCE_CHANGED'
                    self.rows-=1;self.bytes-=size;result.append(old)
                result.append(row);continue
            if role not in self.queues and not self.future(row,now):
                result.append(row);continue
            size=len(_json(row))
            if self.rows+1>self.max_rows or self.bytes+size>self.max_bytes:
                raise EventLogError('OBSERVATION_FUTURE_BUFFER_OVERFLOW',503)
            self.queues.setdefault(role,deque()).append((row,mono_now,size))
            self.rows+=1;self.bytes+=size
        for role in list(self.queues):
            queue=self.queues[role]
            while queue:
                row,arrived,size=queue[0]
                age=max(0.0,mono_now-arrived)
                if age>self.horizon:
                    row['observation_rejection_reason']='FUTURE_TIMESTAMP_TIMEOUT'
                elif self.future(row,now):
                    break
                queue.popleft();self.rows-=1;self.bytes-=size
                row['observation_deferred_s']=round(age,6)
                result.append(row)
            if not queue:del self.queues[role]
        return result


def current_observation(row, previous, started_at, now):
    """UI freshness only. Same wall/monotonic bounds, with explicit rejection reasons."""
    row['observation_checked_t']=now
    if row.get('observation_rejection_reason') in ('FUTURE_TIMESTAMP_TIMEOUT','SOURCE_CHANGED'):return False,row['observation_rejection_reason']
    if row.get('replayed'):return False,'REPLAYED'
    stamp,mono,clock=row.get('t'),row.get('mono'),row.get('clock_id')
    if any(type(v) not in (int,float) or not math.isfinite(v) for v in (stamp,mono)):return False,'INVALID_CLOCK_SAMPLE'
    if not isinstance(clock,str) or not clock:return False,'MISSING_CLOCK_ID'
    if previous[0]!=clock:return False,'CLOCK_ID_CHANGED'
    if stamp<started_at:return False,'PRE_START'
    if stamp>now:return False,'FUTURE_TIMESTAMP'
    if now-stamp>2:return False,'STALE_TIMESTAMP'
    if mono<=previous[1]:return False,'DUPLICATE_OR_REORDERED'
    row['age_upper_s']=now-stamp  # wall-clock: validated producer timestamp age for UI freshness, not an elapsed control duration.
    return True,None


def record_observed_move(console, plan, timeout):
    """Record only a fresh, post-completion stationary observation window.

    Repeated cached poses are not samples. Missing/replaced/incomparable data
    produces an explicit unknown result, never a fabricated zero distance.
    """
    def unknown(reason):
        console.emit('moved',plan=plan['id'],text=plan['text'],moved_m=None,turned_deg=None,settled=False,reason=reason)
    reference=plan.get('completion_observation')
    if not reference:
        unknown('COMPLETION_REFERENCE_MISSING');return
    def finite_pose(row):
        return isinstance(row,dict) and all(type(row.get(k)) in (int,float) and math.isfinite(row[k])
                                           for k in ('x','y','th'))
    if not finite_pose(plan.get('start')):
        unknown('INVALID_MOVEMENT_SAMPLE');return
    # A fleet feed is shared, while completion and movement belong to one robot.
    # Robot identity and producer frame are separate boundaries: a foreign robot
    # must neither complete this movement nor invalidate its stationary window.
    def identity(value):
        return None if value is None or value == '' else value
    identities=[identity(v) for v in (plan.get('robot_id'),plan['start'].get('robot_id'),
                getattr(getattr(console,'stack',None),'robot_id',None)) if identity(v) is not None]
    if any(not isinstance(v,str) or not v for v in identities) or len(set(identities))>1:
        unknown('MOVEMENT_ROBOT_MISMATCH');return
    robot_id=identities[0] if identities else None
    if type(reference.get('mono')) not in (int,float) or not math.isfinite(reference['mono']):
        unknown('INVALID_COMPLETION_REFERENCE');return
    began=time.monotonic();last=None;settled=False;p=None
    # One continuous producer-time window. Bounding-box diagonal and unwrapped
    # yaw range bound all samples, not merely adjacent deltas (slow drift).
    window=deque();yaw=0.0
    while time.monotonic()-began<timeout:
        with console.cond:
            if console.plan is not plan:
                unknown('PLAN_REPLACED_DURING_SETTLE');return
            # Process every received pose, not only the last sample in an SSH
            # batch. Transport batching is not a gap in the producer's clock.
            poses=[r for r in getattr(console, 'events', ())
                   if r.get('event')=='pose' and identity(r.get('robot_id'))==robot_id]
            if console.pose is not None and identity(console.pose.get('robot_id'))==robot_id:
                poses.append(console.pose)
        now=time.monotonic()
        for candidate in poses:
            valid=(candidate.get('observation_current') is True
                   and candidate.get('clock_id')==reference.get('clock_id')
                   and type(candidate.get('mono')) in (int,float)
                   and math.isfinite(candidate['mono']) and candidate['mono']>=reference['mono']
                   and type(candidate.get('received_mono')) in (int,float)
                   and began<=candidate['received_mono']<=now
                   and now-candidate['received_mono']<=2)
            if not valid or (last is not None and candidate['mono']<=last['mono']):
                continue
            p=candidate
            frame=('clock_id','producer_instance_id','stream_id')
            if not plan.get('start') or any(p.get(k)!=plan['start'].get(k) for k in frame):
                unknown('MOVEMENT_FRAME_CHANGED');return
            if not finite_pose(p):
                unknown('INVALID_MOVEMENT_SAMPLE');return
            continuous=last is not None and 0<p['mono']-last['mono']<=.25
            if not continuous:
                window.clear();yaw=0.0
            else:
                yaw+=math.atan2(math.sin(p['th']-last['th']),math.cos(p['th']-last['th']))
            window.append((p['mono'],p['x'],p['y'],yaw))
            # Keep the sample bracketing the start of the most recent 0.5s.
            # No producer sample within that window is discarded due to batching.
            while len(window)>1 and p['mono']-window[1][0]>=.5:
                window.popleft()
            if len(window)>4096:
                unknown('OBSERVATION_WINDOW_OVERFLOW');return
            if p['mono']-window[0][0]>=.5:
                xs=[r[1] for r in window];ys=[r[2] for r in window];angles=[r[3] for r in window]
                settled=(math.hypot(max(xs)-min(xs),max(ys)-min(ys))<.002
                         and max(angles)-min(angles)<.005)
                if settled:break
            last=p
        if settled:break
        # Receipt time is only a freshness bound, never a sampling cadence.
        if last is not None and now-last['received_mono']>2:
            window.clear();last=None
        time.sleep(.1)
    with console.cond:
        if console.plan is not plan:
            unknown('PLAN_REPLACED_DURING_SETTLE');return
        start=plan.get('start')
        if not settled or start is None or p is None:
            unknown('OBSERVATION_NOT_SETTLED');return
        if start.get('clock_id')!=p.get('clock_id') or start.get('producer_instance_id')!=p.get('producer_instance_id') or start.get('stream_id')!=p.get('stream_id'):
            unknown('MOVEMENT_FRAME_CHANGED');return
        dth=math.degrees(math.atan2(math.sin(p['th']-start['th']),math.cos(p['th']-start['th'])))
        console.emit('moved',plan=plan['id'],text=plan['text'],
                     moved_m=round(math.hypot(p['x']-start['x'],p['y']-start['y']),3),turned_deg=round(dth,1),
                     start=[start['x'],start['y'],start['th']],end=[p['x'],p['y'],p['th']],settled=True)


class Subscriber:
    def __init__(self):
        self.rows = deque()
        self.bytes = 0
        self.gap = None
        self.closed = False
        self.ready = threading.Condition()

    def put(self, seq, cursor, raw):
        with self.ready:
            if self.closed or self.gap:
                return
            if len(self.rows) >= 256 or self.bytes + len(raw) > 1024 * 1024:
                start = self.rows[0][0] if self.rows else seq
                self.rows.clear()
                self.bytes = 0
                self.gap = dict(error='SLOW_CONSUMER', gap=dict(from_seq=start,
                    through_seq=seq), snapshot_url='/api/v2/snapshot')
            else:
                self.rows.append((seq, cursor, raw))
                self.bytes += len(raw)
            self.ready.notify_all()

    def take(self, timeout=15):
        with self.ready:
            if not self.rows and not self.gap and not self.closed:
                self.ready.wait(timeout)
            if self.gap:
                return 'gap', self.gap
            if self.rows:
                seq, cursor, raw = self.rows.popleft()
                self.bytes -= len(raw)
                return 'event', (cursor, raw)
            return ('closed' if self.closed else 'heartbeat'), None


class ConsoleFeed:
    def __init__(self, robot_ids=None):
        self.robot_ids = None if robot_ids is None else frozenset(robot_ids)
        if self.robot_ids is not None and (not self.robot_ids or len(self.robot_ids) > 16):
            raise ValueError('CONSOLE_ROBOT_LIMIT')
        self.log = BoundedEventLog()
        self.lock = threading.RLock()
        self.subscribers = set()
        self.latest = {}
        self._health_provider=None;self._robot_health_providers={};self._valid_pose={};self._trust_provider=None
        self._health_sent=None;self._health_last_sent=0.;self._health_revision=0

    def attach_trust(self,provider):
        self._trust_provider=provider

    def trust_observation(self):
        from trust_observation import unconfigured_observation
        if self._trust_provider is None:return unconfigured_observation()
        try:return self._trust_provider()
        except Exception:return unconfigured_observation('TRUST_PROVIDER_FAILED')

    def attach_health(self,provider):
        self._health_provider=provider

    def attach_robot_health(self,robot_id,provider):
        if self.robot_ids is None or robot_id not in self.robot_ids:
            raise ValueError('UNKNOWN_HEALTH_ROBOT')
        with self.lock:self._robot_health_providers[robot_id]=provider

    def observation_health(self):
        try:base=self._health_provider() if self._health_provider else dict(schema_version=1,history=dict(state='UNKNOWN'),source_errors={})
        except Exception:base=dict(schema_version=1,history=dict(state='UNKNOWN'),source_errors={},reader_error='HEALTH_PROVIDER_FAILED')
        now=time.monotonic()
        with self.lock:
            pose_entries={k:dict(v) for k,v in self._valid_pose.items()}
            entries=list(pose_entries.values())
        remaining=max((v['valid_until']-now for v in entries),default=0.)
        state='CURRENT' if remaining>0 else ('STALE' if entries else 'UNKNOWN')
        if base.get('reader_error') or any(k in base.get('source_errors',{}) for k in ('base','observer')):state='UNAVAILABLE'
        if self.robot_ids is not None:
            with self.lock:providers=dict(self._robot_health_providers)
            robots={}
            for robot in sorted(self.robot_ids):
                provider=providers.get(robot)
                if provider:
                    try:robots[robot]=provider()
                    except Exception:robots[robot]=dict(live_state='UNAVAILABLE',reason='HEALTH_PROVIDER_FAILED',valid_for_s=0)
                else:
                    values=[v for (role,r),v in pose_entries.items() if r==robot]
                    available=max((v['valid_until']-now for v in values),default=0.)
                    robots[robot]=dict(live_state='CURRENT' if available>0 else ('STALE' if values else 'UNKNOWN'),valid_for_s=max(0.,available))
            states={v['live_state'] for v in robots.values()}
            state=next(iter(states)) if len(states)==1 else 'PARTIAL'
            remaining=min((v.get('valid_for_s',0) for v in robots.values()),default=0) if state=='CURRENT' else 0
            base['robots']=robots
        base.update(console_instance=self.log.epoch,sample_mono_s=now,live_state=state,valid_for_s=max(0.,remaining),last_valid_wall=max((v['wall'] for v in entries),default=None))
        return base

    def publish_health(self,force=False):
        health=self.observation_health();now=time.monotonic()
        signature=_json({k:health.get(k) for k in ('live_state','reader_error','source_errors')}|{'robots':{k:(v.get('live_state'),v.get('history',{}).get('state')) for k,v in health.get('robots',{}).items()}}|{'history_state':health.get('history',{}).get('state'),'history_error':health.get('history',{}).get('error'),'history_warning':health.get('history',{}).get('warning')})
        with self.lock:
            if force or signature!=self._health_sent or now-self._health_last_sent>=5:
                self._health_sent=signature;self._health_last_sent=now;self._health_revision+=1
                self.append(dict(event='observation_health',source='console',t=time.time(),health_revision=self._health_revision,health=health))

    def append(self, event):
        if event.get('event')=='source_gap':
            with self.lock:
                role,robot=event.get('source'),event.get('robot_id')
                self._valid_pose={k:v for k,v in self._valid_pose.items()
                                  if not (k[0]==role and (self.robot_ids is None or robot is None or k[1]==robot))}
        finite_pose=all(type(event.get(k)) in (int,float) and math.isfinite(event[k]) for k in ('x','y','th'))
        if event.get('event')=='pose' and finite_pose and event.get('observation_current') is True and not event.get('replayed'):
            role,robot=event.get('source'),event.get('robot_id')
            if role in ('base','observer') and (self.robot_ids is None or robot in self.robot_ids):
                age=event.get('age_upper_s')
                if type(age) not in (int,float):
                    # Missing freshness bounds are unknown/stale, not a wall-
                    # clock guess based on an arbitrary producer timestamp.
                    age=2.
                if math.isfinite(age) and 0<=age<=2:
                    with self.lock:self._valid_pose[(role,robot if self.robot_ids is not None else None)]={'valid_until':time.monotonic()+max(0.,2-age),'wall':time.time()}
                    event=dict(event,console_instance=self.log.epoch,console_sample_mono_s=time.monotonic(),console_valid_for_s=max(0.,2-age))
        # Encoding and socket writes never run under the log's producer lock.
        with self.lock:
            seq = self.log.append(event)
            with self.log._lock:
                raw = self.log._rows[-1][1]
            cursor = self.log.snapshot()['cursor']
            if not event.get('replayed') and (event.get('event')=='moved' or (event.get('event')=='pose' and finite_pose)):
                # Installer-bounded robot IDs only; arbitrary incoming IDs cannot
                # grow the latest-state cache or overwrite a different robot.
                role, robot = event.get('source'), event.get('robot_id')
                allowed = self.robot_ids is None or robot in self.robot_ids
                if allowed and role in ('base', 'observer', 'console'):
                    key = (role, event['event']) if self.robot_ids is None else (robot, role, event['event'])
                    self.latest[key] = raw
            for sub in self.subscribers:
                sub.put(seq, cursor, raw)
        return seq

    def snapshot(self):
        with self.lock:
            out = self.log.snapshot()
            rows = tuple(self.latest.values())
        out['latest'] = [json.loads(r) for r in rows]
        out['motion_status'] = 'UNKNOWN'
        out['observation_health']=self.observation_health()
        return out

    def __iter__(self):
        # Compatibility for the bounded planner acknowledgement scan only.
        with self.log._lock:
            rows = tuple(raw for _, raw in self.log._rows)
        return iter(json.loads(raw) for raw in rows)

    def subscribe(self, cursor=None):
        with self.lock:
            if len(self.subscribers) >= 8:
                raise EventLogError('TOO_MANY_CLIENTS', 429)
            sub = Subscriber()
            if cursor is not None:
                # A reconnect backlog is subject to the same queue budget.
                page = self.log.page(cursor, limit=1000)
                for seq, ev in zip(page['sequences'], page['events']):
                    from eventlog import _cursor, _filters
                    sub.put(seq, _cursor(self.log.epoch, int(seq), _filters(None)[1]), _json(ev))
                if int(page['next']) < int(page['high_seq']) and not sub.gap:
                    sub.gap = dict(error='RECONNECT_BACKLOG', snapshot_url='/api/v2/snapshot',
                                   gap=dict(after_seq=page['next'], through_seq=page['high_seq']))
            self.subscribers.add(sub)
            return sub

    def unsubscribe(self, sub):
        with self.lock:
            self.subscribers.discard(sub)
        with sub.ready:
            sub.closed = True
            sub.ready.notify_all()


class History:
    """Single bounded-chunk writer; indexed keyset reads with frozen watermarks."""
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.db = sqlite3.connect(str(path), check_same_thread=False, timeout=.2)
        try:
            self.db.executescript('''PRAGMA journal_mode=WAL;
              CREATE TABLE IF NOT EXISTS meta(epoch TEXT);
              CREATE TABLE IF NOT EXISTS sources(path_key TEXT PRIMARY KEY, identity TEXT, file_id TEXT, seen_size INTEGER);
              CREATE TABLE IF NOT EXISTS source_generations(path_key TEXT, identity TEXT, file_id TEXT, seen_size INTEGER, PRIMARY KEY(path_key,identity));
              CREATE TABLE IF NOT EXISTS origins(file_id TEXT PRIMARY KEY, offset INTEGER NOT NULL);
              CREATE TABLE IF NOT EXISTS archives(path_key TEXT PRIMARY KEY,file_id TEXT,sha256 TEXT,size INTEGER);
              CREATE TABLE IF NOT EXISTS events(
                ingest_id INTEGER PRIMARY KEY, file_id TEXT NOT NULL, offset INTEGER NOT NULL,
                event_id TEXT NOT NULL, event_time REAL, producer TEXT, run_id TEXT,
                payload BLOB NOT NULL, UNIQUE(file_id,offset));''')
            row = self.db.execute('SELECT epoch FROM meta').fetchone()
            self.epoch = row[0] if row else str(uuid.uuid4())
            if not row:
                self.db.execute('INSERT INTO meta VALUES(?)', (self.epoch,))
                self.db.commit()
        except BaseException:
            self.db.close()
            raise
        self.complete = False
        self.error = None

    def file_identity(self, path, stat, alias=None):
        key = hashlib.sha256(str(path.resolve()).encode()).hexdigest()
        identity = str((stat.st_dev, stat.st_ino))
        with self.lock, self.db:
            row = self.db.execute('SELECT identity,file_id,seen_size FROM sources WHERE path_key=?', (key,)).fetchone()
            prior=row
            if not prior and alias is not None:
                alias_key=hashlib.sha256(str(alias.resolve()).encode()).hexdigest()
                prior=self.db.execute('SELECT identity,file_id,seen_size FROM sources WHERE path_key=?',(alias_key,)).fetchone()
                if prior is None or prior[0]!=identity:
                    # A new active file can be indexed before its predecessor's
                    # archive manifest is published. Keep the old logical ID.
                    prior=self.db.execute('SELECT identity,file_id,seen_size FROM source_generations WHERE path_key=? AND identity=?',(alias_key,identity)).fetchone()
            if row is not None:
                self.db.execute('INSERT OR REPLACE INTO source_generations VALUES(?,?,?,?)',(key,*row))
            file_id = prior[1] if prior and prior[0] == identity and stat.st_size >= prior[2] else str(uuid.uuid4())
            self.db.execute('INSERT OR REPLACE INTO sources VALUES(?,?,?,?)', (key,identity,file_id,stat.st_size))
            self.db.execute('INSERT OR REPLACE INTO source_generations VALUES(?,?,?,?)', (key,identity,file_id,stat.st_size))
        return file_id

    def archive_identity(self,path,stat,alias,sha256,size):
        key=hashlib.sha256(str(path.resolve()).encode()).hexdigest()
        with self.lock,self.db:
            row=self.db.execute('SELECT file_id,sha256,size FROM archives WHERE path_key=?',(key,)).fetchone()
            if row:
                if row[2]!=size or (row[1] and sha256 and row[1]!=sha256):
                    raise EventLogError('HISTORY_ARCHIVE_DESCRIPTOR_CHANGED',503)
                if sha256 and not row[1]:self.db.execute('UPDATE archives SET sha256=? WHERE path_key=?',(sha256,key))
                return row[0]
        file_id=self.file_identity(path,stat,alias=alias)
        with self.lock,self.db:
            self.db.execute('INSERT INTO archives VALUES(?,?,?,?)',(key,file_id,sha256,size))
        return file_id

    def offset(self, file_id):
        with self.lock:
            r = self.db.execute('SELECT offset FROM origins WHERE file_id=?', (file_id,)).fetchone()
            return r[0] if r else 0

    def ingest(self, file_id, offset, events, advance=True):
        # No implicit deletion of an existing installation's history.
        wal = self.path.parent / (self.path.name+'-wal')
        if self.path.stat().st_size + (wal.stat().st_size if wal.exists() else 0) > 512*1024*1024:
            raise EventLogError('HISTORY_BUDGET_EXCEEDED', 503)
        with self.lock, self.db:
            for origin, ev in events:
                raw = _json(ev)
                if len(raw) > 65536:
                    raise EventLogError('payload_oversize')
                self.db.execute('INSERT OR IGNORE INTO events(file_id,offset,event_id,event_time,producer,run_id,payload) VALUES(?,?,?,?,?,?,?)',
                    (file_id, int(origin['offset']), file_id+':'+origin['offset'], ev.get('t'),
                     ev.get('clock_id'), ev.get('run_id'), raw))
            if advance:
                self.db.execute('INSERT INTO origins VALUES(?,?) ON CONFLICT(file_id) DO UPDATE SET offset=max(offset,excluded.offset)', (file_id, offset))

    @classmethod
    def read_only_page(cls,path,cursor=None,limit=200):
        # A full or unwritable derived index can still be queried without
        # running its schema initializer, creating a writer, or resetting it.
        with sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True,timeout=.2) as db:
            row=db.execute('SELECT epoch FROM meta').fetchone()
            if not row:raise EventLogError('HISTORY_METADATA_MISSING',503)
        reader=object.__new__(cls);reader.path=path;reader.epoch=row[0]
        reader.error=None;reader.complete=False
        return reader.page(cursor,limit)

    def page(self, cursor=None, limit=200):
        if not 1 <= limit <= 1000:
            raise EventLogError('INVALID_LIMIT')
        if self.error:
            raise EventLogError(self.error, 503)
        after, upper = 0, None
        if cursor:
            try:
                if len(cursor) > 512:
                    raise ValueError()
                data = json.loads(base64.urlsafe_b64decode(cursor+'='*(-len(cursor)%4)))
                if set(data) != {'epoch','after','upper'} or data['epoch'] != self.epoch:
                    raise ValueError()
                after, upper = data['after'], data['upper']
                if type(after) is not int or type(upper) is not int or not 0 <= after <= upper <= 2**63-1:
                    raise ValueError()
            except (ValueError, TypeError, KeyError):
                raise EventLogError('INVALID_HISTORY_CURSOR')
        # A separate read connection does not hold the producer/feed lock.
        with sqlite3.connect(self.path.resolve().as_uri()+'?mode=ro',uri=True,timeout=.2) as db:
            db.execute('BEGIN')
            row=db.execute('SELECT epoch FROM meta').fetchone()
            if not row or row[0]!=self.epoch:raise EventLogError('HISTORY_INDEX_CHANGED',503)
            if upper is None:
                upper = db.execute('SELECT coalesce(max(ingest_id),0) FROM events').fetchone()[0]
            rows = db.execute('SELECT ingest_id,payload FROM events WHERE ingest_id>? AND ingest_id<=? ORDER BY ingest_id LIMIT ?', (after,upper,limit))
            result, used = [], 2048
            for idx, raw in rows:
                if used + len(raw) + 1 > MAX_PAGE_BYTES:
                    break
                result.append(json.loads(raw)); used += len(raw)+1; after = idx
        token = base64.urlsafe_b64encode(_json(dict(epoch=self.epoch, after=after, upper=upper))).rstrip(b'=').decode()
        return dict(events=result, next_cursor=token, upper_ingest_id=str(upper),
                    has_more=after < upper, history_complete=self.complete)


class Source:
    def __init__(self, path, role, history, initial=True):
        self.path, self.role = path, role
        from history_pipeline import open_raw_read
        self.stream = open_raw_read(path)
        stat = os.fstat(self.stream.fileno())
        self.identity = (stat.st_dev, stat.st_ino)
        self.barrier = stat.st_size if initial else 0
        # Inode identity survives reader restart; truncation gets a new generation.
        self.file_id = history.file_identity(path, stat)
        self.last_size = stat.st_size
        self.live = BoundedJSONLines(self.file_id, self.barrier)
        if self.barrier:
            self.stream.seek(self.barrier-1)
            if self.stream.read(1) != b'\n':
                self.live._discard = True
        off = min(history.offset(self.file_id), self.barrier)
        self.backfill = BoundedJSONLines(self.file_id, off)
        self.done = off == self.barrier

    def read(self, replay):
        decoder = self.backfill if replay else self.live
        self.stream.seek(decoder.offset)
        count = min(READ_CHUNK_BYTES, self.barrier-decoder.offset) if replay else READ_CHUNK_BYTES
        rows, faults = decoder.feed(self.stream.read(count))
        if replay and decoder.offset == self.barrier:
            self.done = True
            faults += decoder.finish()
        return decoder, rows, faults


class RuntimeTail:
    def __init__(self, directory, roles, clock_id):
        from history_pipeline import HistoryPipeline,LiveOrigins
        self.directory,self.roles,self.clock_id=directory,tuple(roles),clock_id
        directory.mkdir(parents=True,exist_ok=True)
        self._origins=LiveOrigins();self.sources={};self.source_errors={};self.reader_error=None
        for role in self.roles:
            p=directory/('demo-%s.jsonl'%role)
            if p.exists():
                try:self.sources[role]=Source(p,role,self._origins)
                except (OSError,ValueError) as e:self.source_errors[role]=type(e).__name__
        self.history=HistoryPipeline(directory.parent/'console-history.sqlite3',directory,self.roles,clock_id,History,public_actor,barriers={r:(s.identity,s.barrier) for r,s in self.sources.items()})

    def health(self):
        return dict(schema_version=1,history=self.history.snapshot(),source_errors=dict(self.source_errors),reader_error=self.reader_error)

    def poll(self):
        live=[];dirty=False
        for role in self.roles:
            p=self.directory/('demo-%s.jsonl'%role)
            try:
                if not p.exists():
                    self.source_errors[role]='SOURCE_MISSING';continue
                source=self.sources.get(role);st=p.stat()
                if source and ((st.st_dev,st.st_ino)!=source.identity or st.st_size<source.live.offset):
                    dirty=True;source.stream.close();source=Source(p,role,self._origins);self.sources[role]=source
                    live.append(dict(event='source_gap',source=role,replayed=False,quality='UNKNOWN'))
                if source is None:
                    dirty=True;source=self.sources[role]=Source(p,role,self._origins,initial=False)
                if st.st_size!=source.last_size:
                    dirty=True
                    self._origins.file_identity(p,st);source.last_size=st.st_size
                decoder,rows,faults=source.read(False)
                for row in rows:
                    ev=dict(public_actor(row['event']),source=role,replayed=False,origin=row['origin'],
                            received_t=time.time(),received_mono=time.monotonic(),received_clock_id=self.clock_id,
                            freshness_basis='receiver_only',motion_status='UNKNOWN')
                    # A source cannot spoof the supervisor's health messages.
                    if ev.get('event') in ('observation_health','observation_error'):
                        faults.append(dict(error='reserved_event',origin=row['origin'],count=1));continue
                    if len(_json(ev))>65536:
                        faults.append(dict(error='payload_oversize',origin=row['origin'],count=1));continue
                    live.append(ev)
                for fault in faults:live.append(dict(event='parser_fault',source=role,replayed=False,**fault))
                self.source_errors.pop(role,None)
            except (OSError,ValueError) as e:
                self.source_errors[role]=e.code if isinstance(e,EventLogError) else type(e).__name__
        self.history.notify(invalidate=dirty)
        return live

    def close(self):
        for source in self.sources.values():source.stream.close()
        return self.history.close()


def handle_observation(handler, feed, history):
    """Return True when handled; local console's existing origin policy is unchanged."""
    parsed = urllib.parse.urlsplit(handler.path)
    path = parsed.path
    known = ('/api/events','/events','/api/v2/snapshot','/api/v2/events',
             '/api/v2/events/stream','/api/v2/history','/api/v2/trust')
    if path not in known:
        return False
    try:
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        allowed = set() if path == '/api/v2/trust' else ({'from'} if path == '/api/events' else {'cursor','limit'})
        if any(len(v) != 1 for v in query.values()) or set(query)-allowed:
            raise EventLogError('INVALID_QUERY')
        cursor = query.get('cursor', [None])[0]
        try:
            limit = int(query.get('limit',['200'])[0])
        except ValueError:
            raise EventLogError('INVALID_LIMIT')
        if path == '/api/v2/trust':
            handler.send(200,feed.trust_observation())
        elif path == '/api/v2/snapshot':
            handler.send(200, feed.snapshot())
        elif path == '/api/v2/history':
            handler.send(200, history.page(cursor,limit))
        elif path in ('/api/events','/api/v2/events'):
            out = feed.log.page(after_seq=query.get('from',['0'])[0]) if path == '/api/events' else feed.log.page(cursor,limit=limit)
            # Keep v1's numeric next field, now an absolute sequence.
            if path == '/api/events':
                out['next'] = int(out['next'])
            handler.send(200,out)
        else:
            cursor = handler.headers.get('Last-Event-ID') or cursor
            sub = feed.subscribe(cursor)
            try:
                handler.connection.settimeout(2)
                handler.send_response(200)
                handler.send_header('Content-Type','text/event-stream')
                handler.send_header('Cache-Control','no-store')
                handler.end_headers()
                handler.wfile.write(b': connected\n\n'); handler.wfile.flush()
                while True:
                    kind, data = sub.take()
                    if kind == 'closed':
                        break
                    if kind == 'event':
                        token, raw = data
                        payload = b'id: '+token.encode()+b'\ndata: '+raw+b'\n\n'
                    elif kind == 'gap':
                        payload = b'event: gap\ndata: '+_json(data)+b'\n\n'
                    else:
                        payload = b': keep-alive\n\n'
                    handler.wfile.write(payload); handler.wfile.flush()
                    if kind == 'gap':
                        break
            except (OSError, TimeoutError):
                # A socket unable to accept even the gap closes. Reconnect cursor
                # validation still exposes the retention gap, never silent success.
                pass
            finally:
                feed.unsubscribe(sub)
                handler.close_connection = True
    except EventLogError as exc:
        handler.send(exc.status, exc.details)
    except sqlite3.Error:
        handler.send(503,dict(error='INDEX_UNAVAILABLE'))
    return True


def derive_step_observation(events, permitted, done, watermark_s=2.0, bridge_before=None, bridge_after=None):
    """What the console observed on the drive side between one step's permit and its completion (P37-L2, RV07).

    Names only the measurement points: `drive_observer_nonzero_samples` is the number of nonzero /drive_cmd_vel
    samples the drive observer role logged inside the step's producer-clock window (bound to the planner's clock
    identity via the rows' own clock ids; duplicates by producer+mono counted once); `bridge_nonzero_publish_calls`
    is the bridge status counter difference when both readings were taken. Delivery to the driver and physical
    execution are never observed here. A missing observer, a restart inside the window, or an unknown boundary
    yields null with `coverage` and `reason` — never a fabricated zero.
    """
    out = dict(step=permitted.get('step'), seq=permitted.get('seq'), plan=permitted.get('plan'),
               window_basis='planner-producer-clock', watermark_s=watermark_s,
               delivery_to_driver='NOT_OBSERVED', physical_execution='NOT_VERIFIED',
               bridge_nonzero_publish_calls=None, drive_observer_nonzero_samples=None, coverage='none', reason=None)
    if isinstance(bridge_before, int) and isinstance(bridge_after, int) and bridge_after >= bridge_before:
        out['bridge_nonzero_publish_calls'] = bridge_after - bridge_before
    elif bridge_before is not None or bridge_after is not None:
        out['bridge_status_reason'] = 'BRIDGE_COUNTER_RESET_OR_INVALID'
    t0, t1 = permitted.get('mono'), done.get('mono')
    if not all(type(v) in (int, float) and math.isfinite(v) for v in (t0, t1)) or t1 < t0:
        out['reason'] = 'STEP_BOUNDARY_UNKNOWN'
        return out
    if permitted.get('clock_id') != done.get('clock_id') or permitted.get('producer_instance_id') != done.get('producer_instance_id'):
        out['reason'] = 'PLANNER_RESTARTED_INSIDE_STEP'
        return out
    drive = [e for e in events if e.get('source') == 'drive' and e.get('event') == 'drive_state']
    if not drive:
        out['reason'] = 'DRIVE_OBSERVER_ABSENT'
        return out
    instances = {(e.get('clock_id'), e.get('producer_instance_id')) for e in drive}
    if len(instances) != 1:
        out['reason'] = 'DRIVE_OBSERVER_RESTARTED'
        out['coverage'] = 'partial'
        return out
    # the drive observer and the planner run on the robot host: a shared clock identity makes the two monotonic
    # axes comparable; different identities (another host, a restart) do not
    if next(iter(instances))[0] != permitted.get('clock_id'):
        out['reason'] = 'DRIVE_OBSERVER_CLOCK_NOT_COMPARABLE'
        return out
    seen = set(); nonzero = 0; covered_until = None
    for e in sorted(drive, key=lambda e: e.get('mono', 0)):
        m = e.get('mono')
        if type(m) not in (int, float) or not math.isfinite(m):
            out['reason'] = 'INVALID_CLOCK_SAMPLE'
            return out
        if m < t0 or m > t1:
            if m > t1:
                covered_until = m if covered_until is None else max(covered_until, m)
            continue
        key = (e.get('producer_instance_id'), m)
        if key in seen:
            continue
        seen.add(key)
        covered_until = m if covered_until is None else max(covered_until, m)
        x, z = e.get('x'), e.get('z')
        if type(x) in (int, float) and type(z) in (int, float) and (x != 0 or z != 0):
            nonzero += 1
    if covered_until is None or covered_until < t1:
        out['coverage'] = 'partial'
        out['reason'] = 'OBSERVER_LOG_ENDS_BEFORE_STEP_DONE'
        out['drive_observer_nonzero_samples'] = nonzero if seen else None
        return out
    out['drive_observer_nonzero_samples'] = nonzero
    out['coverage'] = 'full'
    return out
