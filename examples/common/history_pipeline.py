# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Bounded, derived history index. Never on the live reader's critical path.

Only the worker touches indexing state. Work notifications are coalesced, not
an unbounded queue of events. Raw files and contiguous committed cursors own
recovery; losing an in-memory notification does not claim persistence.
"""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import re
from types import SimpleNamespace
import tempfile
import threading
import time
import uuid

from eventlog import BoundedJSONLines, EventLogError, READ_CHUNK_BYTES, _json

def open_raw_read(path,archive=False):
    # No FIFO/block-device hang or symlink escape through a producer-owned
    # filename. Archive directory is opened and held before resolving its leaf.
    directory=None
    try:
        if archive:
            directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
        else:fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd);raise EventLogError('SOURCE_NOT_REGULAR',503)
        return os.fdopen(fd,'rb')
    finally:
        if directory is not None:os.close(directory)

class LiveOrigins:
    """Session-local identities: not durable history IDs or continuity proofs."""
    def __init__(self):self.entries={}
    def file_identity(self,path,st):
        key=str(path);old=self.entries.get(key);ident=(st.st_dev,st.st_ino)
        if not old or old[0]!=ident or st.st_size<old[2]:old=(ident,uuid.uuid4().hex,st.st_size)
        self.entries[key]=(ident,old[1],st.st_size)
        return old[1]
    def offset(self,file_id):return 0

class IndexSource:
    def __init__(self,path,role,history,barrier=None,expected_identity=None,alias=None,archive=None):
        self.path=path;self.role=role;self.stream=open_raw_read(path,archive)
        self.hash_offset=0;self.hasher=hashlib.sha256();self.verified_stamp=None;self.hash_stamp=None
        try:
            st=os.fstat(self.stream.fileno());self.identity=(st.st_dev,st.st_ino);self.last_size=st.st_size
            self.file_id=history.file_identity(path,st) if archive is None else history.archive_identity(path,st,alias,archive.get('sha256'),archive['bytes'])
            offset=min(history.offset(self.file_id),st.st_size)
            self.committed=offset;self.barrier=barrier if barrier is not None and expected_identity==self.identity else 0
            self.reset_decoder()
        except BaseException:self.stream.close();raise
    def reset_decoder(self):
        self.decoder=BoundedJSONLines(self.file_id,self.committed)
        if self.committed:
            self.stream.seek(self.committed-1)
            self.decoder._discard=self.stream.read(1)!=b'\n'
    def close(self):self.stream.close()

DEFAULT_CAP_BYTES=512*1024*1024

def cap_bytes_from_env(env):
    """The history index budget. Unset = 512 MiB. PAIL_CONSOLE_HISTORY_CAP_BYTES lowers it for a measurement run
    (16 MiB .. 512 MiB); anything else refuses by name — the knob cannot raise the budget and is never ignored
    (preview.40 review item 14). The floor is above SQLite's WAL auto-checkpoint (1000 pages = 4 MiB): below it the
    measured DB+WAL size is WAL churn, not data, and a run pauses within seconds of starting (measured 2026-10-30)."""
    raw=env.get('PAIL_CONSOLE_HISTORY_CAP_BYTES')
    if raw is None:return DEFAULT_CAP_BYTES
    try:value=int(raw)
    except (TypeError,ValueError):
        raise ValueError('HISTORY_CAP_OVERRIDE: PAIL_CONSOLE_HISTORY_CAP_BYTES must be an integer number of bytes between 16777216 and 536870912') from None
    if not 16*1024*1024<=value<=DEFAULT_CAP_BYTES:
        raise ValueError('HISTORY_CAP_OVERRIDE: PAIL_CONSOLE_HISTORY_CAP_BYTES=%d is outside 16777216..536870912 (the budget can be lowered for a measurement, never raised)'%value)
    return value

class HistoryPipeline:
    CAP_BYTES=DEFAULT_CAP_BYTES
    def __init__(self,path,directory,roles,clock_id,history_factory,public_actor,barriers=None):
        if os.environ.get('PAIL_CONSOLE_HISTORY_CAP_BYTES') is not None:
            self.CAP_BYTES=cap_bytes_from_env(os.environ)   # a measurement run; the class default stays 512 MiB
        self.path=path;self.directory=directory;self.roles=tuple(roles);self.clock_id=clock_id
        self.factory=history_factory;self.public_actor=public_actor;self.barriers=barriers or {}
        self._lock=threading.RLock();self._page_lock=threading.Lock()
        self._db=None;self._sources={};self._stop=threading.Event();self._wake=threading.Event()
        self._settled=threading.Event();self._state='STARTING';self._error=None;self._error_since=None
        self._revision=0;self._bytes=None;self._complete=False;self._last_success=None
        self._last_error=None;self._gaps={};self._coverage_loaded=False
        self._raw_state=dict(state="UNCONFIGURED",automatic_delete=False)
        self._coverage_path=path.with_name(path.name+'.coverage.json')
        self._thread=threading.Thread(target=self._run,name='pail-history-index',daemon=True);self._thread.start()
    @property
    def db(self):
        self.wait_idle(.2)
        if self._db is None:raise EventLogError('HISTORY_UNAVAILABLE',503)
        return self._db.db
    def source_identity(self,role):
        with self._lock:
            src=self._sources.get(role)
            return src.file_id if src else None
    @property
    def error(self):
        with self._lock:return self._error
    @error.setter
    def error(self,value):self._set('IO_ERROR',value)
    @property
    def complete(self):
        with self._lock:return self._complete
    @property
    def epoch(self):
        with self._lock:return self._db.epoch if self._db else None
    def _set(self,state,error=None):
        with self._lock:
            if (state,error)!=(self._state,self._error):self._revision+=1
            if error:
                self._last_error=dict(code=error,at=time.time())
                if not self._error:self._error_since=time.time()
            if not error:self._error_since=None
            self._state=state;self._error=error
            if error:self._complete=False
    def snapshot(self):
        with self._lock:
            return dict(state=self._state,error=self._error,error_since=self._error_since,
                        revision=self._revision,bytes=self._bytes,limit_bytes=self.CAP_BYTES,
                        warning=bool(self._bytes is not None and self._bytes>=self.CAP_BYTES*.8),
                        history_complete=self._complete,last_success=self._last_success,last_error=self._last_error,
                        gaps={k:dict(v) for k,v in self._gaps.items()},
                        raw_retention=dict(self._raw_state),
                        coverage='GAP_RECORDED' if self._gaps else ('COMPLETE_AT_LAST_SCAN' if self._complete else 'PARTIAL_OR_UNKNOWN'))
    def notify(self,invalidate=True):
        if invalidate:
            with self._lock:self._complete=False
            self._settled.clear();self._wake.set()
    def wait_idle(self,timeout=1):return self._settled.wait(timeout)
    def _size(self):
        total=0
        for p in (self.path,self.path.parent/(self.path.name+'-wal')):
            try:total+=p.stat().st_size
            except FileNotFoundError:pass
        with self._lock:self._bytes=total
        return total
    def _load_coverage(self):
        if self._coverage_loaded:return
        try:
            with self._coverage_path.open('rb') as f:raw=f.read(65537)
        except FileNotFoundError:raw=None
        if raw is not None:
            if len(raw)>65536:raise ValueError('history coverage too large')
            data=json.loads(raw)
            if not isinstance(data,dict) or data.get('schema_version')!=1 or not isinstance(data.get('gaps'),dict) or len(data['gaps'])>128:
                raise ValueError('invalid history coverage')
            for role,gap in data['gaps'].items():
                if not isinstance(role,str) or not isinstance(gap,dict) or type(gap.get('count')) is not int or gap['count']<1:
                    raise ValueError('invalid history gap')
            with self._lock:self._gaps=data['gaps']
        self._coverage_loaded=True

    def _record_gap(self,role,src,reason):
        # Persist the loss marker BEFORE forgetting an unread generation. This
        # sidecar is bounded by configured roles, independent of index quota.
        with self._lock:gaps={k:dict(v) for k,v in self._gaps.items()}
        if role not in gaps and len(gaps)>=128:raise ValueError('history role limit')
        old=gaps.get(role,{})
        gaps[role]=dict(count=old.get('count',0)+1,first_at=old.get('first_at',time.time()),
                       last_at=time.time(),reason=reason,file_id=src.file_id,
                       committed_offset=src.committed,missing_bytes=None)
        encoded=_json(dict(schema_version=1,gaps=gaps))
        if len(encoded)>65536:raise ValueError('history coverage too large')
        fd,name=tempfile.mkstemp(prefix='.coverage-',dir=self.path.parent)
        try:
            with os.fdopen(fd,'wb') as f:f.write(encoded);f.flush();os.fsync(f.fileno())
            os.replace(name,self._coverage_path)
            dirfd=os.open(self.path.parent,os.O_RDONLY)
            try:os.fsync(dirfd)
            finally:os.close(dirfd)
        finally:
            if os.path.exists(name):os.unlink(name)
        with self._lock:self._gaps=gaps;self._complete=False;self._revision+=1

    def _archive_entries(self):
        path=self.directory/'raw-manifest.json'
        try:
            with open_raw_read(path) as f:raw=f.read(262145)
        except FileNotFoundError:return []
        if len(raw)>262144:raise ValueError('raw manifest too large')
        manifest=json.loads(raw)
        if manifest.get('schema_version')!=1 or not isinstance(manifest.get('archives'),list) or len(manifest['archives'])>128:
            raise ValueError('raw manifest invalid')
        entries=[];names=set()
        for entry in manifest['archives']:
            role=entry.get('role');name=entry.get('name');size=entry.get('bytes');sha=entry.get('sha256')
            if (role not in self.roles or not isinstance(name,str) or not re.fullmatch(re.escape(role)+r'\.[0-9a-f]{32}\.jsonl',name)
                    or name in names or type(size) is not int or not 0<size<=64*1024*1024
                    or (sha is not None and (not isinstance(sha,str) or not re.fullmatch('[0-9a-f]{64}',sha)))):
                raise ValueError('raw archive entry invalid')
            names.add(name);entries.append(('archive:'+name,role,self.directory/'raw-archive'/name,entry))
        with self._lock:self._raw_state=dict(state=manifest.get('status','UNKNOWN'),archive_count=len(entries),
            archived_bytes=sum(e[3]['bytes'] for e in entries),pending=manifest.get('pending') is not None,automatic_delete=False)
        return entries

    def _verify_archive(self,src,entry):
        stamp=os.fstat(src.stream.fileno())
        identity=(stamp.st_dev,stamp.st_ino,stamp.st_size,stamp.st_mtime_ns,stamp.st_ctime_ns)
        if stamp.st_size!=entry['bytes']:raise EventLogError('HISTORY_ARCHIVE_CHANGED',503)
        if not entry.get('sha256'):return False
        if src.verified_stamp==(identity,entry['sha256']):return True
        if src.hash_stamp!=identity:
            src.hash_stamp=identity;src.hash_offset=0;src.hasher=hashlib.sha256()
        src.stream.seek(src.hash_offset);data=src.stream.read(READ_CHUNK_BYTES)
        src.hasher.update(data);src.hash_offset+=len(data)
        if src.hash_offset<stamp.st_size:return False
        if src.hasher.hexdigest()!=entry['sha256']:raise EventLogError('HISTORY_ARCHIVE_HASH_MISMATCH',503)
        src.verified_stamp=(identity,entry['sha256']);return True

    def _scan(self):
        self._load_coverage()
        archives=self._archive_entries()
        if self._size()>=int(self.CAP_BYTES*.9):
            raise EventLogError('HISTORY_BUDGET_EXCEEDED',503)
        if self._db is None:
            db=self.factory(self.path)
            with self._lock:self._db=db
        complete=not self._raw_state.get('pending',False);more=False
        entries=archives+[(role,role,self.directory/('demo-'+role+'.jsonl'),None) for role in self.roles]
        for key,role,path,archive in entries:
            if self._stop.is_set():return False
            try:st=path.stat()
            except FileNotFoundError:
                complete=False
                if archive:raise EventLogError('HISTORY_ARCHIVE_UNAVAILABLE',503)
                continue
            src=self._sources.get(key)
            rotating=bool(src and (st.st_dev,st.st_ino)!=src.identity)
            if rotating:
                # Keep the old descriptor until its final newline has been
                # indexed; a rename is not permission to throw away its tail.
                oldstat=os.fstat(src.stream.fileno())
                if src.decoder.offset<oldstat.st_size:
                    st=oldstat;more=True;complete=False
                else:
                    if src.committed<oldstat.st_size:
                        self._record_gap(role,src,'ROTATED_PARTIAL_RECORD')
                    src.close();del self._sources[key];src=None;rotating=False
            if src and not rotating and st.st_size<max(src.last_size,src.decoder.offset):
                self._record_gap(role,src,'SOURCE_TRUNCATED')
                src.close();del self._sources[key];src=None
            if src is None:
                known=self.barriers.get(role)
                barrier=known[1] if known and known[0]==(st.st_dev,st.st_ino) else 0
                src=self._sources[key]=IndexSource(path,role,self._db,barrier,known[0] if known else None,
                    alias=self.directory/('demo-'+role+'.jsonl') if archive else None,archive=archive)
            elif st.st_size!=src.last_size and not rotating:
                self._db.file_identity(path,st);src.last_size=st.st_size
            if archive:
                self._db.archive_identity(path,os.fstat(src.stream.fileno()),self.directory/('demo-'+role+'.jsonl'),archive.get('sha256'),archive['bytes'])
                if not self._verify_archive(src,archive):
                    complete=False
                    if archive.get('sha256'):more=True
                    continue
            src.stream.seek(src.decoder.offset)
            count=min(READ_CHUNK_BYTES,src.barrier-src.decoder.offset) if src.decoder.offset<src.barrier else READ_CHUNK_BYTES
            data=src.stream.read(count)
            if not data:
                if src.committed<st.st_size:complete=False
                continue
            rows,faults=src.decoder.feed(data);events=[]
            if src.barrier and src.decoder.offset==src.barrier:
                partial=src.decoder.buffered_bytes>0
                faults+=src.decoder.finish()
                if partial:src.decoder._discard=True
            for row in rows:
                ev=dict(self.public_actor(row['event']),source=role,replayed=True,origin=row['origin'],
                        received_t=time.time(),received_mono=time.monotonic(),received_clock_id=self.clock_id,
                        freshness_basis='history-index-read',motion_status='UNKNOWN')
                if len(_json(ev))>65536:
                    faults.append(dict(error='payload_oversize',origin=row['origin'],count=1));continue
                events.append((row['origin'],ev))
            for fault in faults:
                events.append((fault['origin'],dict(event='parser_fault',source=role,replayed=True,**fault)))
            # Only a contiguous successful transaction advances the replay point.
            self._db.ingest(src.file_id,src.decoder.line_start,events,advance=True)
            src.committed=src.decoder.line_start
            if src.committed<st.st_size:complete=False
            if src.decoder.offset<st.st_size:more=True
        with self._lock:self._complete=complete and not self._gaps;self._last_success=time.time()
        self._db.complete=self._complete
        return not more
    def _run(self):
        backoff=1
        try:
            while not self._stop.is_set():
                try:
                    complete=self._scan();self._set('ONLINE');backoff=1
                    if complete:self._settled.set()
                    wait=.25 if complete else .02
                except Exception as e:
                    for role,source in list(self._sources.items()):
                        try:source.reset_decoder()
                        except Exception:
                            try:source.close()
                            except Exception:pass
                            self._sources.pop(role,None)
                    code=e.code if isinstance(e,EventLogError) else ('HISTORY_WORKER_ERROR' if not isinstance(e,(OSError,ValueError,sqlite3.Error)) else ('HISTORY_LOCKED' if isinstance(e,sqlite3.OperationalError) and 'locked' in str(e).lower() else 'HISTORY_IO_ERROR'))
                    state='PAUSED_QUOTA' if code=='HISTORY_BUDGET_EXCEEDED' else ('LOCKED' if code=='HISTORY_LOCKED' else ('CORRUPT' if isinstance(e,sqlite3.DatabaseError) and not isinstance(e,sqlite3.OperationalError) else 'IO_ERROR'))
                    self._set(state,code);self._settled.set();wait=backoff;backoff=min(30,backoff*2)
                # Wakeups cannot defeat error backoff and hammer a full index.
                if self.error:self._stop.wait(wait)
                else:self._wake.wait(wait);self._wake.clear()
        finally:
            for src in self._sources.values():src.close()
            if self._db is not None:
                with self._page_lock:self._db.db.close()
    def page(self,cursor=None,limit=200):
        # The UI history endpoint may briefly wait for a small local index;
        # the live poller never does. Large backfill remains explicit/partial.
        self.wait_idle(.2)
        with self._page_lock:
            if self._stop.is_set():raise EventLogError('HISTORY_CLOSED',503)
            if self._db is None:
                reader=getattr(self.factory,'read_only_page',None)
                if reader is None:raise EventLogError(self.error or 'HISTORY_UNAVAILABLE',503)
                result=reader(self.path,cursor,limit)
            else:result=self._db.page(cursor,limit)
        result['history_health']=self.snapshot();result['history_complete']=self.complete
        return result
    def close(self):
        self._stop.set();self._wake.set();self._thread.join(2)
        return not self._thread.is_alive()
