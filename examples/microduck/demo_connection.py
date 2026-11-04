# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Bounded demo-planner transport. No motor command is replayed during reconnection."""
import errno
import json
import socket
import time

class Frames:
    def __init__(self):self.pending=b''
    def feed(self,data):
        self.pending+=data
        if len(self.pending)>1024*1024:raise ValueError('planner reply frame limit')
        rows=[]
        while b'\n' in self.pending:
            line,self.pending=self.pending.split(b'\n',1)
            if line:
                value=json.loads(line)
                if not isinstance(value,dict):raise ValueError('planner reply is not an object')
                rows.append(value)
        return rows

class PlannerConnection:
    def __init__(self,path,record):self.path=path;self.record=record;self.sock=None;self.frames=Frames();self.initial=[]
    def close(self):
        if self.sock is not None:self.sock.close()
        self.sock=None;self.frames=Frames();self.initial=[]
    def connect(self,timeout=15):
        self.close();end=time.monotonic()+timeout;attempts=0
        while True:
            attempts+=1;s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            try:
                s.settimeout(max(.01,min(1,end-time.monotonic())));s.connect(self.path)
                s.sendall(b'{"jsonrpc":"2.0","id":1,"method":"hello","params":{"api_version":44}}\n')
                frames=Frames();rows=[]
                while not any(row.get('id')==1 for row in rows):
                    chunk=s.recv(65536)
                    if not chunk:raise ConnectionError('closed during hello')
                    rows.extend(frames.feed(chunk))
                    if time.monotonic()>=end:raise TimeoutError('hello deadline')
                hello=next(row for row in rows if row.get('id')==1)
                if hello.get('error') or 'result' not in hello:raise ValueError('adapter hello refused')
                self.sock=s;self.frames=frames;self.initial=[row for row in rows if row.get('id')!=1]
                s.setblocking(False);self.record('connected',socket=self.path,attempts=attempts,hello_confirmed=True);return
            except OSError as exc:
                s.close()
                if time.monotonic()>=end:raise TimeoutError('ADAPTER_CONNECT_TIMEOUT: '+str(exc)) from exc
                if not isinstance(exc,(ConnectionError,TimeoutError)) and exc.errno not in (errno.ENOENT,errno.ECONNREFUSED,errno.ECONNRESET,errno.EPIPE):raise
                self.record('connect_wait',attempt=attempts,reason=type(exc).__name__)
                time.sleep(min(.1,max(0,end-time.monotonic())))
            except Exception:
                s.close();raise
    def drain(self):
        if self.sock is None:raise ConnectionError('not connected')
        rows,self.initial=self.initial,[]
        while True:
            try:chunk=self.sock.recv(65536)
            except (BlockingIOError,InterruptedError):break
            if not chunk:raise ConnectionError('adapter closed')
            rows.extend(self.frames.feed(chunk))
        return rows
    def send(self,value):
        if self.sock is None:raise ConnectionError('not connected')
        # A partial nonblocking send must not splice the next RPC into its frame.
        self.sock.settimeout(1)
        try:self.sock.sendall(json.dumps(value).encode()+b'\n')
        except OSError:
            self.close();raise
        finally:
            if self.sock is not None:self.sock.setblocking(False)
