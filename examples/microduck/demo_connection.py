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


# ---- the planner's copy of a step window --------------------------------------------------------------------------
# The adapter starts a step's clock when it receives the first command of that step, and refuses a command that
# arrives after the step's deadline. The planner keeps its own copy of that window, so both readings below have to
# be taken where the adapter's clock cannot be ahead of them. The planner container has a fraction of a CPU: the
# scheduler can hold it for most of a 0.1 s period between any two statements (0.2.1 amd64 replay: one zero command
# arrived 5 ms after the deadline; the stamp had been read after the send, the check at the top of the loop).

def send_stamped(clock, send):
    """(request id, the clock read BEFORE the send). The adapter cannot have the command earlier than this, so a
    window that starts here never ends after the adapter's."""
    at = clock()
    return send(), at


def zero_window_open(clock, stop_until):
    """True while a zero-velocity command may still be sent, on a clock reading taken now, not at the top of the
    loop: what happens between this reading and the send is covered by the margin before the deadline."""
    return clock() < stop_until
