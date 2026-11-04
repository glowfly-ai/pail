# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Operator-side read bridge to a collector that only listens on its container loopback.

One long-lived reader runs inside the collector container and answers one GET per request
line. Callers wait in a bounded queue; a browser that loads several scripts at once is
served in turn instead of being refused. Static dashboard files are kept in memory after
the first read: they come from the pinned image and do not change during a run.

The destination is fixed by the caller of this module, never by the HTTP request. GET only.
"""
import base64
import json
import queue
import subprocess
import threading

READER = r'''
import base64,json,sys,urllib.request,urllib.error
base=sys.argv[1]
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args): return None
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
for line in sys.stdin:
    try:
        path=json.loads(line)['path']
        try: r=opener.open(base+path,timeout=4)
        except urllib.error.HTTPError as e: r=e
        body=r.read(1048577)
        if len(body)>1048576: out={'error':'RESPONSE_LIMIT'}
        else: out={'status':r.status,'type':r.headers.get('Content-Type','application/octet-stream'),'body':base64.b64encode(body).decode()}
    except Exception as e:
        out={'error':type(e).__name__}
    sys.stdout.write(json.dumps(out)+'\n'); sys.stdout.flush()
'''

MAX_WAITING = 32
WAIT_SECONDS = 10
READ_SECONDS = 8
CACHE_ENTRIES = 32
CACHE_BYTES = 4 * 1024 * 1024
BUSY = (429, 'text/plain', b'READER_LIMIT')
UNAVAILABLE = (503, 'text/plain', b'COLLECTOR_UNAVAILABLE')


class CollectorBridge:
    def __init__(self, argv, env=None, static_prefix='/dashboard/', max_waiting=MAX_WAITING,
                 wait_seconds=WAIT_SECONDS, read_seconds=READ_SECONDS):
        self.argv, self.env, self.static_prefix = list(argv), env, static_prefix
        self.max_waiting, self.wait_seconds, self.read_seconds = max_waiting, wait_seconds, read_seconds
        self._turn, self._count = threading.Lock(), threading.Lock()
        self._waiting = 0
        self._proc = self._lines = None
        self._cache, self._cache_bytes = {}, 0
        self.stats = dict(requests=0, cache_hits=0, busy=0, unavailable=0, reader_starts=0)

    def _start(self):
        self._proc = subprocess.Popen(self.argv, env=self.env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, text=True, bufsize=1)
        self._lines = lines = queue.Queue()
        self.stats['reader_starts'] += 1

        def pump(stream):
            for line in stream:
                lines.put(line)
            lines.put(None)
        threading.Thread(target=pump, args=(self._proc.stdout,), daemon=True).start()

    def _stop(self):
        proc, self._proc, self._lines = self._proc, None, None
        if proc is not None:
            for stream in (proc.stdin, proc.stdout):
                try:
                    stream.close()
                except OSError:
                    pass
            proc.kill()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass

    def _exchange(self, path):
        if self._proc is None or self._proc.poll() is not None:
            self._stop()
            self._start()
        try:
            self._proc.stdin.write(json.dumps({'path': path}) + '\n')
            self._proc.stdin.flush()
            line = self._lines.get(timeout=self.read_seconds)
            doc = json.loads(line) if line else None
        except (OSError, ValueError, queue.Empty):
            doc = None
        if not doc or 'error' in doc:
            # The reader's position in its stream is unknown after a failure: replace it.
            self._stop()
            self.stats['unavailable'] += 1
            return UNAVAILABLE
        return doc['status'], doc['type'], base64.b64decode(doc['body'])

    def read(self, path):
        self.stats['requests'] += 1
        static = path.split('?', 1)[0].startswith(self.static_prefix)
        if static and path in self._cache:
            self.stats['cache_hits'] += 1
            return self._cache[path]
        with self._count:
            if self._waiting >= self.max_waiting:
                self.stats['busy'] += 1
                return BUSY
            self._waiting += 1
        try:
            if not self._turn.acquire(timeout=self.wait_seconds):
                self.stats['busy'] += 1
                return BUSY
            try:
                if static and path in self._cache:
                    self.stats['cache_hits'] += 1
                    return self._cache[path]
                answer = self._exchange(path)
                if (static and answer[0] == 200 and len(self._cache) < CACHE_ENTRIES
                        and self._cache_bytes + len(answer[2]) <= CACHE_BYTES):
                    self._cache[path] = answer
                    self._cache_bytes += len(answer[2])
                return answer
            finally:
                self._turn.release()
        finally:
            with self._count:
                self._waiting -= 1

    def close(self):
        with self._turn:
            self._stop()
