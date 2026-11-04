#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""CA-07 — contract I-3 (bit-identical pass-through) and "not this socket" rejection,
measured from the far side of the adapter. (Maintained copy of the MD-1 measurement tool;
the conformance harness runs this one.)

This is a *tap*, not a stand-in for robotd: it listens where the raw socket would be,
records every byte the adapter forwards, and answers only `hello` (so the adapter's
hello capture has something to read). The SUT for behaviour is still `robotd --fake`
(md0_observe.py through the public socket does that part).

    md1_bytes.py <raw-socket-path-to-serve> <public-socket-path-to-dial>

Checks (each prints PASS/FAIL; rc=1 if any FAIL):
  B1  a robot.move line with odd spacing / key order / trailing fields arrives at the
      tap byte-for-byte (the adapter parsed it, but forwarded the *original*)
  B2  a notification (no id) is forwarded byte-for-byte too
  B3  `update.status` gets METHOD_NOT_FOUND from the adapter and the tap sees nothing
  B4  a non-JSON line gets PARSE_ERROR from the adapter and the tap sees nothing
  B5  hello is forwarded and the tap's answer comes back byte-for-byte
"""
import json, os, select, socket, sys, threading, time

RAW, PUB = sys.argv[1], sys.argv[2]
recorded = []          # bytes the tap received, per connection
tap_ready = threading.Event()

HELLO_ANSWER = b'{"jsonrpc":"2.0","id":7,"result":{"api_version":44,"daemon_version":"0.0.0-tap","revision":"tap"}}\n'

def tap():
    if os.path.exists(RAW):
        os.unlink(RAW)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(RAW)
    os.chmod(RAW, 0o660)
    srv.listen(4)
    tap_ready.set()
    while True:
        c, _ = srv.accept()
        buf = b""
        while True:
            chunk = c.recv(65536)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                line += b"\n"
                recorded.append(line)
                try:
                    if json.loads(line).get("method") == "hello":
                        c.sendall(HELLO_ANSWER)
                except Exception:
                    pass
        c.close()

threading.Thread(target=tap, daemon=True).start()
tap_ready.wait(5)

def dial():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(PUB)
    return s

def read_line(s, timeout=2.0):
    s.setblocking(False)
    buf = b""
    t0 = time.monotonic()
    while b"\n" not in buf:
        left = max(0.0, timeout - (time.monotonic() - t0))
        r, _, _ = select.select([s], [], [], left)
        if not r:
            return None
        chunk = s.recv(65536)
        if not chunk:
            return b""
        buf += chunk
    return buf.split(b"\n", 1)[0] + b"\n"

def wait_recorded(n, timeout=2.0):
    t0 = time.monotonic()
    while len(recorded) < n and time.monotonic() - t0 < timeout:
        time.sleep(0.02)
    return len(recorded) >= n

fails = 0
def verdict(tag, ok, detail=""):
    global fails
    print(f"{tag}: {'PASS' if ok else 'FAIL'} {detail}")
    if not ok:
        fails += 1

s = dial()

# B5 hello round trip (first, so the adapter has a pending id to match)
hello = b'{ "jsonrpc": "2.0", "id": 7, "method": "hello", "params": {"api_version": 44} }\n'
s.sendall(hello)
ok = wait_recorded(1) and recorded[0] == hello
verdict("B5a hello forwarded byte-identical", ok, repr(recorded[:1]))
ans = read_line(s)
verdict("B5b hello answer relayed byte-identical", ans == HELLO_ANSWER, repr(ans))

# B1 odd formatting: spaces, key order, a request id as text, nested params order
odd = b'{"method":"robot.move" ,  "params": {"vyaw": 0.0, "vx": 0.12, "vy": 0.0},"id":"m-1","jsonrpc":"2.0"}\n'
s.sendall(odd)
ok = wait_recorded(2) and recorded[1] == odd
verdict("B1 robot.move forwarded byte-identical", ok, repr(recorded[1:2]))

# B2 notification (no id)
note = b'{"jsonrpc":"2.0","method":"robot.move","params":{"vx":0.05,"vy":0,"vyaw":0}}\n'
s.sendall(note)
ok = wait_recorded(3) and recorded[2] == note
verdict("B2 notification forwarded byte-identical", ok, repr(recorded[2:3]))

# B3 foreign method: adapter answers, tap sees nothing new
before = len(recorded)
s.sendall(b'{"jsonrpc":"2.0","id":9,"method":"update.status"}\n')
ans = read_line(s)
try:
    j = json.loads(ans or b"{}")
except Exception:
    j = {}
time.sleep(0.2)
verdict("B3 update.status rejected -32601, not forwarded",
        j.get("id") == 9 and j.get("error", {}).get("code") == -32601 and len(recorded) == before,
        f"answer={ans!r} tap_new={len(recorded)-before}")

# B4 garbage line
before = len(recorded)
s.sendall(b'this is not json\n')
ans = read_line(s)
try:
    j = json.loads(ans or b"{}")
except Exception:
    j = {}
time.sleep(0.2)
verdict("B4 non-JSON gets -32700, not forwarded",
        j.get("error", {}).get("code") == -32700 and len(recorded) == before,
        f"answer={ans!r} tap_new={len(recorded)-before}")

s.close()
print("VERDICT:", "PASS" if fails == 0 else f"FAIL ({fails})")
sys.exit(1 if fails else 0)
