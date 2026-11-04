#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Standalone safety-feed seam for the Microduck rig (CA-10, contract ③).

Sits between the adapter and upstream `robotd` as a transparent Unix-socket proxy. A control
socket (NDJSON, one command per line) lets the conformance backend **stop the safety feed
without closing the connection** — which is the only way to make the feed go *stale* rather
than *absent*.

    duck_state_seam.py --listen /run/duck/robotd_seam.sock \\
                       --upstream /run/duck/robotd.sock --ctl /run/duck/state.ctl

Control: {"op":"stale","on":true} · {"op":"stale","on":false} · {"op":"status"}

Why a seam and not a flag on robotd: `robotd` is **upstream Microduck code and not in this
tree** (only its systemd drop-in is ours). The adapter contract says the adapter is built
around the robot, not the robot around the adapter — so the fault is injected in front of the
robot, exactly as the token seam is injected in front of the issuer. Nothing upstream changes.

What is dropped and what is not (this distinction is the whole point):

  - dropped when armed: `robot.state` **notifications** flowing upstream → adapter. The
    adapter's watch is never touched, so `safety_stale_ms` ages out and the gate must refuse a
    NEW permit (ERR_SAFETY_STALE).
  - never dropped: everything adapter → upstream (so `robot.stop` still reaches the robot
    under a stale feed — a seam that muted stop would be testing a different, safer world),
    and every response frame (`hello`/`robot.subscribe`/`robot.skills`/`robot.health`), so the
    session stays alive rather than reconnecting.

Closing the connection instead of dropping frames would be the wrong fault: the adapter
reconnects on error (safety.rs `run()` backoff) and the feed comes back — that measures
reconnection, not staleness.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import sys
import threading

STATE_METHOD = "robot.state"          # 2026-09-07 wire tap: id-less notification frame


class Seam:
    def __init__(self, upstream: str, tap_log=None):
        self.upstream = upstream
        self.tap_log=tap_log;self.tap_lock=threading.Lock()
        if tap_log:
            with open(tap_log,'a'):pass
            os.chmod(tap_log,0o644)
        self.lock = threading.Lock()
        self.stale = False
        self.picked_up = False
        self.injected = 0
        self.dropped = 0
        self.passed = 0

    # ── control ────────────────────────────────────────────────────────────
    def command(self, msg: dict) -> dict:
        op = msg.get("op")
        if op == "stale":
            with self.lock:
                self.stale = bool(msg.get("on", True))
                return {"ok": True, "stale": self.stale, "dropped": self.dropped}
        if op == "picked_up":
            if type(msg.get("on")) is not bool:
                return {"ok":False,"error":"picked_up requires boolean on"}
            with self.lock:
                self.picked_up=msg["on"]
                return {"ok":True,"picked_up":self.picked_up,"injected":self.injected}
        if op == "status":
            with self.lock:
                return {"ok": True, "stale": self.stale,
                        "dropped": self.dropped, "passed": self.passed, "picked_up":self.picked_up,"injected":self.injected}
        # 알 수 없는 명령을 조용히 무시하면 「제어했다」와 「제어되지 않았다」가 같은
        # 침묵으로 도착한다. 시나리오는 그 침묵 위에서 초록이 된다.
        return {"ok": False, "error": "unknown op: %r" % (op,)}

    def serve_ctl(self, path: str) -> None:
        if os.path.exists(path):
            os.unlink(path)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(path)
        os.chmod(path, 0o660)
        s.listen(8)
        while True:
            c, _ = s.accept()
            threading.Thread(target=self._ctl_conn, args=(c,), daemon=True).start()

    def _ctl_conn(self, c: socket.socket) -> None:
        try:
            f = c.makefile("rwb")
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except ValueError as e:
                    reply = {"ok": False, "error": "bad json: %s" % e}
                else:
                    reply = self.command(msg)
                f.write(json.dumps(reply).encode() + b"\n")
                f.flush()
        except OSError:
            pass
        finally:
            c.close()

    # ── data path ──────────────────────────────────────────────────────────
    def serve(self, listen: str) -> None:
        if os.path.exists(listen):
            os.unlink(listen)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(listen)
        os.chmod(listen, 0o660)
        s.listen(16)
        sys.stderr.write("duck_state_seam: %s -> %s\n" % (listen, self.upstream))
        sys.stderr.flush()
        while True:
            c, _ = s.accept()
            threading.Thread(target=self._conn, args=(c,), daemon=True).start()

    def _conn(self, client: socket.socket) -> None:
        try:
            up = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            up.connect(self.upstream)
        except OSError as e:
            sys.stderr.write("duck_state_seam: upstream connect failed: %s\n" % e)
            client.close()
            return
        # adapter → robot: 그대로. 거르지 않는다.
        threading.Thread(target=self._pump_raw, args=(client, up), daemon=True).start()
        # robot → adapter: 무장 시 robot.state 알림만 떨군다.
        self._pump_filtered(up, client)

    def _record_tap(self,side,line):
        if not self.tap_log:return
        try:msg=json.loads(line)
        except ValueError:return
        identifier=msg.get('id') if isinstance(msg,dict) else None
        if isinstance(identifier,str) and identifier.startswith('ca16-'):
            with self.tap_lock:
                with open(self.tap_log,'a') as f:f.write(json.dumps(dict(side=side,id=identifier,raw_b64=base64.b64encode(line).decode()))+'\n')

    def _pump_raw(self,src: socket.socket, dst: socket.socket) -> None:
        buffered=b''
        try:
            while True:
                b = src.recv(65536)
                if not b:
                    break
                dst.sendall(b)
                if self.tap_log:
                    buffered+=b
                    if len(buffered)>1024*1024:raise OSError('tap frame bound')
                    while b'\n' in buffered:
                        line,buffered=buffered.split(b'\n',1);self._record_tap('request',line+b'\n')
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def _pump_filtered(self, src: socket.socket, dst: socket.socket) -> None:
        buf = b""
        try:
            while True:
                b = src.recv(65536)
                if not b:
                    break
                buf += b
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if self._drop(line):
                        continue
                    self._record_tap('response',line+b'\n')
                    dst.sendall(self._transform(line) + b"\n")
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def _transform(self,line: bytes) -> bytes:
        # Explicit test-only field injection. When disarmed, preserve every
        # original byte. This path is NOT the bit-identical relay measurement.
        with self.lock:armed=self.picked_up
        if not armed:return line
        try:msg=json.loads(line)
        except ValueError:return line
        if (not isinstance(msg,dict) or msg.get("method")!=STATE_METHOD
                or "id" in msg or not isinstance(msg.get("params"),dict)):
            return line
        safety=msg["params"].get("safety")
        if not isinstance(safety,dict):return line
        safety["picked_up"]=True
        with self.lock:self.injected+=1
        return json.dumps(msg,separators=(',',':')).encode()

    def _drop(self, line: bytes) -> bool:
        with self.lock:
            armed = self.stale
        if not armed:
            with self.lock:
                self.passed += 1
            return False
        # 판정은 파싱된 method 로 한다. 바이트에 `robot.state` 가 들어 있는지로 재면
        # 그 문자열을 품은 다른 프레임(오류 메시지·스킬 목록)까지 함께 사라진다.
        try:
            msg = json.loads(line)
        except ValueError:
            return False
        if isinstance(msg, dict) and msg.get("method") == STATE_METHOD:
            with self.lock:
                self.dropped += 1
            return True
        with self.lock:
            self.passed += 1
        return False


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--listen", required=True)
    ap.add_argument("--upstream", required=True)
    ap.add_argument("--ctl", required=True)
    ap.add_argument("--tap-log",help="test-only byte capture for ca16-prefixed request IDs")
    ap.add_argument("--inject-picked-up",action="store_true",help="test-only pickup field injection; not real IMU evidence")
    args = ap.parse_args(argv[1:])

    seam = Seam(args.upstream,args.tap_log)
    seam.picked_up=args.inject_picked_up
    threading.Thread(target=seam.serve_ctl, args=(args.ctl,), daemon=True).start()
    seam.serve(args.listen)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
