# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Microduck adapter backend (`pail-duckd`) for the conformance harness.

Drives the adapter's PUBLIC robot socket exactly as a Microduck client would (NDJSON
JSON-RPC 2.0), observes the FAR SIDE on robotd's raw socket (`robot.state.move`) and reads
the adapter's decision log (`--gate-log`, the adapter's `/pail/gate_state`). Plans go to the
issuer's northbound over plaintext gRPC (dev profile). Faults are container kills through the
Docker Engine API on the mounted socket — no docker CLI needed.

Runs INSIDE the harness container (dev/Dockerfile.harness): the sockets live in docker
volumes that only a container can mount. See tests/adapter_conformance/rig_microduck.sh.

Honest gaps (raised as `Unsupported`, reported as SKIP with the reason, never as PASS):
  token_variant (forge/swap/expire/tight) — needs a rogue token seam in front of the adapter
  inject_safety — level is the robot's own report; only *staleness* is injectable, at the
                  safety-feed seam in front of robotd (CA-10, duck_state_seam.py)
  rogue_publish/subscribe — the socket rig's bypass probe is a separate tool (CB-1)
"""
from __future__ import annotations

import http.client
import json
import os
import socket
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

import grpc

import pail_pb2  # type: ignore
import pail_pb2_grpc  # type: ignore
import operator_service_pb2 as op_pb  # type: ignore
import operator_service_pb2_grpc as op_grpc  # type: ignore

from runner.core.backend import Backend, BridgeObs, GateObs, PermitObs, TwistObs
from runner.mocks.mock_ai import MockAI, load_issuer_signing_key
from runner.verifiers import keys as keymod
from runner.verifiers import segment_chain


class Unsupported(Exception):
    """A step this transport cannot perform. The runner turns it into SKIP + reason."""


def _env(k: str, d: str) -> str:
    return os.environ.get(k, d)


# ---------------------------------------------------------------------------------------
# Docker Engine API over the unix socket (kill / start), because the harness container has
# the socket but not the CLI.
# ---------------------------------------------------------------------------------------
class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str):
        super().__init__("localhost")
        self._path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self._path)


class _Docker:
    def __init__(self, sock_path: str):
        self.sock_path = sock_path

    def _req(self, method: str, url: str) -> int:
        c = _UnixHTTPConnection(self.sock_path)
        c.request(method, url)
        r = c.getresponse()
        r.read()
        c.close()
        return r.status

    def kill(self, name: str, signal: int = 9) -> None:
        st = self._req("POST", f"/containers/{name}/kill?signal={signal}")
        if st not in (204, 409):  # 409 = already not running
            raise RuntimeError(f"docker kill {name}: HTTP {st}")

    def start(self, name: str) -> None:
        st = self._req("POST", f"/containers/{name}/start")
        if st not in (204, 304):  # 304 = already started
            raise RuntimeError(f"docker start {name}: HTTP {st}")

    def running(self, name: str) -> bool:
        c = _UnixHTTPConnection(self.sock_path)
        c.request("GET", f"/containers/{name}/json")
        r = c.getresponse()
        body = r.read()
        c.close()
        if r.status != 200:
            return False
        return bool(json.loads(body)["State"]["Running"])


# ---------------------------------------------------------------------------------------
# NDJSON helpers
# ---------------------------------------------------------------------------------------
def _line(obj: Dict[str, Any]) -> bytes:
    return (json.dumps(obj, separators=(",", ":")) + "\n").encode()


class _FarSide(threading.Thread):
    """Own connection to robotd's raw socket: hello → subscribe → robot.state stream.
    The truth about what reached the robot lives here, never in the adapter."""

    def __init__(self, raw: str, hz: int = 20):
        super().__init__(daemon=True)
        self.raw, self.hz = raw, hz
        self.lock = threading.Lock()
        self.latest: Optional[Dict[str, Any]] = None
        self.latest_t: Optional[float] = None
        self.history: Deque[TwistObs] = deque(maxlen=4000)
        self.requested_history: Deque[TwistObs] = deque(maxlen=4000)
        # NOT `self._stop`: threading.Thread has a private _stop() method that is_alive()/join() call once the thread has
        # finished; an Event under that name made is_alive() raise "'Event' object is not callable" on a finished thread
        # (CA-10 on the first preview.7 pipeline, through observation_health()).
        self._halt = threading.Event()

    def run(self):
        while not self._halt.is_set():
            try:
                self._session()
            except Exception:
                time.sleep(0.5)

    def _session(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(self.raw)
        s.sendall(_line({"jsonrpc": "2.0", "id": 1, "method": "hello", "params": {"api_version": 44}}))
        s.sendall(_line({"jsonrpc": "2.0", "id": 2, "method": "robot.subscribe", "params": {"hz": self.hz}}))
        f = s.makefile("rb")
        while not self._halt.is_set():
            raw = f.readline()
            if not raw:
                return
            try:
                m = json.loads(raw)
            except Exception:
                continue
            if m.get("method") != "robot.state":
                continue
            mv = (m.get("params") or {}).get("move") or {}
            now = time.time()
            with self.lock:
                self.latest = mv
                self.latest_t = now
                ap = mv.get("applied") or [0.0, 0.0, 0.0]
                self.history.append(TwistObs(linear_x=float(ap[0]), angular_z=float(ap[2]), t=now))
                requested = mv.get("requested")
                if isinstance(requested, list) and len(requested) == 3:
                    self.requested_history.append(TwistObs(linear_x=float(requested[0]), angular_z=float(requested[2]), t=now))

    def snapshot(self):
        with self.lock:
            return self.latest, self.latest_t

    def clear(self):
        with self.lock:
            self.history.clear()
            self.requested_history.clear()


class _GateLogTail(threading.Thread):
    """Follows the adapter's --gate-log (NDJSON) from the position at start.

    The adapter is killed and restarted by scenarios (CA-08, CA-09), so the file can be truncated,
    replaced (new inode) or left with a half-written line. The tail reopens on either, buffers a
    partial line until its newline arrives, survives any read error (counted, printed, retried) and
    keeps counters so the harness can tell "nothing was observed" from "the wrong thing was
    observed" (health()). A tail that silently stopped delivering once turned healthy refusals into
    a FAIL that blamed the adapter (2026-10-10)."""

    def __init__(self, path: str, stall_after: Optional[int] = None):
        super().__init__(daemon=True)
        self.path = path
        # demo-inconclusive (PAIL_DUCK_OBSERVATION_FAULT=tail_stall): after this many records of a scenario the
        # tail stops delivering while the file keeps growing — the shape of the preview.5 evaluator's failure,
        # reproduced on purpose so a recipient can see the INCONCLUSIVE path (exit 4, DIAGNOSIS) before relying on it
        self.stall_after = stall_after
        self.lock = threading.Lock()
        self.entries: Deque[Dict[str, Any]] = deque(maxlen=20000)
        self._halt = threading.Event()
        self._pos = 0
        self._ino: Optional[int] = None
        self._partial = b""
        self.lines = 0                 # NDJSON records delivered since start
        self.lines_since_clear = 0     # … since the last clear() (one scenario)
        self.last_line_t: Optional[float] = None
        self.reopens = 0
        self.reopens_since_clear = 0
        self.size_at_clear = 0          # file size when the scenario started (0 when the file did not exist)
        self.pos_at_last_line = 0       # read position right after the last delivered record
        self.errors = 0
        self.last_error = ""

    def _stat(self):
        try:
            st = os.stat(self.path)
            return st.st_ino, st.st_size
        except OSError:
            return None, None

    def run(self):
        while not self._halt.is_set():
            try:
                ino, size = self._stat()
                if ino is None:
                    time.sleep(0.2)
                    continue
                if self._ino is not None and (ino != self._ino or (size is not None and size < self._pos)):
                    print(f"[tail] gate log replaced or truncated (inode {self._ino}->{ino}, size {size}, pos {self._pos}); reading from the start", flush=True)
                    self._pos = 0
                    self._partial = b""
                    self.reopens += 1
                    with self.lock:
                        self.reopens_since_clear += 1
                self._ino = ino
                with open(self.path, "rb") as f:
                    f.seek(self._pos)
                    while not self._halt.is_set():
                        if self.stall_after is not None and self.lines_since_clear >= self.stall_after:
                            time.sleep(0.05)   # deliberately stalled: the file grows, nothing is delivered
                            continue
                        chunk = f.readline()
                        if not chunk:
                            time.sleep(0.01)
                            ino2, size2 = self._stat()
                            if ino2 != self._ino or (size2 is not None and size2 < self._pos):
                                break   # the outer loop reopens from the start
                            continue
                        self._pos += len(chunk)
                        if not chunk.endswith(b"\n"):
                            self._partial += chunk   # the writer has not finished this line yet
                            continue
                        line = self._partial + chunk
                        self._partial = b""
                        try:
                            e = json.loads(line)
                        except Exception:
                            continue
                        e["_t"] = time.time()
                        with self.lock:
                            self.entries.append(e)
                            self.lines += 1
                            self.lines_since_clear += 1
                            self.last_line_t = e["_t"]
                            self.pos_at_last_line = self._pos
            except Exception as exc:   # never die silently: a dead tail reads as "the adapter did nothing"
                self.errors += 1
                self.last_error = f"{type(exc).__name__}: {exc}"
                print(f"[tail] gate log read error #{self.errors}: {self.last_error}; retrying", flush=True)
                time.sleep(0.2)

    def health(self) -> Dict[str, Any]:
        """Counters plus what the FILE did: a log that grew while nothing was delivered is the channel's failure
        (INCONCLUSIVE); a log that did not grow while the adapter was judging is the adapter not writing it — a
        contract violation the harness must call FAIL, not blame on the host (sixth evaluator report, D1/D2)."""
        ino, size = self._stat()
        with self.lock:
            age = None if self.last_line_t is None else round(time.time() - self.last_line_t, 3)
            size_v = size or 0
            return {"tail_alive": self.is_alive(), "lines": self.lines, "lines_since_clear": self.lines_since_clear,
                    "last_line_age_s": age, "reopens": self.reopens, "errors": self.errors, "last_error": self.last_error,
                    "file_exists": ino is not None, "file_bytes": size_v,
                    "file_grew_since_clear": self.reopens_since_clear > 0 or size_v > self.size_at_clear,
                    "file_grew_since_last_line": self.reopens_since_clear > 0 or size_v > max(self.pos_at_last_line, self.size_at_clear if self.lines_since_clear == 0 else 0),
                    "stalled_on_purpose": self.stall_after is not None}

    def since(self, t0: float) -> List[Dict[str, Any]]:
        with self.lock:
            return [e for e in self.entries if e["_t"] >= t0]

    def latest_outcome(self) -> Optional[Dict[str, Any]]:
        with self.lock:
            for e in reversed(self.entries):
                if e.get("kind") == "outcome" and e.get("state"):
                    return e
        return None

    def clear(self):
        with self.lock:
            self.entries.clear()
            self.lines_since_clear = 0
            _ino, _size = self._stat()
            self.size_at_clear = _size or 0
            self.pos_at_last_line = self._pos
            self.reopens_since_clear = 0


class _MovePublisher(threading.Thread):
    """robot.move at `rate` Hz for `dur` seconds on a fresh client connection (the transport
    form of PVS `inject_cmd_vel`)."""

    def __init__(self, public: str, lin: float, ang: float, rate: float, dur: float):
        super().__init__(daemon=True)
        self.public, self.lin, self.ang, self.rate, self.dur = public, lin, ang, rate, dur
        self._halt = threading.Event()

    def run(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(self.public)
        s.setblocking(False)
        s.sendall(_line({"jsonrpc": "2.0", "id": 1, "method": "hello", "params": {"api_version": 44}}))
        t_end = time.monotonic() + self.dur
        i = 100
        period = 1.0 / max(self.rate, 1.0)
        while not self._halt.is_set() and time.monotonic() < t_end:
            try:
                s.sendall(_line({"jsonrpc": "2.0", "id": i, "method": "robot.move",
                                 "params": {"vx": self.lin, "vy": 0.0, "vyaw": self.ang}}))
            except OSError:
                break
            i += 1
            # drain replies so the socket buffer never fills
            try:
                while s.recv(65536):
                    pass
            except (BlockingIOError, OSError):
                pass
            time.sleep(period)
        try:
            s.close()
        except OSError:
            pass

    def stop(self):
        self._halt.set()


class _SkillCaller(threading.Thread):
    """One `robot.do {skill}` on a fresh client connection (the transport form of PVS
    `inject_skill`, SK-2). The connection is held open `dur` seconds so the gate's verdict and
    the upstream's answer (or its absence) are observable, then closed."""

    def __init__(self, public: str, skill: str, dur: float):
        super().__init__(daemon=True)
        self.public, self.skill, self.dur = public, skill, dur

    def run(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(self.public)
        s.setblocking(False)
        s.sendall(_line({"jsonrpc": "2.0", "id": 1, "method": "hello", "params": {"api_version": 44}}))
        time.sleep(0.05)
        try:
            s.sendall(_line({"jsonrpc": "2.0", "id": 300, "method": "robot.do", "params": {"skill": self.skill}}))
        except OSError:
            pass
        t_end = time.monotonic() + self.dur
        while time.monotonic() < t_end:
            try:
                while s.recv(65536):
                    pass
            except (BlockingIOError, OSError):
                pass
            time.sleep(0.1)
        try:
            s.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------------------
class MicroduckBackend(Backend):
    def __init__(self):
        self.public = _env("PAIL_DUCK_PUBLIC", "/run/duck/pail.sock")
        self.raw = _env("PAIL_DUCK_RAW", "/run/duck/robotd.sock")
        self.evidence_sock = _env("PAIL_DUCK_EVIDENCE", "/run/duck/evidence.sock")
        self.gate_log = _env("PAIL_DUCK_GATE_LOG", "/run/duck/gate.ndjson")
        self.issuer_addr = _env("PAIL_DUCK_ISSUER", "duck-issuer:50051")
        self.adapter_ctr = _env("PAIL_DUCK_ADAPTER_CTR", "pail-duckd-run")
        self.issuer_ctr = _env("PAIL_DUCK_ISSUER_CTR", "duck-issuer")
        # The adapter's agent endpoint. With the seam in place that is the seam container; a
        # killed issuer behind a live seam is served as NO_TOKEN (fail-closed), which is a
        # different case from "the agent does not answer".
        self.agent_ctr = _env("PAIL_DUCK_AGENT_CTR", "duck-seam")
        self.blackbox_dir = Path(_env("PAIL_DUCK_BLACKBOX", "/bb"))
        self.keyring_path = Path(_env("PVS_KEYRING", "/work/config/keys/keyring.json"))
        self.issuer_key_path = _env("PVS_ISSUER_KEY", "/work/config/keys/issuer_ed25519.json")
        self.operator_key_path = _env("PVS_OPERATOR_KEY", "/work/config/keys/operator_ed25519.json")
        if self.public.endswith("pail_observe.sock") and os.environ.get("PAIL_DUCK_OBSERVE_RAW"):
            self.raw = os.environ["PAIL_DUCK_OBSERVE_RAW"]
            self.issuer_addr = os.environ["PAIL_DUCK_OBSERVE_ISSUER"]
            self.issuer_ctr = "observe-issuer"
            self.agent_ctr = ""
            self.blackbox_dir = Path(os.environ["PAIL_DUCK_OBSERVE_BLACKBOX"])
        self._op_stub = None
        self._op_sign = None
        self._last_op_nonce = None
        control = os.environ.get("PAIL_DUCK_CONTROL_DIR")
        if control:
            from .public_control import FileControl
            self.docker = FileControl(control)
        else:
            self.docker = _Docker(_env("DOCKER_SOCK", "/var/run/docker.sock"))
        # Optional token seam (pvs/runner/adapters/token_seam_server.py) between the adapter and
        # the issuer: its control socket lets north_cmd serve the negative token variants.
        self.seam_ctl = _env("PAIL_DUCK_SEAM_CTL", "")
        # 안전 피드 심 (CA-10). 없으면 inject_safety 는 종전대로 Unsupported 다 —
        # 「심이 없다」와 「막지 못했다」가 같은 값이 되면 안 된다.
        self.state_ctl = _env("PAIL_DUCK_STATE_CTL", "")
        if self.public.endswith("pail_observe.sock") and os.environ.get("PAIL_DUCK_OBSERVE_RAW"):
            self.seam_ctl = ""
            self.state_ctl = ""
        self._far: Optional[_FarSide] = None
        self._tail: Optional[_GateLogTail] = None
        self._pub: Optional[_MovePublisher] = None
        self._nb = None
        self._ai: Optional[MockAI] = None
        self._issuer_pubs = None
        self.name = "microduck_uds"

    # ---- lifecycle ----
    def setup(self):
        self._far = _FarSide(self.raw)
        self._far.start()
        fault = os.environ.get("PAIL_DUCK_OBSERVATION_FAULT", "")
        self._tail = _GateLogTail(self.gate_log, stall_after=1 if fault == "tail_stall" else None)
        self._tail.start()
        self._nb = pail_pb2_grpc.PailNorthboundStub(grpc.insecure_channel(self.issuer_addr))
        self._op_stub = op_grpc.OperatorServiceStub(grpc.insecure_channel(self.issuer_addr))
        self._op_sign = load_issuer_signing_key(self.operator_key_path)  # op-key-1, not the issuer key
        self._ai = MockAI(self.issuer_key_path)
        kr = keymod.load_keyring(self.keyring_path)
        self._issuer_pubs = keymod.issuer_pubs(kr)
        time.sleep(1.0)  # let the far-side subscription deliver a first frame

    def teardown(self):
        if self._pub:
            self._pub.stop()

    def reset_state(self):
        """Between scenarios: the rig's processes must be up (a scenario may have killed
        them) and the observation buffers start empty. The issuer keeps its chains — every
        scenario submits a fresh plan, so nothing from the previous one can grant."""
        if self._pub:
            self._pub.stop()
            self._pub = None
        for ctr in (self.issuer_ctr, self.agent_ctr, self.adapter_ctr):
            if ctr and not self.docker.running(ctr):
                self.docker.start(ctr)
        # wait for the adapter's public socket and the issuer's northbound to answer
        for _ in range(100):
            ok = os.path.exists(self.public) and os.path.exists(self.raw)
            if ok:
                try:
                    grpc.channel_ready_future(grpc.insecure_channel(self.issuer_addr)).result(timeout=1.0)
                    break
                except Exception:
                    pass
            time.sleep(0.2)
        time.sleep(2.0)  # issuer listeners up; adapter token poll reconnects; far side: fresh frames
        # The issuer keeps state across scenarios AND across restarts (the operator guard is
        # replayed from the journal): a security refusal reported by the adapter (ERR_TAMPERED,
        # …) leaves it in SAFE_STOP until an OPERATOR unlocks — exactly as in production (rc01).
        # So the reset does what an operator does: a signed unlock. "denied" when there was
        # nothing to unlock is fine; a transport failure is logged, and the next submit_plan
        # says SAFE_STOP out loud rather than this reset pretending.
        try:
            print(f"[reset] operator unlock: {self.operator_unlock({})}", flush=True)
        except Exception as e:
            print(f"[reset] operator unlock failed: {e}", flush=True)
        if self.seam_ctl and os.path.exists(self.seam_ctl):
            try:
                self._seam({"op": "clear"})
            except Exception:
                pass
        # 안전 심을 반드시 푼다. 무장한 채 다음 케이스로 넘어가면 그 케이스의 BLOCK 이
        # 자기 이유가 아니라 남은 stale 때문일 수 있다 — 배치 상태 누수.
        if self.state_ctl and os.path.exists(self.state_ctl):
            try:
                self._state_seam({"op": "stale", "on": False})
            except Exception:
                pass
        # After an agent/issuer kill the adapter's token poll reconnects with a backoff that grows with the outage. A case
        # that starts before the link is back is judged under ERR_ISSUER_UNREACHABLE and then under a token the restarted
        # agent re-declared (preview.7 stage-02: CA-10, after a 5 s agent outage in CA-09, saw 13 x ISSUER_UNREACHABLE then
        # 21 x TOKEN_CONSUMED instead of ERR_SAFETY_STALE; preview.6's 2 s outage happened to fit in the sleep above). So the
        # reset waits for the source to answer: a `robot.do` of a skill no robot has — it cannot actuate — must come back
        # judged by a reachable gate (any reason but ISSUER_UNREACHABLE / REPORT_UNAVAILABLE) before the next case starts.
        # Case isolation: cancel the previous case's plan at the issuer BEFORE the next case submits its own. Every case
        # submits plan_id "pvs-plan"; a plan whose window was never spent (CA-09: the stream was blocked after the kill;
        # CA-10: every command refused) leaves the gateway holding an unspent edge lease that it keeps serving — the
        # lease outranks the mirror by design (AV2 §3.2) and nothing tells the gateway about a newer plan until that lease
        # ends — so the next case's commands were judged under the old token (BLOCK ERR_TOKEN_CONSUMED; preview.7
        # stage-02/03). Cancelling the plan revokes its chain (CHAIN_REVOKED beacon → Invalidate → lease dropped).
        self._cancel_previous_plan()
        self._wait_token_source(20.0)
        if self._far:
            self._far.clear()
        if self._tail:
            self._tail.clear()

    def _cancel_previous_plan(self) -> None:
        if not self._nb:
            return
        try:
            results=self._ai.cancel_owned_plans(self._nb)
            print(f"[reset] owned plan withdrawal results: {results}",flush=True)
        except grpc.RpcError as e:
            print(f"[reset] previous plan cancel: {e.code()} (no active plan is fine)", flush=True)
        except Exception as e:   # the reset must not die on this; the next case says what it sees
            print(f"[reset] previous plan cancel failed: {e}", flush=True)

    def _wait_token_source(self, budget_s: float) -> None:
        if not self._tail:
            return
        deadline = time.monotonic() + budget_s
        attempt = 0
        while time.monotonic() < deadline:
            attempt += 1
            before = self._tail.lines
            _SkillCaller(self.public, "pail_reset_probe", 0.3).start()
            t_end = time.monotonic() + 1.5
            while time.monotonic() < t_end:
                if self._tail.lines > before:
                    g = self._tail.latest_outcome() or {}
                    if g.get("reason") not in ("ERR_ISSUER_UNREACHABLE", "ERR_REPORT_UNAVAILABLE"):
                        print(f"[reset] token source reachable after {attempt} probe(s): {g.get('state')} {g.get('reason')}", flush=True)
                        return
                    break
                time.sleep(0.05)
            time.sleep(0.5)
        print(f"[reset] token source still unreachable after {budget_s:.0f} s ({attempt} probes) — the next case will say so", flush=True)

    # ---- actuation ----
    def _seam(self, cmd: Dict[str, Any]) -> Dict[str, Any]:
        if not self.seam_ctl or not os.path.exists(self.seam_ctl):
            raise Unsupported("no token seam in this rig (NEEDS_ROGUE_SEAM)")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(self.seam_ctl)
        s.sendall(_line(cmd))
        f = s.makefile("rb")
        out = json.loads(f.readline() or b"{}")
        s.close()
        if not out.get("ok"):
            raise RuntimeError(f"seam {cmd.get('op')}: {out}")
        return out

    def north_cmd(self, sub: Optional[str], args: Dict[str, Any]) -> None:
        variant = args.get("token_variant")
        if sub == "submit_plan" and not variant:
            resp = self._ai.submit_plan(self._nb, args.get("steps", []))
            if resp.status != pail_pb2.ACCEPTED:
                raise RuntimeError(f"submit_plan rejected: {pail_pb2.SubmitStatus.Name(resp.status)} {resp.rejected_reason}")
            if self._ai.last_operation_outcome!='AUTHORIZED':raise RuntimeError('new execution not authorized: '+self._ai.last_operation_outcome)
            return
        if sub == "submit_plan":
            # Same variants as LiveBackend._serve_negative, minted with the dev issuer key the
            # adapter's keyring trusts — so what is judged is the variant, not the key.
            step = (args.get("steps") or [{}])[0]
            target = step.get("target_object_id", "")
            if variant == "forge_signature":
                st = self._ai.forge_bad_signature(target_object_id=target)
            elif variant == "swap_action":
                st = self._ai.swap_action_type(target_object_id=target)
            elif variant == "expire":
                st = self._ai.expire(delta_ms=int(args.get("delta_ms", -5000)), target_object_id=target)
            elif variant == "tight_constraint":
                st = self._ai.tight_constraint(max_linear=float(args.get("max_linear", 0.1)), target_object_id=target)
            else:
                raise Unsupported(f"token_variant {variant!r} not wired")
            import base64 as _b64
            self._seam({"op": "set", "signed_b64": _b64.b64encode(st.SerializeToString()).decode()})
            return
        raise Unsupported(f"north_cmd {sub!r} not wired for microduck")

    def inject_evidence(self, args: Dict[str, Any]) -> None:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(self.evidence_sock)
        s.sendall(_line({"source": args.get("source", "BARCODE"), "object_id": str(args["object_id"]),
                         "confidence": float(args.get("confidence", 0.95)), "t": int(time.time() * 1000)}))
        time.sleep(0.05)
        s.close()

    def inject_skill(self, args: Dict[str, Any]) -> None:
        _SkillCaller(self.public, str(args["skill"]), float(args.get("dur", 1.0))).start()

    def inject_cmd_vel(self, args: Dict[str, Any]) -> None:
        if self._pub:
            self._pub.stop()
        self._pub = _MovePublisher(self.public, float(args.get("lin", 0.0)), float(args.get("ang", 0.0)),
                                   float(args.get("rate", 10)), float(args.get("dur", 2.0)))
        self._pub.start()

    def _state_seam(self, cmd: Dict[str, Any]) -> Dict[str, Any]:
        if not self.state_ctl or not os.path.exists(self.state_ctl):
            raise Unsupported("no safety-feed seam in this rig (NEEDS_FAULT_INJECTION)")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(self.state_ctl)
        s.sendall(_line(cmd))
        f = s.makefile("rb")
        out = json.loads(f.readline() or b"{}")
        s.close()
        if not out.get("ok"):
            raise RuntimeError(f"state seam {cmd.get('op')}: {out}")
        return out

    def inject_safety(self, args: Dict[str, Any]) -> None:
        """CA-10. The robot reports its own safety, so we do not *publish* a level — we
        control whether its report reaches the adapter (duck_state_seam).

        `{stale: true}` stops `robot.state` from arriving while the connection stays open, so
        the feed ages out and the gate must refuse a NEW permit. `{level: OK}` is the release:
        the robot's own OK flows again. A level other than OK cannot be injected on this
        transport — the fake robot decides that, and saying otherwise would be a fake PASS.
        """
        if args.get("stale"):
            out = self._state_seam({"op": "stale", "on": True})
            print(f"[safety] feed muted at the seam (stale): {out}", flush=True)
            return
        level = str(args.get("level", "OK")).upper()
        if level != "OK":
            raise Unsupported(
                f"Microduck's safety level is the robot's own report; only staleness is "
                f"injectable here, not level={level} (NEEDS_FAULT_INJECTION)")
        out = self._state_seam({"op": "stale", "on": False})
        print(f"[safety] feed released at the seam: {out}", flush=True)

    def operator_unlock(self, args: Dict[str, Any]) -> str:
        """OperatorService.Unlock signed with the operator key (canon pail-unlock:v2, op-key-1)
        — the same request LiveBackend sends; the product's only way out of SAFE_STOP."""
        import base64 as _b64
        nonce = self._last_op_nonce if args.get("reuse_nonce") else os.urandom(16)
        self._last_op_nonce = nonce
        now_ms = int(time.time() * 1000)
        key_id = args.get("key", "op-key-1")
        robot_id = "robot-1"
        canon = (f"pail-unlock:v2:{robot_id}:{now_ms}:{_b64.b64encode(nonce).decode()}:{key_id}").encode()
        sig = self._op_sign.sign(canon).signature
        req = op_pb.UnlockRequest(robot_id=robot_id, unix_ms=now_ms, nonce=nonce,
                                  operator_sig=sig, operator_key_id=key_id)
        try:
            resp = self._op_stub.Unlock(req, timeout=5.0)
            return "unlocked" if resp.accepted else "denied"
        except grpc.RpcError as e:
            return f"error: {e.code()}"

    def fault(self, args: Dict[str, Any]) -> None:
        if "kill" in args:
            target = args["kill"]
            ctr = {"pep_gate": self.adapter_ctr, "adapter": self.adapter_ctr,
                   "issuer": self.issuer_ctr, "services": self.issuer_ctr,
                   "agent": self.agent_ctr or self.issuer_ctr}.get(target)
            if not ctr:
                raise Unsupported(f"fault kill {target!r} has no container in the microduck rig")
            self.docker.kill(ctr, int(args.get("signal", 9)))
            return
        raise Unsupported(f"fault {args!r} not wired for microduck")

    # ---- observation ----
    def gate(self) -> GateObs:
        e = self._tail.latest_outcome() if self._tail else None
        if not e:
            return GateObs()
        return GateObs(state=e.get("state"), reason=e.get("reason"), t=e.get("_t"))

    def bridge(self) -> BridgeObs:
        """Microduck has no motion bridge: the robot's own deadman is the HOLD, and
        `applied` following a non-zero `requested` with no limiter is FORWARDING."""
        mv, t = self._far.snapshot() if self._far else (None, None)
        if not mv or t is None:
            return BridgeObs()
        limited = mv.get("limited_by") or []
        if "deadman" in limited:
            return BridgeObs(state="HOLD", t=t)
        req = mv.get("requested") or [0.0, 0.0, 0.0]
        if any(abs(float(x)) > 1e-6 for x in req) and (time.time() - t) < 0.5:
            return BridgeObs(state="FORWARDING", t=t)
        return BridgeObs(state="HOLD", t=t)

    def drive(self) -> TwistObs:
        if not self._far or not self._far.history:
            return TwistObs()
        return self._far.history[-1]

    def drive_history(self) -> List[TwistObs]:
        return list(self._far.history) if self._far else []

    def permits(self, window_ms: int) -> PermitObs:
        """No permit topic on this transport: a "permit" is every gate outcome in the window
        that says the permit is active (command PERMITs and recheck holds alike)."""
        if not self._tail:
            return PermitObs(window_ms=window_ms)
        t0 = time.time() - window_ms / 1000.0
        seqs = [i for i, e in enumerate(self._tail.since(t0)) if e.get("kind") == "outcome" and e.get("permit_active")]
        return PermitObs(seqs=seqs, window_ms=window_ms)

    def stop_request_asserted(self) -> bool:
        if not self._tail:
            return False
        return any(e.get("kind") == "stop" for e in self._tail.since(time.time() - 3.0))

    def audit_result(self):
        try:
            return segment_chain.verify(self.blackbox_dir, self._issuer_pubs)
        except Exception:
            return None

    def enforcement_supported(self) -> bool:
        return False

    def observation_health(self) -> Dict[str, Any]:
        """The gate-log tail's counters plus whether the far side saw the harness's own command stream
        in the last second (robot.state `requested` reports): with commands flowing and no gate record
        arriving, the observation channel — not the adapter — is what failed."""
        h: Dict[str, Any] = dict(self._tail.health()) if self._tail else {"tail_alive": False, "lines_since_clear": 0}
        if self._far:
            now = time.time()
            with self._far.lock:
                recent = [r for r in self._far.requested_history if r.t is not None and now - r.t <= 1.0]
            h["requested_reports_last_1s"] = len(recent)
            h["commands_flowing"] = any(abs(r.linear_x) > 1e-6 or abs(r.angular_z) > 1e-6 for r in recent)
        # The harness's own 10 Hz command stream (inject_cmd_vel) is still running: then the gate must be
        # writing a record every 100 ms, and a silent log is the channel's silence. A one-shot command
        # (a skill call) writes exactly one record and then nothing — silence after it is normal.
        h["publisher_active"] = bool(self._pub is not None and self._pub.is_alive())
        return h
