# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""LiveBackend  — the real docker/ROS2/gRPC I/O layer.

BUILD-ONLY / LIVE-TIER. This module imports rclpy + grpc and only runs on a ROS2
Humble machine with the compose stack up (PVS_LIVE=1). It is *not* executed by the
host test tier; the verdict *logic* it feeds is unit-tested via FakeBackend, and
every component it composes (MockHAL, SafetyAdapter, MockAI, mock_cloud,
ChaosMonkey, the verifiers) is independently tested on the host. What remains
unproven until a live bring-up is the wiring itself — see LIVE_BRINGUP.md for the
runtime contracts an operator must confirm. The token proxy transport contract is
tested separately without claiming a ROS2 live bring-up.

Design: observations are delegated to the MockHAL / SafetyAdapter rclpy nodes
(the verdict 정본 is /drive_cmd_vel via MockHAL). Actuation drives those nodes,
the gRPC northbound/operator stubs, the fault injector, and the mock cloud.
Negative tokens are served by an in-process rogue TokenService (the Python twin
of cmd/rogue_token_stub); the gate must be pointed at PVS_ROGUE_TOKEN_ADDR for
the token/recovery axes (compose negative-token profile).
"""

# PAIL-CANON-COPY : pail-unlock:v1
# 정본 = services/pail_services_go/internal/canon
# 이 파일은 SUT 를 import 하지 않는 의도된 독립 구현이다. 같은 상수를 쓰면
# 대조가 항등식이 되어 드리프트를 못 잡는다. 정본과 함께 고치지 않으면
# §4.3 골든 벡터가 붉어진다(CI 검사 2). 삭제 대상이 아니다.


from __future__ import annotations

import os
import shutil
import subprocess
import sys
import threading
import uuid
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import grpc

_HERE = Path(__file__).resolve().parent      # runner/live (pb2 stubs import each other top-level)
_RUNNER = _HERE.parent
_PVS = _RUNNER.parent                        # pvs/ — root of the `runner` package
for _p in (str(_HERE), str(_PVS)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import rclpy
from rclpy.executors import MultiThreadedExecutor

import pail_pb2  # type: ignore
import pail_pb2_grpc  # type: ignore
import token_service_pb2 as tok_pb  # type: ignore
import token_service_pb2_grpc as tok_grpc  # type: ignore
import operator_service_pb2 as op_pb  # type: ignore
import operator_service_pb2_grpc as op_grpc  # type: ignore

from runner.core.backend import Backend, GateObs, BridgeObs, TwistObs, PermitObs
from runner.core.model import submit_declaration_error
from runner.mocks.mock_hal import MockHAL
from runner.mocks.mock_ai import MockAI, load_issuer_signing_key, check_no_contract_setting, submit_outcome
from runner.mocks.mock_cloud import BurstListener, AnchorServer
from runner.mocks.safety_adapter import SafetyAdapter
from runner.mocks import rogue_actor
from runner.injectors.chaos_monkey import ChaosMonkey
from runner.verifiers import segment_chain, anchor_check, keys as keymod

_REPO = _RUNNER.parents[1]          # PAIL-v2/
_DEFAULT_KEYRING = _REPO / "config" / "keys" / "keyring.json"
_DEFAULT_ISSUER = _REPO / "config" / "keys" / "issuer_ed25519.json"
_DEFAULT_OPERATOR = _REPO / "config" / "keys" / "operator_ed25519.json"


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


# --------------------------------------------------------------------------
# Rogue TokenService: serves a caller-supplied SignedToken (negative tokens /
# replay). Mirrors cmd/rogue_token_stub — same signed-token contract, driven
# from Python so MockAI's negative factory decides the payload.
# --------------------------------------------------------------------------
def relay_metadata(context, call, names):
    """Copy the allow-listed initial and trailing metadata of an upstream call onto the served context."""
    initial = [(k, v) for k, v in (call.initial_metadata() or ()) if k in names]
    trailing = [(k, v) for k, v in (call.trailing_metadata() or ()) if k in names]
    if initial:
        context.send_initial_metadata(initial)
    if trailing:
        context.set_trailing_metadata(trailing)


class _RogueTokenService(tok_grpc.TokenServiceServicer):
    """Token seam for the token/recovery axes (gate pointed at :50052).

    Default mode is a transparent proxy to the REAL issuer that CAPTURES every
    OK response in issue order — replay_token (ti01) then pins the first
    captured (= consumed) token so the gate's single-use cache must reject it.
    Negative variants (forge/swap/expire/tight) set `signed` and are served
    only after the configured upstream handshake succeeds. Transport failures stay failures.
    """

    def __init__(self, upstream_addr: Optional[str] = None):
        self.signed: Optional["pail_pb2.SignedToken"] = None
        self.status = tok_pb.ActiveTokenStatus.OK
        self.chain_id = "pvs-chain"
        self.upstream_addr = upstream_addr
        self._stub = None
        self._capture_lock = threading.Lock()
        self.captured_headers: list = []
        self.captured: list = []               # distinct OK responses, issue order
        self.replay_index: Optional[int] = None
        self.fake_ack = False   # negative fixture only (see ReportDecision); LiveBackend sets it from PVS_ROGUE_FAKE_ACK

    def reset(self):
        self.signed = None
        self.status = tok_pb.ActiveTokenStatus.OK
        with self._capture_lock:
            self.captured = []
            self.captured_headers = []
            self.replay_index = None

    def _upstream(self):
        if self._stub is None and self.upstream_addr:
            self._stub = tok_grpc.TokenServiceStub(grpc.insecure_channel(self.upstream_addr))
        return self._stub

    def GetActiveToken(self, request, context):
        up = self._upstream()
        if up is None:
            return tok_pb.GetActiveTokenResponse(status=tok_pb.ActiveTokenStatus.NO_TOKEN)
        identity = tuple((k, v) for k, v in context.invocation_metadata()
                         if k == "pail-execution-instance")
        try:
            resp, call = up.GetActiveToken.with_call(request, timeout=2.0, metadata=identity)
        except grpc.RpcError as exc:
            context.abort(exc.code(), "upstream: " + (exc.details() or ""))
        headers = tuple((k, v) for k, v in call.initial_metadata()
                        if k == "pail-execution-instance")
        if self.signed is not None:
            if headers:context.send_initial_metadata(headers)
            return tok_pb.GetActiveTokenResponse(
                status=self.status, chain_id=self.chain_id,
                expected_sequence_index=1, token=self.signed,
                current_subgraph_hash=self.signed.token.subgraph_snapshot_hash)
        # Keep each captured body and its acknowledgement in one critical section.
        with self._capture_lock:
            if resp.status == tok_pb.ActiveTokenStatus.OK:
                if (not self.captured or
                        resp.token.SerializeToString() != self.captured[-1].token.SerializeToString()):
                    self.captured.append(resp)
                    self.captured_headers.append(headers)
            if self.replay_index is not None and self.captured:
                index = min(self.replay_index, len(self.captured) - 1)
                # Replay the original acknowledgement too. A new process must not
                # receive a fresh execution ACK attached to an old pinned token.
                headers = self.captured_headers[index]
                resp = self.captured[index]
        if headers:context.send_initial_metadata(headers)
        return resp

    # PAIL diagnostic/contract metadata the seam relays verbatim from the upstream answer (preview.38 RV01):
    # the C1 cohort header of a census and the execution-reset marker. Never authentication material.
    RELAY_METADATA = ("pail-core-comm-contract", "pail-execution-reset")

    def ReportDecision(self, request, context):
        # ALWAYS forward — the real issuer must hear every decision to advance the chain, log to blackbox, and
        # (rc01/rc02) trip the operator guard NORMAL -> SAFE_STOP on a reported ERR_TAMPERED. An upstream failure
        # is the upstream's status, never an invented acceptance (preview.38 RV01: under the C1 contract an
        # accepted=True without a receipt is a fabricated confirmation). The deliberate negative fixture is
        # --rogue-fake-ack (PVS_ROGUE_FAKE_ACK=1): the consumer must detect the missing receipt.
        if self.fake_ack:
            return tok_pb.ReportDecisionResponse(accepted=True)
        return self._forward("ReportDecision", request, context)

    # Declaration RPCs (AS-2 Attest, AV3 ReportGatewayCensus, SD4 SealConfig)
    # were added to TokenService after this seam was written; the inherited
    # UNIMPLEMENTED read at the gate as "issuer refused the declaration" and
    # the seal was never journalled (실측 2026-09-02: "config seal NOT
    # journalled ... code=12 Method not implemented! addr=127.0.0.1:50052").
    # Pure pass-through, no local fabrication on failure: a declaration the
    # issuer never heard must not be answered "accepted" (H-B2).
    def _forward(self, name, request, context, timeout=2.0):
        up = self._upstream()
        if up is None:
            context.abort(grpc.StatusCode.UNAVAILABLE, "rogue seam has no upstream")
        try:
            resp, call = getattr(up, name).with_call(request, timeout=timeout)
        except grpc.RpcError as e:
            context.abort(e.code(), "upstream: %s" % (e.details() or ""))
        relay_metadata(context, call, self.RELAY_METADATA)
        return resp

    def Attest(self, request, context):
        # one-shot at gate start-up with its own long budget (PAIL_ATTEST_DEADLINE_MS)
        return self._forward("Attest", request, context, timeout=5.0)

    def ReportGatewayCensus(self, request, context):
        return self._forward("ReportGatewayCensus", request, context)

    def SealConfig(self, request, context):
        return self._forward("SealConfig", request, context)


class _RepeatPublisher:
    """Publishes /cmd_vel at `rate` Hz for `dur` s via MockHAL (deadman needs a
    continuous stream, not a single message)."""

    def __init__(self, hal: MockHAL, lin: float, rate: float, dur: float):
        self.hal, self.lin = hal, lin
        self.period = 1.0 / max(rate, 1e-3)
        self.deadline = time.monotonic() + dur
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._loop, daemon=True)

    def start(self):
        self._t.start()

    def _loop(self):
        while not self._stop.is_set() and time.monotonic() < self.deadline:
            self.hal.publish_cmd_vel(self.lin)
            time.sleep(self.period)

    def stop(self):
        self._stop.set()


class LiveBackend(Backend):
    clock = staticmethod(time.monotonic)
    sleep = staticmethod(time.sleep)

    def __init__(self):
        self.robot_id = "robot-1"
        self.compose_file = _env("PVS_COMPOSE_FILE", str(_REPO / "deploy" / "docker-compose.yml"))
        self.grpc_addr = _env("PVS_GRPC_ADDR", "127.0.0.1:50051")
        self.operator_addr = _env("PVS_OPERATOR_ADDR", "127.0.0.1:50053")
        self.rogue_token_addr = _env("PVS_ROGUE_TOKEN_ADDR", "127.0.0.1:50052")
        self.blackbox_dir = Path(_env("PAIL_BLACKBOX_DIR", str(_REPO / "deploy" / ".blackbox")))
        self.anchor_dir = Path(_env("PVS_ANCHOR_DIR", "/tmp/pvs-anchor"))
        self.keyring_path = Path(_env("PVS_KEYRING", str(_DEFAULT_KEYRING)))
        self.issuer_path = Path(_env("PVS_ISSUER_KEY", str(_DEFAULT_ISSUER)))
        self.operator_path = Path(_env("PVS_OPERATOR_KEY", str(_DEFAULT_OPERATOR)))
        self.profile = "insecure"

        self.hal: Optional[MockHAL] = None
        self.safety: Optional[SafetyAdapter] = None
        self.ai: Optional[MockAI] = None
        self._exec = None
        self._spin_thread: Optional[threading.Thread] = None
        self._nb_stub = None
        self._op_stub = None
        self._burst: Optional[BurstListener] = None
        self._anchor: Optional[AnchorServer] = None
        self._chaos: Optional[ChaosMonkey] = None
        self._rogue = _RogueTokenService(upstream_addr=self.grpc_addr)
        self._rogue.fake_ack = _env("PVS_ROGUE_FAKE_ACK", "") == "1"   # --rogue-fake-ack: the deliberate negative fixture
        self._last_probe_request = None
        self._rogue_server = None
        self._cmd_pub: Optional[_RepeatPublisher] = None
        self._issuer_pub = b""
        self._issuer_pubs: dict = {}
        self._burst_pub = b""
        self._op_sign = None
        self._last_op_nonce: Optional[bytes] = None

    # ---------------- lifecycle ----------------
    def setup(self):
        _kr = keymod.load_keyring(self.keyring_path)
        self._issuer_pub = keymod.issuer_pub(_kr)
        # D5-b rotation: chain/anchor verification trusts every issuer key in
        # the keyring (checkpoints by candidate set, anchors by key_id).
        self._issuer_pubs = keymod.issuer_pubs(_kr)
        # D2: bursts are signed by the robot-agent's own key (role=="burst");
        # falls back to the issuer key for the pre-split combined binary.
        self._burst_pub = keymod.burst_pub(_kr)
        self._op_sign = load_issuer_signing_key(self.operator_path)  # operator ed25519 seed (op-key-1)

        if not rclpy.ok():
            rclpy.init()
        self.hal = MockHAL()
        self.safety = SafetyAdapter()
        self._exec = MultiThreadedExecutor()
        self._exec.add_node(self.hal)
        self._exec.add_node(self.safety)
        self._spin_thread = threading.Thread(target=self._exec.spin, daemon=True)
        self._spin_thread.start()

        self._nb_stub = pail_pb2_grpc.PailNorthboundStub(grpc.insecure_channel(self.grpc_addr))
        self._op_stub = op_grpc.OperatorServiceStub(grpc.insecure_channel(self.operator_addr))
        self.ai = MockAI(self.issuer_path, robot_id=self.robot_id)

        # PVS_BURST_TEE (demo/DB-1): raw-datagram copy to the telemetryd
        # sidecar — the emitter is single-unicast, so "나란히 청취" in the
        # compose form is a downstream tee (sidecar death cannot mute us).
        self._burst = BurstListener(self._burst_pub, port=int(_env("PVS_BURST_PORT", "46000")),
                                    tee=_env("PVS_BURST_TEE", "") or None)
        self._burst.start()
        self.anchor_dir.mkdir(parents=True, exist_ok=True)
        # fixed port: the SUT's PAIL_ANCHOR_URL is baked at compose up, so the
        # anchor server cannot bind an ephemeral port (an01 got zero anchors)
        self.anchor_port = int(_env("PVS_ANCHOR_PORT", "46100"))
        self._anchor = AnchorServer(self.anchor_dir, port=self.anchor_port)
        self._anchor.start()
        self._chaos = ChaosMonkey()

        # rogue TokenService for negative-token scenarios (gate points here per profile)
        self._rogue_server = grpc.server(_ThreadPool())
        tok_grpc.add_TokenServiceServicer_to_server(self._rogue, self._rogue_server)
        self._rogue_server.add_insecure_port(self.rogue_token_addr)
        self._rogue_server.start()

    def teardown(self):
        if self._cmd_pub:
            self._cmd_pub.stop()
        if self._rogue_server:
            self._rogue_server.stop(0)
        if self._burst:
            self._burst.stop()
        if self._anchor:
            self._anchor.stop()
        if self._exec:
            self._exec.shutdown()
        for n in (self.hal, self.safety):
            if n:
                n.destroy_node()
        if rclpy.ok():
            rclpy.shutdown()

    def reset_state(self):
        """§9 isolation: recreate the SUT so consumed-token set / issuer chain /
        blackbox segments do not bleed across scenarios."""
        # The blackbox/anchor dirs are host bind mounts and SURVIVE recreate —
        # au02's tampered segment would fail every later audit_chain check.
        # Kill first so nothing is mid-append while we wipe.
        self._compose("kill")
        for d in (self.blackbox_dir, self.anchor_dir):
            if d.is_dir():
                for child in d.iterdir():
                    shutil.rmtree(child) if child.is_dir() else child.unlink()
        # 브링업 서비스 목록. 비면 compose 의 전 서비스(PVS 기본) — 서비스를
        # 여기서 손으로 세지 않는 것이 규율이다. 데모는 이 목록을 좁혀
        # `pail-telemetryd` 를 뺀다: 데모는 자기 수집기(`demo-telemetryd`)를
        # 따로 띄워 46010 을 이미 쥐고 있으므로, compose 판까지 올리면 둘째가
        # 죽은 채 남는다(포트/키링). 미러는 남겨야 운영자 뷰의 permit 행이 선다.
        services = os.environ.get("PVS_SUT_SERVICES", "").split()
        self._compose("up", "-d", "--force-recreate", *services)
        # A fixed sleep loses one-shot messages (evidence at t=0.3): gate startup
        # runs a slow `ros2 pkg list` in its entrypoint and DDS discovery adds
        # more latency. Poll the graph until the gate/bridge are actually wired,
        # then apply a short settle so late-joining readers finish matching.
        self._wait_sut_discovery(timeout=float(_env("PVS_RESET_DISCOVERY_TIMEOUT_S", "60.0")))
        time.sleep(float(_env("PVS_RESET_SETTLE_S", "3.0")))
        if self.hal:
            self.hal.permits.clear()
            self.hal.drive_history.clear()
            self.hal.safe_history.clear()
            self.hal.last_gate = None
            self.hal.last_bridge = None
            self.hal.bridge_history.clear()
        if self._burst:
            self._burst.reset()   # §9: drop prior scenario's bursts + dedup keys
        self._rogue.reset()
        # §9: the safety level is scenario state too — the adapter outlives the
        # recreated SUT and keeps pumping its LAST level at 10Hz, so a prior
        # scenario's UNSAFE (or a C-B7 "SAFE") latches the fresh gate before
        # the next scenario says a word (실측 2026-09-02).
        if self.safety:
            self.safety.set_level("OK")

    def load_scenario(self, sc):
        self.robot_id = getattr(sc, "robot_id", "robot-1")
        self.profile = getattr(sc, "profile", "insecure")
        if self.ai:
            self.ai.robot_id = self.robot_id

    def _compose(self, *args):
        subprocess.run(["docker", "compose", "-f", self.compose_file, *args],
                       check=True)

    def _wait_sut_discovery(self, timeout: float):
        """Block until the RECREATED gate/bridge are actually alive. Passive
        graph counts are unreliable here: the pre-recreate participant's
        endpoints linger until its DDS lease expires, so counts read >=1 while
        the new gate is still booting (`ros2 pkg list` in its entrypoint).
        Instead probe actively: a neutral cmd_vel(0.0) makes the new gate
        answer with a fresh /pail/gate_state (BLOCK/ERR_NO_TOKEN — no token or
        consumed-set side effects), and the bridge heartbeats /pail/bridge_state
        at 1 Hz. Probe residue in hal state is cleared by reset_state()."""
        if not self.hal:
            time.sleep(min(timeout, 3.0))
            return
        self.hal.last_gate = None
        self.hal.last_bridge = None
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.hal.last_gate is None:
                self.hal.publish_cmd_vel(0.0)
            if self.hal.last_gate is not None and self.hal.last_bridge is not None:
                return
            time.sleep(0.5)
        raise TimeoutError(
            "SUT liveness probe failed after %.0fs: gate_state=%s bridge_state=%s"
            % (timeout, self.hal.last_gate, self.hal.last_bridge))

    # ---------------- actuation ----------------
    def north_cmd(self, sub: Optional[str], args: Dict[str, Any]) -> None:
        variant = args.get("token_variant")
        if sub == "submit_plan" and not variant:
            # a plain plan after a negative variant (rc01 recovery) must return
            # the seam to pass-through, or the gate keeps seeing the forgery
            self._rogue.signed = None
            resp = self.ai.submit_plan(self._nb_stub, args.get("steps", []))
            # A refused plan used to be silent here and the scenario then failed downstream
            # as ERR_NO_TOKEN — a token nobody issued reads the same as a token the gate
            # refused (H-B2; measured 2026-09-06 on the adapter map, 6 rows). Name the refusal,
            # and let a step that is *about* the refusal declare it (submit_status / submit_reason).
            err = submit_declaration_error(args, pail_pb2.SubmitStatus.Name(resp.status), resp.rejected_reason)
            if err:
                raise RuntimeError(err)
            if resp.status==pail_pb2.ACCEPTED and self.ai.last_operation_outcome!='AUTHORIZED':
                raise RuntimeError('new execution not authorized: '+self.ai.last_operation_outcome)
            return
        if sub == "submit_plan" and variant:
            self._serve_negative(variant, args)
            return
        if sub == "replay_token":
            # single-use replay: pin the FIRST captured (already-consumed) token
            # so the gate's consumed cache must reject the re-presentation
            self._rogue.replay_index = 0
            return
        if sub == "cancel_plan":
            # End the previous chain at the issuer before a new plan. A step's permit window
            # (max_duration 6 s) outlives the 3 s stream that used it: the gate keeps the old
            # step active and the next plan's token is not served until that window ends, so
            # a drive submitted right after a permitted one read a stale ERR_NO_TOKEN instead
            # of the constraint refusal (Easy Demo P2, measured 2026-09-16). CancelPlan marks
            # the chain CHAIN_CANCELLED and the beacon drops it at the gate at once — the same
            # path the TB3 console's Stop uses. An unknown/ended plan answers cancelled=false.
            results=self.ai.cancel_owned_plans(self._nb_stub)
            args["cancelled"]=bool(results) and all(r['outcome']=='WITHDRAWAL_RECORDED' for r in results)
            args["withdrawal_results"]=results
            return
        raise NotImplementedError(f"north_cmd sub {sub!r} not wired")

    def _serve_negative(self, variant: str, args: Dict[str, Any]) -> None:
        step = (args.get("steps") or [{}])[0]
        target = step.get("target_object_id", "")
        if variant == "forge_signature":
            st = self.ai.forge_bad_signature(target_object_id=target)
        elif variant == "swap_action":
            st = self.ai.swap_action_type(target_object_id=target)
        elif variant == "expire":
            st = self.ai.expire(delta_ms=int(args.get("delta_ms", -5000)), target_object_id=target)
        elif variant == "tight_constraint":
            st = self.ai.tight_constraint(max_linear=float(args.get("max_linear", 0.1)),
                                          target_object_id=target)
        else:
            raise NotImplementedError(f"token_variant {variant!r} not wired")
        self._rogue.signed = st

    def inject_evidence(self, args: Dict[str, Any]) -> None:
        self.hal.publish_evidence(args.get("source", "BARCODE"),
                                  args["object_id"], float(args.get("confidence", 0.95)))

    def inject_skill(self, args: Dict[str, Any]) -> None:
        # The ROS 2 gate judges /cmd_vel only; a skill call has no ingress here (SK-2).
        raise NotImplementedError("inject_skill: the ROS 2 gate has no skill ingress (NO_SKILL_INGRESS)")

    def inject_cmd_vel(self, args: Dict[str, Any]) -> None:
        if self._cmd_pub:
            self._cmd_pub.stop()
        self._cmd_pub = _RepeatPublisher(self.hal, float(args.get("lin", 0.0)),
                                         float(args.get("rate", 10)), float(args.get("dur", 2.0)))
        self._cmd_pub.start()

    def inject_safety(self, args: Dict[str, Any]) -> None:
        if args.get("stale"):
            self.safety.go_stale()
            return
        # C-B7: gate domain is OK|WARN|UNSAFE — "SAFE" parses kUnknown (blocked).
        self.safety.set_level(args.get("level", "OK"), args.get("source", "PVS_SAFETY"))

    def fault(self, args: Dict[str, Any]) -> None:
        if "kill" in args:
            self._chaos.kill(args["kill"], int(args.get("signal", 9)))
        elif "pause" in args:
            self._chaos.pause(args["pause"])
        elif "diskcorrupt" in args:
            dc = args["diskcorrupt"]
            self._chaos.diskcorrupt(self.blackbox_dir, mode=dc.get("mode", "flip"),
                                    byte_index=int(dc.get("byte_index", 80)))
        elif "pktdrop" in args:
            # Live UDP loss can't be shaped from inside BurstListener (offer()/result()
            # only) — SV-02 live needs a UDP forwarding proxy between issuer and :46000.
            # The k-of-n reassembly logic itself is proven host-side in test_mocks.
            raise NotImplementedError(
                "live pktdrop requires a UDP forwarding proxy (SV-02 live-pending); "
                "reassembly proven in host test_mocks")
        elif "anchor" in args:
            if args["anchor"] == "down":
                self._anchor.stop()
            else:
                self._anchor = AnchorServer(self.anchor_dir, port=self.anchor_port)
                self._anchor.start()
        else:
            raise NotImplementedError(f"fault {args!r} not wired")

    def operator_unlock(self, args: Dict[str, Any]) -> str:
        import base64 as _b64
        # nonce is single-use; reuse_nonce replays the last one to prove ErrNonceReplayed
        nonce = self._last_op_nonce if args.get("reuse_nonce") else os.urandom(16)
        self._last_op_nonce = nonce
        now_ms = int(time.time() * 1000)
        # UnlockCanon(v2) = "pail-unlock:v2:" + robotID + ":" + unixMs + ":"
        #                   + base64(nonce) + ":" + operator_key_id
        # R-A (implementation contract, X23 / implementation contract 확대): 이 사본도 조립
        # 지점이다. 규칙이 한쪽에만 있으면 사본은 같아 보이는 두 구현이 된다 —
        # 하네스가 모호한 바이트에 운영자 키로 서명하는 일을 막는다
        # (Go operator.UnlockCanon 과 동치).
        key_id = args.get("key", "op-key-1")
        for field, value in (("robot_id", self.robot_id), ("operator_key_id", key_id)):
            if not value or ":" in value:
                raise ValueError(f"{field}: separator ':' in identifier ({value!r})")
        # 봉투에 싣는 값과 서명 대상에 넣는 값은 **같은 변수**여야 한다. 둘을 따로
        # 적으면 "다른 키를 사칭한다" 시험이 사칭이 아니라 하네스의 어긋남이 되고,
        # 거부가 났을 때 그것이 게이트의 판정인지 우리 실수인지 구분되지 않는다.
        canon = (f"pail-unlock:v2:{self.robot_id}:{now_ms}:"
                 f"{_b64.b64encode(nonce).decode()}:{key_id}").encode()
        sig = self._op_sign.sign(canon).signature  # OPERATOR key (op-key-1), not issuer
        req = op_pb.UnlockRequest(robot_id=self.robot_id, unix_ms=now_ms, nonce=nonce,
                                  operator_sig=sig, operator_key_id=key_id)
        try:
            resp = self._op_stub.Unlock(req, timeout=5.0)
            return "unlocked" if resp.accepted else "denied"
        except grpc.RpcError:
            return "denied"

    def rogue_publish(self, args: Dict[str, Any]) -> str:
        return rogue_actor.rogue_publish_sros2(args.get("topic", ""), args.get("payload", {}),
                                               args.get("key", "none"))

    def rogue_subscribe(self, args: Dict[str, Any]) -> str:
        return rogue_actor.rogue_publish_sros2(args.get("topic", ""), {}, args.get("key", "none"))

    # ---------------- CD (context demo) — CG-E1 visualization, additive ----------------
    _CTX_KIND = {
        "HUMAN_ENTER": op_pb.HUMAN_ENTER, "HUMAN_LEAVE": op_pb.HUMAN_LEAVE,
        "MAINTENANCE_ON": op_pb.MAINTENANCE_ON, "MAINTENANCE_OFF": op_pb.MAINTENANCE_OFF,
    }

    def ingest_context(self, kind: str, node_id: str, arg: str = "") -> Dict[str, Any]:
        # Real IngestContextEvent RPC to the issuer (C2). No UI-side world state.
        k = self._CTX_KIND.get(kind)
        if k is None:
            raise NotImplementedError(f"context kind {kind!r} not wired")
        ack = self._op_stub.IngestContextEvent(
            op_pb.ContextEvent(node_id=node_id, kind=k, arg=arg,
                               unix_ms=int(time.time() * 1000)), timeout=5.0)
        return {"accepted": ack.accepted, "epoch": ack.epoch, "detail": ack.detail}

    def submit_plan_probe(self, robot_id: str, target: str = "") -> Dict[str, Any]:
        # Issuance probe (no driving) — it changes the authorization state (a plan is accepted or rejected and
        # journalled), so it is not read-only. northbound(:50051) direct — pure issuer verdict + snapshot
        # read-back (C1/C3/C4). Uses _nb_stub not rogue seam.
        # preview.38 RV02: every logical probe is a new plan id. The C1 Issuer answers a repeated plan id with the
        # stored outcome of the first submission (no tokens), which an unchanged fixed id turned into schema=0 from
        # the second run on; only a retry of the same request may reuse an id (submit_plan_probe_retry).
        request = pail_pb2.SubmitActionPlanRequest(
            robot_id=robot_id, plan=pail_pb2.ActionPlan(
                plan_id="cd-probe-" + robot_id + "-" + uuid.uuid4().hex[:12],
                steps=[pail_pb2.PlanStep(step_id="s1", type=pail_pb2.STEP_TWIST, target_object_id=target,
                                         twist=pail_pb2.TwistCommand(linear_x=0.1, duration_sec=1.0))]))
        check_no_contract_setting();request.operation_id=request.plan.plan_id
        self._last_probe_request = request
        if getattr(self,'ai',None) is not None:
            self.ai.__dict__.setdefault('_owned_requests',{})[request.plan.plan_id]=robot_id
        response=self._nb_stub.SubmitActionPlan(request,timeout=5.0)
        return self._probe_outcome(robot_id,response,submit_outcome(request,response))

    def submit_plan_probe_retry(self) -> Dict[str, Any]:
        """Re-send the previous probe request unchanged (same id, same payload): the idempotent retry."""
        request = self._last_probe_request
        if request is None:
            raise RuntimeError("no probe to retry")
        response=self._nb_stub.SubmitActionPlan(request,timeout=5.0)
        return self._probe_outcome(request.robot_id,response,submit_outcome(request,response))

    @staticmethod
    def _probe_outcome(robot_id, resp, outcome="UNKNOWN") -> Dict[str, Any]:
        out = {"robot": robot_id, "status": pail_pb2.SubmitStatus.Name(resp.status),
               "reason": resp.rejected_reason, "schema": 0, "kind": "rejected",
               "snapshot_hash": "", "snapshot_len": 0}
        out['operation_outcome']=outcome
        if outcome=='AUTHORIZED' and resp.tokens:
            if not resp.tokens[0].action_token_bytes:raise RuntimeError('SIGNED_TOKEN_BYTES_MISSING')
            tok=pail_pb2.ActionToken.FromString(resp.tokens[0].action_token_bytes)
            out.update(kind="issued", schema=tok.schema_version,
                       snapshot_len=len(tok.subgraph_snapshot_hash),
                       snapshot_hash=tok.subgraph_snapshot_hash.hex())
        elif resp.HasField("receipt") and resp.receipt.operation_state:
            # a C1 Issuer answering a repeated operation id with the stored outcome: not an issuance
            out.update(kind="stored_outcome", operation_state=pail_pb2.OperationState.Name(resp.receipt.operation_state))
        return out

    # ---------------- observation (delegated to MockHAL / SafetyAdapter) ----------------
    def gate(self) -> GateObs:
        g = self.hal.last_gate
        return GateObs() if g is None else GateObs(state=g.state, reason=g.reason)

    def bridge(self) -> BridgeObs:
        b = self.hal.last_bridge
        return BridgeObs() if b is None else BridgeObs(state=b.state)

    def bridge_history(self):
        # The transition time is the bridge's own stamp; the receipt time rides along so a
        # reader can see how much of an observed delay was transport and executor jitter.
        return [BridgeObs(state=st, t=stamp if stamp is not None else rx, t_received=rx)
                for st, stamp, rx in list(self.hal.bridge_history)]

    def drive(self) -> TwistObs:
        h = self.hal.drive_history
        if not h:
            return TwistObs()
        lx, az, t = h[-1]
        return TwistObs(linear_x=lx, angular_z=az, t=t)

    def drive_history(self) -> List[TwistObs]:
        return [TwistObs(linear_x=lx, angular_z=az, t=t) for lx, az, t in self.hal.drive_history]

    def permits(self, window_ms: int) -> PermitObs:
        # PermitObs contract (backend.py): seqs seen IN THE WINDOW. A cumulative
        # list makes every absence check fail against pre-kill heartbeats.
        cutoff = self.hal._now() - window_ms / 1000.0
        return PermitObs(seqs=[s for s, t in self.hal.permits if t >= cutoff],
                         window_ms=window_ms)

    def stop_request_asserted(self) -> bool:
        return self.safety.stop_asserted()

    def burst_result(self):
        return self._burst.result()

    def audit_result(self):
        return segment_chain.verify(self.blackbox_dir, list(self._issuer_pubs.values()))

    def anchor_result(self):
        return anchor_check.cross_check(
            self.anchor_dir, self._issuer_pubs,
            segment_chain.verify(self.blackbox_dir, list(self._issuer_pubs.values())).head_hash)

    def enforcement_supported(self) -> bool:
        return self.profile == "sros2"


def _ThreadPool():
    from concurrent import futures
    return futures.ThreadPoolExecutor(max_workers=4)
