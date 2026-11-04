# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""Mock AI / Northbound client + negative token factory .

Positive path: submit an ActionPlan over gRPC; the SUT issues signed tokens.
Negative path: PVS mints/mutates SignedTokens with the dev issuer key
(config/keys/issuer_ed25519.json) so that each defect maps to one error code:

  forge_bad_signature → ERR_TAMPERED      (flip a signature byte)
  swap_action_type    → ERR_ACTION_MISMATCH (valid sig, wrong action_type)
  expire              → time-window reject (not_after in the past)
  replay              → ERR_TOKEN_CONSUMED (re-present a consumed token)
  over_constraint     → ERR_CONSTRAINT    (twist beyond token constraints)

The signature always covers `action_token_bytes` (proto.Marshal at mint), never
a re-serialization — matching the SUT verifier contract (pail.proto §SignedToken).
"""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
import sys
import time
from pathlib import Path
from typing import List, Optional

# generated grpc modules use absolute `import pail_pb2`
_LIVE = Path(__file__).resolve().parents[1] / "live"
if str(_LIVE) not in sys.path:
    sys.path.insert(0, str(_LIVE))

import pail_pb2  # type: ignore  # noqa: E402
from nacl.signing import SigningKey  # noqa: E402
_ROOT=Path(__file__).resolve().parents[3]
_COMMON_CANDIDATES=[p for p in (_ROOT/'examples/common',_ROOT/'oss/examples/common',_ROOT/'common') if (p/'core_operation_wire.py').is_file()]
if len(_COMMON_CANDIDATES)!=1:raise ImportError('operation receipt helper root missing or ambiguous')
sys.path.insert(0,str(_COMMON_CANDIDATES[0]))
from core_operation_wire import check_no_contract_setting,submit_outcome,cancel_outcome



def load_issuer_signing_key(path) -> SigningKey:
    """issuer_ed25519.json → 32-byte seed SigningKey (Go priv is seed||pub)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    priv = base64.b64decode(data["ed25519_private_key_base64"])
    return SigningKey(priv[:32])


class MockAI:
    def __init__(self, issuer_key_path, key_id: str = "dev-key-1", robot_id: str = "robot-1"):
        self.sign = load_issuer_signing_key(issuer_key_path)
        self.key_id = key_id.encode()
        self.robot_id = robot_id
        self._owned_requests={}
        self.last_operation_outcome="UNKNOWN"

    # ---- positive path (live gRPC) ----
    def submit_plan(self, stub, steps, session_id: str = "pvs") -> "pail_pb2.SubmitActionPlanResponse":
        # preview.38 RV02: a new plan id per logical submission — a C1 Issuer answers a repeated id with the stored
        # outcome of the first one. Only an unchanged retry reuses the id (submit_plan_retry).
        plan = pail_pb2.ActionPlan(plan_id="pvs-plan-" + uuid.uuid4().hex[:12])
        for s in steps:
            step = pail_pb2.PlanStep(step_id=s["step_id"],
                                     target_object_id=s.get("target_object_id", ""))
            step.type = pail_pb2.STEP_TWIST
            tw = s.get("twist", {})
            step.twist.linear_x = float(tw.get("linear_x", 0.0))
            step.twist.angular_z = float(tw.get("angular_z", 0.0))
            step.twist.duration_sec = float(tw.get("duration_sec", 1.0))
            plan.steps.append(step)
        req = pail_pb2.SubmitActionPlanRequest(session_id=session_id, robot_id=self.robot_id, plan=plan)
        check_no_contract_setting();req.operation_id=plan.plan_id
        self._last_request = req
        owned=self.__dict__.setdefault('_owned_requests',{})
        if len(owned)>=256:raise RuntimeError('OWNED_PLAN_RECOVERY_REQUIRED')
        owned[plan.plan_id]=self.robot_id
        response=stub.SubmitActionPlan(req,timeout=5.0)
        self.last_operation_outcome=submit_outcome(req,response)
        if self.last_operation_outcome=='REJECTED':owned.pop(plan.plan_id,None)
        return response

    def submit_plan_retry(self, stub) -> "pail_pb2.SubmitActionPlanResponse":
        """Re-send the previous submission unchanged (same plan id, same payload): the idempotent retry a C1
        Issuer answers with the stored outcome. A different payload under the same id is AlreadyExists."""
        req = getattr(self, "_last_request", None)
        if req is None:
            raise RuntimeError("no submission to retry")
        response=stub.SubmitActionPlan(req,timeout=5.0)
        self.last_operation_outcome=submit_outcome(req,response)
        return response

    def cancel_owned_plans(self,stub):
        results=[]
        for plan,robot in list(self.__dict__.setdefault('_owned_requests',{}).items()):
            request=pail_pb2.CancelPlanRequest(plan_id=plan)
            check_no_contract_setting();request.operation_id=plan
            response=stub.CancelPlan(request,timeout=5.0)
            outcome=cancel_outcome(request,response,robot)
            results.append(dict(plan_id=plan,outcome=outcome))
            if outcome in ('WITHDRAWAL_RECORDED','REJECTED'):self._owned_requests.pop(plan,None)
        return results

    # ---- token minting ----
    def _mint(self, **fields) -> pail_pb2.ActionToken:
        now = int(time.time() * 1000)
        tok = pail_pb2.ActionToken(
            token_id=fields.get("token_id", "pvs-tok"),
            chain_id=fields.get("chain_id", "pvs-chain"),
            # R-A (strict_verify.cpp): token_id / chain_id / robot_id / plan_id must be
            # non-empty and ':'-free, checked right after parse — before the action and
            # expiry checks. An empty plan_id made every negative variant read as
            # ERR_IDENTIFIER_FORMAT instead of the reason under test (measured 2026-09-06
            # on the adapter conformance rig, CA-03/CA-04).
            plan_id=fields.get("plan_id", "pvs-plan"),
            robot_id=self.robot_id,
            step_id=fields.get("step_id", "s1"),
            target_object_id=fields.get("target_object_id", ""),
            issued_at_unix_ms=now,
            not_before_unix_ms=now - 1000,
            not_after_unix_ms=fields.get("not_after", now + 60_000),
            action_type=fields.get("action_type", pail_pb2.ACTION_MOVE),
            schema_version=2,
            # AG-2/CR3 (2026-08-14): the gate's world check (decide_command 3c)
            # treats an EMPTY hash as kIndeterminate → BLOCK ERR_WORLD_
            # INDETERMINATE before the check under test ever runs. A "valid"
            # mock token carries a snapshot hash like the real issuer's; the
            # rogue seam mirrors it into current_subgraph_hash (kMatch).
            subgraph_snapshot_hash=fields.get(
                "subgraph_snapshot_hash", hashlib.sha256(b"pvs-live-world").digest()),
        )
        # C-B5 (implementation contract, 2026-08-14): zero/absent speeds are no longer
        # issuable — strict_verify refuses them as ERR_BAD_TOKEN before any
        # constraint comparison runs. A "valid" mock token must carry real
        # limits, exactly like the real issuer's policy snapshot; scenarios
        # tighten individual fields via constraints={...}.
        c = fields.get("constraints", {})
        tok.constraints.max_linear_speed_mps = c.get("max_linear_speed_mps", 1.0)
        tok.constraints.max_angular_speed_rps = c.get("max_angular_speed_rps", 1.0)
        tok.constraints.max_duration_sec = c.get("max_duration_sec", 60.0)
        return tok

    def _sign(self, tok: pail_pb2.ActionToken) -> pail_pb2.SignedToken:
        raw = tok.SerializeToString()
        sig = self.sign.sign(raw).signature
        return pail_pb2.SignedToken(token=tok, action_token_bytes=raw,
                                    signature=sig, key_id=self.key_id)

    def valid_token(self, **fields) -> pail_pb2.SignedToken:
        return self._sign(self._mint(**fields))

    # ---- negative factory ----
    def forge_bad_signature(self, **fields) -> pail_pb2.SignedToken:
        st = self.valid_token(**fields)
        sig = bytearray(st.signature)
        sig[0] ^= 0xFF  # 1-byte flip → Ed25519 verify fails → ERR_TAMPERED
        st.signature = bytes(sig)
        return st

    def swap_action_type(self, new_type=None, **fields) -> pail_pb2.SignedToken:
        # validly signed, but action_type != the gated step (→ ERR_ACTION_MISMATCH)
        fields["action_type"] = new_type or pail_pb2.ACTION_PICK
        return self.valid_token(**fields)

    def expire(self, delta_ms: int = -5000, **fields) -> pail_pb2.SignedToken:
        now = int(time.time() * 1000)
        fields["not_after"] = now + delta_ms  # in the past
        return self.valid_token(**fields)

    def tight_constraint(self, max_linear: float = 0.3, **fields) -> pail_pb2.SignedToken:
        # a valid token whose constraint the scenario then violates via cmd_vel
        # injection (→ ERR_CONSTRAINT at the gate).
        fields["constraints"] = {"max_linear_speed_mps": max_linear}
        return self.valid_token(**fields)

    def replay(self, consumed: pail_pb2.SignedToken) -> pail_pb2.SignedToken:
        # re-present the exact consumed token → ERR_TOKEN_CONSUMED (single-use)
        return consumed
