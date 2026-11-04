# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""Host-runnable tests for the non-ROS2 mocks (mock_ai factory, mock_cloud I/O).

The rclpy nodes (mock_hal, rogue_actor, safety_adapter) are import/build checked
in test_imports.py; live behavior needs the ROS2 stack.
"""

from __future__ import annotations

import base64
import json
import socket
import sys
import time
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from runner.mocks.mock_ai import MockAI  # noqa: E402
from runner.mocks import mock_cloud  # noqa: E402
from runner.verifiers._crypto import ed25519_verify  # noqa: E402
from runner.verifiers.keys import load_keyring, issuer_pub  # noqa: E402
from tests import golden  # noqa: E402

ISSUER_JSON = None
KEYRING = None

@pytest.fixture(scope="module", autouse=True)
def local_mock_identity(tmp_path_factory):
    """Mock tests own ephemeral keys; never read a deployment's signing identity."""
    global ISSUER_JSON, KEYRING
    from nacl.signing import SigningKey
    directory = tmp_path_factory.mktemp("pail-mock-identity")
    key = SigningKey.generate()
    public = base64.b64encode(bytes(key.verify_key)).decode("ascii")
    ISSUER_JSON = directory / "issuer.json"
    KEYRING = directory / "keyring.json"
    ISSUER_JSON.write_text(json.dumps({"key_id":"dev-key-1", "ed25519_private_key_base64":base64.b64encode(bytes(key)).decode("ascii"), "ed25519_public_key_base64":public}))
    ISSUER_JSON.chmod(0o600)
    KEYRING.write_text(json.dumps({"keys":[{"key_id":"dev-key-1","role":"issuer","ed25519_public_key_base64":public}]}))



# ---------------- mock_ai token factory ----------------

def test_valid_token_signature_verifies_against_keyring():
    ai = MockAI(ISSUER_JSON)
    pub = issuer_pub(load_keyring(KEYRING), "dev-key-1")
    st = ai.valid_token(token_id="t1", target_object_id="880123")
    # signature is over action_token_bytes (SUT contract)
    assert ed25519_verify(pub, st.action_token_bytes, st.signature)


def test_forge_bad_signature_fails_verification():
    ai = MockAI(ISSUER_JSON)
    pub = issuer_pub(load_keyring(KEYRING), "dev-key-1")
    st = ai.forge_bad_signature(token_id="t1")
    assert not ed25519_verify(pub, st.action_token_bytes, st.signature)


def test_swap_action_type_is_valid_but_mismatched():
    import pail_pb2  # via mock_ai sys.path insert
    ai = MockAI(ISSUER_JSON)
    pub = issuer_pub(load_keyring(KEYRING), "dev-key-1")
    st = ai.swap_action_type(new_type=pail_pb2.ACTION_PICK, step_id="s1")
    # validly signed (so it's not a BAD_TOKEN) ...
    assert ed25519_verify(pub, st.action_token_bytes, st.signature)
    # ... but the action_type is PICK, mismatching a MOVE/twist step
    parsed = pail_pb2.ActionToken()
    parsed.ParseFromString(st.action_token_bytes)
    assert parsed.action_type == pail_pb2.ACTION_PICK


def test_expire_sets_not_after_in_past():
    import pail_pb2
    ai = MockAI(ISSUER_JSON)
    st = ai.expire(delta_ms=-5000)
    parsed = pail_pb2.ActionToken()
    parsed.ParseFromString(st.action_token_bytes)
    assert parsed.not_after_unix_ms < int(time.time() * 1000)


# ---------------- mock_cloud burst listener ----------------

def test_burst_listener_dedup_over_udp():
    sk, pub = golden.new_issuer()
    lis = mock_cloud.BurstListener(pub, port=0)
    lis.start()
    try:
        pkt = golden.build_burst(sk, event=3, reason=0x13, unix_ms=1700,
                                 robot_id="robot-1", token_id="tok", burst_seq=99)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for _ in range(5):  # 5 retransmissions, same burst_seq
            s.sendto(pkt, ("127.0.0.1", lis.port))
        s.close()
        time.sleep(0.3)
        res = lis.result()
        assert len(res.events) == 1
        assert res.has_event("ESTOP", "ERR_SAFETY_UNSAFE")
    finally:
        lis.stop()


def test_burst_listener_rejects_forged():
    sk, pub = golden.new_issuer()
    forger, _ = golden.new_issuer()
    lis = mock_cloud.BurstListener(pub, port=0)
    lis.start()
    try:
        bad = golden.build_burst(sk, 1, 0x10, 1700, "robot-1", "tok", 1, forge_key=forger)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(bad, ("127.0.0.1", lis.port))
        s.close()
        time.sleep(0.3)
        res = lis.result()
        assert res.events == []
        assert len(res.rejected) == 1
    finally:
        lis.stop()


# ---------------- mock_cloud anchor server ----------------

def test_anchor_server_append_only(tmp_path):
    srv = mock_cloud.AnchorServer(tmp_path / "anchors", port=0)
    srv.start()
    try:
        url = srv.base_url() + "/anchor_0000000000001_000000_00000001_00000001.json"
        req = urllib.request.Request(url, data=b'{"head_hash_hex":"ab"}', method="PUT")
        with urllib.request.urlopen(req) as r:
            assert r.status == 201
        # rewrite must be rejected (append-only)
        req2 = urllib.request.Request(url, data=b'{"head_hash_hex":"cd"}', method="PUT")
        with pytest.raises(urllib.error.HTTPError) as ei:
            urllib.request.urlopen(req2)
        assert ei.value.code == 409
    finally:
        srv.stop()
