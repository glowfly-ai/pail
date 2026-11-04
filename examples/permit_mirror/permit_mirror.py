#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""Signed permit-liveness observation sidecar.

Observe /pail/permit and /pail/gate_state; send PMIR records under a separate
mirror-role signing identity. This is observation, not a command/authorization path.
Emit periodic liveness even without a permit so the collector can distinguish a
silent mirror (unknown) from an active mirror reporting no permit.

Read the actual permit deadline from discovered QoS. Zero means unobserved; never
invent a fallback window. Permit age is measured on the mirror's own clock and
PERMIT_AGE_NEVER means no permit received since boot, not age zero.

--emit-prefix exercises the wire layout without ROS, signing or network I/O.
Runtime ROS deployment requires the message packages, a mirror key and PyNaCl.
"""

import hashlib
import os
import socket
import struct
import sys
import time

MAGIC = b"PMIR"
VERSION = 1
PACKET_SIZE = 120
SIGNED_PREFIX = 56

# permit 을 한 번도 받지 못했다는 진술. 0(방금 받았다)과 **다른 바이트**여야
# 한다 — 같으면 무수신이 최신으로 도착한다(H-B2).
PERMIT_AGE_NEVER = 0xFFFFFFFF

MODE_UNOBSERVED = 0
MODE_ENFORCE = 1
MODE_OBSERVE = 2

_MODE_BYTE = {"enforce": MODE_ENFORCE, "observe": MODE_OBSERVE}

U16_MAX = 0xFFFF
U32_MAX = 0xFFFFFFFF


def mode_byte(effective_mode):
    """Map effective gate mode to its wire value; unknown modes stay unobserved."""
    return _MODE_BYTE.get(effective_mode or "", MODE_UNOBSERVED)


def robot_id_hash(robot_id):
    return hashlib.sha256(robot_id.encode("utf-8")).digest()[:16]


def build_packet(sign, robot_id, mode, tick_ms, permit_age_ms, deadman_window_ms,
                 permit_seq, mirror_seq, unix_ms):
    """PMIR 패킷 1개. `sign` 은 56바이트 접두어를 받아 64바이트 서명을 낸다.

    폭을 넘는 값은 잘라 넣지 않고 상한으로 **포화**시킨다. 잘라 넣으면 큰
    나이가 작은 나이로 되돌아와(u32 랩) 늙은 permit 이 신선하게 도착한다.
    포화된 나이는 어떤 deadman 창보다 크므로 판정이 보수적으로 기운다.
    """
    if permit_age_ms != PERMIT_AGE_NEVER:
        permit_age_ms = min(int(permit_age_ms), U32_MAX - 1)
    pkt = bytearray(PACKET_SIZE)
    pkt[0:4] = MAGIC
    pkt[4] = VERSION
    pkt[5] = mode
    struct.pack_into("<H", pkt, 6, min(int(tick_ms), U16_MAX))
    struct.pack_into("<Q", pkt, 8, int(unix_ms))
    pkt[16:32] = robot_id_hash(robot_id)
    struct.pack_into("<I", pkt, 32, int(permit_age_ms))
    struct.pack_into("<H", pkt, 36, min(int(deadman_window_ms), U16_MAX))
    struct.pack_into("<I", pkt, 40, int(permit_seq) & U32_MAX)
    struct.pack_into("<I", pkt, 44, int(mirror_seq) & U32_MAX)
    sig = sign(bytes(pkt[0:SIGNED_PREFIX]))
    if len(sig) != 64:
        raise ValueError("Ed25519 signature has %d bytes" % len(sig))
    pkt[56:120] = sig
    return bytes(pkt)


def load_signer(path):
    """미러 개인키를 읽어 서명 함수를 만든다.

    role=mirror 전용 키다(`scripts/gen_dev_keys.py` mirror-key-1). issuer·burst
    키로의 폴백은 두지 않는다 — 검증측(`telemetry.VerifyMirrorKeys`)도 폴백이
    없으므로, 여기서 아무 키나 집으면 화면은 조용히 `unverifiable` 이 된다.
    """
    import base64
    import json

    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    raw = base64.b64decode(doc["ed25519_private_key_base64"])
    # 파일 배치는 Go ed25519.PrivateKey 와 같다: seed(32) || public(32).
    if len(raw) not in (32, 64):
        raise SystemExit("mirror key: private key has %d bytes (expected 32 or 64)" % len(raw))
    key = Ed25519PrivateKey.from_private_bytes(raw[:32])
    return doc.get("key_id", ""), key.sign


class MirrorNode:
    """ROS 배선. 판정 재료는 전부 **관측**이고 기본값을 발명하지 않는다."""

    def __init__(self, node, sign, robot_id, tick_ms, sock, dest):
        self._node = node
        self._sign = sign
        self._robot_id = robot_id
        self._tick_ms = tick_ms
        self._sock = sock
        self._dest = dest

        self._mirror_seq = 0
        self._permit_seq = 0
        self._last_permit_mono = None  # None = 한 번도 못 받음
        self._mode = MODE_UNOBSERVED
        self._sent = 0
        self._errors = 0

    # -- 수신 ---------------------------------------------------------------
    def on_permit(self, msg):
        # 나이는 미러 자기 시계 안의 차이다. permit 의 stamp 를 쓰면 게이트
        # 시계와의 차이가 나이에 섞인다(그리고 sim time 아래에서 음수가 된다).
        self._last_permit_mono = time.monotonic()
        self._permit_seq = int(msg.permit_seq)

    def on_gate_state(self, msg):
        self._mode = mode_byte(getattr(msg, "effective_mode", ""))

    # -- 관측 ---------------------------------------------------------------
    def deadman_window_ms(self):
        """게이트가 `/pail/permit` 에 실제로 걸어 둔 deadline(ms).

        발견 정보가 없으면 0 — "창을 못 봤다"이지 "창이 없다"가 아니다.
        여러 발행자가 서로 다른 창을 걸었으면 **가장 짧은 창**을 싣는다:
        긴 쪽을 실으면 이미 죽은 창을 살아 있다고 적는다.
        """
        try:
            infos = self._node.get_publishers_info_by_topic("/pail/permit")
        except Exception:  # 배포마다 API 유무가 갈린다 — 없으면 미관찰이다
            return 0
        best = 0
        for info in infos:
            dur = getattr(getattr(info, "qos_profile", None), "deadline", None)
            ms = 0
            if dur is not None:
                ms = int(getattr(dur, "nanoseconds", 0) // 1_000_000)
            # rmw 는 "무한"을 아주 큰 값으로 준다 — 창으로 쓰면 영원히 살아 있다.
            if ms <= 0 or ms > U16_MAX:
                continue
            best = ms if best == 0 else min(best, ms)
        return best

    def permit_age_ms(self):
        if self._last_permit_mono is None:
            return PERMIT_AGE_NEVER
        return int((time.monotonic() - self._last_permit_mono) * 1000.0)

    # -- 발신 ---------------------------------------------------------------
    def on_tick(self):
        """틱은 permit 유무와 무관하게 나간다 — 이것이 두 회색을 가른다."""
        self._mirror_seq = (self._mirror_seq + 1) & U32_MAX
        pkt = build_packet(
            self._sign,
            self._robot_id,
            self._mode,
            self._tick_ms,
            self.permit_age_ms(),
            self.deadman_window_ms(),
            self._permit_seq,
            self._mirror_seq,
            int(time.time() * 1000.0),
        )
        try:
            self._sock.sendto(pkt, self._dest)
            self._sent += 1
        except OSError as e:
            # 보내지 못한 것을 보냈다고 적지 않는다. 실패해도 계속 시도한다 —
            # 수신측에는 이 침묵이 곧 "모름"으로 도착하고, 그것이 맞다.
            self._errors += 1
            self._node.get_logger().warning("mirror send failed: %s" % e)


_EMIT_FIELDS = ("robot", "effective_mode", "tick_ms", "permit_age_ms",
                "deadman_window_ms", "permit_seq", "mirror_seq", "unix_ms")


def emit_prefix(args):
    """`--emit-prefix k=v …` — 발신 없이 56바이트 서명 접두어만 hex 로 낸다.

    교차언어 대조용 질의 모드다. 검증측(Go)이 이 접두어를 자기 키로 서명해
    조립하고 필드를 되읽는다 — 그래서 **바이트 배치의 정본은 이 파일 하나**로
    남으면서, 두 언어에 서명 라이브러리를 각각 요구하지 않는다. 생산기와
    검증기가 같은 코드를 공유하면 둘이 함께 틀려도 초록이다.

    묻는 모드는 아무것도 하지 않는다 — 소켓도 열지 않고 ROS 도 부르지 않는다.

    `effective_mode` 는 **ROS 가 싣는 문자열 그대로** 받는다. 바이트로 받으면
    `mode_byte()` 매핑이 이 통로를 비켜 가고, 그러면 「모르는 모드가 미관찰로
    나가는가」를 재려던 대조가 실은 Go 쪽의 바이트 해석만 재게 된다
    (2026-09-02 실측: `DF-DB2-4` 가 아무것도 못 붉혀서 드러났다).
    """
    vals = {}
    for a in args:
        if "=" not in a:
            raise SystemExit("--emit-prefix: %r is not k=v" % a)
        k, v = a.split("=", 1)
        if k not in _EMIT_FIELDS:
            raise SystemExit("--emit-prefix: unknown field %r" % k)
        vals[k] = v
    missing = [k for k in _EMIT_FIELDS if k not in vals]
    if missing:
        raise SystemExit("--emit-prefix: missing fields %s" % ",".join(missing))
    pkt = build_packet(
        lambda _p: b"\x00" * 64,
        vals["robot"],
        mode_byte(vals["effective_mode"]),
        int(vals["tick_ms"]),
        int(vals["permit_age_ms"]),
        int(vals["deadman_window_ms"]),
        int(vals["permit_seq"]),
        int(vals["mirror_seq"]),
        int(vals["unix_ms"]),
    )
    sys.stdout.write(pkt[0:SIGNED_PREFIX].hex() + "\n")
    return 0


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "--emit-prefix":
        return emit_prefix(args[1:])
    # 모르는 플래그는 무시하지 않는다. 무시하면 `--help` 하나가 **발신을
    # 시작하는** 실행이 된다(2026-08-10 실측: 그 사고가 4시간짜리 트리 변형을
    # 걸었다). `--ros-args` 뒤는 rclpy 의 몫이다.
    for a in args:
        if a == "--ros-args":
            break
        if a.startswith("-"):
            raise SystemExit("permit_mirror: unknown argument %r" % a)

    robot_id = os.environ.get("PAIL_ROBOT_ID", "")
    if not robot_id:
        raise SystemExit("permit_mirror: PAIL_ROBOT_ID is required; cannot identify robot-specific rows")
    key_path = os.environ.get("PAIL_MIRROR_KEY_FILE",
                              "/etc/pail/keys/mirror_ed25519.json")
    dest_host = os.environ.get("PAIL_MIRROR_DEST_HOST", "127.0.0.1")
    # 수집기(`cmd/pail_telemetryd`)의 `-listen` 기본값과 같은 자리다. 다른 수를
    # 기본값으로 두면 미러는 잘 도는데 아무도 안 받고, 화면에는 그것이 「미러
    # 없음」(=모름)으로 도착한다 — 사람이 프로세스가 죽었다고 읽는다.
    dest_port = int(os.environ.get("PAIL_MIRROR_DEST_PORT", "46010"))
    tick_ms = int(os.environ.get("PAIL_MIRROR_TICK_MS", "500"))
    if tick_ms <= 0 or tick_ms > U16_MAX:
        raise SystemExit("permit_mirror: PAIL_MIRROR_TICK_MS=%d is out of range"
                         % tick_ms)

    key_id, sign = load_signer(key_path)

    import rclpy
    from pail_msgs.msg import GateState, Permit
    from rclpy.qos import DurabilityPolicy, HistoryPolicy, QoSProfile, ReliabilityPolicy

    rclpy.init(args=[sys.argv[0]] + args)
    node = rclpy.create_node("pail_permit_mirror")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    mirror = MirrorNode(node, sign, robot_id, tick_ms, sock,
                        (dest_host, dest_port))

    # 게이트의 발행 QoS 와 맞춘다(`pep_gate_node.cpp:354-357`): KeepLast(1) +
    # best_effort. RELIABLE 로 받으면 호환되지 않아 **아무것도 받지 못하면서**
    # 노드는 정상으로 보인다.
    permit_qos = QoSProfile(depth=1, history=HistoryPolicy.KEEP_LAST,
                            reliability=ReliabilityPolicy.BEST_EFFORT,
                            durability=DurabilityPolicy.VOLATILE)
    node.create_subscription(Permit, "/pail/permit", mirror.on_permit, permit_qos)
    node.create_subscription(GateState, "/pail/gate_state", mirror.on_gate_state, 10)
    node.create_timer(tick_ms / 1000.0, mirror.on_tick)

    node.get_logger().info(
        "permit mirror: robot=%s key_id=%s dest=%s:%d tick=%dms"
        % (robot_id, key_id, dest_host, dest_port, tick_ms))
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        node.destroy_node()
        rclpy.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
