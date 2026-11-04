# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""Mock Cloud : UDP signed-burst receiver + anchor HTTP server.

Both run on the host without ROS2. The burst receiver feeds packets into the
signature-checking BurstReceiver; the anchor server accepts append-only PUTs and
rejects rewrites (M9).
"""

from __future__ import annotations

import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional

from ..verifiers.burst_verify import BurstReceiver, V2_PACKET_SIZE


class BurstListener:
    """Binds a UDP port and pushes every datagram into a BurstReceiver.

    `tee="host:port"` forwards every raw datagram to a second listener
    (dashboard sidecar). The tee is strictly best-effort and downstream:
    a dead tee target must never disturb this listener (D1 failure-domain
    direction — the sidecar dies alone).
    """

    def __init__(self, issuer_pub: bytes, host: str = "127.0.0.1", port: int = 46000,
                 tee: Optional[str] = None):
        self.receiver = BurstReceiver(issuer_pub)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.port = self.sock.getsockname()[1]
        self._tee_addr: Optional[tuple] = None
        self._tee_sock: Optional[socket.socket] = None
        if tee:
            th, tp = tee.rsplit(":", 1)
            self._tee_addr = (th, int(tp))
            # separate unconnected socket: ICMP unreachable from a dead tee
            # target must not surface as errors on the listening socket
            self._tee_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._stop = threading.Event()
        self._t: Optional[threading.Thread] = None

    def start(self) -> None:
        self._t = threading.Thread(target=self._loop, daemon=True)
        self._t.start()

    def _loop(self) -> None:
        self.sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                data, _ = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            self.receiver.offer(data)
            if self._tee_sock is not None:
                try:
                    self._tee_sock.sendto(data, self._tee_addr)
                except OSError:
                    pass  # best-effort: sidecar absence is its own gap, not ours

    def stop(self) -> None:
        self._stop.set()
        if self._t:
            self._t.join(timeout=1.0)
        self.sock.close()
        if self._tee_sock is not None:
            self._tee_sock.close()

    def reset(self) -> None:
        self.receiver.reset()

    def result(self):
        return self.receiver.result()


class _AnchorHandler(BaseHTTPRequestHandler):
    store_dir: Path = Path(".")

    def log_message(self, *a):  # silence
        pass

    def do_PUT(self):
        name = Path(self.path).name
        dst = self.store_dir / name
        if dst.exists():  # append-only: rewrite rejected
            self.send_response(409)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        dst.write_bytes(body)
        self.send_response(201)
        self.end_headers()


class AnchorServer:
    def __init__(self, store_dir, host: str = "127.0.0.1", port: int = 0):
        self.store_dir = Path(store_dir)
        self.store_dir.mkdir(parents=True, exist_ok=True)
        handler = type("H", (_AnchorHandler,), {"store_dir": self.store_dir})
        self.httpd = ThreadingHTTPServer((host, port), handler)
        self.port = self.httpd.server_address[1]
        self._t: Optional[threading.Thread] = None

    def start(self) -> None:
        self._t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._t.start()

    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def stop(self) -> None:
        self.httpd.shutdown()
        if self._t:
            self._t.join(timeout=1.0)
        # release the listening socket — without server_close() the fixed port
        # stays bound and the anchor-recovery ("up") rebind hits EADDRINUSE.
        self.httpd.server_close()
