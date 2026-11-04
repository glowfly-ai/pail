#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Standalone token seam (the out-of-process form of LiveBackend's in-process rogue seam).

Sits between an adapter and the real issuer as a plaintext TokenService proxy. Transparent by
default: every RPC is forwarded upstream. A control socket (NDJSON, one command per line) lets
the conformance backend substitute the token the adapter is served — a forged signature, a
swapped action, an expired window, a tight constraint — so the negative cases CA-02/03/04 can
be run against an adapter that only ever talks to "its issuer". Reports and attestations
always go upstream: the seam changes what the adapter is TOLD, never what it RECORDS.

    token_seam_server.py --listen 0.0.0.0:50052 --upstream duck-issuer:50051 --ctl /run/duck/seam.ctl

Control commands: {"op":"set","signed_b64":"…"}  {"op":"clear"}  {"op":"status"}
Upstream errors retain their RPC status: never a stale OK or a fabricated execution acknowledgement.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import sys
import threading
from concurrent import futures

import grpc

import pail_pb2  # type: ignore
import token_service_pb2 as tok_pb  # type: ignore
import token_service_pb2_grpc as tok_grpc  # type: ignore


class Seam(tok_grpc.TokenServiceServicer):
    def __init__(self, upstream_addr: str):
        self.lock = threading.Lock()
        self.signed = None
        self.upstream_addr = upstream_addr
        self._stub = tok_grpc.TokenServiceStub(grpc.insecure_channel(upstream_addr))
        self.served_substituted = 0
        self.last_upstream_error = None

    def GetActiveToken(self, request, context):
        # A transparent seam carries the real execution handshake in both
        # directions. It must not invent an ACK for an old/unreachable peer.
        identity = tuple((k, v) for k, v in context.invocation_metadata()
                         if k == "pail-execution-instance")
        try:
            result, call = self._stub.GetActiveToken.with_call(
                request, timeout=2.0, metadata=identity)
            echo = tuple((k, v) for k, v in call.initial_metadata()
                         if k == "pail-execution-instance")
            if echo:
                context.send_initial_metadata(echo)
            self.last_upstream_error = None
            with self.lock:
                signed = self.signed
            if signed is not None:
                self.served_substituted += 1
                return tok_pb.GetActiveTokenResponse(
                    status=tok_pb.ActiveTokenStatus.OK, chain_id=signed.token.chain_id or "seam-chain",
                    expected_sequence_index=1, token=signed,
                    current_subgraph_hash=signed.token.subgraph_snapshot_hash)
            return result
        except grpc.RpcError as e:
            if self.last_upstream_error != e.code():
                print("token seam upstream error:", e.code(), e.details(), flush=True)
                self.last_upstream_error = e.code()
            context.abort(e.code(), "upstream: " + (e.details() or ""))

    # PAIL diagnostic/contract metadata relayed verbatim from the upstream answer (preview.38 RV01)
    RELAY_METADATA = ("pail-core-comm-contract", "pail-execution-reset")

    def _forward(self, name, request, context, timeout=2.0):
        # the upstream's status is the answer; the seam never invents an acceptance or a receipt
        try:
            resp, call = getattr(self._stub, name).with_call(request, timeout=timeout)
        except grpc.RpcError as e:
            context.abort(e.code(), "upstream: %s" % (e.details() or ""))
        initial = [(k, v) for k, v in (call.initial_metadata() or ()) if k in self.RELAY_METADATA]
        trailing = [(k, v) for k, v in (call.trailing_metadata() or ()) if k in self.RELAY_METADATA]
        if initial:
            context.send_initial_metadata(initial)
        if trailing:
            context.set_trailing_metadata(trailing)
        return resp

    def ReportDecision(self, request, context):
        return self._forward("ReportDecision", request, context)

    def Attest(self, request, context):
        return self._forward("Attest", request, context, timeout=5.0)

    def ReportGatewayCensus(self, request, context):
        return self._forward("ReportGatewayCensus", request, context)

    def SealConfig(self, request, context):
        return self._forward("SealConfig", request, context)


def control_loop(seam: Seam, path: str):
    if os.path.exists(path):
        os.unlink(path)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    os.chmod(path, 0o660)
    srv.listen(4)
    while True:
        c, _ = srv.accept()
        f = c.makefile("rwb")
        for line in f:
            try:
                cmd = json.loads(line)
                op = cmd.get("op")
                if op == "set":
                    st = pail_pb2.SignedToken()
                    st.ParseFromString(base64.b64decode(cmd["signed_b64"]))
                    with seam.lock:
                        seam.signed = st
                    out = {"ok": True, "op": "set", "token_id": st.token.token_id}
                elif op == "clear":
                    with seam.lock:
                        seam.signed = None
                    out = {"ok": True, "op": "clear"}
                elif op == "status":
                    with seam.lock:
                        s = seam.signed
                    out = {"ok": True, "substituting": s is not None, "served_substituted": seam.served_substituted}
                else:
                    out = {"ok": False, "error": f"unknown op {op!r}"}
            except Exception as e:  # a malformed command is an error line, not a silent no-op
                out = {"ok": False, "error": str(e)}
            f.write((json.dumps(out) + "\n").encode())
            f.flush()
        c.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default="0.0.0.0:50052")
    ap.add_argument("--upstream", required=True)
    ap.add_argument("--ctl", required=True)
    a = ap.parse_args()
    seam = Seam(a.upstream)
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    tok_grpc.add_TokenServiceServicer_to_server(seam, server)
    server.add_insecure_port(a.listen)
    server.start()
    print(f"token seam: listening {a.listen} upstream {a.upstream} ctl {a.ctl}", flush=True)
    threading.Thread(target=control_loop, args=(seam, a.ctl), daemon=True).start()
    server.wait_for_termination()


if __name__ == "__main__":
    sys.exit(main())
