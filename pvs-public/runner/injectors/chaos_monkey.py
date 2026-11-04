# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""Fault Injector .

Targets individual SUT containers by compose service name. The Docker SDK is
imported lazily so the module is importable on a host without docker; live
methods raise if the daemon is unavailable.

    kill(target, signal)  docker kill --signal  (PEP/bridge/services)
    pause(target)         docker pause          (hang, not crash — deadman)
    netcut(direction)     iptables/compose net  (anchor/service cutoff)
    clockskew(...)        see §6.1 — runtime date is NOT settable in containers
    diskcorrupt(...)      chmod 000 / byte-flip a segment
    pktdrop(keep)         pass only selected burst retransmissions
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

# compose service names (deploy/docker-compose.yml)
SERVICE = {
    "pep_gate": "pail-pep-gate",
    "bridge": "pail-motion-bridge",
    "services": "pail-services",
}


class ChaosMonkey:
    def __init__(self, compose_project: Optional[str] = None):
        self._client = None
        self.compose_project = compose_project

    def _docker(self):
        if self._client is None:
            import docker  # lazy
            self._client = docker.from_env()
        return self._client

    def _container(self, target: str):
        svc = SERVICE.get(target, target)
        client = self._docker()
        # match by compose service label or name substring
        for c in client.containers.list(all=True):
            labels = c.labels or {}
            if labels.get("com.docker.compose.service") == svc or svc in c.name:
                return c
        raise LookupError(f"no container for target {target!r} (service {svc})")

    def kill(self, target: str, signal: int = 9) -> None:
        self._container(target).kill(signal=f"SIG{_signame(signal)}")

    def pause(self, target: str) -> None:
        """Freeze the process: alive but unresponsive → permit heartbeat stops,
        bridge must HOLD on Deadline expiry even though no crash occurred."""
        self._container(target).pause()

    def unpause(self, target: str) -> None:
        self._container(target).unpause()

    def netcut(self, direction: str = "anchor") -> None:
        # disconnect the target service from its network to sever anchor/service
        client = self._docker()
        c = self._container("services")
        for net in client.networks.list():
            try:
                net.disconnect(c, force=True)
            except Exception:
                pass

    def clockskew(self, target: str, ms: int) -> None:
        # §6.1: containers share the host CLOCK_REALTIME; runtime `date` is not
        # isolable and libfaketime only injects at process start. Runtime skew is
        # therefore unsupported here — TC-TI-05 uses a libfaketime boot profile.
        raise NotImplementedError(
            "runtime clockskew is not container-isolable ; "
            "use the libfaketime boot profile for TC-TI-05")

    def diskcorrupt(self, seg_dir, mode: str = "chmod", byte_index: int = 80) -> None:
        seg_dir = Path(seg_dir)
        segs = sorted(seg_dir.glob("pail_blackbox.*.seg"))
        if not segs:
            raise LookupError(f"no segments in {seg_dir}")
        target = segs[-1]
        if mode == "chmod":
            target.chmod(0o000)
        elif mode == "flip":
            data = bytearray(target.read_bytes())
            if byte_index < len(data):
                data[byte_index] ^= 0xFF
                target.write_bytes(data)
        else:
            raise ValueError(f"unknown diskcorrupt mode {mode!r}")

    @staticmethod
    def pktdrop(packets: List[bytes], keep_indices: List[int]) -> List[bytes]:
        """Filter a burst retransmission list to only the kept indices
        (receiver-front filter — TC-SV-02: keep=[3] still recovers the event)."""
        keep = set(keep_indices)
        return [p for i, p in enumerate(packets) if i in keep]


def _signame(signal: int) -> str:
    return {9: "KILL", 15: "TERM", 2: "INT", 19: "STOP"}.get(signal, "KILL")
