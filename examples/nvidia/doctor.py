# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Read-only platform preparation checks. No installation or GPU configuration."""
import argparse
import json
import platform
import re
import shutil
from pathlib import Path
from nvidia_profile import load, digest

def host_facts():
    def read(path):
        try:
            return Path(path).read_text().replace("\x00", "").strip()
        except (OSError, UnicodeError):
            return ""
    return {"system": platform.system(), "arch": platform.machine(),
            "board": read("/proc/device-tree/model"), "l4t": read("/etc/nv_tegra_release"),
            "docker": bool(shutil.which("docker")), "openssl": bool(shutil.which("openssl"))}

def diagnose(profile, facts=None):
    facts = host_facts() if facts is None else facts
    checks = []
    def check(name, ok, observed):
        checks.append({"id": name, "status": "PASS" if ok else "FAIL", "observed": observed})
    check("host_os", facts["system"] in ("Linux", "Darwin"), facts["system"])
    arch = {"arm64": "aarch64", "amd64": "x86_64"}.get(facts["arch"], facts["arch"])
    check("host_arch", arch in ("aarch64", "x86_64") and profile["platform"]["arch"] in ("any", arch), arch)
    for tool in ("docker", "openssl"):
        check(tool + "_executable", facts[tool], facts[tool])
    if profile["target"] == "jetson":
        check("native_linux", facts["system"] == "Linux", facts["system"])
        check("orin_nano_board", "orin nano" in facts["board"].lower(), facts["board"] or "unavailable")
        match = re.search(r"# R(\d+) ", facts["l4t"])
        check("l4t_family", bool(match and int(match[1]) == profile["platform"]["l4t_major"]), facts["l4t"] or "unavailable")
    ok = all(c["status"] == "PASS" for c in checks)
    return {"schema_version": 1, "profile_id": profile["profile_id"], "profile_digest": digest(profile),
            "overall": "PASS" if ok else "FAIL", "hardware_verified": False,
            "support_status": "UNVERIFIED", "checks": checks,
            "coverage": {"host_preflight": True, "docker_daemon": False, "jetson_runtime": False,
                         "gpu": False, "isaac_sim": False, "physical_motion": False},
            "limitations": ["Read-only host checks, not a runtime or compatibility certificate.",
                            "Exact board firmware, OS and JetPack package lock remains unverified."]}

def main():
    a = argparse.ArgumentParser(); a.add_argument("--profile", required=True)
    args = a.parse_args(); profile = load(args.profile)
    if profile['schema_version'] != 1: raise ValueError('use session.py doctor for v2 profiles')
    result = diagnose(profile)
    print(json.dumps(result, indent=2)); return 0 if result["overall"] == "PASS" else 2

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError) as exc:
        print(json.dumps({"overall": "FAIL", "error": str(exc), "hardware_verified": False})); raise SystemExit(2)
