# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Strict dependency-free JSON profiles; configuration is not certification."""
import hashlib
import json
import re
from pathlib import Path

class ProfileError(ValueError):
    pass

def unique(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise ProfileError("duplicate key: " + k)
        result[k] = v
    return result

def read_json(path):
    return json.loads(Path(path).read_text(), object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(ProfileError("nonfinite JSON")))

def validate(value, spec, path="profile"):
    types = {"object": dict, "array": list, "string": str, "integer": int, "boolean": bool}
    if type(value) is not types[spec["type"]]:
        raise ProfileError(path + ": expected " + spec["type"])
    if "enum" in spec and value not in spec["enum"]:
        raise ProfileError(path + ": unsupported value")
    if "const" in spec and value != spec["const"]:
        raise ProfileError(path + ": invalid constant")
    if isinstance(value, dict):
        if set(value) != set(spec["required"]):
            raise ProfileError(path + ": missing or unknown keys")
        for k, v in value.items():
            validate(v, spec["properties"][k], path + "." + k)
    if isinstance(value, list):
        if not spec.get("minItems", 0) <= len(value) <= spec.get("maxItems", 100):
            raise ProfileError(path + ": invalid length")
        for v in value:
            validate(v, spec["items"], path + "[]")
        if spec.get("uniqueItems") and len(set(value)) != len(value):
            raise ProfileError(path + ": duplicates")
    if type(value) is int and not spec.get("minimum", value) <= value <= spec.get("maximum", value):
        raise ProfileError(path + ": out of range")
    if isinstance(value, str) and "pattern" in spec and not re.fullmatch(spec["pattern"], value):
        raise ProfileError(path + ": invalid string")

def load(path):
    data = read_json(path)
    if not isinstance(data, dict) or type(data.get("schema_version")) is not int or data["schema_version"] not in (1, 2, 3, 4):
        raise ProfileError("unsupported schema version")
    schema = "schema-v%d.json" % data["schema_version"] if data["schema_version"] > 1 else "schema.json"
    validate(data, read_json(Path(__file__).parent / "profiles" / schema))
    if data['schema_version']==4:
        usd=Path(data['sim']['usd'])
        if usd.is_absolute() or '..' in usd.parts or str(usd)!=data['sim']['usd']:
            raise ProfileError('local relative USD path required')
        return data
    if data["target"] == "jetson":
        if data["platform"]["arch"] != "aarch64" or data["platform"]["board"] != "orin-nano":
            raise ProfileError("Jetson profile requires aarch64 Orin Nano")
        if data["platform"]["l4t_major"] != 36:
            raise ProfileError("only candidate JetPack 6 / L4T 36 CPU profile is implemented")
    elif data["platform"]["board"] != "none" or data["platform"]["l4t_major"] != 0:
        raise ProfileError("mock cannot claim a Jetson board")
    return data

def digest(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
