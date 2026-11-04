#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Expand the xacro subset used by ROBOTIS turtlebot3_waffle_pi.urdf into plain URDF.

preview.15 evaluation finding P15-M1: at the pinned ROBOTIS commit the file named
`turtlebot3_waffle_pi.urdf` is a xacro document (`xmlns:xacro`, `<xacro:arg
name="namespace" default=""/>`, `${namespace}` prefixes on every link and joint).
Fed to Isaac Sim's URDF importer as-is, the `${namespace}` text survives into the
prim names (`tn__namespacewheel_left_joint_...`) and the converted tree has no
`wheel_left_joint` for the overlay and the profile to drive.

The Isaac image carries no `xacro`, so this script expands exactly the subset that
file uses — `xacro:arg` defaults, `xacro:property` values, `$(arg name)` and
`${name}` substitutions — and refuses anything else (`xacro:include`, `xacro:if`,
`xacro:macro`, expressions). A document without the xacro namespace passes
through unchanged. Output bytes are a pure function of the input.

usage: expand_urdf.py <in.urdf> <out.urdf> [--require-joint NAME ...]
"""
import argparse
import hashlib
import re
import sys
from pathlib import Path

XACRO_NS = 'http://ros.org/wiki/xacro'


def expand(text):
    if XACRO_NS not in text:
        return text, 'plain'
    body = re.sub(r'<!--.*?-->', '', text, flags=re.S)  # comments may quote constructs we do not run
    args = {}
    for name, default in re.findall(r'<xacro:arg\s+name="([^"]+)"\s+default="([^"]*)"\s*/>', body):
        args[name] = default
    props = {}
    for name, value in re.findall(r'<xacro:property\s+name="([^"]+)"\s+value="([^"]*)"\s*/>', body):
        props[name] = re.sub(r'\$\(arg ([A-Za-z_][A-Za-z0-9_]*)\)', lambda m: args[m.group(1)], value)
    out = re.sub(r'[ \t]*<xacro:(?:arg|property)\s[^>]*/>[ \t]*\n?', '', body)
    out = out.replace(' xmlns:xacro="%s"' % XACRO_NS, '')

    def prop(m):
        name = m.group(1)
        if name not in props:
            raise ValueError('unsupported xacro reference ${%s}: expand the file with the xacro tool first' % name)
        return props[name]

    out = re.sub(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}', prop, out)
    leftover = re.search(r'<xacro:|\$\{|\$\(', out)
    if leftover:
        raise ValueError('unsupported xacro construct at offset %d (%s): expand the file with the xacro tool first'
                         % (leftover.start(), out[leftover.start():leftover.start() + 40]))
    return out, 'expanded'


def joint_names(text):
    return re.findall(r'<joint\s+name="([^"]+)"', text)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('src', type=Path)
    ap.add_argument('dst', type=Path)
    ap.add_argument('--require-joint', action='append', default=[], help='joint name that must exist after expansion')
    a = ap.parse_args()
    try:
        out, mode = expand(a.src.read_text(encoding='utf-8'))
    except ValueError as exc:
        # P16-L2: a refusal is one line on stderr, not a traceback.
        sys.stderr.write('expand_urdf: refused: %s\n' % exc)
        return 3
    names = joint_names(out)
    missing = [j for j in a.require_joint if j not in names]
    if missing:
        sys.stderr.write('expand_urdf: joints missing after expansion: %s (found: %s)\n' % (', '.join(missing), ', '.join(names)))
        return 4
    a.dst.write_text(out, encoding='utf-8')
    print('expand_urdf: %s %s -> %s sha256=%s joints=%d' % (mode, a.src, a.dst, hashlib.sha256(out.encode('utf-8')).hexdigest(), len(names)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
