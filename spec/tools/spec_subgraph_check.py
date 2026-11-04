#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""Pin `spec/SUBGRAPH_HASH.md` to the frozen subgraph snapshot-hash vector set.

The failure this checker aims at: `ActionToken.subgraph_snapshot_hash` is signed,
the gate refuses motion when it disagrees with the issuer's live re-derivation,
and until this set existed nobody outside the issuer's source could recompute
it. A signed number that cannot be recomputed from the specification is a
claim, not evidence. This file re-derives every frozen case from the
document's rules with its own encoder (section 3), its own selector (section
5), its own site compiler and event replayer (section 6) — none of which share
code with the generator. Agreement between two implementations is evidence;
agreement between a library and itself is an identity.

  S1   the set exists; MANIFEST.sha256 == directory contents (both ways); per-file hashes
  S2   set_sha256 recomputed == manifest == document claim table
  S3   vocabulary tables (format, kind, state, rel, tag) == values the vectors actually use
  S4   every accept case re-encoded from section 3 (bytes, then hash); every reject case refused with the same reason
  S5   the section 4 quote is a byte substring of the frozen file and is SG-01; SG-01 == golden_g1_sha256
  S6   every selection case re-selected from section 5 (and section 6.3 for ephemeral worlds), evaluated, hashed
  S7   every world case re-compiled from section 6.1 and replayed with section 6.2; graph hash and request hashes
  S8   quoted samples (encoding, selection, world) == frozen cases
  S9   coverage counts of section 8 == measured
  S10  gate reasons == registered reason dictionary; proto field numbers == shipped proto
  S11  the Korean edition carries the same vocabularies and samples
  S12  generator and encoder source constants == section 1 (both layouts; cloud/ in the public tree)

rc: 0 = no FAIL, 1 = FAIL present, 2 = the checker could not establish its own premises.
"""

import ast
import hashlib
import json
import math
import os
import re
import struct
import sys
import unicodedata

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(errors="backslashreplace")

HERE = os.path.dirname(os.path.abspath(__file__))

# (layout, script tail, doc, ko, vector dir, canon manifest, reason dict, pail.proto,
#  token_service.proto, generator source or None, encoder source or None, golden doc or None)
LAYOUTS = (
    ('internal', ('scripts',),
     'oss/spec/SUBGRAPH_HASH.md', 'oss/spec/SUBGRAPH_HASH.ko.md',
     'oss/spec/vectors/subgraph', 'tests/golden/canon/MANIFEST.sha256',
     'tests/golden/contract/reason_dict.vec',
     'proto/pail.proto', 'proto/token_service.proto',
     'services/pail_services_go/cmd/gensubgraphvec/main.go',
     'services/pail_services_go/internal/graph/encode.go',
     'services/pail_services_go/internal/graph/GOLDEN_VECTORS.md'),
    ('public', ('spec', 'tools'),
     'spec/SUBGRAPH_HASH.md', 'spec/SUBGRAPH_HASH.ko.md',
     'spec/subgraph-vectors', 'spec/vectors/canon/MANIFEST.sha256',
     'spec/vectors/contract/reason_dict.vec',
     'sdk/proto/pail.proto', 'sdk/proto/token_service.proto',
     'cloud/cmd/gensubgraphvec/main.go',
     'cloud/internal/graph/encode.go',
     'cloud/internal/graph/GOLDEN_VECTORS.md'),
)

FILES = ('cases.json', 'selection.json', 'world.json')
MANIFEST = 'MANIFEST.sha256'
PIN_TARGET = 'spec/subgraph-vectors/cases.json'

VOCAB_RE = re.compile(r'^<!--[ \t]*vocab:[ \t]*(\S+)[ \t]*-->[ \t]*$', re.M)
SAMPLE_RE = re.compile(r'^<!--[ \t]*sample:[ \t]*(\S+)[ \t]*-->[ \t]*$', re.M)
PIN_RE = re.compile(r'^<!--[ \t]*pin:[ \t]*(\S+)[ \t]*-->[ \t]*$', re.M)
FENCE_RE = re.compile(r'^```[a-zA-Z0-9]*\n(.*?)^```[ \t]*$', re.M | re.S)
BT_RE = re.compile(r'^`([^`]+)`$')
HEX32_RE = re.compile(r'^[0-9a-f]{64}$')

VOCABS = ('format', 'gate_reason', 'kind', 'state', 'rel', 'tag', 'reject', 'event',
          'file', 'coverage', 'claim')
NCOLS = {'format': 1, 'gate_reason': 1, 'kind': 1, 'state': 1, 'rel': 1, 'tag': 1,
         'reject': 1, 'event': 1, 'file': 2, 'coverage': 1, 'claim': 1}
SAMPLES = ('encoding', 'selection', 'world')

FAILS = []
SKIPS = []


def die(msg):
    for code, m in FAILS:
        sys.stdout.write('[FAIL] %s %s\n' % (code, m))
    sys.stdout.write("SPEC-SUBGRAPH: prerequisite failure — %s\n" % msg)
    raise SystemExit(2)


def skip(code, why):
    SKIPS.append((code, why))


def read(path, binary=False):
    try:
        with open(path, 'rb' if binary else 'r', **({} if binary else {'encoding': 'utf-8'})) as fh:
            return fh.read()
    except OSError as exc:
        die("Cannot read: %s (%s)" % (path, exc))


def locate(here=HERE):
    parts = here.replace(os.sep, '/').split('/')
    hit = []
    for row in LAYOUTS:
        name, tail = row[0], row[1]
        if len(parts) > len(tail) and tuple(parts[-len(tail):]) == tail:
            root = os.path.abspath(os.path.join(here, *(['..'] * len(tail))))
            j = lambda p: None if p is None else os.path.join(root, *p.split('/'))
            hit.append((name, root) + tuple(j(p) for p in row[2:]))
    if len(hit) != 1:
        die("Cannot determine layout (%d matches); script location: %s" % (len(hit), here))
    return hit[0]


# ── document tables ──────────────────────────────────────────────────────────
def table_after(doc, pos):
    rows, started = [], False
    for ln in doc[pos:].splitlines():
        s = ln.strip()
        if not s:
            if started:
                break
            continue
        if not s.startswith('|'):
            if started:
                break
            return []
        started = True
        cells = [c.strip() for c in s.strip('|').split('|')]
        if all(set(c) <= set('-: ') for c in cells):
            continue
        rows.append(cells)
    return rows[1:] if rows else []


def backticked(cell):
    m = BT_RE.match(cell.strip())
    return m.group(1) if m else None


def doc_table(doc, code, pos, name, ncols, fails):
    out = {}
    for row in table_after(doc, pos):
        key = backticked(row[0])
        if key is None:
            fails.append((code, "Table `%s`: first column is not a backtick identifier: %r" % (name, row[0][:40])))
            continue
        if len(row) < ncols + 1:
            fails.append((code, "Table `%s`, row `%s` has only %d columns" % (name, key, len(row))))
            continue
        vals, bad = [], False
        for i in range(1, ncols + 1):
            v = backticked(row[i])
            if v is None:
                fails.append((code, "Table `%s`, row `%s`, column %d is not a backtick identifier: %r" % (name, key, i, row[i][:40])))
                bad = True
                break
            vals.append(v)
        if not bad:
            if key in out:
                fails.append((code, "Table `%s` contains duplicate row `%s`" % (name, key)))
            out[key] = tuple(vals)
    if not out:
        fails.append((code, "No rows read from table `%s`; an empty comparison cannot establish agreement" % name))
    return out


def as_int(code, what, s, fails, base=10):
    try:
        return int(s, base)
    except ValueError:
        fails.append((code, "%s is not an integer: %r" % (what, s[:40])))
        return None


def compare_sets(code, what, doc_keys, real_keys, fails):
    missing = sorted(set(real_keys) - set(doc_keys))
    phantom = sorted(set(doc_keys) - set(real_keys))
    if missing:
        fails.append((code, "%s — observed but undocumented: %s" % (what, missing)))
    if phantom:
        fails.append((code, "%s — documented but not observed: %s" % (what, phantom)))
    return not missing and not phantom


# ── independent encoder (section 3) ──────────────────────────────────────────
class Reject(Exception):
    def __init__(self, reason):
        Exception.__init__(self, reason)
        self.reason = reason


def nfc(s):
    return unicodedata.normalize('NFC', s).encode('utf-8')


def lp(s):
    b = nfc(s)
    return struct.pack('>I', len(b)) + b


def attr_value(a):
    t = a.get('t')
    if t == 'string':
        return b'\x01', lp(a['v'])
    if t == 'int64':
        return b'\x02', struct.pack('>q', int(a['v']))
    if t == 'double':
        f = float(a['v'])
        if math.isnan(f) or math.isinf(f):
            raise Reject('non_finite_double')
        if f == 0:
            f = 0.0  # -0.0 → +0.0
        return b'\x03', struct.pack('>d', f)
    if t == 'bool':
        return b'\x04', (b'\x01' if a['v'] else b'\x00')
    raise Reject('unknown_attr_tag')


def encode_node(n, kinds, states):
    if int(n['kind']) == 0 or int(n['kind']) not in kinds:
        raise Reject('kind_unspecified')
    out = lp(n['id']) + bytes([int(n['kind'])]) + bytes([int(n['state'])]) + struct.pack('>Q', int(n['version']))
    attrs = n.get('attrs') or {}
    keys = sorted(attrs, key=nfc)
    out += struct.pack('>I', len(keys))
    for k in keys:
        tag, val = attr_value(attrs[k])
        out += lp(k) + tag + val
    return out


def encode_edge(e):
    return lp(e['from']) + bytes([int(e['rel'])]) + lp(e['to'])


def encode_subgraph(sg, kinds, states, magic=b'PAILSG'):
    out = magic + b'\x01' + struct.pack('>Q', int(sg['epoch']))
    nodes = [(encode_node(n, kinds, states), nfc(n['id'])) for n in sg.get('nodes') or []]
    nodes.sort(key=lambda t: t[0])
    ids = [i for _, i in nodes]
    if len(set(ids)) != len(ids):
        raise Reject('duplicate_node_id')
    out += struct.pack('>I', len(nodes)) + b''.join(b for b, _ in nodes)
    edges = sorted(encode_edge(e) for e in sg.get('edges') or [])
    out += struct.pack('>I', len(edges)) + b''.join(edges)
    return out


# ── independent selector (section 5) and ephemeral world (section 6.3) ───────
REL = {'located_in': 1, 'targets': 2, 'constrains': 3, 'operates': 4, 'occupies': 5}
KIND = {'agent': 1, 'executor': 2, 'object': 3, 'zone': 4, 'human': 5, 'constraint': 6}


def world_index(world):
    return {n['id']: n for n in world['nodes']}, list(world['edges'])


def select(world, robot_id, target_object_id):
    nodes, edges = world_index(world)
    agent = 'robot:' + robot_id
    picked, out_edges = {}, []

    def add(nid):
        if nid in nodes and nid not in picked:
            picked[nid] = json.loads(json.dumps(nodes[nid]))  # deep copy

    add(agent)
    for e in edges:
        if e['from'] == agent and e['rel'] == REL['located_in']:
            add(e['to'])
            out_edges.append(e)
        elif e['from'] == agent and e['rel'] == REL['operates']:
            add(e['to'])
            out_edges.append(e)
    zones = {nid for nid, n in picked.items() if n['kind'] == KIND['zone']}
    for e in edges:
        if e['rel'] == REL['constrains'] and (e['to'] == agent or e['to'] in zones):
            add(e['from'])
            out_edges.append(e)
    for e in edges:
        if e['rel'] == REL['located_in'] and e['to'] in zones:
            n = nodes.get(e['from'])
            if n and n['kind'] == KIND['human']:
                add(e['from'])
                out_edges.append(e)
    if target_object_id:
        obj = 'object:' + target_object_id
        add(obj)
        out_edges.append({'from': agent, 'rel': REL['targets'], 'to': obj})
        for e in edges:
            if e['from'] == obj and e['rel'] == REL['located_in']:
                add(e['to'])
                out_edges.append(e)
    return {'epoch': world['epoch'], 'nodes': list(picked.values()), 'edges': out_edges}


def evaluate(sg):
    for n in sg['nodes']:
        if n['kind'] == KIND['agent']:
            if n['state'] == 1:
                return True, 'NODE_MAINTENANCE'
            if n['state'] == 2:
                return True, 'NODE_CORDONED'
    zones = {n['id'] for n in sg['nodes'] if n['kind'] == KIND['zone']}
    byid = {n['id']: n for n in sg['nodes']}
    for e in sg['edges']:
        if e['rel'] == REL['located_in'] and e['to'] in zones:
            n = byid.get(e['from'])
            if n and n['kind'] == KIND['human']:
                return True, 'HUMAN_IN_ZONE'
    return False, ''


def ephemeral_world(eph):
    agent = 'robot:' + eph['robot_id']
    nodes = [{'id': agent, 'kind': KIND['agent'], 'state': 0, 'version': 1, 'attrs': {}}]
    edges = []
    limits = [('max_linear_speed_mps', eph.get('max_linear_speed_mps', 0)),
              ('max_angular_speed_rps', eph.get('max_angular_speed_rps', 0)),
              ('max_duration_sec', eph.get('max_duration_sec', 0))]
    if any(v > 0 for _, v in limits):
        cid = 'constraint:speed@' + eph['robot_id']
        attrs = {k: {'t': 'double', 'v': repr(float(v))} for k, v in limits if v > 0}
        nodes.append({'id': cid, 'kind': KIND['constraint'], 'state': 0, 'version': 1, 'attrs': attrs})
        edges.append({'from': cid, 'rel': REL['constrains'], 'to': agent})
    if eph.get('target_object_id'):
        nodes.append({'id': 'object:' + eph['target_object_id'], 'kind': KIND['object'], 'state': 0, 'version': 1, 'attrs': {}})
    return {'epoch': 0, 'nodes': nodes, 'edges': edges}


# ── independent compiler (section 6.1) and replayer (section 6.2) ────────────
class CompileError(Exception):
    def __init__(self, reason):
        Exception.__init__(self, reason)
        self.reason = reason


def compile_site(site):
    allowed_top = {'site', 'schema', 'zones', 'objects', 'robots', 'constraints', 'actions', 'policy'}
    if not isinstance(site, dict) or set(site) - allowed_top:
        raise CompileError('unknown_key')
    if not site.get('site'):
        raise CompileError('missing_site')
    nodes, edges = {}, []
    zone_ids, object_ids = [], []
    for z in site.get('zones') or []:
        if set(z) - {'id', 'type', 'adjacent'} or not z.get('id'):
            raise CompileError('unknown_key')
        if z['id'] in zone_ids:
            raise CompileError('duplicate_id')
        zone_ids.append(z['id'])
        attrs = {}
        if z.get('type'):
            attrs['type'] = {'t': 'string', 'v': z['type']}
        if z.get('adjacent'):
            attrs['adjacent'] = {'t': 'string', 'v': ','.join(sorted(z['adjacent']))}
        nodes['zone:' + z['id']] = {'id': 'zone:' + z['id'], 'kind': KIND['zone'], 'state': 0, 'version': 0, 'attrs': attrs}
    for z in site.get('zones') or []:
        for a in z.get('adjacent') or []:
            if a not in zone_ids:
                raise CompileError('dangling_reference')
    for o in site.get('objects') or []:
        if set(o) - {'id', 'at'} or not o.get('id'):
            raise CompileError('unknown_key')
        if o['id'] in object_ids:
            raise CompileError('duplicate_id')
        object_ids.append(o['id'])
        nodes['object:' + o['id']] = {'id': 'object:' + o['id'], 'kind': KIND['object'], 'state': 0, 'version': 0, 'attrs': {}}
        if o.get('at'):
            if o['at'] not in zone_ids:
                raise CompileError('dangling_reference')
            edges.append({'from': 'object:' + o['id'], 'rel': REL['located_in'], 'to': 'zone:' + o['at']})
    seen_robots = set()
    for r in site.get('robots') or []:
        if set(r) - {'id', 'capabilities', 'schema', 'home', 'robot_class'} or not r.get('id'):
            raise CompileError('unknown_key')
        if r['id'] in seen_robots:
            raise CompileError('duplicate_id')
        seen_robots.add(r['id'])
        attrs = {}
        if r.get('capabilities'):
            attrs['capabilities'] = {'t': 'string', 'v': ','.join(sorted(r['capabilities']))}
        if r.get('schema'):
            attrs['schema'] = {'t': 'string', 'v': str(r['schema'])}
        if r.get('robot_class'):
            attrs['robot_class'] = {'t': 'string', 'v': r['robot_class']}
        rid, xid = 'robot:' + r['id'], 'executor:' + r['id']
        nodes[rid] = {'id': rid, 'kind': KIND['agent'], 'state': 0, 'version': 0, 'attrs': attrs}
        nodes[xid] = {'id': xid, 'kind': KIND['executor'], 'state': 0, 'version': 0, 'attrs': {}}
        edges.append({'from': rid, 'rel': REL['operates'], 'to': xid})
        if r.get('home'):
            if r['home'] not in zone_ids:
                raise CompileError('dangling_reference')
            edges.append({'from': rid, 'rel': REL['located_in'], 'to': 'zone:' + r['home']})
    for c in site.get('constraints') or []:
        t = c.get('type')
        fields = set(c) - {'type'}
        if t == 'human_exclusion':
            if fields != {'zone'}:
                raise CompileError('unexpected_field')
            zs = sorted(zone_ids) if c['zone'] == '*' else [c['zone']]
            for z in zs:
                if z not in zone_ids:
                    raise CompileError('dangling_reference')
                cid = 'constraint:human_excl@' + z
                nodes[cid] = {'id': cid, 'kind': KIND['constraint'], 'state': 0, 'version': 0,
                              'attrs': {'ctype': {'t': 'string', 'v': 'human_exclusion'}}}
                edges.append({'from': cid, 'rel': REL['constrains'], 'to': 'zone:' + z})
        elif t == 'exclusive':
            if fields != {'object'}:
                raise CompileError('unexpected_field')
            os_ = sorted(object_ids) if c['object'] == '*' else [c['object']]
            for o in os_:
                if o not in object_ids:
                    raise CompileError('dangling_reference')
                nodes['object:' + o]['attrs']['exclusive'] = {'t': 'bool', 'v': True}
        elif t == 'speed_limit':
            raise CompileError('speed_limit')
        else:
            raise CompileError('unknown_constraint_type')
    return {'epoch': 0, 'nodes': nodes, 'edges': edges}


def apply_event(g, ev):
    """Returns (old_version, new_version, epoch) as the journal would record them."""
    kind, node_id, arg = ev['kind'], ev['node_id'], ev.get('arg', '')
    nodes, edges = g['nodes'], g['edges']
    if kind in ('MAINTENANCE_ON', 'MAINTENANCE_OFF', 'CORDON_ON', 'CORDON_OFF'):
        if node_id not in nodes:
            raise CompileError('unknown_node')
        n = nodes[node_id]
        old = n['version']
        n['state'] = {'MAINTENANCE_ON': 1, 'MAINTENANCE_OFF': 0, 'CORDON_ON': 2, 'CORDON_OFF': 0}[kind]
        n['version'] += 1
        g['epoch'] += 1
        return old, n['version'], g['epoch']
    if kind == 'HUMAN_ENTER':
        if not node_id.startswith('zone:') or node_id not in nodes:
            raise CompileError('unknown_node')
        hid = 'human:' + arg
        old = 0
        if hid not in nodes:
            nodes[hid] = {'id': hid, 'kind': KIND['human'], 'state': 0, 'version': 0, 'attrs': {}}
        else:
            old = nodes[hid]['version']
            nodes[hid]['version'] += 1
        e = {'from': hid, 'rel': REL['located_in'], 'to': node_id}
        if e not in edges:
            edges.append(e)
        g['epoch'] += 1
        return old, nodes[hid]['version'], g['epoch']
    if kind == 'HUMAN_LEAVE':
        hid = 'human:' + arg
        if not node_id.startswith('zone:') or hid not in nodes:
            raise CompileError('unknown_node')
        old = nodes[hid]['version']
        g['edges'] = [e for e in edges if not (e['from'] == hid and e['rel'] == REL['located_in'] and e['to'] == node_id)]
        if any(e['from'] == hid and e['rel'] == REL['located_in'] for e in g['edges']):
            nodes[hid]['version'] += 1
            new = nodes[hid]['version']
        else:
            del nodes[hid]
            new = old + 1
        g['epoch'] += 1
        return old, new, g['epoch']
    if kind == 'OBJECT_MOVE':
        zid = 'zone:' + arg
        if not node_id.startswith('object:') or node_id not in nodes or zid not in nodes:
            raise CompileError('unknown_node')
        old = nodes[node_id]['version']
        g['edges'] = [e for e in edges if not (e['from'] == node_id and e['rel'] == REL['located_in'])]
        g['edges'].append({'from': node_id, 'rel': REL['located_in'], 'to': zid})
        nodes[node_id]['version'] += 1
        g['epoch'] += 1
        return old, nodes[node_id]['version'], g['epoch']
    raise CompileError('unknown_event')


def graph_as_subgraph(g):
    return {'epoch': g['epoch'], 'nodes': list(g['nodes'].values()), 'edges': list(g['edges'])}


def norm_nodes(nodes):
    """Canonical comparison form: sorted by id, attrs as dict, doubles compared as floats."""
    out = []
    for n in sorted(nodes, key=lambda n: n['id']):
        attrs = {}
        for k, a in (n.get('attrs') or {}).items():
            attrs[k] = (a['t'], float(a['v']) if a['t'] == 'double' else a.get('v'))
        out.append((n['id'], int(n['kind']), int(n['state']), int(n['version']), tuple(sorted(attrs.items()))))
    return out


def norm_edges(edges):
    return sorted((e['from'], int(e['rel']), e['to']) for e in edges)


# ── main ─────────────────────────────────────────────────────────────────────
def main():
    (layout, root, doc_path, ko_path, vdir, canon_path, reason_path, pail_proto, token_proto,
     gen_path, enc_path, golden_doc) = locate()
    internal = layout == 'internal'
    fails = FAILS

    doc = read(doc_path)
    vpos = {m.group(1): m.end() for m in VOCAB_RE.finditer(doc)}
    if set(vpos) != set(VOCABS):
        die("Vocabulary tables differ: documented %s / expected %s" % (sorted(vpos), sorted(VOCABS)))
    tables = {name: doc_table(doc, 'S3', vpos[name], name, NCOLS[name], fails) for name in VOCABS}

    # --- S1: set + manifest ----------------------------------------------------
    if not os.path.isdir(vdir):
        fails.append(('S1', "Vector root is missing: %s" % vdir))
        die("No frozen vectors available as derivation inputs")
    man_path = os.path.join(vdir, MANIFEST)
    on_disk = sorted(n for n in os.listdir(vdir) if n != MANIFEST)
    listed, set_line = {}, None
    for ln in read(man_path).splitlines():
        if ln.startswith('#') or not ln.strip():
            continue
        if ln.startswith('set_sha256'):
            parts = ln.split()
            set_line = parts[1] if len(parts) > 1 else None
            continue
        parts = ln.split('  ')
        if len(parts) == 2 and HEX32_RE.match(parts[0]):
            listed[parts[1]] = parts[0]
        else:
            fails.append(('S1', "Cannot parse manifest line: %r" % ln[:60]))
    compare_sets('S1', 'manifest entries vs directory contents', listed, on_disk, fails)
    if sorted(listed) != sorted(FILES):
        fails.append(('S1', "Registered file list differs from the expected three: %s" % sorted(listed)))
    raw = {}
    for name in sorted(set(listed) & set(on_disk)):
        b = read(os.path.join(vdir, name), binary=True)
        raw[name] = b
        got = hashlib.sha256(b).hexdigest()
        if got != listed[name]:
            fails.append(('S1', "%s — file hash differs from the manifest (observed %s)" % (name, got[:16])))
    for name in FILES:
        if name not in raw:
            die("Cannot read %s; derivation input unavailable" % name)

    # --- S2: set hash -----------------------------------------------------------
    body = ''.join('%s  %s\n' % (listed[n], n) for n in sorted(listed))
    calc = hashlib.sha256(body.encode('utf-8')).hexdigest()
    if set_line is None:
        fails.append(('S2', "Manifest lacks a set_sha256 line"))
    elif set_line != calc:
        fails.append(('S2', "Manifest set_sha256 differs: distributed %s / recomputed %s" % (set_line[:16], calc[:16])))
    claim = tables['claim']
    if claim.get('subgraph_set_sha256', (None,))[0] != calc:
        fails.append(('S2', "Documented subgraph_set_sha256 differs from the recomputed set hash (%s)" % calc[:16]))
    canon_set = None
    if os.path.exists(canon_path):
        for ln in read(canon_path).splitlines():
            if ln.startswith('set_sha256'):
                parts = ln.split()
                canon_set = parts[1] if len(parts) > 1 else None
    if canon_set is None:
        fails.append(('S2', "Cannot read set_sha256 from the canon manifest: %s" % canon_path))
    elif claim.get('canon_set_sha256', (None,))[0] != canon_set:
        fails.append(('S2', "Documented canon_set_sha256 differs from the shipped canon manifest"))
    if canon_set is not None and canon_set == calc:
        fails.append(('S2', "The subgraph set hash equals the canon set hash; the documented separation no longer holds"))

    data = {n: json.loads(raw[n].decode('utf-8')) for n in FILES}
    cases = data['cases.json']['cases']
    sel_cases = data['selection.json']['cases']
    world_cases = data['world.json']['cases']

    # --- S3: vocabularies vs observed ------------------------------------------
    fmt = tables['format']
    if fmt.get('magic', (None,))[0] != data['cases.json'].get('format'):
        fails.append(('S3', "format.magic documented %r / cases.json %r" % (fmt.get('magic'), data['cases.json'].get('format'))))
    if as_int('S3', 'format_version', fmt.get('format_version', ('',))[0], fails) != data['cases.json'].get('format_version'):
        fails.append(('S3', "format.format_version differs from cases.json"))
    if fmt.get('hash', (None,))[0] != 'sha256':
        fails.append(('S3', "format.hash must be sha256; the checker implements nothing else"))

    def doc_enum(name):
        out = {}
        for k, (v,) in tables[name].items():
            iv = as_int('S3', '%s.%s' % (name, k), v, fails, 16 if v.startswith('0x') else 10)
            if iv is not None:
                out[k] = iv
        return out

    kinds, states, rels, tags = doc_enum('kind'), doc_enum('state'), doc_enum('rel'), doc_enum('tag')
    if kinds != KIND or rels != REL or tags != {'string': 1, 'int64': 2, 'double': 3, 'bool': 4} or states != {'active': 0, 'maintenance': 1, 'cordoned': 2}:
        fails.append(('S3', "Documented enumerations differ from the values this checker implements (kind/state/rel/tag)"))
    obs_kind, obs_state, obs_rel, obs_tag = set(), set(), set(), set()

    def observe(sg):
        for n in sg.get('nodes') or []:
            obs_kind.add(int(n['kind']))
            obs_state.add(int(n['state']))
            for a in (n.get('attrs') or {}).values():
                if a.get('t') in ('string', 'int64', 'double', 'bool'):
                    obs_tag.add({'string': 1, 'int64': 2, 'double': 3, 'bool': 4}[a['t']])
        for e in sg.get('edges') or []:
            obs_rel.add(int(e['rel']))

    for c in cases:
        if c['expect'] == 'accept':
            observe(c['subgraph'])
    for c in sel_cases:
        observe(c['world'])
    compare_sets('S3', 'kind values', set(kinds.values()), obs_kind, fails)
    compare_sets('S3', 'state values', set(states.values()), obs_state, fails)
    compare_sets('S3', 'rel values', set(rels.values()), obs_rel, fails)
    compare_sets('S3', 'tag values', set(tags.values()), obs_tag, fails)

    # --- S4: encoding ------------------------------------------------------------
    enc_ok, rej_ok = 0, 0
    reject_seen = {}
    for c in cases:
        cid = c['id']
        try:
            b = encode_subgraph(c['subgraph'], set(kinds.values()), set(states.values()))
        except Reject as r:
            b, reason = None, r.reason
        else:
            reason = None
        if c['expect'] == 'accept':
            if b is None:
                fails.append(('S4', "%s — the encoder written from section 3 refused (%s) an accept case" % (cid, reason)))
                continue
            if b.hex() != c.get('canonical_hex'):
                fails.append(('S4', "%s — canonical bytes differ from the frozen value" % cid))
                continue
            if hashlib.sha256(b).hexdigest() != c.get('sha256'):
                fails.append(('S4', "%s — bytes agree but SHA-256 differs from the frozen value" % cid))
                continue
            enc_ok += 1
        elif c['expect'] == 'reject':
            reject_seen[c.get('reason')] = reject_seen.get(c.get('reason'), 0) + 1
            if b is not None:
                fails.append(('S4', "%s — reject case was accepted by the encoder written from section 3" % cid))
                continue
            if reason != c.get('reason'):
                fails.append(('S4', "%s — refused for %s, frozen reason is %s" % (cid, reason, c.get('reason'))))
                continue
            rej_ok += 1
        else:
            fails.append(('S4', "%s — unknown expect value %r" % (cid, c['expect'])))
    doc_reject = {k: as_int('S4', 'reject.%s' % k, v[0], fails) for k, v in tables['reject'].items()}
    if compare_sets('S4', 'reject reasons', doc_reject, reject_seen, fails):
        for k in sorted(reject_seen):
            if doc_reject[k] != reject_seen[k]:
                fails.append(('S4', "reject.%s — documented %s / observed %d" % (k, doc_reject[k], reject_seen[k])))

    # --- S5: pin + golden ----------------------------------------------------------
    by_id = {c['id']: c for c in cases}
    pin = PIN_RE.search(doc)
    if not pin:
        fails.append(('S5', "The document has no pin comment for its quoted bytes"))
    elif pin.group(1) != PIN_TARGET:
        fails.append(('S5', "Pin target is %s, expected %s" % (pin.group(1), PIN_TARGET)))
    else:
        fence = FENCE_RE.search(doc, pin.end())
        if not fence:
            fails.append(('S5', "No quotation block after the pin"))
        else:
            quoted = fence.group(1).strip()
            if quoted not in raw['cases.json'].decode('utf-8'):
                fails.append(('S5', "The quoted bytes are not a substring of the frozen cases.json"))
            if quoted != by_id.get('SG-01', {}).get('canonical_hex'):
                fails.append(('S5', "The quoted bytes are not SG-01's canonical encoding"))
    golden = claim.get('golden_g1_sha256', (None,))[0]
    if by_id.get('SG-01', {}).get('sha256') != golden:
        fails.append(('S5', "SG-01 sha256 differs from the documented golden_g1_sha256"))
    if golden_doc and os.path.exists(golden_doc):
        if golden not in read(golden_doc):
            fails.append(('S5', "golden_g1_sha256 does not appear in the shipped golden vector document"))
    else:
        fails.append(('S5', "Golden vector document is missing: %s" % golden_doc))

    # --- S6: selection -------------------------------------------------------------
    sel_ok, modes, violations = 0, {}, 0
    for c in sel_cases:
        cid = c['id']
        modes[c.get('mode')] = modes.get(c.get('mode'), 0) + 1
        if c.get('mode') == 'ephemeral':
            world = ephemeral_world(c['ephemeral'])
            if norm_nodes(world['nodes']) != norm_nodes(c['world']['nodes']) or norm_edges(world['edges']) != norm_edges(c['world']['edges']) or world['epoch'] != c['world']['epoch']:
                fails.append(('S6', "%s — the ephemeral world built from section 6.3 differs from the frozen world" % cid))
                continue
        elif c.get('mode') == 'site':
            world = c['world']
        else:
            fails.append(('S6', "%s — unknown mode %r" % (cid, c.get('mode'))))
            continue
        sg = select(world, c['request']['robot_id'], c['request'].get('target_object_id', ''))
        got_ids = sorted(n['id'] for n in sg['nodes'])
        if got_ids != c['selected']['node_ids']:
            fails.append(('S6', "%s — selected node ids differ: derived %s / frozen %s" % (cid, got_ids, c['selected']['node_ids'])))
            continue
        if norm_edges(sg['edges']) != norm_edges(c['selected']['edges']):
            fails.append(('S6', "%s — selected edges differ from the frozen value" % cid))
            continue
        v, r = evaluate(sg)
        if v:
            violations += 1
        if [v, r] != [c['evaluate']['violated'], c['evaluate']['reason']]:
            fails.append(('S6', "%s — evaluation differs: derived (%s, %r) / frozen (%s, %r)" % (cid, v, r, c['evaluate']['violated'], c['evaluate']['reason'])))
            continue
        try:
            b = encode_subgraph(sg, set(kinds.values()), set(states.values()))
        except Reject as rj:
            fails.append(('S6', "%s — selected slice is not encodable (%s)" % (cid, rj.reason)))
            continue
        if b.hex() != c['canonical_hex'] or hashlib.sha256(b).hexdigest() != c['sha256']:
            fails.append(('S6', "%s — hash of the selected slice differs from the frozen value" % cid))
            continue
        sel_ok += 1

    # --- S7: world ------------------------------------------------------------------
    world_ok, world_rej, event_seen = 0, 0, {}
    for c in world_cases:
        cid = c['id']
        try:
            g = compile_site(c['site'])
        except CompileError as ce:
            g, reason = None, ce.reason
        else:
            reason = None
        if c['expect'] == 'reject':
            if g is not None:
                fails.append(('S7', "%s — the compiler written from section 6.1 accepted a reject case" % cid))
            elif reason != c.get('reason'):
                fails.append(('S7', "%s — refused for %s, frozen reason is %s" % (cid, reason, c.get('reason'))))
            else:
                world_rej += 1
            continue
        if g is None:
            fails.append(('S7', "%s — compile refused (%s) an accept case" % (cid, reason)))
            continue
        bad = False
        for i, ev in enumerate(c['events']):
            event_seen[ev['kind']] = event_seen.get(ev['kind'], 0) + 1
            try:
                old, new, epoch = apply_event(g, ev)
            except CompileError as ce:
                fails.append(('S7', "%s event %d (%s) — replay refused: %s" % (cid, i, ev['kind'], ce.reason)))
                bad = True
                break
            if (old, new, epoch) != (ev['old_version'], ev['new_version'], ev['epoch']):
                fails.append(('S7', "%s event %d (%s) — journal triple derived (%d,%d,%d) / frozen (%d,%d,%d)"
                              % (cid, i, ev['kind'], old, new, epoch, ev['old_version'], ev['new_version'], ev['epoch'])))
                bad = True
                break
        if bad:
            continue
        sg = graph_as_subgraph(g)
        if sg['epoch'] != c['graph']['epoch'] or norm_nodes(sg['nodes']) != norm_nodes(c['graph']['nodes']) or norm_edges(sg['edges']) != norm_edges(c['graph']['edges']):
            fails.append(('S7', "%s — the replayed world differs from the frozen graph" % cid))
            continue
        try:
            gb = encode_subgraph(sg, set(kinds.values()), set(states.values()), magic=b'PAILCG')
        except Reject as rj:
            fails.append(('S7', "%s — world not encodable (%s)" % (cid, rj.reason)))
            continue
        if hashlib.sha256(gb).hexdigest() != c['graph_sha256']:
            fails.append(('S7', "%s — graph hash differs from the frozen value" % cid))
            continue
        req_bad = False
        for rq in c['requests']:
            s2 = select(sg, rq['robot_id'], rq.get('target_object_id', ''))
            ids = sorted(n['id'] for n in s2['nodes'])
            h = hashlib.sha256(encode_subgraph(s2, set(kinds.values()), set(states.values()))).hexdigest()
            if ids != rq['node_ids'] or h != rq['sha256']:
                fails.append(('S7', "%s request (%s,%s) — derived selection or hash differs" % (cid, rq['robot_id'], rq.get('target_object_id', ''))))
                req_bad = True
        if not req_bad:
            world_ok += 1
    doc_event = {k: as_int('S7', 'event.%s' % k, v[0], fails) for k, v in tables['event'].items()}
    expected_kinds = {'HUMAN_ENTER', 'HUMAN_LEAVE', 'OBJECT_MOVE', 'MAINTENANCE_ON', 'MAINTENANCE_OFF', 'CORDON_ON', 'CORDON_OFF'}
    if set(doc_event) != expected_kinds:
        fails.append(('S7', "Documented event kinds differ from the seven this checker replays: %s" % sorted(doc_event)))
    for k in sorted(doc_event):
        if doc_event[k] != event_seen.get(k, 0):
            fails.append(('S7', "event.%s — documented %s / observed %d" % (k, doc_event[k], event_seen.get(k, 0))))
    if set(event_seen) - set(doc_event):
        fails.append(('S7', "Undocumented event kinds in the vectors: %s" % sorted(set(event_seen) - set(doc_event))))

    # --- S8: samples ----------------------------------------------------------------
    spos = {m.group(1): m.end() for m in SAMPLE_RE.finditer(doc)}
    if set(spos) != set(SAMPLES):
        fails.append(('S8', "Quoted sample list differs: documented %s / expected %s" % (sorted(spos), sorted(SAMPLES))))
    doc_samples = {}
    for name in sorted(set(spos) & set(SAMPLES)):
        fence = FENCE_RE.search(doc, spos[name])
        if not fence:
            fails.append(('S8', "No code block after sample `%s`" % name))
            continue
        try:
            obj = json.loads(fence.group(1))
        except ValueError as exc:
            fails.append(('S8', "Sample `%s` is not JSON: %s" % (name, exc)))
            continue
        doc_samples[name] = obj
        if name == 'encoding':
            c = by_id.get(obj.get('id'))
            ok = c is not None and c.get('sha256') == obj.get('sha256')
        elif name == 'selection':
            c = next((x for x in sel_cases if x['id'] == obj.get('id')), None)
            ok = c is not None and c['selected']['node_ids'] == obj.get('node_ids') and c['sha256'] == obj.get('sha256')
        else:
            c = next((x for x in world_cases if x['id'] == obj.get('id')), None)
            ok = c is not None and c.get('graph_sha256') == obj.get('graph_sha256') and c.get('graph', {}).get('epoch') == obj.get('epoch')
        if not ok:
            fails.append(('S8', "Sample `%s` does not match the frozen case %r" % (name, obj.get('id'))))

    # --- S9: coverage -------------------------------------------------------------------
    accept = [c for c in cases if c['expect'] == 'accept']
    by_hex = {}
    for c in accept:
        by_hex.setdefault(c['canonical_hex'], []).append(c)
    nfc_pairs = 0
    for group in by_hex.values():
        if len(group) >= 2:
            ids = [json.dumps(g['subgraph'], sort_keys=True, ensure_ascii=False) for g in group]
            if len(set(ids)) >= 2 and len({unicodedata.normalize('NFC', i) for i in ids}) == 1:
                nfc_pairs += 1
    length_major = 0
    for c in accept:
        nodes = c['subgraph'].get('nodes') or []
        if len(nodes) < 2:
            continue
        by_str = [n['id'] for n in sorted(nodes, key=lambda n: nfc(n['id']))]
        by_enc = [n['id'] for n in sorted(nodes, key=lambda n: encode_node(n, set(kinds.values()), set(states.values())))]
        if by_str != by_enc:
            length_major += 1
    dup_edges = sum(1 for c in accept if len(c['subgraph'].get('edges') or []) != len({json.dumps(e, sort_keys=True) for e in c['subgraph'].get('edges') or []}))
    empty = sum(1 for c in accept if not (c['subgraph'].get('nodes') or []) and not (c['subgraph'].get('edges') or []))
    measured = {
        'accept_cases': len(accept),
        'reject_cases': len(cases) - len(accept),
        'selection_site': modes.get('site', 0),
        'selection_ephemeral': modes.get('ephemeral', 0),
        'world_accept': sum(1 for c in world_cases if c['expect'] == 'accept'),
        'world_reject': sum(1 for c in world_cases if c['expect'] == 'reject'),
        'nfc_pairs': nfc_pairs,
        'length_major_cases': length_major,
        'duplicate_edge_cases': dup_edges,
        'empty_subgraph_cases': empty,
        'evaluate_violations': violations,
    }
    doc_cov = tables['coverage']
    if compare_sets('S9', 'coverage items', doc_cov, measured, fails):
        for name in sorted(measured):
            want = as_int('S9', '`%s`' % name, doc_cov[name][0], fails)
            if want is not None and want != measured[name]:
                fails.append(('S9', "`%s` — documented %d / observed %d" % (name, want, measured[name])))
    for name in ('nfc_pairs', 'length_major_cases', 'reject_cases', 'evaluate_violations'):
        if measured[name] == 0:
            fails.append(('S9', "`%s` is zero; the rule it exercises is not measured" % name))
    doc_file = tables['file']
    real_file = {'cases.json': ('cases', len(cases)), 'selection.json': ('cases', len(sel_cases)), 'world.json': ('cases', len(world_cases))}
    if compare_sets('S9', 'file list', doc_file, real_file, fails):
        for name in sorted(real_file):
            key, rows = doc_file[name]
            got = as_int('S9', '`%s` rows' % name, rows, fails)
            if key != real_file[name][0] or (got is not None and got != real_file[name][1]):
                fails.append(('S9', "`%s` — documented (%s, %s) / observed %s" % (name, key, rows, real_file[name])))

    # --- S10: gate reasons + proto fields ---------------------------------------------
    reg = {}
    if os.path.exists(reason_path):
        for ln in read(reason_path).splitlines():
            cells = ln.split('\t')
            if len(cells) >= 3 and cells[0] == 'reason':
                reg[cells[1]] = cells[2]
    else:
        fails.append(('S10', "Reason dictionary is missing: %s" % reason_path))
    for name, (code,) in tables['gate_reason'].items():
        if name not in reg:
            fails.append(('S10', "%s is not registered in the reason dictionary" % name))
        elif reg[name].lower() != code.lower():
            fails.append(('S10', "%s — documented code %s / registered %s" % (name, code, reg[name])))
    if set(tables['gate_reason']) != {'ERR_WORLD_CHANGED', 'ERR_WORLD_INDETERMINATE'}:
        fails.append(('S10', "gate_reason table must list exactly the two world-comparison reasons"))
    tf = fmt.get('token_field', ('',))[0]
    rf = fmt.get('response_field', ('',))[0]
    for path, needle, what in ((pail_proto, 'bytes subgraph_snapshot_hash = %s;' % tf, 'token_field'),
                               (token_proto, 'bytes current_subgraph_hash = %s;' % rf, 'response_field')):
        if not os.path.exists(path):
            fails.append(('S10', "Shipped proto is missing: %s" % path))
        elif needle not in read(path):
            fails.append(('S10', "%s — %r not found in %s" % (what, needle, os.path.basename(path))))

    # --- S11: Korean edition ---------------------------------------------------------------
    ko = read(ko_path)
    ko_v = {m.group(1): m.end() for m in VOCAB_RE.finditer(ko)}
    if set(ko_v) != set(vpos):
        fails.append(('S11', "Korean vocabulary tables differ: canonical %s / Korean %s" % (sorted(vpos), sorted(ko_v))))
    else:
        ko_fails = []
        for name in sorted(vpos):
            en = doc_table(doc, 'S11', vpos[name], name, NCOLS[name], [])
            kv = doc_table(ko, 'S11', ko_v[name], name, NCOLS[name], ko_fails)
            if set(kv) != set(en):
                fails.append(('S11', "Table `%s` identifiers differ: canonical %s / Korean %s" % (name, sorted(en), sorted(kv))))
            elif kv != en:
                fails.append(('S11', "Table `%s` values differ; mismatching rows: %s" % (name, sorted(k for k in kv if kv[k] != en[k]))))
        fails.extend(ko_fails)
    ko_s = {m.group(1): m.end() for m in SAMPLE_RE.finditer(ko)}
    if set(ko_s) != set(spos):
        fails.append(('S11', "Korean sample list differs: canonical %s / Korean %s" % (sorted(spos), sorted(ko_s))))
    else:
        for name in sorted(ko_s):
            fence = FENCE_RE.search(ko, ko_s[name])
            if not fence:
                fails.append(('S11', "No code block after Korean sample `%s`" % name))
                continue
            try:
                obj = json.loads(fence.group(1))
            except ValueError as exc:
                fails.append(('S11', "Korean sample `%s` is not JSON: %s" % (name, exc)))
                continue
            if name in doc_samples and obj != doc_samples[name]:
                fails.append(('S11', "Korean sample `%s` differs from the canonical sample" % name))
    ko_pin = PIN_RE.search(ko)
    if ko_pin:
        f2 = FENCE_RE.search(ko, ko_pin.end())
        if not f2 or f2.group(1).strip() != by_id.get('SG-01', {}).get('canonical_hex'):
            fails.append(('S11', "Korean edition quotes different bytes than SG-01"))
    else:
        fails.append(('S11', "Korean edition has no pinned quotation"))

    # --- S12: source constants ------------------------------------------------------------------
    # The generator and the encoder ship in both layouts (under cloud/ in the public
    # snapshot), so the pin is measured in both; a layout that lacks them reports the
    # absence rather than skipping.
    if not (os.path.exists(gen_path) and os.path.exists(enc_path)):
        fails.append(('S12', "Generator or encoder source is missing: %s / %s" % (gen_path, enc_path)))
    else:
        src = read(gen_path)
        m = re.search(r'const\s+GoldenG1SHA256\s*=\s*"([0-9a-f]{64})"', src)
        if not m or m.group(1) != golden:
            fails.append(('S12', "Generator GoldenG1SHA256 differs from the documented golden_g1_sha256"))
        m = re.search(r'FormatMagic\s*=\s*"([A-Z]+)"', src)
        if not m or m.group(1) != fmt.get('magic', (None,))[0]:
            fails.append(('S12', "Generator FormatMagic differs from format.magic"))
        m = re.search(r'FormatVersion\s*=\s*(\d+)', src)
        if not m or m.group(1) != fmt.get('format_version', (None,))[0]:
            fails.append(('S12', "Generator FormatVersion differs from format.format_version"))
        enc = read(enc_path)
        m = re.search(r'magicSubgraph\s*=\s*"([A-Z]+)"', enc)
        if not m or m.group(1) != fmt.get('magic', (None,))[0]:
            fails.append(('S12', "Encoder magicSubgraph differs from format.magic"))
        m = re.search(r'formatVersion\s*=\s*0x0*([0-9a-f]+)', enc)
        if not m or int(m.group(1), 16) != int(fmt.get('format_version', ('0',))[0]):
            fails.append(('S12', "Encoder formatVersion differs from format.format_version"))

    sys.stdout.write(
        "layout %s · encoding %d/%d accept %d/%d reject · selection %d/%d · world %d accept %d reject · vocabularies %d\n"
        % (layout, enc_ok, len(accept), rej_ok, len(cases) - len(accept), sel_ok, len(sel_cases), world_ok, world_rej, len(vpos)))
    for code, why in SKIPS:
        sys.stdout.write('[SKIP] %s %s\n' % (code, why))
    for code, msg in fails:
        sys.stdout.write('[FAIL] %s %s\n' % (code, msg))
    sys.stdout.write('SPEC-SUBGRAPH: %s failures=%d skipped_groups=%d unmeasurable_groups=%d scope=%s\n'
                     % ('FAIL' if fails else 'PASS', len(fails), len(SKIPS), 0, layout))
    return 1 if fails else 0


if __name__ == '__main__':
    if len(sys.argv) > 1:
        sys.stderr.write("%s: no arguments accepted\n" % os.path.basename(sys.argv[0]))
        raise SystemExit(2)
    raise SystemExit(main())
