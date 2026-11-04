# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Hash and summarize a converted Waffle Pi asset tree (runs inside the Isaac Sim image, no GPU, no Kit).

Two tree hashes and a semantic summary (preview.15 P15-L1, preview.16 P16-M1):

- ``assets_sha256``: raw bytes of every file. Not reproducible across runs: the importer writes the names of
  its two scratch directories (``/tmp/tmpXXXXXXXX/`` and ``/tmp/urdf_import_<robot>_<random>/``) into the USD
  ``doc`` strings, and inside the binary crate files (``*.usd``/``*.usdc``) those strings are not bytes a text
  substitution can reach. This is what ``make_isaac_profile.py`` pins for the tree you actually use.
- ``assets_sha256_normalized``: text layers (``*.usda``) with both scratch paths replaced by constants; binary
  crate layers exported to USDA text with pxr (``Sdf.Layer.ExportToString``) and normalized the same way;
  every other file by raw bytes. This is the value to compare across runs and with ASSETS.md.
- ``semantics``: joint prim names, prim count, mesh point/face counts and link masses read from the composed
  stage — what the gate's test actually depends on; ``semantics_sha256`` is its digest.

usage: asset_tree_hash.py <asset-dir> <entry-usda-relative> <expanded-urdf-sha256> <ASSET_TREE.json output>
Refuses (rc 5) when pxr is unavailable instead of silently hashing bytes.
"""
import glob
import hashlib
import json
import re
import sys
from pathlib import Path

TMP_PATTERNS = (re.compile(rb'/tmp/tmp[A-Za-z0-9_]+/'), re.compile(rb'/tmp/urdf_import_[^/\s"]+/'))
NORMALIZATION = '/tmp/tmp*/ -> /tmp/<importer-tmp>/ ; /tmp/urdf_import_*/ -> /tmp/<importer-urdf-tmp>/ ; binary USD layers exported to USDA text first'
BINARY_LAYER = ('.usd', '.usdc')


def _pxr():
    for root in sorted(glob.glob('/isaac-sim/extscache/omni.usd.libs-*')):
        if root not in sys.path:
            sys.path.insert(0, root)
    try:
        from pxr import Sdf, Usd  # noqa: F401
    except ImportError as exc:
        sys.stderr.write('asset_tree_hash: pxr unavailable (%s); run inside the Isaac Sim image with the omni.usd.libs extension on the library path\n' % exc)
        sys.exit(5)
    return Sdf, Usd


def normalize(data):
    data = TMP_PATTERNS[0].sub(b'/tmp/<importer-tmp>/', data)
    return TMP_PATTERNS[1].sub(b'/tmp/<importer-urdf-tmp>/', data)


def layer_text(Sdf, path):
    layer = Sdf.Layer.FindOrOpen(str(path))
    if layer is None:
        raise ValueError('pxr cannot open layer: %s' % path)
    return layer.ExportToString().encode('utf-8')


def semantics(Usd, root, entry):
    stage = Usd.Stage.Open(str(root / entry), Usd.Stage.LoadAll)
    if stage is None:
        raise ValueError('pxr cannot open stage: %s' % entry)
    joints, meshes, masses, prims = [], {}, {}, 0
    # Instance proxies included: the importer writes the meshes as instanceable references, which
    # Stage.Traverse() would skip (0 meshes, measured on the 2026-10-17 trees).
    for prim in Usd.PrimRange(stage.GetPseudoRoot(), Usd.TraverseInstanceProxies()):
        if prim.IsPseudoRoot():
            continue
        prims += 1
        name = prim.GetName()
        if 'Joint' in prim.GetTypeName():
            joints.append(name)
        if prim.GetTypeName() == 'Mesh':
            pts = prim.GetAttribute('points').Get()
            fvc = prim.GetAttribute('faceVertexCounts').Get()
            meshes[str(prim.GetPath())] = {'points': len(pts) if pts else 0, 'faces': len(fvc) if fvc else 0}
        mass = prim.GetAttribute('physics:mass')
        if mass and mass.HasAuthoredValue():
            masses[name] = round(float(mass.Get()), 9)
    return {'entry': entry, 'prims': prims, 'joints': sorted(joints), 'meshes': dict(sorted(meshes.items())), 'masses': dict(sorted(masses.items()))}


def main(argv):
    if len(argv) != 5:
        sys.stderr.write(__doc__)
        return 2
    root, entry, urdf_sha, out = Path(argv[1]), argv[2], argv[3], Path(argv[4])
    Sdf, Usd = _pxr()
    raw, norm = {}, {}
    for p in sorted(root.rglob('*')):
        if p.is_symlink():
            raise ValueError('asset symlink refused: %s' % p)
        if not p.is_file():
            continue
        rel = str(p.relative_to(root))
        data = p.read_bytes()
        raw[rel] = hashlib.sha256(data).hexdigest()
        if p.suffix in BINARY_LAYER:
            data = layer_text(Sdf, p)
        norm[rel] = hashlib.sha256(normalize(data)).hexdigest()
    tree = lambda rows: hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()).hexdigest()  # noqa: E731
    sem = semantics(Usd, root, entry)
    result = {'files': raw, 'files_normalized': norm, 'assets_sha256': tree(raw), 'assets_sha256_normalized': tree(norm),
              'normalization': NORMALIZATION, 'expanded_urdf_sha256': urdf_sha,
              'semantics': sem, 'semantics_sha256': tree(sem)}
    out.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'files': len(raw), 'assets_sha256': result['assets_sha256'], 'assets_sha256_normalized': result['assets_sha256_normalized'],
                      'semantics_sha256': result['semantics_sha256'], 'prims': sem['prims'], 'joints': sem['joints'], 'expanded_urdf_sha256': urdf_sha}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
