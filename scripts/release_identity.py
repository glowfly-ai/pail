#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Check/generate current delivery instructions from release.json; never embed ZIP's own hash.

release.json schema 2 names three archives of one candidate: `full` (the complete tree),
`core` (PAIL-Core, Apache-2.0) and `issuer` (PAIL-Issuer, an overlay over core under its own licence file).
"""
import argparse
import json
from pathlib import Path
import re
import sys
sys.dont_write_bytecode = True

ARTIFACT_KEYS = ('full', 'core', 'issuer')
# schema-3 release id: the final public release `x.y.z`, or `x.y.z-preview.n` during the run-up to
# it. The rc form (`x.y.z-rc.<yyyymmdd>.<n>`) belongs to schema 2 and is not accepted here.
# fullmatch, not match: a trailing space or newline must stay a rejection.
SCHEMA3_RELEASE = re.compile(r'\d+\.\d+\.\d+(?:-preview\.\d+)?')


def is_final_release(release):
    """True for a public release id, False for a preview one. The pattern above admits no other form."""
    return '-preview.' not in release


def unique(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError('Duplicate identity field: ' + key)
        obj[key] = value
    return obj


def safe_name(value, key):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', value):
        raise ValueError('Unsafe release identity: ' + key)


def load_identity(root):
    value = json.loads((root / 'release.json').read_text(), object_pairs_hook=unique)
    if value.get('schema_version') == 3:
        if set(value) != {'schema_version', 'release_id', 'root_directory', 'artifacts'}:
            raise ValueError('Unexpected distribution identity fields')
        release = value['release_id']
        if not isinstance(release, str) or not SCHEMA3_RELEASE.fullmatch(release):
            raise ValueError('Expected a semantic release identifier: x.y.z or x.y.z-preview.n')
        safe_name(value['root_directory'], 'root_directory')
        expected = {'core': f'PAIL-Core-{release}-src.zip',
                    'issuer': f'PAIL-Issuer-Eval-{release}-linux-arm64-image.tar',
                    'evaluation': f'PAIL-Evaluation-{release}.zip',
                    'offline': f'PAIL-Evaluation-{release}-linux-arm64-offline.zip'}
        if value['artifacts'] != expected or value['root_directory'] != 'pail-core':
            raise ValueError('Distribution artifact names/root disagree with release identity')
        value['artifact'] = expected['core']
        return value
    if set(value) != {'schema_version', 'release_id', 'root_directory', 'artifacts'} or value['schema_version'] != 2:
        raise ValueError('Unsupported release identity schema')
    for key in ['release_id', 'root_directory']:
        safe_name(value[key], key)
    arts = value['artifacts']
    if not isinstance(arts, dict) or set(arts) != set(ARTIFACT_KEYS):
        raise ValueError('artifacts must name exactly full, core and issuer')
    # <major>.<minor>.<patch>-rc.<yyyymmdd>.<n>[.<fix>] — the optional fourth field is a
    # documentation/packaging follow-up of the same candidate (first used by rc21.1).
    rc = re.fullmatch(r'\d+\.\d+\.\d+-rc\.(\d{8})\.(\d+)(?:\.(\d+))?', value['release_id'])
    for key in ARTIFACT_KEYS:
        safe_name(arts[key], 'artifacts.' + key)
        if not arts[key].endswith('.zip'):
            raise ValueError('Expected a ZIP artifact basename for ' + key)
        if rc and not arts[key].endswith('-' + rc[1] + '-rc' + rc[2] + ('.' + rc[3] if rc[3] else '') + '.zip'):
            raise ValueError('RC artifact date/number disagrees with release_id: ' + key)
    if len(set(arts.values())) != len(ARTIFACT_KEYS):
        raise ValueError('artifact basenames must be distinct')
    # Compatibility field for callers that address the complete tree.
    value['artifact'] = arts['full']
    return value


def block(identity, kind):
    # The schema-2 'one archive, both bundles' wording below is FROZEN: an earlier immutable archive's RELEASE.md was
    # generated from it and is still verified byte for byte by a maintainer test.
    # It describes that earlier delivery form, not the terms of a split Core delivery (see ISSUER_EVALUATION.md).
    release, folder = identity['release_id'], identity['root_directory']
    if identity['schema_version'] == 3:
        names = identity['artifacts']
        if kind == 'delivery':
            # A published release is not a local candidate; only the wording of this first sentence
            # differs between the two forms. Both keep the four-artifact sentence.
            opening = (f"Public release: **`{release}`**." if is_final_release(release)
                       else f"Current local candidate: **`{release}`**.")
            body = (f"{opening} Four separate artifacts per architecture; the Linux ARM64 set:\n\n"
                    f"- `{names['core']}` — Apache-2.0 Core source, including the complete robot gateway (one source ZIP for both architectures).\n"
                    f"- `{names['issuer']}` — Issuer evaluation image, executable only (Linux ARM64).\n"
                    f"- `{names['evaluation']}` — evaluation bootstrap; the runtime images are the separate TAR downloads of the same release.\n"
                    f"- `{names['offline']}` — same evaluation with pinned runtime images included.\n\n"
                    "The Linux amd64 delivery uses the same names with `linux-amd64` in place of `linux-arm64`:\n"
                    "the evaluation bootstrap `…-linux-amd64.zip`, the offline bundle `…-linux-amd64-offline.zip`,\n"
                    "the Core runtime images `…-linux-amd64-images.tar` and the Issuer image `…-linux-amd64-image.tar`;\n"
                    "its `images.lock.json` says `amd64` and its VALIDATION names its own image identities.\n"
                    "Each ZIP and TAR travels with a `.sha256` and a `.manifest.json`. Which set to use is decided by the\n"
                    "Docker daemon's CPU architecture, not by preference (the launcher refuses the other one).\n\n"
                    "Core builds and tests without the Issuer; the gate runs fail-closed until an issuer is present.\n"
                    "Evaluation uses the real single-node Issuer executable under separate evaluation terms.\n"
                    "The bootstrap bundle pulls nothing from a registry: load the image archives.\n"
                    "Offline means runtime, not rebuilding all source without dependencies.\n\n"
                    f"```sh\nshasum -a 256 -c {names['core']}.sha256\n```")
        elif kind == 'verify':
            body = (f"```sh\npython3 {folder}/scripts/verify_release.py \\\n"
                    f"  --root {folder} \\\n  --manifest {names['core']}.manifest.json \\\n"
                    f"  --zip {names['core']} \\\n  --expected-release {release}\n```\n\n"
                    "Obtain the manifest through a trusted channel. The evaluation launcher checks\n"
                    "its image lock before starting services; checksums alone do not authenticate a publisher.")
        else:
            raise ValueError('Unknown identity block')
        return f'<!-- release-identity:{kind}:start -->\n{body}\n<!-- release-identity:{kind}:end -->'
    full, core, issuer = (identity['artifacts'][k] for k in ARTIFACT_KEYS)
    if kind == 'delivery':
        # The delivery is ONE archive. What makes the license boundary is not the split into
        # archives but four things — the cloud/issuer/ directory, the per-file SPDX header,
        # cloud/issuer/LICENSE and NOTICE — and this one archive carries all four. The manifest's
        # source_files_bundle names the bundle of every path, so a recipient of this archive
        # alone can decide the license of any file mechanically.
        body = (f'Current candidate: **`{release}`**. The delivery is **one archive** with a `.sha256`\n'
                f'and a `.manifest.json` beside it (three files):\n\n'
                f'- `{full}` — the complete tree. It carries **both license bundles**: PAIL-Core\n'
                f'  (Apache-2.0) and PAIL-Issuer (BUSL-1.1, under `cloud/issuer/`). The demos, the\n'
                f'  E2E runner and the Linux release gate consume this archive.\n\n'
                f'Which license covers a given file is answered three ways inside this one archive:\n'
                f'the `cloud/issuer/` directory with its own `LICENSE`, the per-file SPDX header, and\n'
                f'the manifest field `source_files_bundle` (`core` or `issuer` for every path, with\n'
                f'`bundle_file_counts` as the totals). See `README.md` §License and `NOTICE`.\n\n'
                f'**Split archives on request.** `{core}`\n'
                f'(PAIL-Core only, Apache-2.0) and `{issuer}`\n'
                f'(PAIL-Issuer only, BUSL-1.1) can be produced from the same source selection for\n'
                f'recipients who must not receive non-OSI-licensed source. They are not published by\n'
                f'default. PAIL-Core alone does **not** build or run the demos, the E2E runner or the\n'
                f'Linux gate — those build the issuing services from `cloud/issuer/`, and each runner\n'
                f'refuses with that reason. Extracting the PAIL-Issuer archive **over** PAIL-Core into\n'
                f'the same `{folder}` root reproduces this archive byte for byte.\n\n'
                'Run beside these files, even when older releases are also present:\n\n'
                f'```sh\nshasum -a 256 -c {full}.sha256\n```')
    elif kind == 'verify':
        body = (f'```sh\npython3 {folder}/scripts/verify_release.py \\\n'
                f'  --root {folder} \\\n  --manifest {full}.manifest.json \\\n'
                f'  --zip {full} \\\n  --expected-release {release}\n```\n\n'
                f'The `.manifest.json` must travel with the archive; the verifier reads it out of band\n'
                f'and refuses when it is absent. If you received the split archives instead, use\n'
                f'`{core}.manifest.json` with `--zip {core}`, and for the\n'
                f'PAIL-Issuer archive extracted on its own (not over core) add\n'
                f'`--identity-root <extracted PAIL-Core root>` — the overlay carries no `release.json`.\n'
                f'Extracted over core, the tree verifies against the complete-tree manifest above.')
    else:
        raise ValueError('Unknown identity block')
    return f'<!-- release-identity:{kind}:start -->\n{body}\n<!-- release-identity:{kind}:end -->'


def generated_document(text, identity):
    for kind in ['delivery', 'verify']:
        pattern = rf'<!-- release-identity:{kind}:start -->.*?<!-- release-identity:{kind}:end -->'
        text, count = re.subn(pattern, lambda _: block(identity, kind), text, flags=re.S)
        if count != 1:
            raise ValueError('Missing/duplicate generated identity block: ' + kind)
    return text


def validate_identity(root):
    identity = load_identity(root)
    if (root / 'VERSION').read_text().strip() != identity['release_id']:
        raise ValueError('VERSION disagrees with release.json')
    doc = (root / 'RELEASE.md').read_text()
    if generated_document(doc, identity) != doc:
        raise ValueError('RELEASE.md delivery commands disagree with release.json')
    artifacts = set(re.findall(r'PAIL-[A-Za-z0-9._-]+\.(?:zip|tar)', doc))
    if artifacts != set(identity['artifacts'].values()):
        raise ValueError('RELEASE.md names a different set of artifact basenames')
    # RELEASE.md points at CHANGELOG.md as the source of this candidate's changes, so the
    # top section has to carry this candidate's name. An external review (2026-09-18) found an
    # rc whose top section was `## Unreleased`: the candidate's own changes were filed under
    # "things not released yet".
    changelog = (root / 'CHANGELOG.md').read_text()
    heads = re.findall(r'^##\s+(.+?)\s*$', changelog, re.M)
    if not heads:
        raise ValueError('CHANGELOG.md has no "## " section heading — the check measured nothing')
    if heads[0] != identity['release_id']:
        raise ValueError('CHANGELOG.md top section is %r, not this candidate %r'
                         % (heads[0], identity['release_id']))
    return identity


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    ap.add_argument('--write', action='store_true', help='Maintainer: update VERSION and marked RELEASE.md blocks')
    args = ap.parse_args()
    try:
        if args.write:
            identity = load_identity(args.root)
            path = args.root / 'RELEASE.md'
            doc = generated_document(path.read_text(), identity)
            path.write_text(doc)
            (args.root / 'VERSION').write_text(identity['release_id'] + '\n')
        identity = validate_identity(args.root)
        print('RELEASE_IDENTITY: PASS ' + json.dumps(identity))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print('RELEASE_IDENTITY: FAIL ' + str(exc))
        return 1


if __name__ == '__main__':
    sys.exit(main())
