# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Binary-Issuer image binding for evaluation. Never pulls or builds implicitly."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tarfile


class EvaluationRequired(ValueError):
    pass


def split_distribution(root):
    path = Path(root) / 'release.json'
    if not path.is_file():
        return False
    return json.loads(path.read_text()).get('schema_version') == 3


def protocol_digest(root):
    rows = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted((Path(root) / 'sdk/proto').glob('*.proto'))}
    if not rows:
        raise EvaluationRequired('PROTOCOL_MISSING: sdk/proto/*.proto')
    return hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


OCI_INDEX_TYPES = ('application/vnd.oci.image.index.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json')
OCI_MANIFEST_TYPES = ('application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json')


def _oci_kind(node):
    """index | manifest | config | None, from the metadata document itself (never from its name)."""
    if node.get('mediaType') in OCI_INDEX_TYPES and isinstance(node.get('manifests'), list):
        return 'index'
    if node.get('schemaVersion') == 2 and node.get('mediaType') in OCI_MANIFEST_TYPES and isinstance(node.get('config'), dict):
        return 'manifest'
    if 'schemaVersion' not in node and isinstance(node.get('rootfs'), dict) and 'architecture' in node:
        return 'config'
    return None


def _identity_from_archive(root, data, pinned):
    """Prove the pinned image identity from the supplied OCI archive, whichever digest kind the lock holds.

    A Docker daemon names an image by its *config* digest (classic graph drivers: overlay2 and friends) or by
    its *manifest/index* digest (containerd image store: Docker Desktop, Docker 29 defaults). The packager
    pins whatever its own daemon reported, so a bundle exported on one kind of store must still be proven
    on the other (preview.16 evaluation P16-H2: an amd64 lock with config digests refused every containerd
    host with "unsupported OCI manifest"). Every metadata byte is hashed back to its digest; the config commits
    to the uncompressed rootfs layer chain. TAR contents are never extracted. No tag lookup: missing proof is a
    refusal, not permission to use a tag.

    Returns (config_id, diff_ids, candidate_ids): the IDs under which a local store may know this exact image —
    the config digest, the platform manifest digest and the index digest when the archive carries one.
    """
    digest_pattern = r'sha256:[a-f0-9]{64}'
    for name in data.get('archives', {}):
        if Path(name).name != name or not name.endswith('.tar'):
            raise ValueError('invalid image archive name')
        path = root.parent / 'images' / name
        if path.is_symlink():
            raise ValueError('symlinked image archive')
        if not path.is_file():
            continue
        with tarfile.open(path, 'r:') as archive:
            members = archive.getmembers()
            def blob(digest):
                if not re.fullmatch(digest_pattern, digest):
                    raise ValueError('invalid OCI digest')
                matches = [m for m in members if m.name == 'blobs/sha256/' + digest[7:]]
                if len(matches) != 1 or not matches[0].isfile() or not 0 < matches[0].size <= 2 * 1024 * 1024:
                    raise ValueError('missing, duplicate, or unsafe OCI metadata')
                raw = archive.extractfile(matches[0]).read()
                if 'sha256:' + hashlib.sha256(raw).hexdigest() != digest:
                    raise ValueError('OCI metadata digest mismatch')
                return json.loads(raw)
            def platform_manifest(index):
                choices = [m for m in index['manifests'] if m.get('platform', {}).get('os') == 'linux'
                           and m.get('platform', {}).get('architecture') == data['architecture']]
                if len(choices) != 1:
                    raise ValueError('ambiguous or missing OCI platform')
                return choices[0]['digest']
            if not any(m.name == 'blobs/sha256/' + pinned[7:] for m in members):
                continue
            node = blob(pinned)
            kind = _oci_kind(node)
            candidates = [pinned]
            if kind == 'index':
                manifest_id = platform_manifest(node)
                candidates.append(manifest_id)
                node = blob(manifest_id)
                kind = _oci_kind(node)
            if kind == 'manifest':
                config_id = node['config']['digest']
                candidates.append(config_id)
                config = blob(config_id)
                # A store may also know this image by an index that lists this manifest (multi-platform load).
                for m in members:
                    if not (m.isfile() and m.name.startswith('blobs/sha256/') and 0 < m.size <= 2 * 1024 * 1024):
                        continue
                    try:
                        doc = json.loads(archive.extractfile(m).read())
                    except ValueError:
                        continue
                    if _oci_kind(doc) == 'index' and any(e.get('digest') in candidates for e in doc['manifests'] if isinstance(e, dict)):
                        digest = 'sha256:' + m.name[len('blobs/sha256/'):]
                        blob(digest)
                        candidates.append(digest)
            elif kind == 'config':
                # The lock holds a config digest (classic store at the packager): find the manifest(s) in this
                # archive that commit to it, so a containerd store can be asked by the name it uses.
                config_id, config = pinned, node
                manifest_ids = []
                for m in members:
                    if not (m.isfile() and m.name.startswith('blobs/sha256/') and 0 < m.size <= 2 * 1024 * 1024):
                        continue
                    try:
                        doc = json.loads(archive.extractfile(m).read())
                    except ValueError:
                        continue
                    if _oci_kind(doc) == 'manifest' and doc['config'].get('digest') == pinned:
                        digest = 'sha256:' + m.name[len('blobs/sha256/'):]
                        blob(digest)  # re-verifies the bytes against their digest
                        manifest_ids.append(digest)
                    elif _oci_kind(doc) == 'index':
                        for entry in doc['manifests']:
                            try:
                                sub = blob(entry['digest'])
                            except ValueError:
                                continue
                            if _oci_kind(sub) == 'manifest' and sub['config'].get('digest') == pinned:
                                manifest_ids.append('sha256:' + m.name[len('blobs/sha256/'):])
                                manifest_ids.append(entry['digest'])
                if not manifest_ids:
                    raise ValueError('no OCI manifest in the supplied archive commits to the pinned config')
                candidates.extend(sorted(set(manifest_ids)))
            else:
                raise ValueError('unsupported OCI metadata: the pinned digest is neither index, manifest nor config')
            if _oci_kind(config) != 'config':
                raise ValueError('unsupported OCI config')
            if config.get('os') != 'linux' or config.get('architecture') != data['architecture']:
                raise ValueError('OCI config platform mismatch')
            fs = config['rootfs']
            if fs.get('type') != 'layers' or not isinstance(fs.get('diff_ids'), list) or not all(re.fullmatch(digest_pattern, x) for x in fs['diff_ids']):
                raise ValueError('invalid OCI rootfs')
            seen = []
            for c in candidates:
                if c not in seen:
                    seen.append(c)
            return config_id, fs['diff_ids'], seen
    raise EvaluationRequired('IMAGE_MISSING: locked OCI image unavailable; load it or retain the supplied images TARs for the identity proof')


def _config_from_archive(root, data, pinned):
    """Compatibility wrapper: (config_id, diff_ids) of the pinned image, any digest kind."""
    config_id, layers, _ = _identity_from_archive(root, data, pinned)
    return config_id, layers


def _store_driver():
    """What this daemon calls its image store, for error messages only (never a decision input)."""
    try:
        p = subprocess.run(['docker', 'info', '--format', '{{.Driver}}'], capture_output=True, text=True, timeout=30)
    except Exception:  # noqa: BLE001 — message decoration must never become a different failure
        return 'unknown'
    return (p.stdout.strip() or 'unknown') if p.returncode == 0 else 'unknown'


def _lock_id_kind(root, data, pinned):
    """index | manifest | config | unknown — what the lock's digest names inside the supplied archive."""
    try:
        for name in data.get('archives', {}):
            path = root.parent / 'images' / name
            if Path(name).name != name or path.is_symlink() or not path.is_file():
                continue
            with tarfile.open(path, 'r:') as archive:
                for m in archive.getmembers():
                    if m.name == 'blobs/sha256/' + pinned[7:] and m.isfile() and 0 < m.size <= 2 * 1024 * 1024:
                        return _oci_kind(json.loads(archive.extractfile(m).read())) or 'unknown'
    except (OSError, ValueError, tarfile.TarError, KeyError, TypeError):
        pass
    return 'unknown'


def _inspect(image):
    p = subprocess.run(['docker', 'image', 'inspect', image], capture_output=True, text=True, timeout=30)
    if p.returncode:
        error = (p.stderr + p.stdout).lower()
        if 'permission denied' in error:
            raise EvaluationRequired('DOCKER_PERMISSION_DENIED: Docker socket access denied; check group/login, not image installation')
        if any(word in error for word in ('cannot connect', 'is the docker daemon', 'error during connect')):
            raise EvaluationRequired('DOCKER_UNAVAILABLE: start/check the Docker daemon')
        if 'no such image' not in error:
            raise EvaluationRequired('DOCKER_INSPECT_FAILED: cannot prove local image identity')
        return None
    return json.loads(p.stdout)[0]


def runtime_images(root):
    """The evaluation bundle places images.lock.json beside pail-core, not in its source.

    Keeping the lock outside the source avoids a circular source-hash/image-ID dependency.
    The delivered lock is covered by the evaluation archive's external manifest.
    """
    root = Path(root).resolve()
    lock = root.parent / 'images.lock.json'
    try:
        if lock.is_symlink():
            raise ValueError('symlinked lock')
        data = json.loads(lock.read_text())
        if data['schema_version'] != 1 or data['release_id'] != (root / 'VERSION').read_text().strip():
            raise ValueError('release mismatch')
        if data['protocol_sha256'] != protocol_digest(root):
            raise ValueError('protocol mismatch')
        if set(data['images']) != {'issuer', 'microduck', 'tb3_gate'}:
            raise ValueError('image role set')
        resolved = {}
        for role, entry in data['images'].items():
            image = entry['id']
            if not re.fullmatch(r'sha256:[a-f0-9]{64}', image):
                raise ValueError('non-immutable image ID: ' + role)
            pinned = image
            info = _inspect(image)
            if info is None:
                # Not known under the pinned digest: this daemon may name the same image by its other digest
                # kind (config vs manifest/index). Prove the alternatives from the supplied archive, then ask
                # for each of them; the rootfs layer chain must match the proven config either way.
                try:
                    config_id, layers, candidates = _identity_from_archive(root, data, pinned)
                except EvaluationRequired as exc:
                    raise EvaluationRequired('IMAGE_MISSING: %s; this Docker store (driver %s) does not know the pinned %s digest and no supplied image archive proves it; load the supplied image archive before running (%s)'
                                             % (role, _store_driver(), _lock_id_kind(root, data, pinned), exc)) from exc
                for candidate in candidates:
                    info = _inspect(candidate)
                    if info is not None:
                        image = candidate
                        break
                if info is not None and info.get('RootFS', {}).get('Layers') != layers:
                    raise ValueError('runtime rootfs differs from pinned OCI config: ' + role)
            if info is None:
                raise EvaluationRequired('IMAGE_MISSING: %s; this Docker store (driver %s) does not hold the image pinned by a %s digest; load the supplied image archive before running'
                                         % (role, _store_driver(), _lock_id_kind(root, data, pinned)))
            if info['Id'] != image or info['Os'] != 'linux' or info['Architecture'] != data['architecture']:
                raise ValueError('image platform or identity mismatch: ' + role)
            labels = info['Config'].get('Labels') or {}
            expected = {'issuer': 'issuer-eval', 'microduck': 'core-microduck', 'tb3_gate': 'core-tb3-gate'}
            if labels.get('org.pail.component') != expected[role] or labels.get('org.pail.release') != data['release_id']:
                raise ValueError('wrong Issuer/Core component/release: ' + role)
            resolved[role] = image
        return resolved
    except EvaluationRequired:
        raise
    except (OSError, ValueError, KeyError, TypeError, IndexError, tarfile.TarError, subprocess.SubprocessError) as exc:
        raise EvaluationRequired('EVALUATION_REQUIRED: valid images.lock.json beside pail-core and the matching local images are required; ' + str(exc)) from exc


def issuer_image(root):
    return runtime_images(root)['issuer']


def docker_architecture():
    out = subprocess.run(['docker', 'info', '--format', '{{.Architecture}}'], capture_output=True, text=True, timeout=30).stdout.strip()
    return {'aarch64': 'arm64', 'arm64': 'arm64', 'x86_64': 'amd64', 'amd64': 'amd64'}.get(out, out)


def platform_note(root, daemon_arch=None):
    """0.2.2 F5: 'native', or 'emulated bundle=<lock> docker=<daemon>' when the bundle's images run on another
    architecture. A Core-only tree has no lock: its images are built here, for this daemon."""
    lock = Path(root).parent / 'images.lock.json'
    if not lock.is_file():
        return 'native'
    bundle = json.loads(lock.read_text())['architecture']
    daemon = daemon_arch or docker_architecture()
    return 'native' if bundle == daemon else 'emulated bundle=%s docker=%s' % (bundle, daemon)


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--root', required=True, type=Path)
    what = ap.add_mutually_exclusive_group(required=True)
    what.add_argument('--role', choices=('issuer', 'microduck', 'tb3_gate'))
    what.add_argument('--platform', action='store_true', help='print native, or emulated bundle=<arch> docker=<arch>')
    args = ap.parse_args()
    print(platform_note(args.root) if args.platform else runtime_images(args.root)[args.role])
