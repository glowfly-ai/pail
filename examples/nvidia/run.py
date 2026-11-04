# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Bounded CPU-only synthetic reference, using a locked PAIL evaluation bundle.

No image pull/build, no NVIDIA SDK install, no hardware driver or movement.
start is synchronous. stop requests interruption of this runner's own child only.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
import hashlib
from nvidia_profile import load, digest, read_json, ProfileError
from doctor import diagnose
from verify import verify_reference

class MissingEvidence(ValueError):
    pass

def atomic(path, value):
    temp = path.with_name(path.name + '.tmp-' + uuid.uuid4().hex)
    with temp.open('x') as stream:
        json.dump(value, stream, indent=2); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    temp.replace(path)

def source_hashes(core):
    return {str(p.relative_to(core)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(core.rglob('*')) if p.is_file() and '__pycache__' not in p.parts}

def validate_core(core):
    # This is explicitly user-selected local code, not code from a remote manifest.
    for name in ('release.json', 'VERSION', 'examples/tb3/run.py', 'examples/common/evaluation_runtime.py'):
        if not (core / name).is_file():
            raise MissingEvidence('Extract a matching evaluation bundle; missing ' + name)
    if read_json(core / 'release.json').get('schema_version') != 3:
        raise MissingEvidence('Only binary-Issuer evaluation bundles are supported; no implicit build')
    lock_path = core.parent / 'images.lock.json'
    lock = read_json(lock_path)
    spec = importlib.util.spec_from_file_location('nv_evaluation_runtime', core / 'examples/common/evaluation_runtime.py')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    images = module.runtime_images(core)  # existing protocol/release/platform/immutable image checks
    return {'release': (core / 'VERSION').read_text().strip(), 'images': images,
            'architecture': lock['architecture'], 'lock_sha256': hashlib.sha256(lock_path.read_bytes()).hexdigest()}

def result_base(profile, run_id):
    return {'schema_version': 1, 'run_id': run_id, 'profile_id': profile['profile_id'],
            'profile_digest': digest(profile), 'hardware_verified': False, 'support_status': 'UNVERIFIED',
            'target_requested': profile['target'], 'target_observed': 'not_run',
            'coverage': {'real_gate_bridge': False, 'endpoint_model': False, 'jetson_runtime': False,
                         'gpu': False, 'isaac_sim': False, 'physical_motion': False}, 'checks': [],
            'limitations': ['No NVIDIA hardware compatibility claim.',
                            'Synthetic reference observes ROS commands, not actuator delivery.',
                            'Mock endpoint timeout model is separate from the existing ROS sink.']}

def prepare(profile, state, core):
    pre = diagnose(profile)
    if pre['overall'] != 'PASS':
        raise ProfileError('Host preflight failed: ' + json.dumps(pre['checks']))
    binding = validate_core(core)
    if profile['target'] == 'jetson' and binding['architecture'] != 'arm64':
        raise ProfileError('Jetson requires arm64 evaluation images')
    # Do not create state until all prerequisites have been checked.
    if state == core or core in state.parents or state in core.parents:
        raise ProfileError('State and source must be disjoint')
    state.mkdir(mode=0o700, parents=False, exist_ok=False)
    owned = {'schema_version': 1, 'run_id': 'nv-' + uuid.uuid4().hex,
             'profile': profile, 'profile_digest': digest(profile), 'core': str(core),
             'source_hashes': source_hashes(core), 'runtime': binding, 'preflight': pre}
    atomic(state / 'prepared.json', owned)
    out = result_base(profile, owned['run_id']); out['overall'] = 'NOT_RUN'
    atomic(state / 'result.json', out)
    return out

def prepared(state, profile):
    if state.is_symlink() or not state.is_dir():
        raise ProfileError('Invalid state directory')
    data = read_json(state / 'prepared.json')
    if data['profile_digest'] != digest(profile) or data['profile'] != profile:
        raise ProfileError('Prepared profile changed')
    return data

def cleanup_check(state, report):
    project = report.get('project', '')
    import re
    if not re.fullmatch(r'pail-tb3-[a-f0-9]{12}', project):
        return {'status': 'INCONCLUSIVE', 'reason': 'No owned project recorded; inspect reference log before retry'}
    proc = subprocess.run(['docker', 'ps', '-aq', '--filter', 'label=com.docker.compose.project=' + project],
                          capture_output=True, text=True, timeout=20)
    return {'status': 'PASS' if proc.returncode == 0 and not proc.stdout.strip() else 'FAIL',
            'project': project, 'remaining_containers': proc.stdout.split()}

def start(profile, state):
    data = prepared(state, profile); core = Path(data['core'])
    if diagnose(profile)['overall'] != 'PASS':
        raise ProfileError('Host preflight no longer passes')
    if source_hashes(core) != data['source_hashes'] or validate_core(core) != data['runtime']:
        raise ProfileError('Prepared source/image lock changed')
    # Exclusive once-only marker: never reuse private state or erase failed evidence.
    fd = os.open(state / 'started', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600); os.close(fd)
    out = result_base(profile, data['run_id']); out['overall'] = 'RUNNING'
    out['runtime'] = data['runtime']; out['source_sha256'] = digest(data['source_hashes'])
    atomic(state / 'result.json', out)
    proc = None; interrupted = False
    try:
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
        with (state / 'reference.log').open('x') as log:
            proc = subprocess.Popen([sys.executable, '-B', str(core / 'examples/tb3/run.py'), '--state',
                                     str(state / 'reference'), '--skip-build'], stdout=log, stderr=subprocess.STDOUT,
                                    env=env, start_new_session=True)
            deadline = time.monotonic() + 1200
            while proc.poll() is None:
                if (state / 'stop-request').exists() or time.monotonic() > deadline:
                    interrupted = True
                    proc.send_signal(signal.SIGINT)
                    try:
                        proc.wait(timeout=90)
                    except subprocess.TimeoutExpired:
                        # Preserve evidence and ownership; never broad-kill Docker/ROS processes.
                        out['orphan_child_pid'] = proc.pid
                    break
                time.sleep(.25)
    except KeyboardInterrupt:
        interrupted = True
        if proc and proc.poll() is None:
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=90)
            except subprocess.TimeoutExpired:
                out['orphan_child_pid'] = proc.pid
    except (OSError, subprocess.SubprocessError) as exc:
        out['error'] = str(exc)
    finally:
        report = {}
        try:
            report = read_json(state / 'reference/evidence/FINAL_RESULT.json')
        except (OSError, ValueError):
            pass
        rc = proc.poll() if proc else None
        check = verify_reference(report, rc)
        out['checks'] = [check]
        try:
            out['cleanup'] = cleanup_check(state, report)
        except (OSError, subprocess.SubprocessError) as exc:
            out['cleanup'] = {'status': 'INCONCLUSIVE', 'reason': str(exc)}
        unchanged = source_hashes(core) == data['source_hashes']
        out['source_unchanged'] = unchanged
        passed = check['status'] == 'PASS' and not interrupted and unchanged and out['cleanup']['status'] == 'PASS'
        out['overall'] = 'PASS' if passed else 'FAIL' if report else 'INCONCLUSIVE'
        out['interrupted'] = interrupted
        out['coverage']['real_gate_bridge'] = check['status'] == 'PASS'
        out['target_observed'] = 'synthetic_ros_reference'
        if profile['target'] == 'jetson':
            out['coverage']['jetson_runtime'] = check['status'] == 'PASS'
            # A CPU smoke does not promote the profile to hardware-verified support.
            out['target_observed'] = 'jetson_cpu_synthetic_reference'
        atomic(state / 'result.json', out)
    return out

def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('command', choices=['doctor', 'prepare', 'start', 'status', 'stop'])
    parser.add_argument('--profile', required=True, type=Path)
    parser.add_argument('--state', type=Path)
    parser.add_argument('--core', type=Path)
    parser.add_argument('--require-verified', action='store_true')
    a = parser.parse_args(); profile = load(a.profile)
    if profile['schema_version'] != 1:
        raise ProfileError('v2 managed profiles require session.py; run.py preserves the v1 bounded suite')
    if a.require_verified:
        raise MissingEvidence('No Jetson/Sim verified profile shipped; UNVERIFIED cannot be promoted by configuration')
    if a.command == 'doctor':
        out = diagnose(profile)
    else:
        if not a.state:
            raise ProfileError('--state required')
        if a.state.is_symlink():
            raise ProfileError('Symlink state is not supported')
        state = a.state.resolve()
        if a.command == 'prepare':
            if not a.core:
                raise ProfileError('--core extracted evaluation pail-core required')
            out = prepare(profile, state, a.core.resolve())
        else:
            prepared(state, profile)
            if a.command == 'start':
                out = start(profile, state)
            else:
                out = read_json(state / 'result.json')
                if a.command == 'stop' and out['overall'] == 'RUNNING':
                    atomic(state / 'stop-request', {'request': 'interrupt_owned_reference'})
                    out = dict(out, stop_requested=True)  # not a claim of successful stop/cleanup
    print(json.dumps(out, indent=2))
    return 0 if out['overall'] in ('PASS', 'NOT_RUN', 'RUNNING') else 3 if out['overall'] == 'INCONCLUSIVE' else 2 if a.command == 'doctor' else 4

if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(json.dumps({'overall': 'INCONCLUSIVE' if isinstance(exc, MissingEvidence) else 'FAIL',
                          'hardware_verified': False, 'error': str(exc)}))
        raise SystemExit(3 if isinstance(exc, MissingEvidence) else 2)
