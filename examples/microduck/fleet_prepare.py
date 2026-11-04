# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Container-only provisioning of a NEW software fleet. Never adopts existing keys."""
import hashlib
import importlib.util
import json
import os
import shutil
from pathlib import Path

import yaml


def main():
    state = Path('/fleet')
    meta = json.loads((state / 'fleet-run.json').read_text())
    rows = meta['robots']
    os.chown('/collector-data', 10001, 10001)
    os.chmod('/collector-data', 0o700)
    first = state / 'robots' / rows[0]['key']
    spec = importlib.util.spec_from_file_location('keygen', '/opt/pail/keygen.py')
    kg = importlib.util.module_from_spec(spec); spec.loader.exec_module(kg)
    kg.KEYS = str(first / 'private/config/keys')
    if Path(kg.KEYS).exists():
        raise RuntimeError('NEW_FLEET_REQUIRED: private keys already exist')
    kg.selftest(); kg.generate(False)
    ring = json.loads((Path(kg.KEYS) / 'keyring.json').read_text())
    ring['keys'] = [k for k in ring['keys'] if k['key_id'] != 'agent-key-1']
    site = yaml.safe_load(Path('/reference/fixtures/demo/site.yaml').read_text())
    prototype = site['robots'][0]
    site['robots'] = [dict(prototype, id=r['robot_id']) for r in rows]
    registry = {'version': 1, 'robots': [dict(robot_id=r['robot_id'], role='robot',
                fingerprints=[hashlib.sha256(('software-dev-unused-tls-' + r['robot_id']).encode()).hexdigest()]) for r in rows]}
    for row in rows:
        base = state / 'robots' / row['key']
        for name, mode in [('private', 0o700), ('private/agent-key', 0o700), ('private/config', 0o700),
                           ('private/blackbox', 0o700), ('private/observe-blackbox', 0o700),
                           ('public/config/keys', 0o755), ('run', 0o755), ('run/raw', 0o750),
                           ('evidence/runtime', 0o755), ('evidence/ledger', 0o755)]:
            p = base / name; p.mkdir(parents=True, exist_ok=True); p.chmod(mode)
        agent = base / 'private/agent-key/agent_ed25519.json'
        kg._write_key(str(agent), row['key'] + '-key')
        key = json.loads(agent.read_text())
        ring['keys'].append({'key_id': key['key_id'], 'ed25519_public_key_base64': key['ed25519_public_key_base64'], 'role': 'burst'})
    observation = {'schema_version': 1, 'source_map': {
        'schema_version': 1, 'source_id': meta['run_id'], 'deployment_id': meta['deployment_id'],
        'providers': [{'provider_id': r['key'], 'kind': 'normalized_jsonl',
                       'expected_deployment_id': meta['deployment_id'], 'expected_robot_id': r['robot_id'],
                       'expected_identity': r['robot_id'], 'path_ref': '/observations/' + r['key'] + '/observation.jsonl',
                       'allowed_event_kinds': ['motion', 'pose', 'gate', 'permit', 'liveness'], 'expected_owner': meta['run_id'],
                       'expected_run_id': meta['run_id'], 'expected_stream_id': r['stream_id'],
                       'trust_basis': 'local_self_report', 'role': 'primary',
                       # a request, not a fact: the collector compares each record with its own clock
                       'clock_binding': 'shared_kernel_monotonic'} for r in rows] + [
                      # the plan and ledger columns come from the ledger the collector itself verifies,
                      # never from a robot's report: no path, no address, no robot
                      {'provider_id': 'ledger', 'kind': 'collector_ledger', 'trust_basis': 'collector_verified',
                       'allowed_event_kinds': ['plan', 'ledger'], 'role': 'primary'}]}}
    requesters = None
    if meta['profile'] == 'software-fleet-mtls':
        from fleet_mtls import provision
        registry, requesters, certificates = provision(state, rows)
        # Public enrollment receipt: no PEM/private material, expiry is explicit.
        (state / 'tls-enrollment.json').write_text(json.dumps({'profile':meta['profile'], 'certificates':certificates}))
        (state / 'tls-enrollment.json').chmod(0o644)
    if (meta.get('config') or {}).get('observation_path') == 'push':
        # the robots upload their records (design 15): each observer gets a certificate the registry
        # binds to its robot, the collector gets its own, and no observation file is shared
        from fleet_mtls import provision_push
        push_fingerprints, push_records = provision_push(state, rows)
        for entry in registry['robots']:
            entry['fingerprints'] = list(entry['fingerprints']) + [push_fingerprints[entry['robot_id']]]
        observation['source_map']['providers'] = [
            {'provider_id': r['key'], 'kind': 'normalized_push',
             'expected_deployment_id': meta['deployment_id'], 'expected_robot_id': r['robot_id'],
             'expected_identity': r['robot_id'], 'allowed_event_kinds': ['motion', 'pose', 'gate', 'permit', 'liveness'],
             'expected_owner': meta['run_id'], 'expected_run_id': meta['run_id'], 'expected_stream_id': r['stream_id'],
             'trust_basis': 'authenticated_self_report', 'role': 'primary'} for r in rows] + [
            p for p in observation['source_map']['providers'] if p['kind'] == 'collector_ledger']
        (state / 'push-enrollment.json').write_text(json.dumps({'observation_path': 'push', 'certificates': push_records}))
        (state / 'push-enrollment.json').chmod(0o644)
    for row in rows:
        base = state / 'robots' / row['key']
        for config in (base / 'private/config', base / 'public/config'):
            (config / 'keys').mkdir(exist_ok=True)
            for name in ('policy.yaml', 'skills.microduck.yaml'):
                shutil.copyfile(Path('/reference/fixtures/demo') / name, config / name)
            shutil.copyfile('/reference/fixtures/duck_skills.yaml', config / 'duck_skills.yaml')
            (config / 'site_model.yaml').write_text(yaml.safe_dump(site, sort_keys=False))
            (config / 'robot_registry.yaml').write_text(yaml.safe_dump(registry, sort_keys=False))
            if requesters is not None:
                (config / 'requesters.yaml').write_text(yaml.safe_dump(requesters, sort_keys=False))
            (config / 'keys/keyring.json').write_text(json.dumps(ring))
            (config / 'observation.json').write_text(json.dumps(observation))
            for p in config.rglob('*'):
                if p.is_file() and 'ed25519' not in p.name and p.suffix != '.key':
                    p.chmod(0o644)
        planner = base / 'evidence/runtime/demo-planner.jsonl'
        planner.touch(); planner.chmod(0o644); os.chown(planner, 12345, 10002)
        for root in ('private', 'run'):
            for p in [base / root, *(base / root).rglob('*')]:
                if p.is_symlink():
                    raise RuntimeError('UNEXPECTED_SYMLINK')
                os.chown(p, 10001, 10001)
        os.chown(base / 'evidence/runtime', 10001, 10001)
    print(json.dumps({'prepared': True, 'robots': [r['robot_id'] for r in rows],
                      'transport': 'mTLS TCP and local adapter UDS' if requesters is not None else 'software-dev synthetic identities; not mTLS enrollment'}))


if __name__ == '__main__':
    main()
