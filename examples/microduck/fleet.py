# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Strict software fleet configuration, isolated topology and durable command intents.

No robot address, socket path, shell command or credential is accepted from a command
request. software-dev uses synthetic identities, NOT authenticated robot enrollment.
"""
import copy
import hashlib
import json
import math
import os
import re
import sqlite3
import threading
import uuid
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
ROBOT_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z')
REQUEST_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z')
FLEET_FIELDS = ('schema_version', 'deployment_id', 'profile', 'robots', 'budget')
# How the collector gets the robots' observation records (design 15.1). 'files': the robot
# side writes them where the collector reads them (one machine). 'push': the robot side
# uploads them over an authenticated connection and echoes the collector's challenge; the
# collector shares no file with any robot.
OBSERVATION_PATHS = ('files', 'push')
PUSH_PORT = 8443
PUSH_URL = 'https://collector:%d/v1/observations/push' % PUSH_PORT
# Configuration version 2 (design 14.1): a budget that grows with the robots. The shared
# containers (issuer, ledger copy, collector) divide `shared`; the robot-side containers of
# ONE robot divide `per_robot`, so a robot's share does not depend on how many robots there
# are. Version 1 (one fixed total for everything) is still accepted as it was.
ROBOT_FIELDS_V2 = ('robot_id', 'display_name')
ROBOT_OPTIONAL_V2 = ('kind',)
ROBOT_KINDS = ('microduck',)          # closed list; tb3 is a later release
BUDGET_FIELDS_V2 = ('shared', 'per_robot', 'parallelism')
BUDGET_PART_FIELDS = ('cpus', 'memory_mib')
SHARED_WEIGHTS = {'issuer': 4, 'collector': 2, 'ledger': 1}
ROBOT_WEIGHTS = {'agent': 3, 'adapter': 3, 'fake': 1, 'state-seam': 1, 'demo-planner': 1, 'demo-observer': 1, 'demo-evidence': 1}
MIN_CPUS, MIN_MEMORY_MIB = 0.05, 64    # below this a container cannot run: refused before Docker
HOST_MEMORY_FRACTION = 0.8             # design 14.3: memory up to 80 % of the host, CPUs up to all
ROBOT_FIELDS = ('robot_id', 'display_name')
BUDGET_FIELDS = ('cpus', 'memory_mib', 'parallelism')
ROLES = ('agent', 'fake', 'state-seam', 'adapter', 'demo-planner', 'demo-observer', 'demo-evidence')


class FleetError(ValueError):
    pass


class StrictLoader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise FleetError('CONFIG_ALIAS')
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        out = {}
        for k, v in node.value:
            key = self.construct_object(k, deep=deep)
            if not isinstance(key, str) or key in out:
                raise FleetError('CONFIG_DUPLICATE_OR_NONSTRING_KEY')
            out[key] = self.construct_object(v, deep=deep)
        return out


def fields(obj, required, optional=()):
    if not isinstance(obj, dict) or set(obj) - set(required) - set(optional) or set(required) - set(obj):
        raise FleetError('CONFIG_FIELDS')


def local_key(robot_id):
    # Preserve case and avoid punctuation/case folding collisions in Compose names.
    return 'r-' + hashlib.sha256(robot_id.encode()).hexdigest()[:24]


def robot_kind(row):
    """The kind of a robot of either configuration version."""
    return row.get('kind', 'microduck')


def budget_part(part, name):
    fields(part, BUDGET_PART_FIELDS)
    if (type(part['cpus']) not in (float, int) or isinstance(part['cpus'], bool) or not math.isfinite(part['cpus']) or not 0 < part['cpus'] <= 64
            or type(part['memory_mib']) is not int or isinstance(part['memory_mib'], bool) or not 1 <= part['memory_mib'] <= 262144):
        raise FleetError(name)


def observation_path(config):
    return config.get('observation_path', 'files')


def validate_config(doc):
    fields(doc, FLEET_FIELDS, ('recovery_policy',) + (('observation_path',) if isinstance(doc, dict) and doc.get('schema_version') == 2 else ()))
    if type(doc['schema_version']) is not int or doc['schema_version'] not in (1, 2):
        raise FleetError('CONFIG_SCHEMA')
    version = doc['schema_version']
    if 'observation_path' in doc and doc['observation_path'] not in OBSERVATION_PATHS:
        raise FleetError('OBSERVATION_PATH')
    try:
        dep = uuid.UUID(doc['deployment_id'])
        if str(dep) != doc['deployment_id'] or not dep.int:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise FleetError('CONFIG_DEPLOYMENT') from None
    if doc['profile'] not in ('software-dev', 'software-fleet-mtls'):
        raise FleetError('CONFIG_PROFILE')
    if 'recovery_policy' in doc:
        policy=doc['recovery_policy']
        if policy=={'mode':'operator'}:pass
        else:
            fields(policy,('mode','software_only','cooldown_s','max_attempts'))
            if (policy['mode']!='software-aging' or policy['software_only'] is not True
                    or type(policy['cooldown_s']) not in (int,float) or not math.isfinite(policy['cooldown_s'])
                    or not 5<=policy['cooldown_s']<=300 or type(policy['max_attempts']) is not int or not 1<=policy['max_attempts']<=3):
                raise FleetError('RECOVERY_POLICY_INVALID')
    rows = doc['robots']
    if not isinstance(rows, list) or not 1 <= len(rows) <= 16:
        raise FleetError('CONFIG_ROBOT_COUNT')
    seen, keys = set(), set()
    for row in rows:
        if version == 2:
            fields(row, ROBOT_FIELDS_V2, ROBOT_OPTIONAL_V2)
            if 'kind' in row and row['kind'] not in ROBOT_KINDS:
                raise FleetError('KIND_UNSUPPORTED')
        else:
            fields(row, ROBOT_FIELDS)
        rid = row['robot_id']
        if not isinstance(rid, str) or not ROBOT_ID.fullmatch(rid) or rid in seen or local_key(rid) in keys:
            raise FleetError('CONFIG_ROBOT_ID')
        name = row['display_name']
        if not isinstance(name, str) or not 1 <= len(name) <= 128 or any(ord(c) < 32 for c in name):
            raise FleetError('CONFIG_DISPLAY_NAME')
        seen.add(rid); keys.add(local_key(rid))
    b = doc['budget']
    if version == 2:
        fields(b, BUDGET_FIELDS_V2)
        budget_part(b['shared'], 'CONFIG_RESOURCE_BUDGET')
        budget_part(b['per_robot'], 'CONFIG_RESOURCE_BUDGET')
        if type(b['parallelism']) is not int or not 1 <= b['parallelism'] <= 2:
            raise FleetError('CONFIG_RESOURCE_BUDGET')
        # a budget that leaves a container below what it needs is refused here, before any state
        container_shares(doc)
        return copy.deepcopy(doc)
    fields(b, BUDGET_FIELDS)
    if (type(b['cpus']) not in (float, int) or not math.isfinite(b['cpus']) or not 0 < b['cpus'] <= 2
            or type(b['memory_mib']) is not int or not 1024 <= b['memory_mib'] <= 3072
            or type(b['parallelism']) is not int or not 1 <= b['parallelism'] <= 2):
        raise FleetError('CONFIG_RESOURCE_BUDGET')
    return copy.deepcopy(doc)


def notices(config):
    """What the operator should know about a configuration that was accepted."""
    if config['schema_version'] == 1:
        return ['CONFIG_V1: budget is one fixed total for every container; version 2 gives the shared containers and each robot their own share (design 14.1)']
    return []


def total_budget(config):
    """(cpus, memory_mib) the whole fleet may use."""
    b, n = config['budget'], len(config['robots'])
    if config['schema_version'] == 2:
        return b['shared']['cpus'] + b['per_robot']['cpus'] * n, b['shared']['memory_mib'] + b['per_robot']['memory_mib'] * n
    return b['cpus'], b['memory_mib']


def split(cpus, memory_mib, weights):
    total = sum(weights.values())
    return {name: (math.floor(cpus * w / total * 10000) / 10000, memory_mib * w // total) for name, w in weights.items()}


def container_shares(config):
    """(cpus, memory_mib) of every container role, by name: 'issuer', 'collector', 'ledger' and
    '<robot_id>/<role>'. Version 2: the shared containers divide `shared` and each robot's
    containers divide `per_robot`, so a robot's share is the same whatever n is. Version 1:
    every container divides the one total, as before."""
    b = config['budget']
    if config['schema_version'] == 2:
        out = dict(split(b['shared']['cpus'], b['shared']['memory_mib'], SHARED_WEIGHTS))
        for row in config['robots']:
            for role, share in split(b['per_robot']['cpus'], b['per_robot']['memory_mib'], ROBOT_WEIGHTS).items():
                out[row['robot_id'] + '/' + role] = share
    else:
        weights = {name: (4 if name == 'issuer' else 1) for name in SHARED_WEIGHTS}
        for row in config['robots']:
            for role in ROBOT_WEIGHTS:
                weights[row['robot_id'] + '/' + role] = 3 if role in ('agent', 'adapter') else 1
        out = split(b['cpus'], b['memory_mib'], weights)
    if config['schema_version'] == 2:
        for name, (cpus, memory_mib) in out.items():
            if cpus < MIN_CPUS or memory_mib < MIN_MEMORY_MIB:
                raise FleetError('BUDGET_BELOW_MINIMUM')
    return out


def capacity_check(config, host):
    """Refuse a fleet that this host cannot hold (design 14.3). host = (cpus, memory_bytes) as
    Docker reports them, or None when they could not be read: then nothing is assumed and the
    fleet is refused with CAPACITY_UNKNOWN. What other projects use is not subtracted: Docker does
    not say. Passing means the fleet is not plainly too large, not that it is comfortable."""
    if not host or len(host) != 2 or not all(type(v) in (int, float) and math.isfinite(v) and v > 0 for v in host):
        raise FleetError('CAPACITY_UNKNOWN')
    host_cpus, host_memory_mib = host[0], host[1] / (1024 * 1024) * HOST_MEMORY_FRACTION
    need_cpus, need_memory = total_budget(config)
    if need_cpus <= host_cpus and need_memory <= host_memory_mib:
        return {'host_cpus': host[0], 'host_memory_mib': host[1] // (1024 * 1024), 'need_cpus': need_cpus, 'need_memory_mib': need_memory, 'max_robots': max_robots(config, host)}
    if config['schema_version'] == 2:
        raise FleetError('CAPACITY_EXCEEDED: this host fits at most %d robots of this budget (needs %.2f CPUs and %d MiB; host %d CPUs and %d MiB usable)'
                         % (max_robots(config, host), need_cpus, need_memory, host[0], int(host_memory_mib)))
    raise FleetError('CAPACITY_EXCEEDED: the fixed total of this version 1 budget (%.2f CPUs, %d MiB) exceeds the host (%d CPUs, %d MiB usable)'
                     % (need_cpus, need_memory, host[0], int(host_memory_mib)))


def max_robots(config, host):
    """How many robots of this budget the host holds: version 2 only; version 1 has no per-robot share."""
    if config['schema_version'] != 2:
        return None
    b = config['budget']
    host_cpus, host_memory_mib = host[0], host[1] / (1024 * 1024) * HOST_MEMORY_FRACTION
    by_cpu = (host_cpus - b['shared']['cpus']) / b['per_robot']['cpus']
    by_memory = (host_memory_mib - b['shared']['memory_mib']) / b['per_robot']['memory_mib']
    return max(0, int(math.floor(min(by_cpu, by_memory))))


def load_config(path):
    raw = Path(path).read_bytes()
    if len(raw) > 65536:
        raise FleetError('CONFIG_OVERSIZE')
    return validate_config(yaml.load(raw, Loader=StrictLoader))


def atomic_json(path, value, mode=0o600):
    path = Path(path)
    temp = path.with_name(path.name + '.next-' + uuid.uuid4().hex)
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, 'w') as out:
            json.dump(value, out, allow_nan=False, sort_keys=True)
            out.write('\n'); out.flush(); os.fsync(out.fileno())
        temp.replace(path)
        fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if temp.exists():
            temp.unlink()


def render(config, state, image, run_id, issuer_image=None):
    """Generate all binding sites together; no user-defined service/socket overrides. There is one communication
    contract (0.2.0-preview.40): nothing selects it, so no peer carries a PAIL_CORE_COMM_CONTRACT setting."""
    config = validate_config(config)
    state = Path(state).resolve()
    if issuer_image is not None and not re.fullmatch(r'sha256:[a-f0-9]{64}', issuer_image):
        raise FleetError('ISSUER_IMAGE_DIGEST_REQUIRED')
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', image):
        raise FleetError('IMAGE_DIGEST_REQUIRED')
    if str(uuid.UUID(run_id)) != run_id:
        raise FleetError('RUN_ID')
    base = yaml.safe_load((HERE / 'compose.yaml').read_text())
    overlay = yaml.safe_load((HERE / 'compose.demo.yaml').read_text())
    templates = copy.deepcopy(base['services'])
    for role, patch in overlay['services'].items():
        target = templates.setdefault(role, {})
        for field, value in patch.items():
            if field == 'volumes':
                # Compose volume merge is by target; reproduce only the known templates.
                mounts = {mount_target(v): v for v in target.get(field, [])}
                mounts.update({mount_target(v): v for v in value})
                target[field] = list(mounts.values())
            elif isinstance(value, dict) and isinstance(target.get(field), dict):
                target[field].update(copy.deepcopy(value))
            else:
                target[field] = copy.deepcopy(value)
    keys = {r['robot_id']: local_key(r['robot_id']) for r in config['robots']}
    first = next(iter(keys.values()))
    services, volumes, networks = {}, {}, {}
    push = observation_path(config) == 'push'
    rows = []
    for robot in config['robots']:
        rid, key = robot['robot_id'], keys[robot['robot_id']]
        robot_state = state / 'robots' / key
        networks[key] = {'internal': True}
        volumes[key + '-run'] = {}; volumes[key + '-private'] = {}
        row = dict(robot, profile=config['profile'], key=key, state=str(robot_state), stream_id=str(uuid.uuid4()),
                   services={role: key + '-' + role for role in ROLES})
        rows.append(row)
        for role in ROLES:
            service = copy.deepcopy(templates[role])
            service['image'] = image
            service['networks'] = {key: {'aliases': ['agent'] if role == 'agent' else []}}
            service['volumes'] = [remap_mount(v, robot_state, key) for v in service.get('volumes', [])]
            env = service.setdefault('environment', {})
            env.update(PAIL_ROBOT_ID=rid, PAIL_FLEET_RUN_ID=run_id,
                       PAIL_FLEET_DEPLOYMENT_ID=config['deployment_id'], PAIL_FLEET_STREAM_ID=row['stream_id'],
                       GOMAXPROCS='2', GOMEMLIMIT='192MiB')
            if push and role == 'demo-observer':
                # the observer of this robot is the one robot-side member of the uplink: it uploads with
                # its own certificate, from the private volume of its robot, read-only
                service['networks']['uplink'] = {}
                env.update(PAIL_OBSERVATION_PUSH_URL=PUSH_URL, PAIL_OBSERVATION_PUSH_CA='/push/ca.crt',
                           PAIL_OBSERVATION_PUSH_CERT='/push/client.crt', PAIL_OBSERVATION_PUSH_KEY='/push/client.key')
                service['volumes'].append({'type': 'volume', 'source': key + '-private', 'target': '/push', 'read_only': True, 'volume': {'subpath': 'observer-key/push_certs'}})
            if role == 'agent':
                env['PAIL_AGENT_KEY_ID'] = key + '-key'
                # OI-01: the agent's retried decision-report queue survives a restart on the
                # robot's run volume (the template mounts it; the mTLS profile's UDS lives there too).
                env['PAIL_REPORT_QUEUE_DIR'] = '/run/duck/report_queue'
            if role == 'adapter':
                cmd = service['command']
                cmd[cmd.index('--robot-id') + 1] = rid
            if config['profile'] == 'software-fleet-mtls':
                if role == 'agent':
                    env.update(PAIL_GRPC_TLS='on', PAIL_GRPC_CA='/etc/pail/grpc_certs/ca.crt',
                               PAIL_GRPC_CERT='/run/pail-secrets/grpc_certs/server.crt',
                               PAIL_GRPC_KEY='/run/pail-secrets/grpc_certs/server.key',
                               PAIL_GRPC_CLIENT_CERT='/run/pail-secrets/grpc_certs/client.crt',
                               PAIL_GRPC_CLIENT_KEY='/run/pail-secrets/grpc_certs/client.key',
                               PAIL_GRPC_UDS_PATH='/run/duck/agent.sock')
                elif role == 'adapter':
                    cmd[cmd.index('--agent') + 1] = 'unix:/run/duck/agent.sock'
            service['labels'] = {'org.pail.run': run_id, 'org.pail.robot': rid, 'org.pail.role': role}
            services[row['services'][role]] = service
    issuer = copy.deepcopy(templates['issuer'])
    issuer.update(image=issuer_image or image, networks={key: {'aliases': ['issuer']} for key in keys.values()})
    issuer['volumes'] = [remap_mount(v, state / 'robots' / first, first) for v in issuer['volumes']]
    issuer['environment'].update(GOMAXPROCS='2', GOMEMLIMIT='256MiB')
    issuer['labels'] = {'org.pail.run': run_id, 'org.pail.role': 'issuer'}
    if config['profile'] == 'software-fleet-mtls':
        issuer['environment'].update(PAIL_GRPC_TLS='on', PAIL_REQUESTERS='/etc/pail/requesters.yaml')
    services['issuer'] = issuer
    ledger = copy.deepcopy(templates['demo-ledger'])
    ledger.update(image=image, network_mode='none')
    ledger.pop('networks', None)
    ledger['volumes'] = [remap_mount(v, state / 'robots' / first, first) for v in ledger['volumes']]
    ledger['labels'] = {'org.pail.run': run_id, 'org.pail.role': 'ledger'}
    services['ledger'] = ledger
    volumes['collector-data'] = {}
    networks['observation'] = {'internal': True}
    collector = {'image': image, 'user': '10001:10001', 'networks': ['observation'],
                 'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'],
                 'command': ['pail_telemetryd', '-dir', '/data', '-blackbox-dir', '/ledger',
                             '-registry', '/config/robot_registry.yaml', '-http', '127.0.0.1:8080',
                             '-listen', '127.0.0.1:46000', '-observability-config', '/config/observation.json'],
                 'environment': {'PAIL_PROFILE': 'dev', 'PAIL_KEYRING_MODE': 'unsigned-dev',
                                 'PAIL_KEYRING': '/config/keys/keyring.json', 'GOMAXPROCS': '2', 'GOMEMLIMIT': '256MiB'},
                 'volumes': ['collector-data:/data', str(state / 'robots' / first / 'public/config') + ':/config:ro',
                             str(state / 'robots' / first / 'evidence/ledger') + ':/ledger:ro'],
                 'labels': {'org.pail.run': run_id, 'org.pail.role': 'collector'}}
    if push:
        # the collector listens on the uplink for the robots' uploads and shares no file with them
        networks['uplink'] = {'internal': True}
        collector['networks'] = ['observation', 'uplink']
        collector['command'] += ['-push-listen', '0.0.0.0:%d' % PUSH_PORT, '-push-ca', '/push/ca.crt', '-push-cert', '/push/server.crt', '-push-key', '/push/server.key']
        collector['volumes'].append({'type': 'volume', 'source': first + '-private', 'target': '/push', 'read_only': True, 'volume': {'subpath': 'config/push_certs'}})
    else:
        for row in rows:
            collector['volumes'].append(str(Path(row['state']) / 'evidence/runtime') + ':/observations/' + row['key'] + ':ro')
    services['collector'] = collector
    # Version 1: total resident-service limits, one fixed total divided by weight. Version 2: the
    # shared containers divide `shared`, each robot's containers divide `per_robot` (design 14.2).
    shares = container_shares(config)
    by_service = {'issuer': shares['issuer'], 'collector': shares['collector'], 'ledger': shares['ledger']}
    for row in rows:
        for role, name in row['services'].items():
            by_service[name] = shares[row['robot_id'] + '/' + role]
    for name, service in services.items():
        cpus, memory_mib = by_service[name]
        service['cpus'] = cpus
        service['mem_limit'] = str(memory_mib) + 'm'
        service['memswap_limit'] = service['mem_limit']
        service['pids_limit'] = 128
    total_cpus, total_memory = total_budget(config)
    prepare = {'image': image, 'user': '0:0', 'network_mode': 'none',
               'command': ['python', '/reference/fleet_prepare.py'],
               'volumes': [str(state) + ':/fleet', str(HERE) + ':/reference:ro', 'collector-data:/collector-data'],
               'cpus': total_cpus, 'mem_limit': str(total_memory) + 'm',
               'labels': {'org.pail.run': run_id, 'org.pail.role': 'prepare'}}
    for row in rows:
        for suffix, dest in [('private', 'private'), ('run', 'run')]:
            prepare['volumes'].append(row['key'] + '-' + suffix + ':/fleet/robots/' + row['key'] + '/' + dest)
    services['prepare'] = prepare
    for name in volumes:
        volumes[name]['labels'] = {'org.pail.run': run_id}
    result = {'services': services, 'networks': networks, 'volumes': volumes}
    validate_topology(result, rows, image, run_id)
    return result, rows


def mount_target(mount):
    return mount['target'] if isinstance(mount, dict) else mount.split(':')[1]


def remap_mount(mount, state, key):
    if isinstance(mount, dict):
        result = copy.deepcopy(mount)
        result['source'] = key + '-' + result['source']
        return result
    return mount.replace('${PAIL_DUCK_STATE}', str(state)).replace('run:/run/duck', key + '-run:/run/duck').replace('private:/', key + '-private:/')


def validate_topology(doc, rows, image, run_id):
    """Fail before Docker on crossed sockets, network aliases, images or IDs."""
    peers=['issuer']+[r['services'][role] for r in rows for role in ('agent','adapter')]
    values=[doc['services'][name].get('environment',{}).get('PAIL_CORE_COMM_CONTRACT') for name in peers]
    # one communication contract (0.2.0-preview.40): a fleet rendered under the removed `legacy` contract is not revived;
    # an earlier release's `v1` marker on an existing run is tolerated (same wire), a new render carries no marker
    if any(v=='legacy' for v in values):raise FleetError('LEGACY_RUN_UNSUPPORTED: this fleet was rendered under the removed `legacy` contract; clean it with this release\'s `cleanup --state <dir>` (stopping it with the release that created it also works), then start a new fleet')
    if any(v not in (None,'v1') for v in values):raise FleetError('CORE_CONTRACT_COHORT_MISMATCH')

    if any(r.get('profile') == 'software-fleet-mtls' for r in rows):
        if any(r.get('profile') != 'software-fleet-mtls' for r in rows):
            raise FleetError('BINDING_PROFILE')
        env = doc['services']['issuer']['environment']
        if env.get('PAIL_GRPC_TLS') != 'on' or env.get('PAIL_REQUESTERS') != '/etc/pail/requesters.yaml':
            raise FleetError('BINDING_ISSUER_MTLS')
    # Observation is one way. The collector is the only member of the observation network and
    # a member of nothing else; the issuer stays on the robot networks it serves. The screen is
    # never a reason to attach the authorization path to the observation side.
    robot_networks = {row['key'] for row in rows}
    push = 'uplink' in doc.get('networks', {})
    observers = {row['services']['demo-observer'] for row in rows}
    for name, s in doc['services'].items():
        attached = set(s.get('networks') or ())
        if name == 'collector':
            if attached != ({'observation', 'uplink'} if push else {'observation'}) or s.get('ports') or s.get('network_mode'):
                raise FleetError('BINDING_COLLECTOR_NETWORK')
        elif 'observation' in attached:
            raise FleetError('BINDING_OBSERVATION_NETWORK')
        elif name == 'issuer' and attached != robot_networks:
            raise FleetError('BINDING_ISSUER_NETWORK')
        # the uplink (design 15.1) joins each robot's observer to the collector and nothing else:
        # the issuer, the agents and the adapters are never reachable from it
        if 'uplink' in attached and name != 'collector' and name not in observers:
            raise FleetError('BINDING_UPLINK_NETWORK')
        if push and name in observers and 'uplink' not in attached:
            raise FleetError('BINDING_UPLINK_NETWORK')
    for row in rows:
        key, rid = row['key'], row['robot_id']
        for role, name in row['services'].items():
            s = doc['services'][name]
            if s['image'] != image or s['labels']['org.pail.run'] != run_id or s['environment']['PAIL_ROBOT_ID'] != rid:
                raise FleetError('BINDING_ID_IMAGE')
            own = {key, 'uplink'} if push and role == 'demo-observer' else {key}
            if set(s['networks']) != own or s.get('ports') or s.get('devices') or s.get('privileged') or s.get('network_mode'):
                raise FleetError('BINDING_NETWORK')
            for mount in s.get('volumes', []):
                src = mount['source'] if isinstance(mount, dict) else mount.split(':')[0]
                if mount_target(mount) == '/run/duck' and src != key + '-run':
                    raise FleetError('BINDING_SOCKET')
                if mount_target(mount) == '/run/pail-secrets' and src != key + '-private':
                    raise FleetError('BINDING_KEY')
                if src.endswith('-private') and isinstance(mount, dict) and mount_target(mount) == '/push':
                    # the observer's upload material: its own robot's, read-only, the certificate part only
                    if (role != 'demo-observer' or not push or src != key + '-private'
                            or mount.get('volume', {}).get('subpath') != 'observer-key/push_certs' or mount.get('read_only') is not True):
                        raise FleetError('PRIVATE_VOLUME_EXPOSURE')
                elif row.get('profile') == 'software-fleet-mtls' and src.endswith('-private'):
                    if (role != 'agent' or src != key+'-private' or not isinstance(mount, dict)
                            or mount_target(mount) != '/run/pail-secrets'
                            or mount.get('volume', {}).get('subpath') != 'agent-key'
                            or mount.get('read_only') is not True):
                        raise FleetError('PRIVATE_VOLUME_EXPOSURE')
            if role == 'agent' and (s['environment']['PAIL_CLOUD_ADDR'] != 'issuer:50051' or s['environment']['PAIL_AGENT_KEY_ID'] != key + '-key'):
                raise FleetError('BINDING_AGENT')
            if role == 'agent' and row.get('profile') == 'software-fleet-mtls':
                expected = {'PAIL_GRPC_TLS':'on', 'PAIL_GRPC_CA':'/etc/pail/grpc_certs/ca.crt',
                            'PAIL_GRPC_CERT':'/run/pail-secrets/grpc_certs/server.crt',
                            'PAIL_GRPC_KEY':'/run/pail-secrets/grpc_certs/server.key',
                            'PAIL_GRPC_CLIENT_CERT':'/run/pail-secrets/grpc_certs/client.crt',
                            'PAIL_GRPC_CLIENT_KEY':'/run/pail-secrets/grpc_certs/client.key',
                            'PAIL_GRPC_UDS_PATH':'/run/duck/agent.sock'}
                if any(s['environment'].get(k) != v for k,v in expected.items()):
                    raise FleetError('BINDING_MTLS')
            if role == 'adapter':
                cmd = s['command']
                if cmd[cmd.index('--robot-id') + 1] != rid or cmd[cmd.index('--agent') + 1] != ('unix:/run/duck/agent.sock' if row.get('profile') == 'software-fleet-mtls' else 'http://agent:50051') or cmd[cmd.index('--raw') + 1] != '/run/duck/raw/state-seam.sock':
                    raise FleetError('BINDING_ADAPTER')


class IntentStore:
    """Persist PREPARED/UNKNOWN before sending; replay never calls the sender again.

    A crash between dispatch and recording its response is deliberately UNKNOWN.
    The operator must inspect the stored plan, not blindly resubmit the intention.
    """
    def __init__(self, path, robots, existing=False):
        self.robots = tuple(robots)
        self.lock = threading.Lock()
        path=Path(path)
        if path.is_symlink() or (existing and not path.is_file()):raise FleetError('INTENT_HISTORY_MISSING')
        existed=path.exists()
        self.db = sqlite3.connect(path.resolve().as_uri()+'?mode=rw',uri=True,check_same_thread=False,isolation_level=None) if existed else sqlite3.connect(path,check_same_thread=False,isolation_level=None)
        try:
            if existed:
                cols=[r[1] for r in self.db.execute('PRAGMA table_info(intents)')]
                if cols!=['request_id','robot_id','digest','plan_id','response'] or self.db.execute('PRAGMA user_version').fetchone()[0]!=1:
                    raise FleetError('INTENT_HISTORY_SCHEMA')
                if self.db.execute('PRAGMA quick_check').fetchone()[0]!='ok':raise FleetError('INTENT_HISTORY_CORRUPT')
            else:
                os.chmod(path,0o600)
                self.db.execute('CREATE TABLE intents(request_id TEXT PRIMARY KEY, robot_id TEXT NOT NULL, digest TEXT NOT NULL, plan_id TEXT NOT NULL, response TEXT NOT NULL)')
                self.db.execute('PRAGMA user_version=1')
            self.db.execute('PRAGMA synchronous=FULL')
        except Exception:self.db.close();raise

    def close(self):
        self.db.close()

    def validate_request(self, request):
        fields(request, ('request_id', 'text'), ('robot_id',))
        rid = request.get('robot_id')
        if rid is None:
            if len(self.robots) != 1:
                raise FleetError('TARGET_REQUIRED')
            rid = self.robots[0]
        if rid not in self.robots:
            raise FleetError('TARGET_UNKNOWN')
        reqid, text = request['request_id'], request['text']
        if not isinstance(reqid, str) or not REQUEST_ID.fullmatch(reqid):
            raise FleetError('REQUEST_ID')
        if not isinstance(text, str) or not 1 <= len(text) <= 4096:
            raise FleetError('COMMAND_TEXT')
        digest = hashlib.sha256(json.dumps([rid, text], ensure_ascii=True).encode()).hexdigest()
        return rid,reqid,text,digest

    def lookup(self, request):
        rid,reqid,text,digest=self.validate_request(request)
        with self.lock:
            row=self.db.execute('SELECT digest,response FROM intents WHERE request_id=?',(reqid,)).fetchone()
            if row and row[0]!=digest:raise FleetError('REQUEST_ID_CONFLICT')
            return json.loads(row[1]) if row else None

    def execute(self, request, sender):
        rid,reqid,text,digest=self.validate_request(request)
        with self.lock:
            row = self.db.execute('SELECT digest,response FROM intents WHERE request_id=?', (reqid,)).fetchone()
            if row:
                if row[0] != digest:
                    raise FleetError('REQUEST_ID_CONFLICT')
                return json.loads(row[1])
            plan = 'fleet-' + uuid.uuid4().hex
            unknown = {'robot_id': rid, 'request_id': reqid, 'plan_id': plan, 'execution': 'UNKNOWN', 'accepted': None}
            self.db.execute('INSERT INTO intents VALUES(?,?,?,?,?)', (reqid, rid, digest, plan, json.dumps(unknown)))
        # Do not hold the database lock during I/O: the other robot can progress.
        try:
            response = sender(rid, text, plan)
        except Exception:
            return unknown
        result = dict(response, robot_id=rid, request_id=reqid, plan_id=plan)
        with self.lock:
            self.db.execute('UPDATE intents SET response=? WHERE request_id=?', (json.dumps(result, allow_nan=False), reqid))
        return result
