# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Owned software fleet runner; shared issuer, separate robot groups and one console."""
import copy
import base64
import urllib.parse
import http.server
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

import demo
from fleet import FleetError, IntentStore, atomic_json, load_config, render, validate_topology, capacity_check, notices
from compose_failure import failed_step  # P24-L1: the first cause of a failed fleet start names the daemon's condition, not an exception class
from lifecycle import Lifecycle, sha, canonical, fingerprint_files, validate_inventory
import hashlib
import sqlite3
from recovery import Recovery
from diagnostics import ProbeError, transport
from collector_bridge import CollectorBridge, READER, UNAVAILABLE
from run_names import project_name, release_id  # preview.40 review item 01: pail-<kind>-<release>-<run>


class RobotStack(demo.Stack):
    def __init__(self, fleet, row):
        super().__init__(Path(row['state']), fleet.image, fleet.project, issuer_image=fleet.issuer_image, )
        self.fleet, self.row, self.robot_id = fleet, row, row['robot_id']
        self.compose, self.env = fleet.compose, fleet.env
        self.pending = threading.local()

    def probe(self, *args, timeout=30):
        args = list(args)
        if args[0] in ('submit', 'skill') and getattr(self.pending, 'plan', None):
            args += ['--plan-id', self.pending.plan]
        service = self.row['services']['agent']
        if args[0] in ('verify', 'unlock'):
            # verify and unlock use keys that live only in the issuer's /etc/pail/keys (issuer key,
            # operator key); the robot's agent holds the keyring alone, and the operator key must not
            # be put on the robot side. The single-robot console runs every probe in the issuer; the
            # fleet runs the robot's own probes in its agent and these two in the issuer (O8-02 T23:
            # an unlock from the agent was answered 400 UNKNOWN — FileNotFoundError in the probe).
            service = 'issuer'
        cmd = self.compose + ['exec', '-T', service, 'python', '/reference/demo_probe.py', *args]
        started=time.monotonic()
        try:p = subprocess.run(cmd, env=self.env, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise ProbeError(dict(transport(basis='timeout'),endpoint='agent_to_issuer',operation=args[0],duration_ms=(time.monotonic()-started)*1000)) from None
        rows = [line for line in p.stdout.splitlines() if line.startswith('{')]
        try:body=json.loads(rows[-1]) if rows else {}
        except (ValueError,TypeError):body={}
        if not isinstance(body,dict):body={}
        if not body:rows=[]
        if p.returncode or not rows or body.get('error'):
            diag=body.get('diagnostic') or transport(basis='probe_process_failed')
            raise ProbeError(dict(diag,endpoint='agent_to_issuer',operation=args[0],duration_ms=round((time.monotonic()-started)*1000,3)))
        return body

    def write_control(self,instruction=False,**changes):
        recovery=getattr(self.fleet,'recovery',None)
        if recovery is None:return super().write_control(instruction=instruction,**changes)
        with recovery.mu:
            if recovery.paused(self.robot_id) or recovery.closed.is_set():
                if changes.get('mode') in ('plan','skill','raw'):raise FleetError('ROBOT_PAUSED_BEFORE_DISPATCH')
                changes.update(mode='idle',steps=[],raw={})
                instruction=True
            return super().write_control(instruction=instruction,**changes)

    def fault(self, service, action):
        if service not in ('agent', 'adapter', 'demo-observer') or action not in ('stop', 'start'):
            raise FleetError('FAULT_SCOPE')
        target = self.row['services'][service]
        self.fleet.owned()
        self.fleet.run(['stop' if action == 'stop' else 'start', target], 'fault-' + self.row['key'])
        self.fleet.recovery.fail(self.robot_id,'RESTART',transport(basis='instance_changed' if action=='start' else 'service_not_running'))
        # the console's own fault: record the service's new start time so that the inventory pass does not report
        # this same restart as a new fault after the operator has confirmed (see restart_robot)
        self.fleet.recovery.note_instances([i for i in self.fleet.recovery_inventory() if i['robot_id'] == self.robot_id], seed=True)
        return {'ok': True, 'robot_id': self.robot_id, 'service': service, 'action': action}

    def restart_robot(self):
        """Restart the robot side of THIS robot: its fake, seam, adapter and demo actors. The
        issuer, the ledger, the collector and every other robot are not touched. The robot is
        paused for the operator afterwards, as after any restart of its services."""
        names = [self.row['services'][role] for role in ROBOT_SERVICES]
        self.write_control(instruction=True, mode='idle', steps=[], raw={}, override_linear=None, safety='OK', tag=demo.TARGET)
        before = {}
        for role in ('planner', 'observer', 'evidence'):
            p = self.logs / 'runtime' / ('demo-' + role + '.jsonl')
            before[role] = p.stat().st_size if p.exists() else 0
        self.fleet.owned()
        self.fleet.run(['restart', *names], 'restart-' + self.row['key'], timeout=120)
        self.fleet.recovery.fail(self.robot_id, 'RESTART', transport(basis='instance_changed'))
        # This restart is the console's own: record the containers' new start times NOW, before the operator can
        # confirm. Otherwise the supervisor's 2 s inventory pass reports them as a NEW fault after the confirmation,
        # pauses the robot again and cancels the plan the operator just issued (Linux recipient replay 2026-10-10,
        # scene R 3 of 6: idle + NORTHBOUND_CANCEL ~1 s after `issued`, the move stalled on ERR_NO_TOKEN).
        self.fleet.recovery.note_instances([i for i in self.fleet.recovery_inventory() if i['robot_id'] == self.robot_id], seed=True)
        self.wait_exec(self.row['services']['fake'], "import os,sys; sys.exit(0 if os.path.exists('/run/duck/raw/robotd.sock') else 1)", 'fake socket', timeout=30)
        self.wait_exec(self.row['services']['state-seam'], "import os,sys; sys.exit(0 if os.path.exists('/run/duck/raw/state-seam.sock') else 1)", 'state seam', timeout=30)
        self.wait_exec(self.row['services']['adapter'], "import os,sys; sys.exit(0 if os.path.exists('/run/duck/pail.sock') else 1)", 'adapter socket', timeout=30)
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            fresh = {role: demo.read_rows(self.logs / 'runtime' / ('demo-' + role + '.jsonl'), before[role]) for role in before}
            if all(any(r.get('event') == event and r.get('robot_id') == self.robot_id and r.get('run_id') == self.fleet.run_id for r in fresh[role])
                   for role in fresh for event in ('ready', 'connected')):
                return {'robot_id': self.robot_id, 'restarted': names}
            time.sleep(.25)
        raise FleetError('ACTOR_READINESS_TIMEOUT')


class RobotFeed:
    """What one robot's console writes and reads. Every event goes to the fleet feed as before.
    An event this console read from its own robot's files, or made itself, also goes to the
    robot's own feed: that is what the console page of the robot shows. An event that names
    another robot is not the robot's, whatever file it was read from."""
    def __init__(self, shared, robot_id):
        self.shared, self.robot_id = shared, robot_id
        self.own = demo.ConsoleFeed()

    def attach_trust(self,provider):
        self.own.attach_trust(provider)

    def trust_observation(self):
        return self.own.trust_observation()

    def attach_health(self,provider):
        self.own.attach_health(provider)
        self.shared.attach_robot_health(self.robot_id,self.own.observation_health)

    def observation_health(self):
        return self.own.observation_health()

    def publish_health(self,force=False):
        self.own.publish_health(force)
        self.shared.publish_health(force)

    def append(self, event):
        seq = self.shared.append(event)
        if event.get('robot_id') in (None, self.robot_id):
            self.own.append(event)
        return seq

    def __iter__(self):
        return iter(self.shared)

    def __getattr__(self, name):
        return getattr(self.shared, name)


# What the console page of one robot may ask for besides a command. The names are those of the
# single-robot console API; each acts on the robot of the path and on no other.
ROBOT_ACTIONS = ('rogue', 'raw', 'inputs', 'fault', 'unlock', 'verify', 'restart_robot')
ROBOT_SERVICES = ('fake', 'state-seam', 'adapter', 'demo-planner', 'demo-observer', 'demo-evidence')


class RobotConsole(demo.Console):
    def __init__(self, stack, feed):
        self.command_lock = threading.Lock()
        super().__init__(stack, feed=RobotFeed(feed, stack.robot_id))

    def emit(self, kind, **kw):
        # every event of this console names its robot; an answer of the robot's stack that already
        # names it (fault, restart) is not a second value for it, and another robot's name is refused
        if kw.setdefault('robot_id', self.stack.robot_id) != self.stack.robot_id:
            raise FleetError('ROBOT_ID_MISMATCH')
        super().emit(kind, **kw)

    def verify(self):
        """The ledger verified at the issuer, then the collector asked for this robot's ledger events —
        through the fleet's read bridge (the collector's loopback is not this console's to dial), in
        the form the single-robot console answers."""
        r = self.stack.probe('verify', timeout=90)
        out = {'ok': bool(r.get('ok')), 'output': r.get('output', ''), 'dashboard': None}
        fleet = self.stack.fleet
        if fleet.dashboard_url:
            try:
                now_ms = int(time.time() * 1000)
                # the newest 200 rows of the robot are enough to answer "does the collector hold this robot's
                # ledger": the whole window of a long run would outlast the bridge's reader timeout
                path = '/v1/ledger/events?robot=%s&from_ms=%d&to_ms=%d&limit=200' % (urllib.parse.quote(self.stack.robot_id, safe=''), now_ms - 6 * 3600 * 1000, now_ms)
                for attempt in range(3):   # the bridge answers 429/503 while its reader is busy or being replaced
                    status, _, body = fleet.read_collector(path)
                    if status not in (429, 503):
                        break
                    time.sleep(1.0)
                if status != 200:
                    raise ValueError('collector answered %s' % status)
                doc = json.loads(body)
                rows = doc.get('rows') or []
                out['dashboard'] = {'ok': bool(rows), 'rows': len(rows), 'verify': doc.get('verify'), 'url': fleet.dashboard_url}
            except (OSError, ValueError, subprocess.TimeoutExpired) as ex:
                out['dashboard'] = {'ok': False, 'detail': str(ex)[:300], 'url': fleet.dashboard_url}
        self.emit('ledger_verified', ok=out['ok'], output=out['output'][-600:], dashboard=out['dashboard'])
        return out

    def observe_record(self,record):
        self.stack.fleet.recovery.observe(self.stack.robot_id,record)

    def _issued(self,text,r,steps,explain,mode,**control):
        try:return super()._issued(text,r,steps,explain,mode,**control)
        except FleetError as ex:
            if str(ex)!='ROBOT_PAUSED_BEFORE_DISPATCH':raise
            return {'accepted':True,'plan':r.get('plan'),'tokens':r.get('tokens',[]),
                    'execution':'PAUSED','new_command_required':True,'steps':steps,'explain':explain}

    def state(self):
        with self.cond:
            return dict(super().state(), robot_id=self.stack.robot_id, pose=self.pose,
                        plan=copy.deepcopy(self.plan), recovery=self.stack.fleet.recovery.snapshot(self.stack.robot_id))


class FleetRunner:
    def __init__(self, config, state, image, project=None, issuer_image=None, contract=None, stored_cohort=False):
        # one communication contract (0.2.0-preview.40): a run recorded under the removed `legacy` contract is not
        # revived; an ambient selecting variable — present at all, even empty (0.2.0-preview.41, P40-L2) — is refused
        # by name (the message of core_operation_wire.py)
        if contract=='legacy':raise FleetError('LEGACY_RUN_UNSUPPORTED: this fleet was recorded with the removed `legacy` contract; clean it with this release\'s `cleanup --state <dir>` (stopping it with the release that created it also works), then start a new fleet')
        if 'PAIL_CORE_COMM_CONTRACT' in os.environ:raise FleetError('CORE_COMM_CONTRACT_SETTING_REMOVED')
        self.lifecycle = Lifecycle(state)
        self.config, self.state, self.image = config, self.lifecycle.root, image
        self.admission = threading.Condition(threading.RLock())
        self.accepting = False
        self.inflight = 0
        self.stop_lock = threading.Lock()
        self.resources_closed = False
        self.run_id = str(uuid.uuid4())
        self.project = project or project_name('duck-fleet', release_id(demo.ROOT))
        if not self.project.startswith(('pail-duck-fleet-', 'pail-mobs-auto-', 'pail-opsview-auto-')) or not all(c in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in self.project):
            raise FleetError('PROJECT_SCOPE')
        self.issuer_image = issuer_image or image
        self.doc, self.rows = render(config, self.state, image, self.run_id, issuer_image=self.issuer_image)
        self.compose = ['docker', 'compose', '--parallel', str(config['budget']['parallelism']),
                        '--project-name', self.project, '-f', str(self.state / 'fleet.compose.json')]
        self.env = dict(os.environ)
        self.stacks, self.consoles, self.store = {}, {}, None
        self.feed = demo.ConsoleFeed(robot_ids=[r['robot_id'] for r in config['robots']])
        self.started = False
        self.guard = lambda: None
        self.dashboard_url = None
        # what the host has, as Docker reports it; read once, before any state is made (design 14.3)
        self.host_capacity = host_capacity
        # One long-lived reader in the collector container; callers queue instead of being refused.
        self.bridge = CollectorBridge(self.compose + ['exec', '-T', 'collector', 'python', '-u', '-c', READER,
                                                      'http://127.0.0.1:8080'], env=self.env)
        self.recovery=Recovery(self)
        # Helpers are mounted read-only from the exact source snapshot, including on agents.
        for row in self.rows:
            self.doc['services'][row['services']['agent']]['volumes'].append(str(Path(row['state']) / 'runtime/reference') + ':/reference:ro')

    def record_start_failure(self, exc):
        """The first cause of a failed start or run, before any cleanup."""
        try:
            (self.state / 'evidence').mkdir(parents=True, exist_ok=True)
            with (self.state / 'evidence' / 'failure.json').open('a') as f:
                f.write(json.dumps({'unix_ms': int(time.time() * 1000), 'kind': type(exc).__name__,
                                    'error': str(exc)}, sort_keys=True) + '\n')
        except OSError:
            pass

    def record_refusal(self, robot_id, path, exc):
        """One line per refused robot operation in evidence/console-refusals.jsonl. Best effort:
        the refusal stands whether or not it could be written."""
        try:
            line = json.dumps({'unix_ms': int(time.time() * 1000), 'robot_id': robot_id, 'path': path,
                               'error': str(exc), 'kind': type(exc).__name__}, sort_keys=True)
            with (self.state / 'evidence' / 'console-refusals.jsonl').open('a') as f:
                f.write(line + '\n')
        except OSError:
            pass

    def run(self, args, label, timeout=180):
        self.guard()
        path = self.state / 'evidence' / (label + '.log')
        with path.open('a') as log:
            p = subprocess.run(self.compose + args, env=self.env, stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
        if p.returncode:
            # rc23 fleet-start-failure-masked / P24-L1: STOP_RECOVERY_REQUIRED used to carry `CalledProcessError` as its
            # first cause; the condition the daemon reported (address pool, port, disk, image) is the cause.
            raise FleetError(failed_step(label, p.returncode, path))

    def setup(self):
        self.guard()
        if self.state.is_symlink() or (self.state.exists() and any(self.state.iterdir())):
            raise FleetError('NEW_FLEET_REQUIRED')
        if demo.ROOT == self.state or demo.ROOT in self.state.parents:
            raise FleetError('STATE_OUTSIDE_SOURCE_REQUIRED')
        validate_topology(self.doc, self.rows, self.image, self.run_id)
        # a fleet the host cannot hold is refused here: no directory, no volume, no container
        self.capacity = capacity_check(self.config, self.host_capacity())
        self.state.mkdir(parents=True, exist_ok=True); self.state.chmod(0o755)
        for name in ('evidence', 'robots'):
            (self.state / name).mkdir()
        (self.state / 'control').mkdir(mode=0o700)
        for row in self.rows:
            base = Path(row['state'])
            for name in ('demo-control', 'evidence', 'runtime', 'runtime/reference', 'runtime/reference/fixtures'):
                (base / name).mkdir(parents=True, exist_ok=True)
                (base / name).chmod(0o755)   # container-readable regardless of the operator's umask (contaminated-host replay, 2026-10-21)
            for path in demo.HERE.glob('*.py'):
                shutil.copyfile(path, base / 'runtime/reference' / path.name)
                (base / 'runtime/reference' / path.name).chmod(0o644)
            for src, dst in ((demo.HERE.parent/'common/diagnostics.py','diagnostics.py'),(demo.HERE.parent/'common/observation.py','observation.py'),(demo.HERE.parent/'common/raw_retention.py','raw_retention.py')):
                shutil.copyfile(src, base/'runtime/reference'/dst)
                (base/'runtime/reference'/dst).chmod(0o644)
            for path in (demo.HERE / 'fixtures/demo').glob('*'):
                shutil.copyfile(path, base / 'runtime/reference/fixtures' / path.name)
                (base / 'runtime/reference/fixtures' / path.name).chmod(0o644)
            stack = RobotStack(self, row)
            self.stacks[row['robot_id']] = stack
            stack.write_control()
        atomic_json(self.state / 'fleet.compose.json', self.doc, 0o644)
        self.meta = {'schema_version': 2, 'run_id': self.run_id, 'project': self.project, 'image': self.image, 'issuer_image': self.issuer_image,
                     'profile': self.config['profile'], 'deployment_id': self.config['deployment_id'],
                     'robots': self.rows, 'hardware_tested': False, 'status': 'PREPARING'}
        self.meta.update(state_root=str(self.state), config=self.config, capacity=self.capacity,
                         service_names=[n for n in self.doc['services'] if n!='prepare'],
                         volume_names=list(self.doc['volumes']), network_names=list(self.doc['networks']),
                         history_db_version=1, created_at_ms=int(time.time()*1000))
        self.lifecycle.initialize(self.meta);self.meta=self.lifecycle.meta
        self.run(['run', '--rm', '--no-deps', 'prepare'], 'prepare')
        if self.config['profile'] == 'software-fleet-mtls':
            self.meta['tls_enrollment'] = json.loads((self.state / 'tls-enrollment.json').read_text())
            self.lifecycle.write()
        self.store = IntentStore(self.state / 'control/intents.sqlite', self.stacks)
        self.pin_files()
        self.meta['identity_pins']=self.identity_probe()
        # Volumes exist after prepare; service/network enrollment happens after start.
        self.meta['managed_volumes']=self.inspect_volumes()
        self.lifecycle.write()

    def inventory(self):
        self.lifecycle.verify_pins(expiry=False)
        ids=subprocess.check_output(['docker','ps','-aq','--filter','label=com.docker.compose.project='+self.project],env=self.env,text=True).split()
        items=json.loads(subprocess.check_output(['docker','inspect',*ids],env=self.env,text=True)) if ids else []
        items=[c for c in items if c['Config'].get('Labels',{}).get('com.docker.compose.service')!='prepare']
        volids=subprocess.check_output(['docker','volume','ls','-q','--filter','label=com.docker.compose.project='+self.project],text=True).split()
        volumes=json.loads(subprocess.check_output(['docker','volume','inspect',*volids],text=True)) if volids else []
        netids=subprocess.check_output(['docker','network','ls','-q','--filter','label=com.docker.compose.project='+self.project],text=True).split()
        nets=json.loads(subprocess.check_output(['docker','network','inspect',*netids],text=True)) if netids else []
        return items,volumes,nets

    def inspect_volumes(self):
        from lifecycle import volume_projection
        ids=subprocess.check_output(['docker','volume','ls','-q','--filter','label=com.docker.compose.project='+self.project],text=True).split()
        values=json.loads(subprocess.check_output(['docker','volume','inspect',*ids],text=True))
        result={}
        for v in values:
            labels=v.get('Labels') or {};key=labels.get('com.docker.compose.volume')
            if key not in self.doc['volumes'] or labels.get('org.pail.run')!=self.run_id:raise FleetError('FOREIGN_VOLUME')
            result[key]=volume_projection(v)
        if set(result)!=set(self.doc['volumes']):raise FleetError('VOLUME_SET_CHANGED')
        return result

    def owned(self, partial=False, enroll=False):
        items,volumes,nets=self.inventory()
        containers,vpins,npins=validate_inventory(self.meta,items,volumes,nets,allow_partial=partial)
        if enroll:
            self.meta.update(managed_containers=containers,managed_volumes=vpins,managed_networks=npins)
            self.lifecycle.write()
        return items

    @staticmethod
    def controller_pins():
        return {folder.name+'/'+p.name:sha(p) for folder in (demo.HERE,demo.HERE.parent/'common')
                for p in folder.glob('*.py')}

    def pin_files(self):
        paths=[self.state/'fleet.compose.json']
        for row in self.rows:
            paths.extend([Path(row['state'])/'public/config',Path(row['state'])/'runtime/reference'])
        # Pin code/data, not user manuals/images or dynamic observation history.
        paths.extend(p for p in demo.HERE.rglob('*') if p.is_file() and p.suffix in ('.py','.yaml','.json','.html') and '__pycache__' not in p.parts)
        paths.extend((demo.HERE.parent/'common').glob('*.py'))
        for svc in self.doc['services'].values():
            for mount in svc.get('volumes',[]):
                if isinstance(mount,str):
                    src=Path(mount.split(':')[0])
                    if src.is_absolute() and src.is_file():paths.append(src)
        self.meta['file_pins']=fingerprint_files(paths)
        self.meta['controller_source']=self.controller_pins()
        self.meta['compose_sha256']=sha(self.state/'fleet.compose.json')
        self.meta['config_digest']=hashlib.sha256(canonical(self.config)).hexdigest()
        self.meta['source_manifest_sha256']=hashlib.sha256(canonical(self.meta['file_pins'])).hexdigest()
        version=demo.ROOT/'VERSION'
        if not version.exists():version=demo.ROOT/'oss/VERSION'
        self.meta['source_release']=version.read_text().strip() if version.exists() else 'unidentified'

    def identity_probe(self):
        self.guard()
        p=subprocess.run(self.compose+['run','--rm','--no-deps','prepare','python','-c',(demo.HERE/'lifecycle_probe.py').read_text()],env=self.env,capture_output=True,text=True,timeout=90)
        if p.returncode:raise FleetError('IDENTITY_PROBE_FAILED')
        return json.loads(p.stdout)

    def reset_idle(self):
        for stack in self.stacks.values():
            file=stack.state/'demo-control/demo.json'
            old=json.loads(file.read_text()) if file.exists() else {}
            value=old.get('instruction',0)
            if type(value)!=int or not 0<=value<9007199254740000:raise FleetError('CONTROL_INSTRUCTION_INVALID')
            stack.control['instruction']=value
            stack.write_control(instruction=True,mode='idle',steps=[],raw={},instruction_epoch=str(uuid.uuid4()))

    def pending_plans(self):
        # Newest accepted plan replaces older accepted plans. Retain ALL more
        # recent UNKNOWN submissions: any one might have reached the issuer.
        pred="(json_extract(response,'$.accepted')=1 OR json_extract(response,'$.execution')='UNKNOWN')"
        self.store.db.execute('CREATE INDEX IF NOT EXISTS intents_active_candidates ON intents(robot_id) WHERE '+pred)
        found=[]
        for rid in self.stacks:
            rows=self.store.db.execute('SELECT plan_id,response FROM intents WHERE robot_id=? AND '+pred+' ORDER BY rowid DESC LIMIT 4097',(rid,))
            count=0
            for plan,response in rows:
                count+=1
                if count>4096:raise FleetError('PLAN_RECONCILIATION_LIMIT')
                found.append((rid,plan))
                if json.loads(response).get('accepted') is True:break
        return found

    def reconcile_plans(self,robot_id=None):
        outcomes=[];deadline=time.monotonic()+30
        for rid,plan in self.pending_plans():
            if robot_id is not None and rid!=robot_id:continue
            stack=self.stacks[rid]
            if time.monotonic()>=deadline:raise FleetError('RECONCILIATION_TIMEOUT')
            result=stack.probe('cancel','--plan',plan,timeout=min(10,deadline-time.monotonic()))
            if not result.get('cancelled'):
                if time.monotonic()>=deadline:raise FleetError('RECONCILIATION_TIMEOUT')
                state=stack.probe('plan_status','--plan',plan,timeout=min(10,deadline-time.monotonic())).get('state')
                if state not in ('COMPLETED','FAILED','CANCELLED','PLAN_STATE_UNSPECIFIED'):raise FleetError('CANCEL_UNKNOWN')
            outcomes.append({'robot_id':rid,'plan_id':plan,'cancelled':result.get('cancelled')})
            self.meta['reconciliation']=outcomes;self.lifecycle.write()
        return outcomes

    def start(self, resume=False):
        self.lifecycle.verify_pins()
        self.meta['intent_db_sha256']=None
        self.lifecycle.transition('STARTING')
        self.reset_idle()
        ready_before={}
        for row in self.rows:
            for role in ('planner','observer','evidence'):
                p=Path(row['state'])/'evidence/runtime'/('demo-'+role+'.jsonl')
                ready_before[(row['robot_id'],role)]=p.stat().st_size if p.exists() else 0
        bases = ['issuer'] + [r['services'][role] for r in self.rows for role in ('agent', 'fake', 'state-seam')]
        self.started = True  # Partial startup is owned and must also be stopped on failure.
        self.run((['start',*bases] if resume else ['up','-d','--no-build','--pull','never',*bases]),'up',timeout=240)
        for row in self.rows:
            stack = self.stacks[row['robot_id']]
            stack.wait_exec(row['services']['agent'], "import socket; s=socket.create_connection(('127.0.0.1',50051),2); s.close()", 'agent listener', timeout=30)
            stack.wait_exec(row['services']['fake'], "import os,sys; sys.exit(0 if os.path.exists('/run/duck/raw/robotd.sock') else 1)", 'fake socket', timeout=30)
            stack.wait_exec(row['services']['state-seam'], "import os,sys; sys.exit(0 if os.path.exists('/run/duck/raw/state-seam.sock') else 1)", 'state seam', timeout=30)
        if self.config['profile'] == 'software-fleet-mtls':
            for stack in self.stacks.values():
                if stack.probe('status').get('issuer') != 'OK':
                    raise FleetError('AGENT_MTLS_NOT_READY')
        if resume:
            self.reconcile_plans()  # Actors stay stopped until prior authority is reconciled.
        adapter_services=[r['services']['adapter'] for r in self.rows]
        self.run((['start',*adapter_services] if resume else ['up','-d','--no-build','--pull','never',*adapter_services]),'up-adapters')
        for row in self.rows:
            stack = self.stacks[row['robot_id']]
            stack.wait_exec(row['services']['adapter'], "import os,sys; sys.exit(0 if os.path.exists('/run/duck/pail.sock') else 1)", 'adapter socket', timeout=30)
        actors = ['ledger', 'collector'] + [r['services'][role] for r in self.rows for role in ('demo-planner', 'demo-observer', 'demo-evidence')]
        self.run((['start',*actors] if resume else ['up','-d','--no-build','--pull','never',*actors]),'up-actors')
        owned = self.owned(enroll=not resume)
        atomic_json(self.state / 'evidence/owned.json', {'run_id': self.run_id, 'containers': [x['Id'] for x in owned]}, 0o644)
        deadline = time.monotonic() + 90
        for row in self.rows:
            stack = self.stacks[row['robot_id']]
            while time.monotonic() < deadline:
                fresh={role:demo.read_rows(stack.logs/'runtime'/('demo-'+role+'.jsonl'),ready_before[(row['robot_id'],role)])
                       for role in ('planner','observer','evidence')}
                if all(any(r.get('event') == event and r.get('robot_id') == row['robot_id']
                           and r.get('run_id') == self.run_id for r in fresh[role])
                       for role in fresh for event in ('ready','connected')):
                    break
                time.sleep(.25)
            else:
                raise FleetError('ACTOR_READINESS_TIMEOUT')
            self.meta.setdefault('actor_generations',{})[row['robot_id']]={role:
                [r['producer_instance_id'] for r in demo.read_rows(stack.logs/'runtime'/('demo-'+role+'.jsonl'),ready_before[(row['robot_id'],role)])
                 if r.get('event')=='ready' and r.get('producer_instance_id')][-1]
                for role in ('planner','observer','evidence')}
            self.consoles[row['robot_id']] = RobotConsole(stack, self.feed)
        self.lifecycle.transition('READY_IDLE')
        self.accepting=True
        self.recovery.start()

    def command(self, request, automatic=False, recovery_request_id=None):
        self.guard();self.owned()
        rid,reqid,text,digest=self.store.validate_request(request)
        prior=self.store.lookup(request)
        if prior is not None:return prior
        parsed=demo.parse(text);stop=bool(parsed.get('stop'))
        if self.recovery.paused(rid) and not stop:
            return {'accepted':False,'execution':'PAUSED','robot_id':rid,'resume_requirement':'OPERATOR_CONFIRMATION'}
        with self.admission:
            if not self.accepting:raise FleetError('COMMAND_ADMISSION_CLOSED')
            self.lifecycle.transition('RUNNING_DEMO')
            self.inflight+=1
        try:
            def dispatch(rid,text,plan):
                console,stack=self.consoles[rid],self.stacks[rid]
                with console.command_lock:
                    with self.recovery.mu:
                        intent=self.recovery.rows[rid]
                        if intent['paused'] and not stop:
                            return {'accepted':False,'execution':'PAUSED','resume_requirement':'OPERATOR_CONFIRMATION'}
                        if automatic and (intent['intent']!='CONTINUE_REQUESTED' or intent['request_id']!=recovery_request_id):
                            return {'accepted':False,'execution':'READY_IDLE','error':'INTENT_CHANGED'}
                        if 'error' not in parsed:self.recovery.request(rid,request,stop,automatic)
                    stack.pending.plan=plan
                    try:return console.command(text)
                    except ProbeError as ex:
                        self.recovery.fail(rid,'TRANSPORT',ex.diagnostic);raise
                    finally:stack.pending.plan=None
            result=self.store.execute(request,dispatch)
            if result.get('execution')=='UNKNOWN' and not self.recovery.paused(rid):self.recovery.fail(rid,'TRANSPORT',transport(basis='command_result_unknown'))
            self.recovery.result(rid,result,request_id=reqid)
            return result
        finally:
            with self.admission:self.inflight-=1;self.admission.notify_all()

    def robot_action(self, rid, action, request):
        """One action of a robot's console page, on that robot. A command is not an action: it
        goes through command(), with its request id."""
        self.guard();self.owned()
        if action not in ROBOT_ACTIONS:raise FleetError('ACTION_UNKNOWN')
        if rid not in self.consoles:raise FleetError('TARGET_UNKNOWN')
        if not isinstance(request,dict):raise FleetError('REQUEST_FORM')
        with self.admission:
            if not self.accepting:raise FleetError('COMMAND_ADMISSION_CLOSED')
            self.inflight+=1
        try:
            console=self.consoles[rid]
            with console.command_lock:
                # what would make the robot try to move is not sent while it waits for the operator
                if action in ('rogue','raw') and self.recovery.paused(rid):
                    return {'ok':False,'execution':'PAUSED','robot_id':rid,'resume_requirement':'OPERATOR_CONFIRMATION'}
                if action=='rogue':return console.rogue(request.get('linear'))
                if action=='raw':return console.raw(float(request['linear']),float(request.get('angular',0)),float(request['duration']))
                if action=='inputs':return console.feed(request.get('tag'),request.get('safety'))
                if action=='fault':return console.fault(str(request.get('service','agent')),str(request.get('action','')))
                if action=='unlock':return console.unlock()
                if action=='verify':return console.verify()
                return console.restart_robot()
        finally:
            with self.admission:self.inflight-=1;self.admission.notify_all()

    def summary(self):
        """The summary state of every robot, as the collector judged it. Read, never computed here."""
        ids=[r['robot_id'] for r in self.config['robots']]
        status,_,body=self.read_collector('/v2/observation/robots?limit=200')
        if status!=200:raise FleetError('COLLECTOR_UNAVAILABLE')
        doc=json.loads(body)
        if doc.get('document_kind')!='RobotObservationSnapshot' or not isinstance(doc.get('robots'),list):raise FleetError('COLLECTOR_ANSWER')
        out={}
        for row in doc['robots']:
            rid=(row.get('robot_key') or {}).get('robot_id');s=row.get('summary')
            if rid in ids and isinstance(s,dict) and isinstance(s.get('state'),str):
                out[rid]={'state':s['state'],'reason':s.get('reason'),'decided_by_rule':s.get('decided_by_rule'),'physical_stop_proven':False}
        return {'robots':out,'as_of_ms':doc.get('as_of_ms'),'source':'collector'}

    def robot_state(self, rid):
        ids=[r['robot_id'] for r in self.config['robots']]
        if rid not in ids:raise FleetError('TARGET_UNKNOWN')
        if rid not in self.consoles:raise FleetError('ROBOT_NOT_READY')
        state=self.consoles[rid].state()
        state.update(dashboard_url=self.dashboard_url,fleet={'robots':ids,'index':ids.index(rid)+1,'count':len(ids),
            'profile':self.config['profile'],'list_url':'/','hardware_tested':False})
        return state

    def confirm_recovery(self,request):
        from fleet import fields
        fields(request,('robot_id','confirmation'))
        with self.admission:
            if not self.accepting:raise FleetError('COMMAND_ADMISSION_CLOSED')
            self.inflight+=1
        try:
            self.owned()
            return self.recovery.confirm(request['robot_id'],request['confirmation'])
        finally:
            with self.admission:self.inflight-=1;self.admission.notify_all()

    def recovery_inventory(self):
        # Read only the already pinned container IDs, never discover/manage foreign resources.
        ids=[entry['id'] for entry in self.meta.get('managed_containers',{}).values()]
        if not ids:return []
        result=subprocess.run(['docker','inspect',*ids],capture_output=True,text=True,timeout=5)
        if result.returncode:raise FleetError('RECOVERY_INVENTORY_UNAVAILABLE')
        rows=[]
        for item in json.loads(result.stdout):
            labels=item['Config'].get('Labels',{})
            if labels.get('org.pail.run')!=self.run_id:raise FleetError('RECOVERY_INVENTORY_IDENTITY')
            rid=labels.get('org.pail.robot');role=labels.get('org.pail.role')
            if rid in self.stacks and role in ('agent','adapter','demo-observer'):
                state=item['State'];rows.append({'robot_id':rid,'role':role,'started_at':state.get('StartedAt'),
                    'running':state['Running'],'oom_killed':state.get('OOMKilled',False)})
        return rows

    def reinitialize_clock_component(self,rid):
        # Software fleet only, after explicit reconciliation. No clock-setting command.
        if self.config['profile'] not in ('software-dev','software-fleet-mtls'):raise FleetError('HARDWARE_AUTO_RESTART_FORBIDDEN')
        stack=self.stacks[rid];name=stack.row['services']['adapter']
        with self.consoles[rid].command_lock:
            stack.write_control(instruction=True,mode='idle',steps=[],raw={})
            since=time.time();deadline=time.monotonic()+5
            while time.monotonic()<deadline:
                pose=self.consoles[rid].pose
                if pose and pose.get('t',0)>=since and abs(pose.get('v',1))<.005 and abs(pose.get('w',1))<.01:break
                time.sleep(.1)
            else:raise FleetError('ZERO_OBSERVATION_UNCONFIRMED')
            self.owned()
            if self.recovery.closed.is_set():raise FleetError('SERVICE_STOPPING')
            self.run(['stop',name],'clock-stop-'+stack.row['key'],timeout=15)
            if self.recovery.closed.is_set():raise FleetError('SERVICE_STOPPING')
            self.run(['start',name],'clock-start-'+stack.row['key'],timeout=15)
            stack.wait_exec(name,"import os,sys; sys.exit(0 if os.path.exists('/run/duck/pail.sock') else 1)",'adapter after clock reset',timeout=10)
            if self.recovery.closed.is_set():raise FleetError('SERVICE_STOPPING')
            self.consoles[rid].emit('component_reinitialized',component='adapter',reason='operator_clock_recovery',new_motion_started=False)

    def read_collector(self, path):
        validate_read_path(path)
        # The collector keeps its loopback bind and never receives Docker access.
        # This operator-side bridge has a fixed destination and GET-only surface.
        return self.bridge.read(path)

    def stop_services(self):
        with self.stop_lock:
            if self.meta.get('lifecycle_state')=='STOPPED':
                if not any(c['State']['Running'] for c in self.owned()):return
                self.lifecycle.transition('RECOVERY_REQUIRED',reason='STOPPED_STATE_DISAGREES')
            self.owned(partial=not bool(self.meta.get('managed_containers')))
            errors=[]
            with self.admission:
                self.accepting=False
                self.meta['last_operation_id']=str(uuid.uuid4())
                self.lifecycle.transition('STOP_REQUESTED')
                if not self.admission.wait_for(lambda:self.inflight==0,timeout=30):errors.append('INFLIGHT_UNKNOWN')
            try:
                self.recovery.close()
                self.reset_idle()
                if not errors:self.reconcile_plans()
                # Fresh observer evidence of fake applied zero; never physical-stop proof.
                since=time.time();deadline=time.monotonic()+5
                while time.monotonic()<deadline:
                    if self.consoles and all(c.pose and c.pose.get('t',0)>=since and abs(c.pose.get('v',1))<.005 and abs(c.pose.get('w',1))<.01 for c in self.consoles.values()):break
                    time.sleep(.1)
                else:errors.append('ZERO_OBSERVATION_UNCONFIRMED')
            except Exception as e:errors.append(str(e))
            self.lifecycle.transition('STOPPING',errors=errors)
            for c in self.consoles.values():c.close()
            self.consoles={}
            try:
                self.owned(partial=not bool(self.meta.get('managed_containers')))
                self.run(['stop',*self.meta['service_names']],'stop')
                items=self.owned(partial=not bool(self.meta.get('managed_containers')))
                if any(c['State']['Running'] for c in items):errors.append('SERVICES_STILL_RUNNING')
                elif self.identity_probe()!=self.meta['identity_pins']:errors.append('IDENTITY_CHANGED')
            except Exception as e:errors.append(str(e))
            self.started=False
            self.store.db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            self.meta['intent_db_sha256']=sha(self.state/'control/intents.sqlite') if not errors else None
            self.lifecycle.transition('RECOVERY_REQUIRED' if errors else 'STOPPED',errors=errors,physical_stop_proven=False)
            if errors:raise FleetError('STOP_RECOVERY_REQUIRED: '+','.join(errors))

    @classmethod
    def load_existing(cls,state):
        life=Lifecycle(state);life.acquire(create=False)
        runner=None
        try:
            meta=life.read();life.verify_pins(expiry=False)
            if cls.controller_pins()!=meta['controller_source']:raise FleetError('CONTROLLER_SOURCE_CHANGED')
            # a run recorded under the removed `legacy` contract is not revived
            runner=cls(meta['config'],state,meta['image'],project=meta['project'],issuer_image=meta.get('issuer_image'),contract=meta.get('contract'),stored_cohort=True)
            runner.lifecycle=life;runner.meta=life.meta;runner.run_id=meta['run_id']
            runner.recovery.restore(meta.get('recovery'))
            runner.doc=json.loads((runner.state/'fleet.compose.json').read_text());runner.rows=meta['robots']
            validate_topology(runner.doc,runner.rows,runner.image,runner.run_id)
            runner.stacks={r['robot_id']:RobotStack(runner,r) for r in runner.rows}
            dbpath=runner.state/'control/intents.sqlite'
            if not dbpath.is_file() or dbpath.is_symlink():raise FleetError('INTENT_HISTORY_MISSING')
            if meta['lifecycle_state']=='STOPPED' and sha(dbpath)!=meta.get('intent_db_sha256'):raise FleetError('INTENT_HISTORY_CHANGED')
            runner.store=IntentStore(dbpath,runner.stacks,existing=True)
            items=runner.owned()
            if not any(c['State']['Running'] for c in items):
                if runner.identity_probe()!=meta['identity_pins']:raise FleetError('IDENTITY_CHANGED')
            return runner
        except Exception:
            if runner and runner.store:runner.store.close()
            life.release();raise

    @classmethod
    def restore(cls,state,recover=False):
        return cls.load_existing(state).resume(recover)

    def resume(self,recover=False):
        runner=self;life=runner.lifecycle;meta=runner.meta
        try:
            life.verify_pins()
            if meta['lifecycle_state']!='STOPPED' and not recover:raise FleetError('RECOVERY_REQUIRED: explicit recover needed')
            items=runner.owned()
            if recover:
                life.transition('RECOVERY_REQUIRED',reason='INTERRUPTED_RECOVERY')
                runner.reset_idle()
                runner.run(['stop',*meta['service_names']],'recover-stop')
                if any(c['State']['Running'] for c in runner.owned()):raise FleetError('SERVICES_STILL_RUNNING')
                if runner.identity_probe()!=meta['identity_pins']:raise FleetError('IDENTITY_CHANGED')
            elif any(c['State']['Running'] for c in items):raise FleetError('STOPPED_STATE_DISAGREES')
            meta['controller_instance_id']=str(uuid.uuid4());meta['last_operation_id']=str(uuid.uuid4())
            life.transition('RESUME_CHECK',explicit_recovery=recover)
            runner.start(resume=True)
            return runner
        except Exception:
            # Partial start is not a stopped fleet. Preserve the explicit recovery state.
            if runner.started:
                try:runner.stop_services()
                except Exception:pass
            if runner.store:runner.store.close();runner.store=None
            for c in runner.consoles.values():c.close()
            atomic_json(life.control/'last-refusal.json',{'error':'RESUME_REFUSED','operation':'recover' if recover else 'resume'})
            life.release();raise

    def close(self):
        if self.resources_closed:return
        try:
            if self.started:self.stop_services()
        finally:
            for c in self.consoles.values():c.close()
            if self.store:self.store.close();self.store=None
            self.recovery.close()
            self.lifecycle.release();self.resources_closed=True


def host_capacity():
    """(cpus, memory_bytes) of the Docker host, or None when Docker does not say."""
    try:
        p = subprocess.run(['docker', 'info', '--format', '{{.NCPU}} {{.MemTotal}}'], capture_output=True, text=True, timeout=30)
        cpus, memory = p.stdout.split()
        return (int(cpus), int(memory)) if p.returncode == 0 else None
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def robot_route(path, robots):
    """'/robot/<id>/<rest>' -> (id, '/<rest>'), for a robot of the fleet configuration only.
    The path is taken as it was sent and never decoded or resolved: the segment after
    '/robot/' is a robot id of the configuration or it is nothing, and what follows is
    matched against the fixed names of the API as it stands."""
    if not path.startswith('/robot/'):
        return None
    rid, slash, rest = path[len('/robot/'):].partition('/')
    if rid not in robots or not slash:
        raise FleetError('ROBOT_UNKNOWN')
    return rid, '/' + rest


def handler_for(fleet):
    page = (demo.HERE / 'fleet_ui.html').read_bytes()
    # One page file: the console of a robot in a fleet is the single-robot console page.
    robot_page = (demo.HERE / 'demo_ui.html').read_bytes()
    robots = tuple(r['robot_id'] for r in fleet.config['robots'])

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def robot_get(self, rid, path, query):
            if path in ('/', '/index.html'):
                return self.send(200, robot_page)
            if path == '/api/state':
                try:
                    return self.send(200, fleet.robot_state(rid))
                except FleetError as exc:
                    return self.send(503, {'error': str(exc)})
            console = fleet.consoles.get(rid)
            if console is None:
                return self.send(503, {'error': 'ROBOT_NOT_READY'})
            self.path = path + ('?' + query if query else '')
            if demo.handle_observation(self, console.events.own, console.runtime.history):
                return
            return self.send(404, {'error': 'NOT_FOUND'})

        def robot_post(self, rid, path, req):
            if not isinstance(req, dict):
                raise FleetError('REQUEST_FORM')
            # the robot is the one of the path; a body that names another is refused, not corrected
            if 'robot_id' in req and req['robot_id'] != rid:
                return self.send(400, {'error': 'ROBOT_ID_MISMATCH'})
            if path == '/api/command':
                return self.send(200, fleet.command({'robot_id': rid, 'request_id': req.get('request_id'), 'text': req.get('text')}))
            if path == '/api/recovery':
                return self.send(200, fleet.confirm_recovery({'robot_id': rid, 'confirmation': req.get('confirmation')}))
            action = path[len('/api/'):] if path.startswith('/api/') else ''
            if action not in ROBOT_ACTIONS:
                return self.send(404, {'error': 'NOT_FOUND'})
            return self.send(200, fleet.robot_action(rid, action, req))

        def send(self, status, value):
            body = value if isinstance(value, bytes) else json.dumps(value, allow_nan=False).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'text/html; charset=utf-8' if isinstance(value, bytes) else 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers(); self.wfile.write(body)

        def do_GET(self):
            parsed = urllib.parse.urlsplit(self.path)
            try:
                route = robot_route(parsed.path, robots)
            except FleetError as exc:
                return self.send(404, {'error': str(exc)})
            if route:
                return self.robot_get(route[0], route[1], parsed.query)
            # the list page may carry the language of the reader in its address (?lang=)
            if parsed.path == '/':
                return self.send(200, page)
            if self.path == '/api/summary':
                try:
                    return self.send(200, fleet.summary())
                except (ValueError, subprocess.TimeoutExpired):
                    return self.send(503, {'error': 'COLLECTOR_UNAVAILABLE'})
            if self.path == '/api/state':
                return self.send(200, {'robots': [c.state() for c in fleet.consoles.values()], 'profile': fleet.config['profile'], 'hardware_tested': False, 'dashboard_url': fleet.dashboard_url})
            if self.path.startswith(('/api/v2/events', '/api/v2/snapshot')) and demo.handle_observation(self, fleet.feed, None):
                return
            self.send(404, {'error': 'NOT_FOUND'})

        def do_POST(self):
            if self.headers.get('Origin') not in (None, 'http://127.0.0.1:%d' % self.server.server_address[1], 'http://localhost:%d' % self.server.server_address[1]):
                return self.send(403, {'error': 'ORIGIN'})
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 8192:
                    return self.send(413, {'error': 'REQUEST_SIZE'})
                self.connection.settimeout(5)
                req = json.loads(self.rfile.read(length))
                try:
                    route = robot_route(urllib.parse.urlsplit(self.path).path, robots)
                except FleetError as exc:
                    return self.send(404, {'error': str(exc)})
                if route:
                    if urllib.parse.urlsplit(self.path).query:
                        return self.send(400, {'error': 'QUERY_NOT_ALLOWED'})
                    try:
                        return self.robot_post(route[0], route[1], req)
                    except (FleetError, RuntimeError, subprocess.TimeoutExpired, TypeError) as exc:
                        # as the single-robot console answers: the page shows the reason, and
                        # the refusal is kept (a 400 used to leave no trace anywhere)
                        console = fleet.consoles.get(route[0])
                        if console is not None:
                            console.emit('console_error', path=route[1], detail=str(exc))
                        record = getattr(fleet, 'record_refusal', None)
                        if record is not None:
                            record(route[0], route[1], exc)
                        return self.send(400, {'error': str(exc)})
                if self.path=='/api/recovery':
                    return self.send(200,fleet.confirm_recovery(req))
                if self.path != '/api/command':
                    return self.send(404, {'error': 'NOT_FOUND'})
                return self.send(200, fleet.command(req))
            except (ValueError, KeyError, OSError) as exc:
                return self.send(400, {'error': str(exc)})
    return Handler


def validate_read_path(path):
    parsed = urllib.parse.urlsplit(path)
    decoded = urllib.parse.unquote(parsed.path)
    if (len(path) > 4096 or parsed.scheme or parsed.netloc or parsed.fragment
            or '..' in decoded.split('/') or any(ord(c) < 32 for c in decoded)
            or not (parsed.path.startswith(('/dashboard/', '/v1/ledger/', '/v1/telemetry/', '/v2/observation/')) or parsed.path == '/healthz')):
        raise FleetError('READ_PATH')


def dashboard_handler(fleet):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            try:
                status, mime, body = fleet.read_collector(self.path)
            except (ValueError, subprocess.TimeoutExpired):
                status, mime, body = 503, 'text/plain', b'COLLECTOR_UNAVAILABLE'
            self.send_response(status)
            self.send_header('Content-Type', mime)
            if status == 429:
                self.send_header('Retry-After', '1')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers(); self.wfile.write(body)
    return Handler


def run_servers(fleet,args,start_new=False,resuming=False):
    from lifecycle import serve_control
    import signal
    def stop_on_term(signum,frame):
        # The single-robot demo already does this. A fleet runner that only knew Ctrl-C was killed by SIGTERM
        # without its teardown and left all 17 containers running (measured 2026-10-09 on the build VM:
        # `kill -TERM` of a nohup'd fleet, the same signal the evaluation launcher escalates to after its
        # 90 s SIGINT grace). SIGTERM is now the same clean stop as Ctrl-C.
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM,stop_on_term)
    server=None;dashboard=None;control=None;dashboard_started=False;primary=None
    try:
        server=demo.Server(('127.0.0.1',args.port),handler_for(fleet))
        if not args.no_dashboard:
            dashboard=demo.Server(('127.0.0.1',args.dashboard_port),dashboard_handler(fleet))
            fleet.dashboard_url='http://127.0.0.1:%d/dashboard/?tab=fleet'%dashboard.server_address[1]
        if start_new:fleet.setup();fleet.start()
        if resuming:fleet.resume(recover=args.action=='recover')
        control=serve_control(fleet,server.shutdown)
        if dashboard:
            threading.Thread(target=dashboard.serve_forever,daemon=True).start();dashboard_started=True
        print('FLEET_CONSOLE=http://127.0.0.1:%d/'%server.server_address[1],flush=True)
        if dashboard:print('DASHBOARD='+fleet.dashboard_url,flush=True)
        server.serve_forever()
    except KeyboardInterrupt:pass
    except BaseException as ex:
        # The cleanup below stops the services, and a stop that cannot
        # confirm zero raises its own STOP_RECOVERY_REQUIRED, which replaced this exception.
        # Keep the first cause: on the terminal now, in evidence, and in the final error.
        primary=ex
        fleet.record_start_failure(ex)
        print('FLEET_FAILED: %s: %s'%(type(ex).__name__,ex),file=sys.stderr,flush=True)
        raise
    finally:
        fleet.bridge.close()  # the reader ends with the collector container; do not leave it to chance
        if server:server.server_close()
        if dashboard:
            if dashboard_started:dashboard.shutdown()
            dashboard.server_close()
        if control:control.shutdown();control.server_close()
        try:
            fleet.close()
        except FleetError as cleanup:
            if primary is None:raise
            raise FleetError('%s (first cause: %s: %s)'%(cleanup,type(primary).__name__,primary)) from primary
    return 0


def adopt(state,config):
    """0.2.0-preview.40: adoption existed for fleets started before the contract was recorded (the removed `legacy`
    cohort). Such a fleet is not revived under the single contract — clean it with this release's `cleanup` (or stop it
    with the release that made it)."""
    raise FleetError('LEGACY_RUN_UNSUPPORTED: this fleet predates the single contract; clean it with this release\'s `cleanup --state <dir>` (stopping it with the release that created it also works), then start a new fleet')


def manage(args):
    from lifecycle import inspect,request_stop
    if args.action in ('status','inspect'):
        print(json.dumps(inspect(args.state)));return 0
    if args.action=='adopt':
        if not args.fleet or not args.confirm_stopped:raise FleetError('ADOPTION_REQUIRES_CONFIG_AND_STOP_CONFIRMATION')
        adopt(args.state,load_config(args.fleet));print(json.dumps(inspect(args.state)));return 0
    if args.action=='stop':
        result=request_stop(args.state)
        if result is not None:print(json.dumps(result));return 0
        fleet=FleetRunner.load_existing(args.state)
        try:
            if fleet.meta['lifecycle_state']!='STOPPED' or any(c['State']['Running'] for c in fleet.owned()):
                fleet.started=True
                fleet.consoles={rid:RobotConsole(stack,fleet.feed) for rid,stack in fleet.stacks.items()}
                fleet.stop_services()
            print(json.dumps({'status':fleet.meta['lifecycle_state']}));return 0
        finally:fleet.close()
    fleet=FleetRunner.load_existing(args.state)
    return run_servers(fleet,args,resuming=True)


def main(args):
    demo.preview.require_issuer()
    if args.fleet:config=load_config(args.fleet)
    else:
        from fleet import validate_config
        config=validate_config({'schema_version':1,'deployment_id':str(uuid.uuid4()),'profile':'software-dev',
            'robots':[{'robot_id':args.robot_id,'display_name':args.robot_id}],
            'budget':{'cpus':2,'memory_mib':3072,'parallelism':2}})
    if os.environ.get('PAIL_ROBOT_ID') and (len(config['robots'])!=1 or os.environ['PAIL_ROBOT_ID']!=config['robots'][0]['robot_id']):
        raise FleetError('CONFIG_ENV_ROBOT_ID_CONFLICT')
    for line in notices(config):
        print('NOTICE ' + line, file=sys.stderr, flush=True)
    image=subprocess.check_output(['docker','image','inspect',args.image,'--format','{{.Id}}'],text=True).strip()
    return run_servers(FleetRunner(config,args.state,image,issuer_image=demo.preview.require_issuer(),),args,start_new=True)
