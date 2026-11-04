#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Live TB3 demo console — tell the robot what to do and watch PAIL decide (no hardware).

  python3 examples/tb3/demo.py up [--state /new/dir] [--port 8765]
  python3 examples/tb3/demo.py up --skip-build --cloud-image TAG --gate-image TAG

Starts the same stack as run.py (real issuer, real gate, real motion bridge, generated
keys) plus a simulated base, then serves a console on http://127.0.0.1:<port>/ only.
Type "forward 1 m" (or "앞으로 1m"): the console turns it into a twist plan and asks the
issuer. Within the policy limits the gate permits it and the simulated base moves;
above them the issuer refuses the plan, nothing moves, and the console shows which
limit was exceeded. Ctrl-C stops the stack. Positions are a simulation of the gated
command, not a robot measurement.
"""
import argparse, hashlib, http.server, json, math, os, re, shutil, signal, socket, socketserver, subprocess, sys, tempfile, threading, time, urllib.parse, uuid
from pathlib import Path
import sqlite3

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE.parent / 'common'))
from console_feed import ConsoleFeed, RuntimeTail, handle_observation, FutureObservations, current_observation, record_observed_move, derive_step_observation
from eventlog import EventLogError
from diagnostics import ClockWatch
from build_runtime import BuildRequired, select_prepared
from resource_budget import BoundedServer
from compose_failure import failed_step  # P24-L1: a failed compose step names the daemon's condition on the DEMO_REFUSED line
from run_names import project_name, release_id  # preview.40 review item 01: pail-<kind>-<release>-<run>
ROLES = [('planner', 'oem_planner'), ('base', 'driver'), ('safety', 'safety_adapter'), ('evidence', 'perception')]

# Demo policy: one call may move at most 0.1 m/s × 15 s = 1.5 m, or turn 0.5 rad/s × 15 s.
LIMITS = {'sls.linear_mps': 0.1, 'sls.angular_rps': 0.5, 'step.max_duration_s': 15.0}
CRUISE = {'linear': 0.1, 'angular': 0.5}
CLOCK_STEP_S = 0.25  # observation tolerance only; the gate's own drift limit is unchanged
UNITS = {'sls.linear_mps': 'm/s', 'sls.angular_rps': 'rad/s', 'step.max_duration_s': 's'}


# ---------------------------------------------------------------------------------------
# Command language (rule based; the console plays the AI requester, PAIL does not trust it)
# ---------------------------------------------------------------------------------------
NUM = r'(?<![\d.])(-?(?:\d+(?:\.\d+)?|\.\d+))'
SPEED = re.compile(NUM + r'\s*(?:m/s|mps|㎧)')
DIST = re.compile(NUM + r'\s*(cm|centimet(?:er|re)s?|센티|m\b|meters?|metres?|미터|m(?=\s|$|로|으로|,))')
ANGLE = re.compile(NUM + r'\s*(?:°|deg(?:rees?)?|도)')
WORDS = {
    'forward': ['forward', 'ahead', 'front', '앞으로', '앞', '전진'],
    'back': ['backward', 'backwards', 'back', 'reverse', '뒤로', '뒤', '후진'],
    'left': ['left', '왼쪽', '좌'],
    'right': ['right', '오른쪽', '우'],
    'stop': ['stop', 'halt', '정지', '멈춰', '멈춤'],
}


def has(text, key):
    return any(w in text for w in WORDS[key])


def parse(text):
    """Return {'steps': [...], 'explain': [...]} or {'error': ...}. Speeds default to cruise."""
    t = text.strip().lower()
    if not t:
        return {'error': 'empty command'}
    if has(t, 'stop'):
        return {'stop': True, 'steps': [], 'explain': ['stop']}
    sm = SPEED.search(t)
    speed = abs(float(sm.group(1))) if sm else CRUISE['linear']
    t_wo_speed = SPEED.sub(' ', t)
    dm, am = DIST.search(t_wo_speed), ANGLE.search(t_wo_speed)
    steps, explain = [], []

    def turn(deg, direction):
        w = CRUISE['angular'] * (1 if direction == 'left' else -1)
        rad = math.radians(abs(deg))
        d = round(rad / CRUISE['angular'], 2)
        steps.append({'linear': 0.0, 'angular': w, 'duration': d})
        explain.append('turn %s %g° = %.2f rad/s × %.2f s' % (direction, abs(deg), abs(w), d))

    def move(meters, direction):
        v = speed * (1 if direction == 'forward' else -1)
        if speed == 0:
            return 'speed must be greater than 0'
        d = round(abs(meters) / speed, 2)
        steps.append({'linear': v, 'angular': 0.0, 'duration': d})
        explain.append('%s %g m = %.2f m/s × %.2f s' % (direction, abs(meters), speed, d))

    meters = None
    if dm:
        meters = float(dm.group(1)) / (100.0 if dm.group(2).startswith(('cm', 'cent', '센티')) else 1.0)
    side = 'left' if has(t, 'left') else 'right' if has(t, 'right') else None
    if am and side:
        turn(float(am.group(1)), side)
        if meters is not None:
            move(meters, 'forward')
    elif side and meters is not None:
        turn(90, side)          # a differential-drive base cannot move sideways
        move(meters, 'forward')
    elif meters is not None and (has(t, 'forward') or has(t, 'back')):
        err = move(meters, 'back' if has(t, 'back') else 'forward')
        if err:
            return {'error': err}
    else:
        return {'error': 'not understood — try "forward 1 m", "back 0.5 m", "left 90 deg", "left 1 m", "forward 1 m at 0.3 m/s"'}
    return {'steps': steps, 'explain': explain}


# ---------------------------------------------------------------------------------------
# Stack
# ---------------------------------------------------------------------------------------
class IssuerTransportError(RuntimeError):
    """Transport failure: retryable for readiness, ambiguous for plan submission."""


def contract_compose_files(here, env):
    """Compose files of the stack. There is one communication contract (0.2.0-preview.40) and no setting that selects
    it: a PAIL_CORE_COMM_CONTRACT variable present at all in the ambient environment — any value, an empty one included
    (0.2.0-preview.41, P40-L2) — is refused by name before anything starts (the same message as internal/corecomm and
    core_operation_wire.py); nothing is exported to the services."""
    if 'PAIL_CORE_COMM_CONTRACT' in env:
        raise SystemExit('CORE_COMM_CONTRACT_SETTING_REMOVED: PAIL_CORE_COMM_CONTRACT has no meaning (there is one communication contract); unset it')
    return [here / 'compose.yaml']


class Stack:
    def __init__(self, state, cloud, gate, project):
        self.state, self.cloud, self.gate, self.project = state, cloud, gate, project
        self.env = dict(os.environ, PAIL_TB3_STATE=str(state), PAIL_TB3_CLOUD_IMAGE=cloud, PAIL_TB3_GATE_IMAGE=gate)
        files = contract_compose_files(HERE, self.env)
        self.compose = ['docker', 'compose', '--parallel', '2', '-p', project] + [x for f in files for x in ('-f', str(f))]
        self.logs = state / 'evidence'
        self.seq = 0
        self.control = {'seq': 0, 'instruction': 0, 'mode': 'idle', 'steps': [], 'tag': 'sample-box', 'safety': 'OK'}
        self.lock = threading.Lock()

    def run(self, args, name, timeout=1800, check=True):
        with (self.logs / (name + '.log')).open('w') as f:
            p = subprocess.run(args, cwd=ROOT, env=self.env, stdout=f, stderr=subprocess.STDOUT, timeout=timeout)
        body = (self.logs / (name + '.log')).read_text()
        if check and p.returncode:
            raise RuntimeError(failed_step(name, p.returncode, self.logs / (name + '.log')))
        return body

    def write_control(self, instruction=False, **changes):
        """instruction=True when the planner's task changes; feed switches leave a running plan alone."""
        with self.lock:
            self.seq += 1
            self.control = dict(self.control, **changes, seq=self.seq)
            if instruction:
                self.control['instruction'] = self.control.get('instruction', 0) + 1
            tmp = self.state / 'control' / 'demo.next'
            with tmp.open('w') as f:
                f.write(json.dumps(self.control)); f.flush(); os.fsync(f.fileno())
            tmp.chmod(0o644)
            tmp.replace(self.state / 'control' / 'demo.json')
            return dict(self.control)

    def exec_issuer(self, *args, timeout=30):
        p = subprocess.run(self.compose + ['exec', '-T', 'issuer', *args], cwd=ROOT, env=self.env,
                           capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr

    def probe(self, *args):
        rc, out, err = self.exec_issuer('tb3-probe', *args, timeout=45)
        if rc:
            detail = (err or out).strip()[-400:]
            if any(x in detail for x in ('Unavailable', 'DeadlineExceeded', 'i/o timeout', 'context deadline exceeded')):
                raise IssuerTransportError('ISSUER_UNREACHABLE_OR_OUTCOME_UNKNOWN: check the current plan before retrying; ' + detail)
            raise RuntimeError('tb3-probe rc=%d: %s' % (rc, detail))
        return json.loads(out.strip().splitlines()[-1])

    def setup(self, build):
        e, cfg = self.logs, self.state / 'runtime/config'
        tool = HERE / 'permissions.py'
        subprocess.run([sys.executable, '-B', str(tool), 'init', '--state', str(self.state)], check=True)
        (e / 'runtime').mkdir(exist_ok=True)
        if build:raise BuildRequired('BUILD_REQUIRED: use explicit demo.py build before creating runtime state')
        for f in ['policy.yaml', 'sros2_policy.xml', 'skills.diff_drive_amr.yaml']:
            shutil.copy2(ROOT / 'config' / f, cfg / f)
        pol = (cfg / 'policy.yaml').read_text()
        for old, new in [('max_linear_speed_mps: 1.0', 'max_linear_speed_mps: %g' % LIMITS['sls.linear_mps']),
                         ('sls.linear_mps: 1.0', 'sls.linear_mps: %g' % LIMITS['sls.linear_mps']),
                         ('max_angular_speed_rps: 1.0', 'max_angular_speed_rps: %g' % LIMITS['sls.angular_rps']),
                         ('sls.angular_rps: 1.0', 'sls.angular_rps: %g' % LIMITS['sls.angular_rps']),
                         ('step.max_duration_s: 30', 'step.max_duration_s: %g' % LIMITS['step.max_duration_s']),
                         ('token_ttl_ms: 3600000', 'token_ttl_ms: 60000')]:
            if pol.count(old) != 1:
                raise RuntimeError('policy template changed; review demo limit: ' + old)
            pol = pol.replace(old, new)
        if '\ntoken_schema:' in pol:
            raise RuntimeError('review existing token schema before overriding')
        (cfg / 'policy.yaml').write_text(pol + '\ntoken_schema: 5\n')
        shutil.copy2(HERE / 'site_model.yaml', cfg / 'site_model.yaml')
        shutil.copy2(ROOT / 'scripts/gen_dev_keys.py', self.state / 'runtime/scripts/gen_dev_keys.py')
        self.run([sys.executable, '-B', str(self.state / 'runtime/scripts/gen_dev_keys.py')], 'generate-keys')
        uid = '%d:%d' % (os.getuid(), os.getgid())
        self.run(['docker', 'run', '--rm', '-u', uid, '-e', 'HOME=/tmp', '-v', str(ROOT) + ':/src:ro', '-v', str(self.state) + ':/state',
                  '--entrypoint', 'bash', self.gate, '-c', 'source /opt/ros/humble/setup.bash && bash /src/scripts/sros2_provision.sh /state/runtime/config robot-01'], 'provision')
        der = subprocess.check_output(['openssl', 'x509', '-in', str(cfg / 'grpc_certs/robot-01/client.crt'), '-outform', 'DER'])
        fp = hashlib.sha256(der).hexdigest()
        (cfg / 'requesters.yaml').write_text('version: 1\nrequesters:\n  - match: {caller: mtls, cert_sha256: "%s"}\n    kind: agentic_ai\n    id: demo-console\n    skills: [twist]\n' % fp)

        def sign(args, name):
            return self.run(['docker', 'run', '--rm', '-u', uid, '--network', 'none', '-v', str(cfg) + ':/config', '-v', str(self.state / 'root-keys') + ':/root-keys',
                             '--entrypoint', 'pail-keyring-sign', self.cloud] + args, name)
        text = sign(['gen-root', '--out', '/root-keys/root.json', '--key-id', 'reference-root'], 'generate-root')
        (cfg / 'keys/root_pub.b64').write_text(next(l.split('=', 1)[1] for l in text.splitlines() if l.startswith('ROOT_PUBKEY_B64=')) + '\n')
        now = int(time.time())  # a demo session may run for hours; the bundle stays inside the 24 h ceiling
        (cfg / 'keys/payload.json').write_text(json.dumps(dict(bundle_version=1, issued_at_unix=now, expires_at_unix=now + 8 * 3600,
                                                               keys=json.loads((cfg / 'keys/keyring.json').read_text())['keys'])))
        sign(['sign', '--root', '/root-keys/root.json', '--payload', '/config/keys/payload.json', '--out', '/config/keys/keyring_bundle.json'], 'sign-bundle')
        ref = self.state / 'runtime/reference'
        self.run([sys.executable,'-B',str(tool),'stage','--state',str(self.state),'--core',str(ROOT),'--demo'],'reference-files')
        (self.state / 'control/input.json').write_text(json.dumps({'on': False, 'speed': 0}))
        (self.state / 'control/input.json').chmod(0o644)
        self.write_control()
        self.run(['docker', 'run', '--rm', '-u', '0', '--network', 'none', '-v', str(self.state) + ':/state', '--entrypoint', 'python3', self.gate,
                  '/state/runtime/reference/permissions.py', 'prepare', '--state', '/state'], 'runtime-ownership')
        mounts = []
        for name, ro in [('runtime/config', True), ('runtime/reference', True), ('control', True), ('evidence/runtime', False), ('blackbox', False), ('keyring-state', False)]:
            mounts += ['-v', str(self.state / name) + ':/state/' + name + (':ro' if ro else '')]
        self.run(['docker', 'run', '--rm', '--network', 'none', '-u', '10001:10001', *mounts, '--entrypoint', 'sh', self.gate, '-c',
                  'umask 077; exec python3 /state/runtime/reference/permissions.py runtime --state /state'], 'permission-service')
        self.run([sys.executable, '-B', str(tool), 'host', '--state', str(self.state)], 'permission-host')

    def up(self):
        self.run(self.compose + ['up', '-d'], 'up')
        end = time.time() + 90
        while time.time() < end:
            try:
                if self.probe('-mode', 'peek')['status'] in ('NO_TOKEN', 'OK'):
                    break
            except (RuntimeError, ValueError):
                pass
            time.sleep(1)
        else:
            raise RuntimeError('issuer did not become ready')
        self.start_actors()

    def start_actors(self):
        for role, enclave in ROLES:
            self.run(self.compose + ['exec', '-d', '-e', 'ROS_SECURITY_ENCLAVE_OVERRIDE=/' + enclave, 'robot', 'bash', '-c',
                                     'source /opt/ros/humble/setup.bash && source /opt/pail_ws/install/setup.bash && umask 077 && '
                                     'touch /evidence/runtime/demo-%s-process.log && chmod 0644 /evidence/runtime/demo-%s-process.log && '
                                     'exec python3 -u /reference/demo_io.py --role %s > /evidence/runtime/demo-%s-process.log 2>&1' % (role, role, role, role)],
                     'actor-' + role)
        since = time.time() - 1
        end = time.time() + 60
        while time.time() < end:
            if all(any(r.get('event') == 'ready' and r.get('t', 0) >= since for r in read_rows(self.logs / 'runtime' / ('demo-%s.jsonl' % role))) for role, _ in ROLES):
                return
            time.sleep(.5)
        raise RuntimeError('demo actors did not report ready; see evidence/runtime/demo-*-process.log')

    def restart_robot(self):
        """Restart the gate side. The gate never re-anchors its clock after a jump (it refuses
        instead), so a restart is the recovery; the refusal threshold is not relaxed."""
        self.write_control(instruction=True, mode='idle', steps=[], override_linear=None)
        self.run(self.compose + ['restart', 'robot'], 'restart-robot')
        self.start_actors()

    def down(self):
        """Stop, not down: the run's containers and network stay (stopped) so that `evaluation.py cleanup` removes
        exactly what this run recorded (README §4/§7, review 22-1). The automatic test tool (run.py) still removes
        its own stack when it ends."""
        self.run(self.compose + ['stop'], 'down', check=False)


def read_rows(path, offset=0):
    try:
        with path.open() as f:
            f.seek(offset)
            body = f.read()
    except FileNotFoundError:
        return []
    out = []
    for line in body.splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return out


def completion_unknown(plan, row):
    """The `moved` record for a completion row the console could not call current (P36-L2): the movement is
    unknown, with the reason and the measured age bound — the same shape as console_feed's unknown results."""
    return dict(plan=plan['id'], text=plan.get('text'), moved_m=None, turned_deg=None, settled=False,
                reason='COMPLETION_REFERENCE_STALE', rejection_reason=row.get('observation_rejection_reason'),
                age_upper_s=row.get('age_upper_s'), freshness_basis=row.get('freshness_basis'))


# ---------------------------------------------------------------------------------------
# Console
# ---------------------------------------------------------------------------------------
class Console:
    defer_future_wallclock = True
    def __init__(self, stack):
        self.stack = stack
        self.clock_id = "console-" + uuid.uuid4().hex
        self.events = ConsoleFeed()
        self.cond = threading.Condition()
        self.offsets = {}
        self.clock = {}
        self.clock_watch = ClockWatch(threshold=CLOCK_STEP_S)             # role -> last wall-minus-monotonic offset seen
        self.pose = None            # the robot side's latest pose row
        self.plan = None            # the last issued plan: id, chain, text, start pose, how it ended
        self.runtime = RuntimeTail(self.stack.logs / 'runtime', [role for role, _ in ROLES], self.clock_id)
        self.events.attach_health(self.runtime.health)
        self.started_at = time.time()
        self.seen_samples = {}
        self.future_observations = FutureObservations()
        self.closed = threading.Event()
        self.worker = threading.Thread(target=self.tail, daemon=True)
        self.worker.start()

    def emit(self, kind, **kw):
        with self.cond:
            self.events.append(dict(t=time.time(), mono=time.monotonic(), clock_id=self.clock_id, source='console', event=kind, **kw))
            self.cond.notify_all()

    def close(self):
        self.closed.set()
        self.worker.join(3)
        if not self.worker.is_alive():
            self.runtime.close()

    def prepare_sample_batch(self, rows):
        pass

    def sample_is_current(self, r):
        role = r['source']
        stamp, mono, clock = r.get('t'), r.get('mono'), r.get('clock_id')
        fresh,rejection=current_observation(r,self.seen_samples.get(role,(clock,-1)),self.started_at,time.time())
        if rejection:r['observation_rejection_reason']=rejection
        return fresh


    def tail(self):
        while not self.closed.is_set():
            try:
                rows = self.runtime.poll()
                self.prepare_sample_batch(rows)
                with self.cond:
                    for r in rows:
                        role = r['source']
                        step = self.clock_watch.observe(role, r)
                        if step:
                            self.emit('clock_step', role=role, jump_s=step['jump_s'], diagnostic=step)
                    if self.defer_future_wallclock:
                        rows = self.future_observations.ready(rows,time.time(),time.monotonic())
                    for r in rows:
                        role = r['source']
                        # Legacy receiver timestamps are not proof of current motion.
                        # Reject pre-start, delayed and repeated samples for state/actions.
                        stamp, mono, clock = r.get('t'), r.get('mono'), r.get('clock_id')
                        fresh = self.sample_is_current(r)
                        r['observation_current'] = bool(fresh)
                        if r.get('event') in ('plan_done','plan_timeout'):
                            r['plan_matches_current']=bool(self.plan and r.get('plan_id') and r['plan_id']==self.plan.get('id'))
                        self.events.append(r)
                        if hasattr(self, 'observe_step'): self.observe_step(r)
                        if fresh:
                            self.seen_samples[role] = (clock, mono)
                            if r.get('event') == 'pose':
                                self.pose = r
                        if r.get('event') == 'plan_done' and r.get('plan_matches_current') and not self.plan.get('ended'):
                            if fresh:
                                self.plan['ended'] = 'done'
                                self.plan['completion_observation']={'clock_id':clock,'mono':mono}
                                threading.Thread(target=self.record_move, args=(self.plan,), daemon=True).start()
                            else:
                                reason = r.get('observation_rejection_reason') or 'UNKNOWN_REJECTION'
                                if reason == 'FUTURE_TIMESTAMP':
                                    pass  # the deferral buffer re-delivers it once its stamp has passed: not a rejection yet
                                else:
                                    # P37-N2: every completion row that is finally rejected is recorded with its reason —
                                    # never silently absent. Recording and ending are separate: only a late but attributed
                                    # completion (same plan, same source, in order; merely too old to measure — the hardware
                                    # console's age bound or the software console's stale stamp) ends the plan, with the
                                    # movement recorded as unknown (P36-L2). A replayed, duplicate or re-sourced row is not
                                    # evidence of this execution's end: the plan stays open for a later valid completion
                                    # or the existing timeout/cancel/replacement path.
                                    self.emit('completion_rejected', plan=self.plan['id'], reason=reason, age_upper_s=r.get('age_upper_s'),
                                              freshness_basis=r.get('freshness_basis'), producer_clock_id=clock, producer_mono=mono)
                                    if reason in ('AGE_UPPER_BOUND', 'STALE_TIMESTAMP'):
                                        self.plan['ended'] = 'done'
                                        self.emit('moved', **completion_unknown(self.plan, r))
                    if hasattr(self, 'flush_step_observations'): self.flush_step_observations()
                    self.runtime.reader_error=None
                    if hasattr(self.events,'publish_health'):self.events.publish_health()
                    self.cond.notify_all()
            except (OSError, ValueError, sqlite3.Error) as exc:
                self.runtime.reader_error=exc.code if isinstance(exc,EventLogError) else 'OBSERVATION_READER_ERROR'
                self.emit('observation_error',code=self.runtime.reader_error)
                if hasattr(self.events,'publish_health'):self.events.publish_health(force=True)
                self.closed.wait(1)
            self.closed.wait(.05)

    # ---- P37-L2 / RV07: per-step drive-side observation, derived after a watermark -------------------------------
    STEP_OBSERVATION_WATERMARK_S = 2.0

    def bridge_nonzero_publish_calls(self):
        """The bridge status counter when the console can read it (hardware console, status socket); None here."""
        return None

    def observe_step(self, r):
        """Remember the planner's step boundaries of the current plan (called under self.cond)."""
        if r.get('source') != 'planner' or r.get('event') not in ('step_permitted', 'step_done') or not self.plan or self.plan.get('ended') and r.get('event') == 'step_permitted':
            return
        pending = self.__dict__.setdefault('_step_windows', {})
        key = (self.plan.get('id'), r.get('seq'), r.get('step'))
        if r['event'] == 'step_permitted':
            pending[key] = {'permitted': dict(r, plan=self.plan.get('id')), 'bridge_before': self.bridge_nonzero_publish_calls()}
        elif key in pending and 'done' not in pending[key]:
            pending[key]['done'] = dict(r)
            pending[key]['bridge_after'] = self.bridge_nonzero_publish_calls()
            pending[key]['due_mono'] = time.monotonic() + self.STEP_OBSERVATION_WATERMARK_S

    def flush_step_observations(self):
        """Emit `step_observation` for every completed step whose watermark has passed (called under self.cond)."""
        pending = self.__dict__.get('_step_windows') or {}
        now = time.monotonic()
        for key in [k for k, w in pending.items() if 'done' in w and now >= w['due_mono']]:
            w = pending.pop(key)
            self.emit('step_observation', **derive_step_observation(list(self.events), w['permitted'], w['done'],
                                                                   self.STEP_OBSERVATION_WATERMARK_S, w.get('bridge_before'), w.get('bridge_after')))

    def record_move(self, plan):
        """UI measurement only; require new samples from this plan's frame."""
        record_observed_move(self,plan,4.0)

    def command(self, text):
        parsed = parse(text)
        if 'error' in parsed:
            self.emit('parse_error', text=text, detail=parsed['error'])
            return dict(parsed, accepted=False)
        if parsed.get('stop'):
            # The planner is told first (nothing is sent to the base any more), then the plan
            # is cancelled at the issuer: until 2026-09-15 stop only idled the planner, and the
            # cancelled plan's remaining step window stayed live — a plan issued right after
            # could run on the previous plan's token. CancelPlan ends the chain (CHAIN_CANCELLED
            # in the ledger) so the next plan is served on its own token only.
            stop_id = uuid.uuid4().hex
            self.emit('stop_requested', text=text, stop_id=stop_id)
            control = self.stack.write_control(instruction=True, mode='idle', steps=[], override_linear=None, stop_id=stop_id)
            self.emit('stop_dispatched', stop_id=stop_id, instruction=control['instruction'], delivery=control.get('_delivery'))
            plan, cancelled = self.plan, None
            if plan and not plan.get('ended'):
                r = self.stack.probe('-mode', 'cancel', '-plan', plan['id'])
                cancelled = bool(r.get('cancelled'))
                if cancelled:
                    plan['ended'] = 'cancelled'
            self.emit('stopped', text=text, stop_id=stop_id, plan=plan['id'] if plan else None, cancelled=cancelled)
            return dict(parsed, accepted=False, cancelled=cancelled)
        return self.submit(text, parsed['steps'], parsed['explain'])

    def wait_ack(self, instruction, timeout):
        """True once the planner recorded that it read instruction number `instruction`."""
        end = time.monotonic() + timeout
        with self.cond:
            while time.monotonic() < end:
                if any(e.get('source') == 'planner' and e.get('event') == 'instruction' and e.get('instruction') == instruction for e in self.events):
                    return True
                self.cond.wait(max(0.0, end - time.monotonic()))
        return False

    def submit(self, text, steps, explain, override_linear=None):
        if self.stack.control.get('mode') == 'raw':
            # A raw stream (driving without permission) that is still running would be the first
            # thing the new permit lets through, and the gate's step clock would start on it
            # before the planner has even read the plan (seen on a real TurtleBot3 2026-09-16:
            # the plan's last commands were then refused as a step overrun). End it first and
            # wait for the planner's acknowledgement.
            c = self.stack.write_control(instruction=True, mode='idle', steps=[], override_linear=None)
            self.emit('raw_ended', acknowledged=self.wait_ack(c['instruction'], 2.0))
        self.emit('plan', text=text, steps=steps, explain=explain)
        r = self.stack.probe('-mode', 'submit', '-steps', json.dumps([{k: s[k] for k in ('linear', 'angular', 'duration')} for s in steps]))
        if r.get('operation_outcome') in ('UNKNOWN','HISTORICAL_ONLY'):
            uncertain=r['operation_outcome']=='UNKNOWN'
            self.emit('operation_unknown' if uncertain else 'operation_historical',plan=r.get('plan'),
                      detail='Authorization outcome unconfirmed; inspect this plan before retrying' if uncertain else 'Historical receipt only; no new controller execution was started')
            return {'accepted':not uncertain,'execution':'UNKNOWN' if uncertain else 'NOT_DISPATCHED',
                    'plan':r.get('plan'),'new_command_required':not uncertain,'steps':[], 'explain':explain}
        if r.get('status') != 'ACCEPTED':
            d = r.get('denial') or {}
            self.emit('refused', text=text, code=d.get('code'), detail=d.get('detail') or r.get('rejected'),
                      exceeded=d.get('exceeded') or [], warning=warning(steps, d.get('exceeded') or []))
            return {'accepted': False, 'denial': d, 'steps': steps, 'explain': explain}
        tokens = r['tokens']
        run = [dict(s, token=t['id']) for s, t in zip(steps, tokens)]
        with self.cond:
            self.plan = {'id': r.get('plan'), 'chain': r.get('chain'), 'text': text, 'start': self.pose, 'ended': None}
        self.emit('issued', text=text, plan=r.get('plan'), chain=r.get('chain'), tokens=[{'id': t['id'], 'constraints': t['constraints']} for t in tokens])
        self.stack.write_control(instruction=True, mode='plan', steps=run, plan_id=r.get('plan'), override_linear=override_linear)
        return {'accepted': True, 'plan': r.get('plan'), 'tokens': tokens, 'steps': run, 'explain': explain}

    def rogue(self, linear):
        c = self.stack.control
        if c.get('mode') != 'plan':
            return {'ok': False, 'detail': 'no plan is running'}
        self.stack.write_control(instruction=True, override_linear=linear)
        self.emit('planner_override', linear=linear)
        return {'ok': True}

    def raw(self, linear, angular, duration):
        self.stack.write_control(instruction=True, mode='raw', raw={'linear': linear, 'angular': angular, 'duration': duration}, steps=[], override_linear=None)
        self.emit('raw_drive', linear=linear, angular=angular, duration=duration)
        return {'ok': True}

    def feed(self, tag=None, safety=None):
        ch = {}
        if tag is not None:
            ch['tag'] = tag
        if safety is not None:
            ch['safety'] = safety
        self.stack.write_control(**ch)
        self.emit('inputs', **ch)
        return {'ok': True}

    def unlock(self):
        r = self.stack.probe('-mode', 'unlock')
        self.emit('unlock', **r)
        return r

    def verify(self):
        rc, out, err = self.stack.exec_issuer('blackbox_verify', '-check-chain', '-dir', '/var/log/pail_blackbox', '-keyfile', '/etc/pail/keys/issuer_ed25519.json', timeout=60)
        ok = rc == 0 and 'OK: chain verified' in out
        self.emit('ledger_verified', ok=ok, output=(out + err).strip()[-600:])
        return {'ok': ok, 'output': (out + err).strip()}

    def restart_robot(self, operation_id=None):
        # One restart path (0.2.0-preview.41): the robot side is started again as `up` did and the console waits for
        # the gate's readiness marker. The judge (demo_scenes.py) still sends an operation_id with the request; the
        # manual restart keeps no operation record, so the value is accepted and ignored.
        self.emit('robot_restarting')
        self.stack.restart_robot()
        self.emit('robot_restarted')
        return {'ok': True}

    def state(self):
        return {'limits': LIMITS, 'units': UNITS, 'cruise': CRUISE, 'per_call_max_m': LIMITS['sls.linear_mps'] * LIMITS['step.max_duration_s'],
                'per_call_max_rad': LIMITS['sls.angular_rps'] * LIMITS['step.max_duration_s'], 'control': self.stack.control,
                'position_source': 'simulation'}


def warning(steps, exceeded):
    """The human sentence for a refusal, built from the machine fields (never from detail)."""
    out = []
    for e in exceeded:
        name, req, mx = e.get('name'), e.get('requested'), e.get('max')
        if name == 'step.max_duration_s':
            s = next((s for s in steps if abs(s['duration'] - float(req)) < 1e-6), steps[0] if steps else None)
            v = abs(s['linear']) if s else 0
            if v > 0:
                out.append({'en': 'Requested %.2f m (%.2f m/s × %g s) is above the per-call limit of %.2f m (%g s). Nothing was executed — split it into shorter moves.' % (v * float(req), v, float(req), v * float(mx), float(mx)),
                            'ko': '요청한 %.2f m(%.2f m/s × %g초)는 1회 한도 %.2f m(%g초)를 넘어 실행하지 않았습니다. 짧게 나눠 요청하세요.' % (v * float(req), v, float(req), v * float(mx), float(mx))})
                continue
            out.append({'en': 'Requested %g s is above the per-call limit of %g s. Nothing was executed.' % (float(req), float(mx)),
                        'ko': '요청한 %g초는 1회 한도 %g초를 넘어 실행하지 않았습니다.' % (float(req), float(mx))})
        elif name in UNITS:
            out.append({'en': 'Requested %s %s %s is above the limit of %s %s. Nothing was executed.' % (name, req, UNITS[name], mx, UNITS[name]),
                        'ko': '요청한 %s %s %s는 한도 %s %s를 넘어 실행하지 않았습니다.' % (name, req, UNITS[name], mx, UNITS[name])})
        else:
            out.append({'en': 'Requested %s=%s is above %s. Nothing was executed.' % (name, req, mx), 'ko': '요청한 %s=%s는 한도 %s를 넘어 실행하지 않았습니다.' % (name, req, mx)})
    return out


def handler_for(console):
    page = (HERE / 'demo_ui.html').read_bytes()

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def send(self, code, body, ctype='application/json'):
            b = body if isinstance(body, bytes) else json.dumps(body, separators=(',', ':'), allow_nan=False).encode()
            self.send_response(code)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(b)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            path = urllib.parse.urlsplit(self.path).path  # '/?lang=ko' is the page too
            if path in ('/', '/index.html'):
                return self.send(200, page, 'text/html; charset=utf-8')
            if path == '/api/state':
                return self.send(200, console.state())
            if handle_observation(self, console.events, console.runtime.history):
                return
            return self.send(404, {'error': 'not found'})

        def do_POST(self):
            if self.headers.get('Origin') not in (None, 'http://127.0.0.1:%d' % self.server.server_address[1], 'http://localhost:%d' % self.server.server_address[1]):
                return self.send(403, {'error': 'cross-origin request refused'})
            n = int(self.headers.get('Content-Length') or 0)
            try:
                req = json.loads(self.rfile.read(n) or b'{}')
                if self.path == '/api/command':
                    return self.send(200, console.command(str(req.get('text', ''))))
                if self.path == '/api/plan':  # explicit steps (scene automation)
                    return self.send(200, console.submit(req.get('text', 'plan'), req['steps'], req.get('explain', []), req.get('override_linear')))
                if self.path == '/api/rogue':
                    return self.send(200, console.rogue(req.get('linear')))
                if self.path == '/api/raw':
                    return self.send(200, console.raw(float(req['linear']), float(req.get('angular', 0)), float(req['duration'])))
                if self.path == '/api/inputs':
                    return self.send(200, console.feed(req.get('tag'), req.get('safety')))
                if self.path == '/api/unlock':
                    return self.send(200, console.unlock())
                if self.path == '/api/verify':
                    return self.send(200, console.verify())
                if self.path == '/api/restart_robot':
                    return self.send(200, console.restart_robot(req.get('operation_id')))
            except (IssuerTransportError, subprocess.TimeoutExpired) as ex:
                console.emit('console_error', path=self.path, detail=str(ex))
                return self.send(503, {'error': str(ex), 'outcome': 'unknown; check current plan before retrying'})
            except (KeyError, ValueError, RuntimeError) as ex:
                console.emit('console_error', path=self.path, detail=str(ex))
                return self.send(400, {'error': str(ex)})
            return self.send(404, {'error': 'not found'})
    return H


def selftest():
    """Offline checks (no Docker): command language, refusal sentences, clock-step detection."""
    fails = []

    def check(name, ok, got):
        print(('PASS ' if ok else 'FAIL ') + name + ('' if ok else ' — ' + repr(got)))
        if not ok:
            fails.append(name)
    cases = {
        'forward 1 m': [(0.1, 0.0, 10.0)], '앞으로 1m': [(0.1, 0.0, 10.0)], 'back 0.5 m': [(-0.1, 0.0, 5.0)], '뒤로 50cm': [(-0.1, 0.0, 5.0)],
        'left 90 deg': [(0.0, 0.5, 3.14)], '오른쪽으로 90도': [(0.0, -0.5, 3.14)], 'forward 1 m at 0.3 m/s': [(0.3, 0.0, 3.33)],
        'left 1 m': [(0.0, 0.5, 3.14), (0.1, 0.0, 10.0)], '왼쪽으로 1미터': [(0.0, 0.5, 3.14), (0.1, 0.0, 10.0)],
    }
    for text, want in cases.items():
        got = [(s['linear'], s['angular'], s['duration']) for s in parse(text).get('steps', [])]
        check('parse %r' % text, got == want, got)
    check('parse rejects nonsense', 'error' in parse('dance'), parse('dance'))
    w = warning([{'linear': 0.1, 'angular': 0.0, 'duration': 30.0}], [{'name': 'step.max_duration_s', 'requested': 30, 'max': 15}])
    check('duration refusal names the distance limit', w and '1.50 m' in w[0]['en'] and '1.50 m' in w[0]['ko'], w)
    w = warning([{'linear': 0.3, 'angular': 0.0, 'duration': 3.33}], [{'name': 'sls.linear_mps', 'requested': 0.3, 'max': 0.1}])
    check('speed refusal names the speed limit', w and '0.1 m/s' in w[0]['en'], w)
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / 'evidence' / 'runtime').mkdir(parents=True)

        class FakeStack:
            logs = root / 'evidence'
        c = Console(FakeStack())
        rows = [dict(t=100.0 + i, mono=10.0 + i, event='pose', clock_id='selftest-clock') for i in range(3)] + [dict(t=105.0, mono=13.0, event='pose', clock_id='selftest-clock')]
        (root / 'evidence/runtime/demo-base.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in rows))
        end = time.time() + 3
        while time.time() < end and not [e for e in c.events if e['event'] == 'clock_step']:
            time.sleep(.05)
        steps = [e for e in c.events if e['event'] == 'clock_step']
        c.close()
        check('a 2 s wall-clock step is reported', len(steps) == 1 and abs(steps[0]['jump_s'] - 2.0) < 1e-6, steps)
    print('SELFTEST=%s' % ('PASS' if not fails else 'FAIL'))
    return 0 if not fails else 1


def port_check(ports, hint, hold=()):
    """Refuse before any state, build or provisioning when a needed local port is busy.

    ports: [(label, port)]. Returns {label: socket} for the labels in `hold` — those stay
    bound and listening until the caller hands the port over — or None when a port is busy.
    This demo has one port, the console, and binds it for real right after this check, so
    nothing is held here (the Microduck demo holds its dashboard port through the build).
    """
    busy, held = [], {}
    for label, port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('127.0.0.1', port))
            if label in hold:
                s.listen(1)
                held[label] = s
                s = None
        except OSError as ex:
            busy.append('%s port %d (%s)' % (label, port, ex.strerror or ex))
        finally:
            if s is not None:
                s.close()
    if busy:
        for h in held.values():
            h.close()
        print('PORT_CHECK: BUSY ' + '; '.join(busy) + ' on 127.0.0.1.', file=sys.stderr)
        print('No state was created, nothing was built, no existing process was stopped.', file=sys.stderr)
        print('Choose free ports, for example: ' + hint, file=sys.stderr)
        return None
    return held


class Server(BoundedServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('action', choices=['up','start','build','parse','selftest'])
    ap.add_argument('--state', type=Path)
    ap.add_argument('--port', type=int, default=8765)
    ap.add_argument('--skip-build', action='store_true', help='reuse --cloud-image/--gate-image instead of building')
    ap.add_argument('--cloud-image')
    ap.add_argument('--gate-image')
    ap.add_argument('--build', action='store_true', help='explicitly prepare images before start')
    ap.add_argument('--build-record', type=Path, help='prepared image receipt outside source')
    ap.add_argument('--build-window-confirmed', action='store_true', help='operator confirms an isolated software build window')
    ap.add_argument('--trust-profile', type=Path, help='operator-owned read-only trust inspection profile; no signing or application from the console')
    ap.add_argument('text', nargs='*')
    a = ap.parse_args()
    if a.trust_profile is not None:
        if a.action not in ('up','start'):
            ap.error('--trust-profile is a startup observation option')
        from ops_state import load_private
        profile = load_private(a.trust_profile)
        if not isinstance(profile,dict):ap.error('trust profile must be an object')

    if a.action == 'parse':  # offline check of the command language
        print(json.dumps(parse(' '.join(a.text)), ensure_ascii=False))
        return 0
    if a.action == 'selftest':
        return selftest()
    from evaluation_runtime import split_distribution, runtime_images
    if a.action!='build' and a.state is not None:
        state_path=a.state.resolve()
        if a.state.is_symlink() or state_path==ROOT or ROOT in state_path.parents or (state_path.exists() and (not state_path.is_dir() or any(state_path.iterdir()))):
            print('NEW_EMPTY_STATE_OUTSIDE_SOURCE_REQUIRED',file=sys.stderr);return 2
    build_ports={}
    if a.action!='build':
        # ports before the image lookup: a busy port is refused in zero seconds with its own name whatever else is
        # missing (P24-N1, executed bind-first pin)
        wanted=[('console',a.port)]
        build_ports=port_check(wanted,'--port 8787',hold=tuple(x[0] for x in wanted))
        if build_ports is None:return 2
    if split_distribution(ROOT) and a.action != 'build':
        try:
            images = runtime_images(ROOT)
            a.cloud_image, a.gate_image = images['issuer'], images['tb3_gate']
        except ValueError as ex:
            for held_port in build_ports.values():held_port.close()
            print(str(ex), file=sys.stderr)
            return 2
    try:
        prepared=select_prepared('tb3',a,ROOT)
        if a.action=='build':
            print(json.dumps(prepared));return 0
        a.cloud_image=prepared['images']['cloud'];a.gate_image=prepared['images']['gate'];a.skip_build=True
    except (BuildRequired,OSError,ValueError,subprocess.SubprocessError) as ex:
        print(str(ex),file=sys.stderr);return 2
    finally:
        for held_port in build_ports.values():held_port.close()
    if os.name != 'posix':
        print('Native Windows is not supported by this demo. Use Linux/macOS.', file=sys.stderr)
        return 2
    for tool in ('docker', 'openssl'):
        if not shutil.which(tool):
            print('Missing prerequisite: ' + tool, file=sys.stderr)
            return 2
    if port_check([('console', a.port)], 'python3 examples/tb3/demo.py up --port 8778') is None:
        return 2
    state = (a.state or Path(tempfile.mkdtemp(prefix='pail-tb3-demo-'))).resolve()
    if state == ROOT or ROOT in state.parents:
        raise SystemExit('state must be outside the source tree')
    if state.exists() and any(state.iterdir()):
        raise SystemExit('state must be empty')
    release = release_id(ROOT)
    project = project_name('tb3-demo', release)   # the release and a per-run value are readable from `docker ps`
    if a.skip_build:
        if not (a.cloud_image and a.gate_image):
            raise SystemExit('--skip-build needs --cloud-image and --gate-image')
        cloud, gate = a.cloud_image, a.gate_image
    else:
        cloud, gate = 'pail/tb3-cloud:' + project, 'pail/tb3-gate:' + project
    stack = Stack(state, cloud, gate, project)
    print('STATE=' + str(state), flush=True)

    def stop_on_term(signum, frame):  # a backgrounded shell job ignores SIGINT; TERM must also clean up
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop_on_term)
    trust_cache = None
    started = False
    try:
        srv = Server(('127.0.0.1', a.port), None)  # bind first: a busy console port fails before any build or provisioning
        stack.setup(build=False)
        stack.up()
        started = True
        console = Console(stack)
        if a.trust_profile is not None:
            from trust_observation import TrustObservationCache
            trust_cache=TrustObservationCache(a.trust_profile)
            console.events.attach_trust(trust_cache.snapshot)
        else:   # preview.40 review item 11: say which trust mode this run uses even without an operator profile
            from trust_observation import launcher_observation
            console.events.attach_trust(lambda: launcher_observation('bundle', state / 'runtime/config/keys/keyring_bundle.json', state / 'runtime/config/keys/root_pub.b64'))

        srv.RequestHandlerClass = handler_for(console)
        (state / 'evidence' / 'console.json').write_text(json.dumps({'url': 'http://127.0.0.1:%d/' % a.port, 'project': project, 'release': release, 'cloud_image': cloud, 'gate_image': gate}))
        print('CONSOLE=http://127.0.0.1:%d/' % a.port, flush=True)
        console.emit('ready', limits=LIMITS)
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if trust_cache is not None:trust_cache.close()
        if started or (state / 'evidence' / 'up.log').exists():
            print('Stopping the stack…', flush=True)
            stack.down()
    return 0


if __name__ == '__main__':
    # a failure ends with a named refusal line, never a bare traceback (class pin C2)
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError) as exc:
        print('DEMO_REFUSED: ' + str(exc), file=sys.stderr, flush=True)
        sys.exit(2)
