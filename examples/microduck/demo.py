#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Live Microduck demo console — tell the robot what to do, watch PAIL decide, and see the
same decisions in the public observation dashboard (no hardware).

  python3 examples/microduck/demo.py up [--state /new/dir] [--port 8767] [--dashboard-port 18092]
  python3 examples/microduck/demo.py up --skip-build --image pail/microduck-preview:local-<id>

Starts the preview stack (upstream robotd --fake, issuer, robot agent, pail-duckd with
libpail_gate, fresh keys) plus demo actors on the robot side, serves a console on
http://127.0.0.1:<port>/ and a ledger dashboard (pail_telemetryd) on
http://127.0.0.1:<dashboard-port>/ — both on this machine only. Type "forward 1 m" (or
"앞으로 1m"): the console turns it into a twist plan and asks the issuer. Within the policy
the adapter permits it and the simulated position moves; above it the issuer refuses the
plan, nothing moves, and the console shows which limit was exceeded. Ctrl-C stops the stack.
Positions are the integral of the velocity robotd --fake reports as applied, not a robot
measurement; the tag and the safety seam are synthetic.
"""
import argparse, hashlib, http.server, json, math, os, platform, re, shutil, signal, socket, socketserver, subprocess, sys, tempfile, threading, time, urllib.parse, uuid
from pathlib import Path
import sqlite3

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE.parent / 'common'))
from console_feed import ConsoleFeed, RuntimeTail, handle_observation, FutureObservations, current_observation, record_observed_move
from eventlog import EventLogError
from diagnostics import ClockWatch
from build_runtime import BuildRequired, select_prepared
from resource_budget import BoundedServer
from compose_failure import failed_step  # P24-L1: a failed compose step names the daemon's condition on the DEMO_REFUSED line
from run_names import project_name, release_id  # preview.40 review item 01: pail-<kind>-<release>-<run>
sys.path.insert(0, str(HERE))
import run as preview  # noqa: E402  (doctor / build / tree manifest of the preview runner)

REFERENCE = ['demo_io.py', 'demo_connection.py', 'demo_probe.py', 'demo_prepare.py']
FIXTURES = ['policy.yaml', 'skills.microduck.yaml', 'site.yaml']
ROLES = ['planner', 'observer', 'evidence', 'ledger']

# Demo policy (fixtures/demo/policy.yaml): one call may run at most 0.2 m/s for 12 s (2.4 m).
LIMITS = {'sls.linear_mps': 0.2, 'sls.angular_rps': 1.0, 'step.max_duration_s': 12.0}
CRUISE = {'linear': 0.1, 'angular': 0.5}
STOP_WINDOW_S = 0.25   # added to every requested step: the planner spends it on zero-velocity commands inside the permit
TARGET = 'box-12'   # the synthetic site's object the raw move is authorized against (scene 7)
CLOCK_STEP_S = 0.25
UNITS = {'sls.linear_mps': 'm/s', 'sls.angular_rps': 'rad/s', 'step.max_duration_s': 's'}
SKILLS = {'wave': 'NONE', 'sit_toggle': 'NONE', 'walk': 'MOVE', 'roulade': 'MOVE', 'kick_left': 'MOVE', 'kick_right': 'MOVE', 'ground_pick': 'MANIPULATE'}


# ---------------------------------------------------------------------------------------
# Command language (rule based; the console plays the AI requester, PAIL does not trust it).
# Same grammar as the TurtleBot3 demo so the two consoles read the same sentences.
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
    'wave': ['wave', '손 흔들', '손흔들', '인사'],
}


def has(text, key):
    return any(w in text for w in WORDS[key])


def parse(text):
    """Return {'steps': [...], 'explain': [...]} | {'skill': name} | {'stop': True} | {'error': ...}."""
    t = text.strip().lower()
    if not t:
        return {'error': 'empty command'}
    if has(t, 'stop'):
        return {'stop': True, 'steps': [], 'explain': ['stop']}
    if has(t, 'wave'):
        return {'skill': 'wave', 'steps': [], 'explain': ['robot.do wave (skill, class NONE)']}
    for name in SKILLS:
        if t == name or t == 'do ' + name:
            return {'skill': name, 'steps': [], 'explain': ['robot.do %s (skill, class %s)' % (name, SKILLS[name])]}
    sm = SPEED.search(t)
    speed = abs(float(sm.group(1))) if sm else CRUISE['linear']
    steps, explain = [], []

    def turn(deg, direction):
        w = CRUISE['angular'] * (1 if direction == 'left' else -1)
        dur = round(math.radians(abs(deg)) / CRUISE['angular'], 2)
        steps.append({'linear': 0.0, 'angular': w, 'duration': round(dur + STOP_WINDOW_S, 2)})
        explain.append('turn %s %g° = %.2f rad/s × %.2f s (+%.2f s stop)' % (direction, abs(deg), CRUISE['angular'], dur, STOP_WINDOW_S))

    def move(meters, direction):
        if speed <= 0:
            return 'speed must be positive'
        dur = round(abs(meters) / speed, 2)
        v = speed * (1 if direction == 'forward' else -1)
        steps.append({'linear': v, 'angular': 0.0, 'duration': round(dur + STOP_WINDOW_S, 2)})
        explain.append('%s %g m = %.2f m/s × %.2f s (+%.2f s stop)' % (direction, abs(meters), speed, dur, STOP_WINDOW_S))
        return None

    dm = DIST.search(t)
    meters = None
    if dm:
        meters = float(dm.group(1)) / (100.0 if dm.group(2).startswith(('cm', 'centi', '센티')) else 1.0)
    am = ANGLE.search(t)
    side = 'left' if has(t, 'left') else 'right' if has(t, 'right') else None
    if am and side:
        turn(float(am.group(1)), side)
        if meters is not None:
            move(meters, 'forward')
    elif side and meters is not None:
        turn(90, side)          # the demo keeps the TB3 grammar: a sideways request is a turn and a straight move
        move(meters, 'forward')
    elif meters is not None and (has(t, 'forward') or has(t, 'back')):
        err = move(meters, 'back' if has(t, 'back') else 'forward')
        if err:
            return {'error': err}
    else:
        return {'error': 'not understood — try "forward 1 m", "back 0.5 m", "left 90 deg", "left 1 m", "forward 1 m at 0.3 m/s", "wave"'}
    return {'steps': steps, 'explain': explain}


def warning(steps, exceeded):
    """The human sentence for a refusal, built from the machine fields (never from detail)."""
    out = []
    for e in exceeded:
        name, req, mx = e.get('name'), e.get('requested'), e.get('max')
        if name == 'step.max_duration_s':
            s = next((s for s in steps if abs(s['duration'] - float(req)) < 1e-6), steps[0] if steps else None)
            v = abs(s['linear']) if s else 0
            if v > 0:
                motion = max(0.0, float(req) - STOP_WINDOW_S)   # the request is motion + the stop window
                reach = v * max(0.0, float(mx) - STOP_WINDOW_S)
                out.append({'en': 'Requested %.2f m (%.2f m/s × %g s + %g s stop) is above the per-call limit of %g s (%.2f m at this speed). Nothing was executed — split it into shorter moves.' % (v * motion, v, motion, STOP_WINDOW_S, float(mx), reach),
                            'ko': '요청한 %.2f m(%.2f m/s × %g초 + 정지 %g초)는 1회 한도 %g초(이 속도로 %.2f m)를 넘어 실행하지 않았습니다. 짧게 나눠 요청하세요.' % (v * motion, v, motion, STOP_WINDOW_S, float(mx), reach)})
                continue
            out.append({'en': 'Requested %g s is above the per-call limit of %g s. Nothing was executed.' % (float(req), float(mx)),
                        'ko': '요청한 %g초는 1회 한도 %g초를 넘어 실행하지 않았습니다.' % (float(req), float(mx))})
        elif name in UNITS:
            out.append({'en': 'Requested %s %s %s is above the limit of %s %s. Nothing was executed.' % (name, req, UNITS[name], mx, UNITS[name]),
                        'ko': '요청한 %s %s %s는 한도 %s %s를 넘어 실행하지 않았습니다.' % (name, req, UNITS[name], mx, UNITS[name])})
        else:
            out.append({'en': 'Requested %s=%s is above %s. Nothing was executed.' % (name, req, mx), 'ko': '요청한 %s=%s는 한도 %s를 넘어 실행하지 않았습니다.' % (name, req, mx)})
    return out


# ---------------------------------------------------------------------------------------
# Stack
# ---------------------------------------------------------------------------------------
def contract_compose_files(here, env):
    """Compose files of the stack. There is one communication contract (0.2.0-preview.40) and no setting that selects
    it: a PAIL_CORE_COMM_CONTRACT variable present at all in the ambient environment — any value, an empty one included
    (0.2.0-preview.41, P40-L2) — is refused by name before anything starts (the same message as internal/corecomm and
    core_operation_wire.py); nothing is exported to the services."""
    if 'PAIL_CORE_COMM_CONTRACT' in env:
        raise SystemExit('CORE_COMM_CONTRACT_SETTING_REMOVED: PAIL_CORE_COMM_CONTRACT has no meaning (there is one communication contract); unset it')
    return [here / 'compose.yaml', here / 'compose.demo.yaml']


class Stack:
    def __init__(self, state, image, project, issuer_image=None):
        self.state, self.image, self.project = state, image, project
        self.env = dict(os.environ, PAIL_DUCK_STATE=str(state), PAIL_DUCK_IMAGE=image,
                        PAIL_DUCK_ISSUER_IMAGE=issuer_image or image)
        files = contract_compose_files(HERE, self.env)
        self.compose = ['docker', 'compose', '--parallel', '2', '--project-name', project] + [x for f in files for x in ('-f', str(f))]
        self.logs = state / 'evidence'
        self.seq = 0
        self.control = {'seq': 0, 'instruction': 0, 'mode': 'idle', 'steps': [], 'tag': TARGET, 'safety': 'OK'}
        self.lock = threading.Lock()

    def run(self, args, name, timeout=1800, check=True):
        with (self.logs / (name + '.log')).open('a') as f:
            p = subprocess.run(args, cwd=ROOT, env=self.env, stdout=f, stderr=subprocess.STDOUT, timeout=timeout)
        if check and p.returncode:
            raise RuntimeError(failed_step(name, p.returncode, self.logs / (name + '.log')))
        return (self.logs / (name + '.log')).read_text()

    def write_control(self, instruction=False, **changes):
        """instruction=True when the planner's task changes; feed switches leave a running plan alone."""
        with self.lock:
            self.seq += 1
            self.control = dict(self.control, **changes, seq=self.seq)
            if instruction:
                self.control['instruction'] = self.control.get('instruction', 0) + 1
            d = self.state / 'demo-control'
            tmp = d / 'demo.next'
            with tmp.open('w') as f:
                f.write(json.dumps(self.control)); f.flush(); os.fsync(f.fileno())
            tmp.chmod(0o644)
            tmp.replace(d / 'demo.json')
            return dict(self.control)

    def probe(self, *args, timeout=30):
        p = subprocess.run(self.compose + ['exec', '-T', 'tools', 'python', '/reference/demo_probe.py', *args], cwd=ROOT, env=self.env,
                           capture_output=True, text=True, timeout=timeout)
        lines = [l for l in p.stdout.strip().splitlines() if l.startswith('{')]
        if not lines:
            raise RuntimeError('demo_probe %s rc=%d: %s' % (args[0], p.returncode, (p.stderr or p.stdout).strip()[-400:]))
        return json.loads(lines[-1])

    def setup(self, build):
        for d, mode in [('demo-control', 0o755), ('evidence', 0o755), ('runtime', 0o755), ('runtime/reference', 0o755), ('runtime/reference/fixtures', 0o755), ('dashboard', 0o700), ('control', 0o700)]:
            (self.state / d).mkdir(parents=True, exist_ok=True)
            (self.state / d).chmod(mode)
        for name in REFERENCE:
            shutil.copyfile(HERE / name, self.state / 'runtime/reference' / name)
            (self.state / 'runtime/reference' / name).chmod(0o644)
        # every file staged for a container is readable by its non-root user regardless of the operator's umask: a
        # tree extracted under umask 077 left these two 0600 and the actors failed to start (contaminated-host replay, 2026-10-21)
        for src, dst in ((HERE.parent / 'common/diagnostics.py', 'diagnostics.py'), (HERE.parent / 'common/observation.py', 'observation.py'), (HERE.parent / 'common/raw_retention.py', 'raw_retention.py')):
            shutil.copyfile(src, self.state / 'runtime/reference' / dst)
            (self.state / 'runtime/reference' / dst).chmod(0o644)
        for name in FIXTURES:
            shutil.copyfile(HERE / 'fixtures/demo' / name, self.state / 'runtime/reference/fixtures' / name)
            (self.state / 'runtime/reference/fixtures' / name).chmod(0o644)
        source = preview.tree_manifest(ROOT) if hasattr(preview, 'tree_manifest') else __import__('results').tree_manifest(ROOT)
        preview.atomic_json(self.state / 'source-manifest.json', source)
        if build:
            print('Building public Core, adapter and the official fake from this tree (first build may take 10–20 minutes)…', flush=True)
            self.image = preview.build(preview.IMAGE, self.logs / 'build.log')
        else:
            self.image = subprocess.check_output(['docker', 'image', 'inspect', self.image, '--format', '{{.Id}}'], text=True).strip()
        labels = json.loads(subprocess.check_output(['docker', 'image', 'inspect', self.image, '--format', '{{json .Config.Labels}}'], text=True)) or {}
        from build_runtime import image_matches_inputs, image_input_mismatch   # what the image's build reads, not every Core file
        architecture = subprocess.check_output(['docker', 'image', 'inspect', self.image, '--format', '{{.Architecture}}'], text=True).strip()
        fresh, image_input = image_matches_inputs(ROOT, 'microduck', labels, architecture)
        self.env['PAIL_DUCK_IMAGE'] = self.image
        preview.atomic_json(self.state / 'run.json', dict(run_id=uuid.uuid4().hex, project=self.project, state=str(self.state), image=self.image,
                                                          profile='live-demo', source_manifest_sha256=source['sha256'], image_input_sha256=image_input, image_matches_source=fresh,
                                                          hardware_tested=False, environment=preview.doctor(), started_at_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())))
        if not fresh:
            print(image_input_mismatch(ROOT, 'microduck', labels, architecture), flush=True)
        self.write_control()
        self.run(self.compose + ['run', '--rm', 'prepare'], 'prepare')
        self.run(self.compose + ['run', '--rm', 'demo-prepare'], 'demo-prepare')
        access = json.loads((self.logs / 'demo-access.json').read_text())
        if not access.get('passed'):
            raise RuntimeError('access contract failed: ' + json.dumps(access))

    def wait_exec(self, service, code, label, timeout=60):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            p = subprocess.run(self.compose + ['exec', '-T', service, 'python', '-c', code], cwd=ROOT, env=self.env, capture_output=True, text=True)
            if p.returncode == 0:
                return
            time.sleep(0.5)
        raise RuntimeError('readiness deadline expired: ' + label)

    def up(self):
        self.run(self.compose + ['up', '-d', 'issuer', 'tools', 'agent', 'fake', 'state-seam'], 'up')
        self.wait_exec('fake', 'import os,sys; sys.exit(0 if os.path.exists("/run/duck/raw/robotd.sock") else 1)', 'fake socket')
        self.wait_exec('state-seam', 'import os,sys; sys.exit(0 if os.path.exists("/run/duck/raw/state-seam.sock") and os.path.exists("/run/duck/state.ctl") else 1)', 'state seam')
        self.run(self.compose + ['up', '-d', 'adapter'], 'up')
        end = time.monotonic() + 90
        while time.monotonic() < end:
            p = subprocess.run(self.compose + ['run', '--rm', '--no-deps', 'harness', 'python', '/opt/pail/example/support.py', 'ready'], cwd=ROOT, env=self.env, capture_output=True, text=True)
            if p.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError('adapter/issuer did not become ready; see evidence/up.log and docker compose logs')
        self.start_actors()

    def start_actors(self):
        since = time.time() - 1
        self.run(self.compose + ['up', '-d', 'demo-observer', 'demo-evidence', 'demo-ledger', 'demo-planner'], 'up-actors')
        end = time.time() + 60
        while time.time() < end:
            if all(any(r.get('event') == 'ready' and r.get('t', 0) >= since for r in read_rows(self.logs / 'runtime' / ('demo-%s.jsonl' % role))) for role in ROLES):
                return
            time.sleep(.5)
        raise RuntimeError('demo actors did not report ready; see docker compose logs demo-*')

    def restart_robot(self):
        """Restart the robot side: fake, seam, adapter and every demo actor. Returns only when the
        adapter answers and all four actors have reported ready AFTER the restart (the planner's
        ready follows its reconnect). Before 2026-09-16 the planner was left to reconnect on its
        own and the console returned first: on Linux a plan issued 0.4 s after the restart was
        permitted about a second before the planner's first command, and its last commands were
        refused as a step overrun."""
        # a restart also puts the synthetic inputs back to nominal (2026-09-16: a wrong tag left
        # from scene 7 survived a restart and every later plan kept failing with TARGET_MISMATCH)
        self.write_control(instruction=True, mode='idle', steps=[], override_linear=None, safety='OK', tag=TARGET)
        since = time.time() - 1
        self.run(self.compose + ['restart', 'fake', 'state-seam', 'adapter', 'demo-observer', 'demo-evidence', 'demo-ledger', 'demo-planner'], 'restart-robot')
        self.wait_exec('fake', 'import os,sys; sys.exit(0 if os.path.exists("/run/duck/raw/robotd.sock") else 1)', 'fake socket')
        end = time.monotonic() + 90
        while time.monotonic() < end:
            p = subprocess.run(self.compose + ['run', '--rm', '--no-deps', 'harness', 'python', '/opt/pail/example/support.py', 'ready'], cwd=ROOT, env=self.env, capture_output=True, text=True)
            if p.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError('robot side did not come back')
        end = time.time() + 60
        while time.time() < end:
            if all(any(r.get('event') == 'ready' and r.get('t', 0) >= since for r in read_rows(self.logs / 'runtime' / ('demo-%s.jsonl' % role))) for role in ROLES):
                return
            time.sleep(.5)
        raise RuntimeError('demo actors did not report ready after the restart; see docker compose logs demo-*')

    def fault(self, service, action):
        """Scene 8-A: the issuer link. Only the robot agent may be stopped/started, with the compose project's own tools."""
        if service != 'agent' or action not in ('stop', 'start'):
            raise ValueError('only agent stop/start is allowed')
        if action == 'stop':
            self.run(self.compose + ['kill', '-s', 'SIGTERM', 'agent'], 'fault-agent', check=False)
        else:
            self.run(self.compose + ['start', 'agent'], 'fault-agent')
        return {'ok': True, 'service': service, 'action': action}

    def down(self):
        """Collect the service logs, then stop (not down): the run's containers and network stay (stopped) so that
        `evaluation.py cleanup` removes exactly what this run recorded (README §4/§7, review 22-1); an orphan of the
        project is removed by cleanup as well (it selects by the project label)."""
        self.run(self.compose + ['logs', '--no-color'], 'services', check=False)
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


# ---------------------------------------------------------------------------------------
# Dashboard: the public observation UI (pail_telemetryd) built natively, reading the
# ledger mirror. Same recipe as examples/viewer/run.py, on a live mirror instead of a
# stopped snapshot.
# ---------------------------------------------------------------------------------------
class Dashboard:
    def __init__(self, state, port, binary=None, build=False, holder=None):
        self.state, self.port, self.child = state, port, None
        self.holder = holder  # the dashboard port, held since the preflight; released in start()
        self.out = state / 'dashboard'
        self.binary = Path(binary) if binary else self.out / 'pail_telemetryd'
        self.build = build and not binary
        self.url = 'http://127.0.0.1:%d/dashboard/?tab=timeline&preset=1h' % port

    def prepare(self, log):
        if platform.system() not in ['Darwin', 'Linux']:
            raise RuntimeError('dashboard: macOS or Linux/WSL2 only')
        arch = {'arm64': 'arm64', 'aarch64': 'arm64', 'x86_64': 'amd64', 'AMD64': 'amd64'}.get(platform.machine())
        if self.build:raise BuildRequired('BUILD_REQUIRED: dashboard compilation requires explicit demo.py build')
        if not self.binary.is_file():
            raise RuntimeError('dashboard binary missing: ' + str(self.binary))
        self.binary.chmod(0o700)

    def start(self, log):
        mirror = self.state / 'evidence/ledger'
        end = time.time() + 30
        while time.time() < end and not any(mirror.rglob('*.seg')) and not any(p.is_file() for p in mirror.rglob('*')):
            time.sleep(.5)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(('127.0.0.1', 0)); udp = s.getsockname()[1]
        env = dict(os.environ, PAIL_PROFILE='dev', PAIL_KEYRING_MODE='unsigned-dev', PAIL_KEYRING=str(self.state / 'public/config/keys/keyring.json'))
        env.pop('PAIL_TELEMETRY_TOKEN', None)
        args = [str(self.binary), '-dir', str(self.out), '-blackbox-dir', str(mirror), '-registry', str(self.state / 'public/config/robot_registry.yaml'),
                '-http', '127.0.0.1:%d' % self.port, '-listen', '127.0.0.1:%d' % udp, '-tick', '2s']
        self.release_port()  # hand-over: the only moment the port is free before the dashboard binds it
        self.child = subprocess.Popen(args, env=env, stdout=log.open('a'), stderr=subprocess.STDOUT)
        end = time.time() + 20
        while time.time() < end:
            try:
                with urllib.request.urlopen('http://127.0.0.1:%d/healthz' % self.port, timeout=2) as r:
                    if r.status == 200:
                        return
            except (OSError, ValueError):
                time.sleep(.5)
        tail = ''
        try:
            lines = [ln for ln in log.read_text(errors='replace').splitlines() if ln.strip()]
            tail = lines[-1] if lines else ''
        except OSError:
            pass
        if 'address already in use' in tail:
            raise RuntimeError('dashboard port %d was taken after the preflight: %s' % (self.port, tail))
        raise RuntimeError('dashboard did not answer /healthz; last log line: %s (evidence/dashboard.log)' % (tail or '<empty>'))

    def release_port(self):
        if self.holder is not None:
            self.holder.close()
            self.holder = None

    def stop(self):
        self.release_port()
        if self.child and self.child.poll() is None:
            self.child.terminate()
            try:
                self.child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.child.kill()


import urllib.request  # noqa: E402


# ---------------------------------------------------------------------------------------
# Console
# ---------------------------------------------------------------------------------------
class Console:
    defer_future_wallclock = True
    # 0.2.2 F1: a raw stream still running when the next token is requested would be the first thing the new permit
    # lets through, and the gate's step clock would start on it before the planner had read the plan (0.2.1 fleet
    # robot-1 scene 6; the TB3 console found the same on a real TurtleBot3 on 2026-09-16). End raw, wait for the
    # planner's acknowledgement and for its post-stop zero window (STOP_CMD_S 0.5 s in demo_io.py), then issue.
    RAW_STOP_CONFIRM_S = 2.0
    RAW_STOP_SETTLE_S = 0.6
    def __init__(self, stack, dashboard=None, feed=None):
        self.stack = stack
        self.dashboard = dashboard
        self.clock_id = "console-" + uuid.uuid4().hex
        self.events = ConsoleFeed() if feed is None else feed
        self.cond = threading.Condition()
        self.offsets = {}
        self.clock = {}
        self.clock_watch = ClockWatch(threshold=CLOCK_STEP_S)
        self.pose = None
        self.plan = None
        self.runtime = RuntimeTail(self.stack.logs / 'runtime', ROLES, self.clock_id)
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

    def tail(self):
        while not self.closed.is_set():
            try:
                rows = self.runtime.poll()
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
                        fresh, rejection = current_observation(r,self.seen_samples.get(role,(clock,-1)),self.started_at,time.time())
                        if rejection:r['observation_rejection_reason']=rejection
                        r['observation_current'] = bool(fresh)
                        if r.get('event') in ('plan_done','plan_timeout'):
                            r['plan_matches_current']=bool(self.plan and r.get('plan_id') and r['plan_id']==self.plan.get('id'))
                        if hasattr(self,'observe_record'):self.observe_record(r)
                        self.events.append(r)
                        if fresh:
                            self.seen_samples[role] = (clock, mono)
                            if r.get('event') == 'pose':
                                self.pose = r
                            elif r.get('event') == 'plan_done' and self.plan and r.get('plan_id') and r.get('plan_id') == self.plan.get('id') and not self.plan.get('ended'):
                                self.plan['ended'] = 'done'
                                self.plan['completion_observation']={'clock_id':clock,'mono':mono}
                                threading.Thread(target=self.record_move, args=(self.plan,), daemon=True).start()
                            elif r.get('event') == 'plan_timeout' and self.plan and r.get('plan_id') and r.get('plan_id') == self.plan.get('id') and not self.plan.get('ended'):
                                self.plan['ended'] = 'timeout'
                                threading.Thread(target=self.cancel_plan, args=(self.plan, 'plan_timeout'), daemon=True).start()
                    self.runtime.reader_error=None
                    if hasattr(self.events,'publish_health'):self.events.publish_health()
                    self.cond.notify_all()
            except (OSError, ValueError, sqlite3.Error) as exc:
                self.runtime.reader_error=exc.code if isinstance(exc,EventLogError) else 'OBSERVATION_READER_ERROR'
                self.emit('observation_error',code=self.runtime.reader_error)
                if hasattr(self.events,'publish_health'):self.events.publish_health(force=True)
                self.closed.wait(1)
            self.closed.wait(.05)

    def record_move(self, plan):
        """UI measurement only; require new samples from this plan's frame."""
        record_observed_move(self,plan,5.0)

    def cancel_plan(self, plan, why):
        try:
            r = self.stack.probe('cancel', '--plan', plan['id'])
            self.emit('plan_cancelled', plan=plan['id'], why=why, cancelled=bool(r.get('cancelled')))
        except (RuntimeError, ValueError, subprocess.TimeoutExpired) as ex:
            self.emit('console_error', path='cancel', detail=str(ex))

    # -- actions ---------------------------------------------------------------------
    def command(self, text):
        parsed = parse(text)
        if 'error' in parsed:
            self.emit('parse_error', text=text, detail=parsed['error'])
            return dict(parsed, accepted=False)
        if parsed.get('stop'):
            stop_id = uuid.uuid4().hex
            self.emit('stop_requested', text=text, stop_id=stop_id)
            control = self.stack.write_control(instruction=True, mode='idle', steps=[], override_linear=None, stop_id=stop_id)
            self.emit('stop_dispatched', stop_id=stop_id, instruction=control['instruction'], delivery=None)
            plan, cancelled = self.plan, None
            if plan and not plan.get('ended'):
                r = self.stack.probe('cancel', '--plan', plan['id'])
                cancelled = bool(r.get('cancelled'))
                if cancelled:
                    plan['ended'] = 'cancelled'
            self.emit('stopped', text=text, stop_id=stop_id, plan=plan['id'] if plan else None, cancelled=cancelled)
            return dict(parsed, accepted=False, cancelled=cancelled)
        if parsed.get('skill'):
            return self.skill(parsed['skill'], text)
        return self.submit(text, parsed['steps'], parsed['explain'])

    def _issued(self, text, r, steps, explain, mode, **control):
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
        run = [dict(s, token=t['id']) for s, t in zip(steps, tokens)] if steps else []
        with self.cond:
            self.plan = {'id': r.get('plan'), 'chain': r.get('chain'), 'text': text, 'start': self.pose, 'ended': None}
        self.emit('issued', text=text, plan=r.get('plan'), chain=r.get('chain'), tokens=[{'id': t['id'], 'skill': t.get('skill'), 'constraints': t['constraints']} for t in tokens])
        self.stack.write_control(instruction=True, mode=mode, steps=run, plan_id=r.get('plan'), **control)
        return {'accepted': True, 'plan': r.get('plan'), 'tokens': tokens, 'steps': run, 'explain': explain}

    def wait_ack(self, instruction, timeout):
        """True once the planner recorded that it read instruction number `instruction`."""
        end = time.monotonic() + timeout
        with self.cond:
            while time.monotonic() < end:
                if any(e.get('source') == 'planner' and e.get('event') == 'instruction' and e.get('instruction') == instruction for e in self.events):
                    return True
                self.cond.wait(max(0.0, end - time.monotonic()))
        return False

    def end_raw_before_issue(self, text):
        """None when nothing streams (or the stream ended and settled); a refusal when the planner never confirmed."""
        if self.stack.control.get('mode') != 'raw':
            return None
        t0 = time.monotonic()
        c = self.stack.write_control(instruction=True, mode='idle', steps=[], override_linear=None)
        if not self.wait_ack(c['instruction'], self.RAW_STOP_CONFIRM_S):
            detail = 'the planner did not confirm the end of the raw drive within %.1f s; no token was requested' % self.RAW_STOP_CONFIRM_S
            self.emit('raw_stop_unconfirmed', text=text, instruction=c['instruction'], detail=detail)
            return {'accepted': False, 'reason': 'RAW_STOP_UNCONFIRMED', 'detail': detail}
        time.sleep(self.RAW_STOP_SETTLE_S)
        self.emit('raw_ended', acknowledged=True, waited_s=round(time.monotonic() - t0, 3))
        return None

    def submit(self, text, steps, explain, override_linear=None):
        refused = self.end_raw_before_issue(text)
        if refused:
            return refused
        self.emit('plan', text=text, steps=steps, explain=explain)
        r = self.stack.probe('submit', '--steps', json.dumps([{k: s[k] for k in ('linear', 'angular', 'duration')} for s in steps]), '--target', TARGET)
        return self._issued(text, r, steps, explain, 'plan', override_linear=override_linear)

    def skill(self, name, text=None):
        if name not in SKILLS:
            self.emit('parse_error', text=text or name, detail='unknown skill %r' % name)
            return {'accepted': False, 'error': 'unknown skill'}
        refused = self.end_raw_before_issue(text or name)
        if refused:
            return refused
        explain = ['robot.do %s (skill, class %s)' % (name, SKILLS[name])]
        self.emit('plan', text=text or name, steps=[], explain=explain, skill=name)
        r = self.stack.probe('skill', '--name', name, '--classes', SKILLS[name], '--duration', '3')
        return self._issued(text or name, r, [], explain, 'skill', skill=name, override_linear=None)

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
            if safety not in ('OK', 'STALE'):
                raise ValueError('safety must be OK or STALE (the fake cannot be made UNSAFE)')
            ch['safety'] = safety
        self.stack.write_control(**ch)
        self.emit('inputs', **ch)
        return {'ok': True}

    def fault(self, service, action):
        r = self.stack.fault(service, action)
        self.emit('fault', **r)
        return r

    def unlock(self):
        r = self.stack.probe('unlock')
        self.emit('unlock', **r)
        return r

    def verify(self):
        r = self.stack.probe('verify', timeout=90)
        out = {'ok': bool(r.get('ok')), 'output': r.get('output', ''), 'dashboard': None}
        if self.dashboard is not None:
            try:
                now_ms = int(time.time() * 1000)
                q = 'robot=robot-1&from_ms=%d&to_ms=%d' % (now_ms - 6 * 3600 * 1000, now_ms)
                with urllib.request.urlopen('http://127.0.0.1:%d/v1/ledger/events?%s' % (self.dashboard.port, q), timeout=5) as resp:
                    body = json.loads(resp.read())
                rows = body.get('rows') or []
                out['dashboard'] = {'ok': bool(rows), 'rows': len(rows), 'verify': body.get('verify'), 'url': self.dashboard.url}
            except (OSError, ValueError) as ex:
                out['dashboard'] = {'ok': False, 'detail': str(ex), 'url': self.dashboard.url}
        self.emit('ledger_verified', ok=out['ok'], output=out['output'][-600:], dashboard=out['dashboard'])
        return out

    def restart_robot(self):
        self.emit('robot_restarting')
        self.stack.restart_robot()
        self.emit('robot_restarted')
        return {'ok': True}

    def state(self):
        return {'limits': LIMITS, 'units': UNITS, 'cruise': CRUISE, 'stop_window_s': STOP_WINDOW_S, 'per_call_max_m': LIMITS['sls.linear_mps'] * LIMITS['step.max_duration_s'],
                'per_call_max_rad': LIMITS['sls.angular_rps'] * LIMITS['step.max_duration_s'], 'control': self.stack.control,
                'position_source': 'simulation', 'position_note': 'integral of the velocity robotd --fake reports as applied',
                'robot': 'microduck', 'target': TARGET, 'skills': SKILLS, 'safety_levels': ['OK', 'STALE'],
                'dashboard_url': self.dashboard.url if self.dashboard else None, 'live_feed': False}


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
            path = urllib.parse.urlsplit(self.path).path
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
                if self.path == '/api/plan':
                    return self.send(200, console.submit(req.get('text', 'plan'), req['steps'], req.get('explain', []), req.get('override_linear')))
                if self.path == '/api/skill':
                    return self.send(200, console.skill(str(req.get('name', ''))))
                if self.path == '/api/rogue':
                    return self.send(200, console.rogue(req.get('linear')))
                if self.path == '/api/raw':
                    return self.send(200, console.raw(float(req['linear']), float(req.get('angular', 0)), float(req['duration'])))
                if self.path == '/api/inputs':
                    return self.send(200, console.feed(req.get('tag'), req.get('safety')))
                if self.path == '/api/fault':
                    return self.send(200, console.fault(str(req.get('service', 'agent')), str(req.get('action', ''))))
                if self.path == '/api/unlock':
                    return self.send(200, console.unlock())
                if self.path == '/api/verify':
                    return self.send(200, console.verify())
                if self.path == '/api/restart_robot':
                    return self.send(200, console.restart_robot())
            except (KeyError, ValueError, RuntimeError, subprocess.TimeoutExpired) as ex:
                console.emit('console_error', path=self.path, detail=str(ex))
                return self.send(400, {'error': str(ex)})
            return self.send(404, {'error': 'not found'})
    return H


def selftest():
    """Offline checks (no Docker): command language and refusal sentences."""
    fails = []

    def check(name, ok, got):
        print(('PASS ' if ok else 'FAIL ') + name + ('' if ok else ' — ' + repr(got)))
        if not ok:
            fails.append(name)
    cases = {
        'forward 1 m': [(0.1, 0.0, 10.25)], '앞으로 1m': [(0.1, 0.0, 10.25)], 'back 0.5 m': [(-0.1, 0.0, 5.25)],
        'left 90 deg': [(0.0, 0.5, 3.39)], 'forward 1 m at 0.3 m/s': [(0.3, 0.0, 3.58)], 'left 1 m': [(0.0, 0.5, 3.39), (0.1, 0.0, 10.25)],
    }
    for text, want in cases.items():
        got = [(s['linear'], s['angular'], s['duration']) for s in parse(text).get('steps', [])]
        check('parse %r' % text, got == want, got)
    check('parse wave as a skill', parse('wave').get('skill') == 'wave' and parse('손 흔들어').get('skill') == 'wave', parse('wave'))
    check('parse rejects nonsense', 'error' in parse('dance'), parse('dance'))
    w = warning([{'linear': 0.1, 'angular': 0.0, 'duration': 50.25}], [{'name': 'step.max_duration_s', 'requested': 50.25, 'max': 12}])
    check('duration refusal names the requested distance and the reach', w and '5.00 m' in w[0]['en'] and '1.18 m' in w[0]['en'] and '5.00 m' in w[0]['ko'], w)
    print('SELFTEST=%s' % ('PASS' if not fails else 'FAIL'))
    return 0 if not fails else 1


def port_check(ports, hint, hold=()):
    """Refuse before any state, build or provisioning when a needed local port is busy.

    ports: [(label, port)]. Returns {label: socket} for the labels in `hold` — those stay
    bound and listening until the caller hands the port over — or None when a port is busy.
    The console is bound for real right after this. The dashboard binds its own port much
    later (after the image build, minutes on a cold cache), so its port is HELD here and
    released only at the instant the dashboard process is started; probing alone would leave
    the whole build as a window in which another process could take it.
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
    ap.add_argument('action', choices=['up','start','build','parse','selftest','status','inspect','stop','resume','recover','adopt'])
    ap.add_argument('--json', action='store_true', help='machine-readable lifecycle status')
    ap.add_argument('--confirm-stopped', action='store_true', help='explicit legacy fleet adoption acknowledgement')
    ap.add_argument('--fleet', type=Path, help='strict software fleet YAML; requires a prepared image and new state')
    ap.add_argument('--state', type=Path)
    ap.add_argument('--robot-id', help='explicit single-robot identity; mutually exclusive with --fleet')
    ap.add_argument('--port', type=int, default=8767)
    ap.add_argument('--dashboard-port', type=int, default=18092)
    ap.add_argument('--no-dashboard', action='store_true', help='console only; do not build or start pail_telemetryd')
    ap.add_argument('--dashboard-binary', help='reuse a pail_telemetryd binary built earlier by this tool (developer shortcut)')
    ap.add_argument('--skip-build', action='store_true', help='reuse --image instead of building (developer shortcut; not a clean-build claim)')
    ap.add_argument('--image', default=None)
    ap.add_argument('--build', action='store_true', help='explicitly prepare artifacts before start')
    ap.add_argument('--build-record', type=Path, help='prepared image/native artifact receipt outside source')
    ap.add_argument('--build-window-confirmed', action='store_true', help='operator confirms a software-only/isolated build window')
    ap.add_argument('--trust-profile', type=Path, help='operator-owned read-only trust inspection profile; no signing or application from the console')
    ap.add_argument('text', nargs='*')
    a = ap.parse_args()
    if a.trust_profile is not None:
        if a.action not in ('up','start'):
            ap.error('--trust-profile is a startup observation option')
        if a.fleet is not None:ap.error('fleet trust inspection requires per-robot profiles; global --trust-profile is unsupported')
        from ops_state import load_private
        profile = load_private(a.trust_profile)
        if not isinstance(profile,dict):ap.error('trust profile must be an object')

    if a.action == 'parse':
        print(json.dumps(parse(' '.join(a.text)), ensure_ascii=False))
        return 0
    if a.action == 'selftest':
        return selftest()
    if a.action in ('status','inspect','stop','resume','recover','adopt'):
        if a.state is None:ap.error('lifecycle requires --state')
        if a.image is not None or a.skip_build or a.build or a.build_record or a.build_window_confirmed:ap.error('lifecycle uses the pinned image; image/build overrides are not allowed')
        if a.robot_id or (a.fleet and a.action!='adopt'):ap.error('lifecycle uses the stored fleet identity')
        try:
            from fleet_runtime import manage
            return manage(a)
        except (ValueError,OSError,RuntimeError,KeyError,subprocess.SubprocessError,sqlite3.Error) as ex:
            print(json.dumps({'error':str(ex),'action':a.action,'outcome':'RECOVERY_REQUIRED'}));return 2
    if a.fleet and a.robot_id is not None:ap.error('--fleet and --robot-id are mutually exclusive')
    try:
        if a.fleet:
            from fleet import load_config
            load_config(a.fleet)
        if a.robot_id is not None:
            from fleet import ROBOT_ID
            if not ROBOT_ID.fullmatch(a.robot_id):raise ValueError('CONFIG_ROBOT_ID')
    except (ValueError,OSError) as ex:
        print(str(ex),file=sys.stderr);return 2
    if a.action!='build' and a.state is not None:
        state_path=a.state.resolve()
        if a.state.is_symlink() or state_path==ROOT or ROOT in state_path.parents or (state_path.exists() and (not state_path.is_dir() or any(state_path.iterdir()))):
            print('NEW_EMPTY_STATE_OUTSIDE_SOURCE_REQUIRED',file=sys.stderr);return 2
    build_ports={}
    if a.action!='build':
        # ports before the issuer-image lookup: a busy port is refused in zero seconds with its own name whatever
        # else is missing (P24-N1, executed bind-first pin)
        wanted=[('console',a.port)] + ([] if a.no_dashboard or a.fleet or a.robot_id else [('dashboard',a.dashboard_port)])
        build_ports=port_check(wanted,'--port 8787 --dashboard-port 18107',hold=tuple(x[0] for x in wanted))
        if build_ports is None:return 2
    try:
        if a.action != 'build':preview.require_issuer()
    except ValueError as ex:
        for held_port in build_ports.values():held_port.close()
        print(str(ex),file=sys.stderr);return 2
    try:
        prepared=select_prepared('microduck',a,ROOT,needs_dashboard=not (a.no_dashboard or a.fleet or a.robot_id))
        if a.action=='build':
            print(json.dumps(prepared));return 0
        a.image=prepared['images']['runtime']
        if prepared.get('dashboard'):a.dashboard_binary=prepared['dashboard']['path']
        a.skip_build=True
    except (BuildRequired,ValueError,OSError,subprocess.SubprocessError) as ex:
        print(str(ex),file=sys.stderr);return 2
    finally:
        for held_port in build_ports.values():held_port.close()
    if a.fleet and a.robot_id:
        ap.error('--fleet and --robot-id are mutually exclusive')
    if a.fleet or a.robot_id:
        if a.state is None:
            ap.error('--fleet requires --state')
        from fleet_runtime import main as fleet_main
        try:return fleet_main(a)
        except (ValueError,OSError,RuntimeError,KeyError,subprocess.SubprocessError,sqlite3.Error) as ex:
            print(json.dumps({'error':str(ex),'action':a.action,'outcome':'FAILED'}));return 2
    try:
        preview.require_issuer()
    except ValueError as ex:
        print(str(ex), file=sys.stderr)
        return 2
    if os.name != 'posix':
        print('Native Windows is not supported by this demo. Use Linux/macOS.', file=sys.stderr)
        return 2
    if not shutil.which('docker'):
        print('Missing prerequisite: docker', file=sys.stderr)
        return 2
    # Ports first: a busy port must fail in zero seconds with its own name, before mkdtemp,
    # the image build or provisioning (2026-09-18: the dashboard port used to fail ~33 s in,
    # as "did not answer /healthz", leaving a state directory that blocked the retry).
    wanted = [('console', a.port)] + ([] if a.no_dashboard else [('dashboard', a.dashboard_port)])
    held = port_check(wanted, 'python3 examples/microduck/demo.py up --port 8777 --dashboard-port 18097',
                      hold=('dashboard',))
    if held is None:
        return 2
    state = (a.state or Path(tempfile.mkdtemp(prefix='pail-duck-demo-'))).resolve()
    if state == ROOT or ROOT in state.parents:
        raise SystemExit('state must be outside the source tree')
    if state.exists() and any(state.iterdir()):
        raise SystemExit('state must be empty')
    state.mkdir(parents=True, exist_ok=True)
    state.chmod(0o755)
    release = release_id(ROOT)
    project = project_name('duck-demo', release)   # the release and a per-run value are readable from `docker ps`
    stack = Stack(state, a.image, project, issuer_image=preview.require_issuer())
    dashboard = None if a.no_dashboard else Dashboard(state, a.dashboard_port, a.dashboard_binary, build=False,
                                                      holder=held.get('dashboard'))
    print('STATE=' + str(state), flush=True)

    def stop_on_term(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop_on_term)
    trust_cache = None
    started = False
    try:
        srv = Server(('127.0.0.1', a.port), None)  # bind first: a busy console port fails before any build or provisioning
        stack.setup(build=False)
        if dashboard:
            dashboard.prepare(state / 'evidence/dashboard-build.log')
        stack.up()
        started = True
        if dashboard:
            dashboard.start(state / 'evidence/dashboard.log')
            print('DASHBOARD=' + dashboard.url + ' (ledger mirror of this run; no live decision feed on this robot class)', flush=True)
        console = Console(stack, dashboard)
        if a.trust_profile is not None:
            from trust_observation import TrustObservationCache
            trust_cache=TrustObservationCache(a.trust_profile)
            console.events.attach_trust(trust_cache.snapshot)
        else:   # preview.40 review item 11: say which trust mode this run uses even without an operator profile
            from trust_observation import launcher_observation
            console.events.attach_trust(lambda: launcher_observation('unsigned-dev'))

        srv.RequestHandlerClass = handler_for(console)
        (state / 'evidence' / 'console.json').write_text(json.dumps({'url': 'http://127.0.0.1:%d/' % a.port, 'project': project, 'release': release, 'image': stack.image, 'dashboard': dashboard.url if dashboard else None}))
        print('CONSOLE=http://127.0.0.1:%d/' % a.port, flush=True)
        console.emit('ready', limits=LIMITS, dashboard=dashboard.url if dashboard else None)
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if trust_cache is not None:trust_cache.close()
        if dashboard:
            dashboard.stop()
        if started or (state / 'evidence' / 'up.log').exists():
            try:print('Stopping the stack…', flush=True)
            except BrokenPipeError:pass
            stack.down()
    return 0


if __name__ == '__main__':
    # a failure ends with a named refusal line, never a bare traceback (class pin C2)
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError) as exc:
        print('DEMO_REFUSED: ' + str(exc), file=sys.stderr, flush=True)
        sys.exit(2)
