#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""TB3 live demo console for a REAL TurtleBot3 — runs on the operator PC.

  python3 examples/tb3/hardware/console_hw.py --state /tmp/new-dir --robot ubuntu@robot.local \\
      --rig-dir /home/ubuntu/pail-hw --issuer 192.0.2.10:50064 --certs /path/config/grpc_certs \\
      --operator-key /path/config/keys/operator_ed25519.json --journal /path/state/blackbox \\
      --issuer-key /path/config/keys/issuer_ed25519.json --tool-image pail/tb3-cloud:<tag>

Reuses the public demo console (examples/tb3/demo.py: command language, refusal sentences,
event stream, page and the same HTTP API the judge drives) with a different stack underneath:

  requester → issuer   this PC, mTLS with the robot's client certificate (tb3-probe)
  instruction → robot  ssh atomic write of control/demo.json in the rig directory
  robot → console      ssh `docker logs -f` of the demo participants, mirrored to local JSONL
  ledger verify        blackbox_verify on the issuer's journal directory on this PC
  restart robot side   ssh start_demo_rig.sh restart-gate

tb3-probe and blackbox_verify run from --tool-image (the public cloud image; the files they
need are bind-mounted read-only at their own paths) unless --probe-bin/--verify-bin name
native binaries. The position shown is wheel odometry from the real encoders. With raised
wheels it is how far the wheels turned, not how far a robot on the floor would travel.
"""
import argparse, inspect, json, math, os, shlex, signal, subprocess, sys, threading, time, uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import demo  # noqa: E402

AUTHORIZATION_RESERVE_S = 0.35  # 0.10 discovery + 0.25 stop budget, submitted to the Issuer

ROLES = {'planner': 'pailhw-planner', 'base': 'pailhw-robot', 'drive': 'pailhw-drive', 'safety': 'pailhw-safety', 'evidence': 'pailhw-evidence'}


def validate_tool_platform(a, platform=None):
    if (platform or sys.platform) == 'darwin' and not (a.probe_bin and a.verify_bin):
        raise ValueError('macOS hardware console requires native tools: run hardware/build_native_tools.sh, then use --probe-bin and --verify-bin (HARDWARE.md section 5)')


def remote_sample_rejection(row, reference, now, last=-1):
    """Why a row is not current under the remote-clock policy, or None when it is (P37-N2: the reason is recorded,
    not only the verdict).

    The remote clock was queried AFTER these rows were received. Charge the ENTIRE SSH round trip plus local
    processing delay to sample age. No equal-PC/robot-wall-clock assumption and no replay-as-current fallback.
    """
    mono = row.get('mono')
    if not reference or reference.get('clock_id') == 'unavailable':
        return 'REMOTE_REFERENCE_MISSING'
    if row.get('replayed'):
        return 'REPLAYED'
    if isinstance(mono, bool) or not isinstance(mono, (int, float)) or not math.isfinite(mono):
        return 'INVALID_CLOCK_SAMPLE'
    if row.get('clock_id') != reference['clock_id']:
        return 'CLOCK_ID_CHANGED'
    if mono <= last:
        return 'DUPLICATE_OR_REORDERED'
    remote_age = reference['remote_mono'] - mono
    transport_upper = now - reference['before']
    row['freshness_basis'] = 'remote-monotonic-query-upper-bound'
    row['age_upper_s'] = remote_age + transport_upper
    if remote_age < 0 or transport_upper < 0:
        return 'REMOTE_CLOCK_REVERSED'
    if row['age_upper_s'] > 2.0:
        return 'AGE_UPPER_BOUND'
    return None


def remote_sample_current(row, reference, now, last=-1):
    """Boolean form of remote_sample_rejection (the verdict alone)."""
    return remote_sample_rejection(row, reference, now, last) is None


def clock_identity():
    # Namespace inode numbers may differ even when CLOCK_MONOTONIC has the same
    # kernel origin and offset. Compare the boot and the actual monotonic offset.
    try:
        with open('/proc/sys/kernel/random/boot_id') as f:
            boot = f.read().strip()
        with open('/proc/self/timens_offsets') as f:
            rows = [line.split() for line in f if line.split() and line.split()[0] == 'monotonic']
        if not boot or len(rows) != 1 or len(rows[0]) != 3:
            return 'unavailable'
        seconds, nanos = int(rows[0][1]), int(rows[0][2])
        return boot + ':monotonic-offset-ns=' + str(seconds * 1000000000 + nanos)
    except (OSError, ValueError):
        return 'unavailable'


# Keep the loaded definition with the running process. Re-reading an edited
# source file through inspect on every request can select the wrong function.
CLOCK_IDENTITY_SOURCE = inspect.getsource(clock_identity)


def checked_limits(limits, override):
    names = set(demo.UNITS)
    if not isinstance(limits, dict) or set(limits) != names:
        raise ValueError('policy must define exactly the three TB3 twist limits')
    for name, value in limits.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
            raise ValueError('invalid positive finite policy limit: ' + name)
    if override is not None:
        supplied = json.loads(override)
        checked_limits(supplied, None)
        if supplied != limits:
            raise ValueError('--limits disagrees with the selected policy; remove the override or correct the configuration')
    return dict(limits)


def policy_display(a):
    """Offline metadata only: mount policy inputs, never private keys, into the parser."""
    config = (a.config or a.certs.parent).resolve()
    paths = [config / 'policy.yaml', config / 'site_model.yaml', *sorted(config.glob('skills.*.yaml'))]
    if len(paths) < 3 or any(not p.is_file() for p in paths):
        raise ValueError('missing policy, site model or skill registry in ' + str(config))
    if a.probe_bin:
        cmd = [str(a.probe_bin)]
    else:
        cmd = ['docker', 'run', '--rm', '--network', 'none', '-u', str(os.getuid()) + ':' + str(os.getgid())]
        for p in paths:
            cmd += ['-v', '%s:%s:ro' % (p, p)]
        cmd += [a.tool_image, 'tb3-probe']
    p = subprocess.run(cmd + ['-mode', 'limits', '-config', str(config), '-robot', a.robot_id, '-target', a.target],
                       capture_output=True, text=True, timeout=60)
    if p.returncode:
        raise ValueError('policy display resolution failed: ' + p.stderr[-1200:])
    source = json.loads(p.stdout)
    limits = checked_limits(source['limits'], a.limits)
    source['config_directory'] = str(config)
    return limits, source


class RemoteStack:
    def __init__(self, a, state):
        self.a, self.state = a, state
        self.logs = state / 'evidence'
        (self.logs / 'runtime').mkdir(parents=True, exist_ok=True)
        self.ssh_base = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-o', 'ControlMaster=auto',
                         '-o', 'ControlPath=/tmp/pail-hw-ssh-%r@%h', '-o', 'ControlPersist=600', a.robot]
        self.seq = 0
        self.control = {'seq': 0, 'instruction': 0, 'mode': 'idle', 'steps': [], 'tag': a.target, 'safety': 'OK'}
        self.lock = threading.Lock()
        self.started = time.time()
        # P023-M1: the mirror children and the ssh multiplexing master belong to THIS process and are ended by
        # shutdown(). An orphaned `docker logs -f` never ends, so it held ControlPersist open past its 600 s and
        # the next console start was refused by the robot's sshd (reported as an unmeasurable clock).
        self.mirrors = []
        self.stopping = threading.Event()

    def ssh(self, command, stdin=None, timeout=60):
        return subprocess.run(self.ssh_base + [command], input=stdin, capture_output=True, text=True, timeout=timeout)

    def write_control(self, instruction=False, **changes):
        with self.lock:
            self.seq += 1
            self.control = dict(self.control, **changes, seq=self.seq)
            if instruction:
                self.control['instruction'] = self.control.get('instruction', 0) + 1
            body = json.dumps(self.control)
            # Timestamp the publication on the robot, bracketing the atomic rename. No PC/robot subtraction.
            writer = "import json,os,sys,time\n" + CLOCK_IDENTITY_SOURCE + """
os.chdir(sys.argv[1])
body=sys.stdin.read()
with open('demo.next','w') as f:
 f.write(body);f.flush();os.fsync(f.fileno())
os.chmod('demo.next',0o644)
clock=clock_identity()
a=time.monotonic();os.replace('demo.next','demo.json');b=time.monotonic()
print(json.dumps(dict(clock_id=clock,published_before_mono=a,published_after_mono=b)))
"""
            p = self.ssh('python3 -c %s %s' % (shlex.quote(writer), shlex.quote(self.a.rig_dir + '/control')), stdin=body)
            if p.returncode:
                raise RuntimeError('control write failed on the robot: ' + (p.stderr or p.stdout)[-300:])
            with (self.logs / 'control-writes.jsonl').open('a') as f:
                f.write(json.dumps(dict(t=time.time(), control=self.control)) + '\n')
            return dict(self.control, _delivery=json.loads(p.stdout))

    # -- tools: native binaries, or the public cloud image with the needed files mounted at their own paths
    def tool(self, name, files, network=True):
        native = self.a.probe_bin if name == 'tb3-probe' else self.a.verify_bin
        if native:
            return [str(native)]
        cmd = ['docker', 'run', '--rm', '-u', '0']
        if not network:
            cmd += ['--network', 'none']
        for f in files:
            cmd += ['-v', '%s:%s:ro' % (f, f)]
        return cmd + [self.a.tool_image, name]

    def probe(self, *args):
        a = self.a
        ca, cert, key = a.certs / 'ca.crt', a.certs / a.robot_id / 'client.crt', a.certs / a.robot_id / 'client.key'
        cmd = self.tool('tb3-probe', [ca, cert, key, a.operator_key]) + [*args, '-addr', a.issuer, '-robot', a.robot_id, '-target', a.target,
                                                                        '-ca', str(ca), '-cert', str(cert), '-key', str(key), '-operator-key', str(a.operator_key)]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if p.returncode:
            raise RuntimeError('tb3-probe rc=%d: %s' % (p.returncode, (p.stderr or p.stdout).strip()[-400:]))
        out = json.loads(p.stdout.strip().splitlines()[-1])
        with (self.logs / 'probe.jsonl').open('a') as f:
            f.write(json.dumps(dict(t=time.time(), args=list(args), out=out)) + '\n')
        return out

    def exec_issuer(self, *args, timeout=90):
        if args and args[0] == 'blackbox_verify':
            cmd = self.tool('blackbox_verify', [self.a.journal, self.a.issuer_key], network=False) + \
                ['-check-chain', '-dir', str(self.a.journal), '-keyfile', str(self.a.issuer_key)]
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return p.returncode, p.stdout, p.stderr
        raise RuntimeError('unsupported issuer command on the hardware console: %s' % (args,))

    def restart_robot(self):
        self.write_control(instruction=True, mode='idle', steps=[], override_linear=None)
        p = self.ssh('%s/start_demo_rig.sh restart-gate' % shlex.quote(self.a.rig_dir), timeout=270)
        if p.returncode:
            raise RuntimeError('gate restart/IO readiness failed: ' + (p.stderr or p.stdout)[-600:])
        if 'GATE_RESTARTED' not in p.stdout:
            raise RuntimeError('gate restart completion marker missing')

    def mirror(self, role, container):
        """ssh docker logs -f → local JSONL (the console tails local files)."""
        out = self.logs / 'runtime' / ('demo-%s.jsonl' % role)
        since = int(self.started - 5)
        last_t = 0.0  # `--since` has one-second resolution: a reconnect replays that second
        while not self.stopping.is_set():
            proc = subprocess.Popen(self.ssh_base + ['docker logs -f --since %d %s 2>&1' % (since, container)], stdout=subprocess.PIPE, text=True)
            self.mirrors.append(proc)
            for line in proc.stdout:
                line = line.strip()
                if line.startswith('{') and '"event"' in line:
                    try:
                        row = json.loads(line)
                    except ValueError:
                        continue
                    t = float(row.get('t', 0))
                    if t <= last_t:
                        continue
                    last_t, since = t, max(since, int(t))
                    with out.open('a') as f:
                        f.write(json.dumps(row) + '\n')
            proc.wait()
            try:
                self.mirrors.remove(proc)
            except ValueError:
                pass
            if self.stopping.wait(2):  # container restarted or ssh dropped: resume; replayed rows are skipped by time
                break

    def shutdown(self):
        """End what this process started: the `ssh docker logs -f` mirrors first, then the multiplexing master.

        P023-M1: the mirror threads are daemons, so interpreter exit left their ssh children running under PID 1.
        Each one holds the ControlPersist master open, and after a few console restarts the robot's sshd refuses
        new sessions — which the next start reported only as a clock it could not measure."""
        self.stopping.set()
        for proc in list(self.mirrors):
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
            except OSError:
                pass
        try:    # `ssh -O exit` closes the mux master now instead of leaving it for ControlPersist
            subprocess.run(self.ssh_base[:-1] + ['-O', 'exit', self.ssh_base[-1]], capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.SubprocessError):
            pass


class HardwareConsole(demo.Console):
    # This console brackets the robot monotonic clock; host wall time is not its freshness clock.
    defer_future_wallclock = False
    def __init__(self, stack, placement):
        self.stack, self.placement = stack, placement
        self.prepare_sample_batch([True])
        if not self.remote_reference or self.remote_reference['clock_id'] == 'unavailable':
            # P023-M1: name WHY it could not be measured. An sshd that refuses new sessions (leaked mirrors of an
            # earlier console) reads nothing like a clock problem, and that was the whole refusal line before.
            why = getattr(self, 'clock_failure', None)
            raise ValueError('robot monotonic clock could not be measured; hardware observation is not ready' +
                             (' — ' + why if why else ''))
        self.start_reference = dict(self.remote_reference)
        super().__init__(stack)

    def prepare_sample_batch(self, rows):
        self.remote_reference = None
        self.clock_failure = None
        if not rows:
            return
        before = time.monotonic()
        script = 'import json,time\n' + CLOCK_IDENTITY_SOURCE + "\nprint(json.dumps(dict(clock_id=clock_identity(),mono=time.monotonic())))"
        try:
            p = self.stack.ssh('python3 -c ' + shlex.quote(script), timeout=3)
            if p.returncode:
                self.clock_failure = 'ssh rc=%d: %s' % (p.returncode, ((p.stderr or '') + (p.stdout or '')).strip()[-300:])
                return
            measured = json.loads(p.stdout)
            self.remote_reference = dict(clock_id=measured['clock_id'], remote_mono=measured['mono'],
                                         before=before, after=time.monotonic())
            with (self.stack.logs / 'remote-clock-brackets.jsonl').open('a') as f:
                f.write(json.dumps(self.remote_reference) + '\n')
        except (ValueError, KeyError, OSError, subprocess.TimeoutExpired) as ex:
            # unmeasured is not current; raw events remain in the record — but the cause is kept for the refusal
            self.clock_failure = type(ex).__name__ + ': ' + str(ex)[-300:]

    def sample_is_current(self, row):
        # P37-N2: a row that is not current carries why (observation_rejection_reason); the tail loop records a
        # rejected completion with that reason and ends the plan only for AGE_UPPER_BOUND
        reason = self.sample_rejection(row)
        if reason:
            row['observation_rejection_reason'] = reason
        return reason is None

    def sample_rejection(self, row):
        if row.get('clock_id') != self.start_reference['clock_id']:
            return 'CLOCK_ID_CHANGED'
        if not isinstance(row.get('mono'), (int, float)):
            return 'INVALID_CLOCK_SAMPLE'
        if row['mono'] < self.start_reference['remote_mono']:
            return 'PRE_START'
        role = row['source']
        previous = self.seen_samples.get(role, (row.get('clock_id'), -1))
        if previous[0] != row.get('clock_id'):
            return 'CLOCK_ID_CHANGED'
        return remote_sample_rejection(row, getattr(self, 'remote_reference', None),
                                       time.monotonic(), previous[1])

    def submit(self, text, steps, explain, override_linear=None):
        # Reserve before issuance, never extend an existing signed token. Keep
        # invalid original requests unchanged so the issuer reports their real fault.
        legal_shape = all(0 < s['duration'] <= demo.LIMITS['step.max_duration_s'] and
                          abs(s['linear']) <= demo.LIMITS['sls.linear_mps'] and
                          abs(s['angular']) <= demo.LIMITS['sls.angular_rps'] for s in steps)
        if legal_shape:
            steps = [dict(s, motion_duration=s['duration'],
                          duration=s['duration'] + AUTHORIZATION_RESERVE_S) for s in steps]
            explain = str(explain) + ' (authorization includes %.2fs startup/stop reserve per step)' % AUTHORIZATION_RESERVE_S
        return super().submit(text, steps, explain, override_linear=override_linear)

    def state(self):
        s = super().state()
        s['policy_source'] = getattr(self, 'policy_source', None)
        available = max(0.0, demo.LIMITS['step.max_duration_s'] - AUTHORIZATION_RESERVE_S)
        s['per_call_max_m'] = demo.LIMITS['sls.linear_mps'] * available
        s['per_call_max_rad'] = demo.LIMITS['sls.angular_rps'] * available
        s['timing_profile'] = dict(authorization_reserve_s=AUTHORIZATION_RESERVE_S,
                                   motion_duration_separate=True, policy_limits_unchanged=True)
        s['position_source'] = 'encoders (%s)' % self.placement
        s['robot'] = 'TurtleBot3 (real base driver, %s)' % self.placement
        return s

    def feed(self, tag=None, safety=None):
        if tag == 'other-box':      # the page's "wrong tag" button speaks the reference ids
            tag = self.stack.a.other_tag
        elif tag == 'sample-box':
            tag = self.stack.a.target
        return super().feed(tag, safety)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--state', type=Path, required=True, help='new empty directory for this run\'s evidence')
    ap.add_argument('--port', type=int, default=8765)
    ap.add_argument('--placement', choices=['raised', 'floor'], default='raised')
    ap.add_argument('--robot', required=True, help='ssh destination of the robot, e.g. ubuntu@robot.local')
    ap.add_argument('--rig-dir', required=True, help='directory on the robot holding start_demo_rig.sh and control/')
    ap.add_argument('--issuer', required=True, help='issuer host:port reachable from this PC')
    ap.add_argument('--robot-id', default='robot-01')
    ap.add_argument('--target', default='sample-box', help='target object id of every plan (site model)')
    ap.add_argument('--other-tag', default='other-box', help='the tag the "wrong tag" button selects')
    ap.add_argument('--certs', type=Path, required=True, help='directory with ca.crt and <robot-id>/client.{crt,key}')
    ap.add_argument('--operator-key', type=Path, required=True, help='operator signing key JSON (unlock)')
    ap.add_argument('--journal', type=Path, required=True, help='the issuer\'s blackbox journal directory on this PC')
    ap.add_argument('--issuer-key', type=Path, required=True, help='issuer key JSON (its public half verifies the journal)')
    ap.add_argument('--tool-image', default='', help='public cloud image providing tb3-probe and blackbox_verify')
    ap.add_argument('--probe-bin', type=Path, help='native tb3-probe instead of --tool-image')
    ap.add_argument('--verify-bin', type=Path, help='native blackbox_verify instead of --tool-image')
    ap.add_argument('--config', type=Path, help='issuer configuration directory; defaults to --certs parent (offline policy display, not live attestation)')
    ap.add_argument('--limits', help='optional assertion JSON; must equal the resolved policy (never overrides it)')
    a = ap.parse_args()
    if not a.tool_image and not (a.probe_bin and a.verify_bin):
        raise SystemExit('give --tool-image, or both --probe-bin and --verify-bin')
    try:
        validate_tool_platform(a)
    except ValueError as ex:
        raise SystemExit(str(ex))
    for k in ('probe_bin', 'verify_bin'):
        if getattr(a, k):
            setattr(a, k, getattr(a, k).resolve())
    for p in [a.certs / 'ca.crt', a.certs / a.robot_id / 'client.crt', a.certs / a.robot_id / 'client.key', a.operator_key, a.issuer_key, a.journal]:
        if not p.exists():
            raise SystemExit('missing: %s' % p)
    for k in ('certs', 'operator_key', 'journal', 'issuer_key'):
        setattr(a, k, getattr(a, k).resolve())
    state = a.state.resolve()
    if state.exists() and any(state.iterdir()):
        raise SystemExit('state must be empty')
    placement = 'raised wheels' if a.placement == 'raised' else 'floor'
    try:
        limits, policy_source = policy_display(a)
    except (ValueError, KeyError, OSError, subprocess.TimeoutExpired) as ex:
        raise SystemExit("policy display refused: " + str(ex))
    demo.LIMITS.clear()
    demo.LIMITS.update(limits)
    demo.ROLES[:] = list(ROLES.items())
    srv = demo.Server(('127.0.0.1', a.port), None)  # bind first: a busy port fails before anything touches the robot
    stack = RemoteStack(a, state)
    print('STATE=' + str(state), flush=True)
    try:
        stack.probe('-mode', 'peek')  # use the actual tool before any robot write
    except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired) as ex:
        (stack.logs / 'startup-error.txt').write_text(str(ex) + '\n')
        srv.server_close()
        print('STARTUP_REFUSED: cannot reach Issuer ' + a.issuer +
              '; check address/port, issuer_host.sh up and the matching mTLS certificates. Details: ' +
              str(stack.logs / 'startup-error.txt'), file=sys.stderr)
        return 1
    stack.write_control(instruction=True)  # a known idle instruction before anything else
    for role, container in ROLES.items():
        threading.Thread(target=stack.mirror, args=(role, container), daemon=True).start()
    console = HardwareConsole(stack, placement)
    console.policy_source = policy_source
    srv.RequestHandlerClass = demo.handler_for(console)
    (state / 'evidence' / 'console.json').write_text(json.dumps({'url': 'http://127.0.0.1:%d/' % a.port, 'robot': a.robot, 'issuer': a.issuer,
                                                                 'placement': placement, 'tool_image': a.tool_image, 'policy_source': policy_source}))
    print('CONSOLE=http://127.0.0.1:%d/' % a.port, flush=True)
    # the judge must target this console's port (P22-N3: the HARDWARE.md command defaulted to 8765 and, with the
    # console on another port, would have sent scenes to whatever answered there)
    print('JUDGE: python3 examples/tb3/demo_scenes.py --url http://127.0.0.1:%d --out "$PAIL_RESULTS_DIR/hw-raised-scenes.json"' % a.port, flush=True)
    console.emit('ready', limits=demo.LIMITS, policy_source=policy_source, position_source='encoders', placement=placement)

    def stop(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            stack.write_control(instruction=True, mode='idle', steps=[], override_linear=None)
        except Exception as ex:  # the robot side must still be told to stop; report if it could not be
            print('WARNING: could not write the idle instruction on exit: %s' % ex, file=sys.stderr)
        stack.shutdown()  # after the idle instruction: it needs the ssh connection this closes
    return 0


if __name__ == '__main__':
    # a failure ends with a named refusal line, never a bare traceback (class pin C2)
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError) as exc:
        print('CONSOLE_REFUSED: ' + str(exc), file=sys.stderr, flush=True)
        sys.exit(2)
