#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Live demo actors for the Microduck preview stack (no hardware). One process per role:

  planner   plays the AI requester: reads the console's instruction (/control/demo.json) and
            sends robot.move / robot.do on the PUBLIC socket only (uid 12345, public group).
            PAIL does not trust it; the adapter decides what reaches robotd. A command the
            adapter drops gets no reply, so "a reply arrived" is how the planner learns that
            its step is permitted.
  observer  its own connection to the RAW socket: hello + robot.subscribe only, never a
            command (the file is short on purpose). Integrates the velocity robotd --fake
            reports as APPLIED into a pose (source=simulation), records requested/applied,
            and copies the adapter's gate log (outcome/stop lines) into the shared record.
            Also drives the state seam (safety feed stale/fresh) for scene 8-S.
  evidence  synthetic identity reading on the adapter's evidence socket (the tag the
            console selects). Not a real NFC/RFID reader.
  ledger    mirrors the issuer's live journal (private volume, root only) into the shared
            evidence directory so a host-side dashboard can read it. Bytes are copied, never
            rewritten; the mirror is refreshed every second.

Instruction file /control/demo.json, written atomically by the console:
  {"seq": n, "instruction": k, "mode": "idle" | "plan" | "raw" | "skill",
   "steps": [{"linear": v, "angular": w, "duration": s, "token": id}, ...],
   "override_linear": null | v, "raw": {"linear": v, "angular": w, "duration": s},
   "skill": "wave", "tag": "box-12", "safety": "OK" | "STALE"}
seq changes on every write; instruction changes only when the planner's task changes, so
switching the tag or the safety seam never restarts a running plan.
Every observation is a JSON line under /evidence/runtime/demo-<role>.jsonl.
"""
import uuid
import hashlib
import argparse, json, math, os, shutil, socket, sys, threading, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import observation  # examples/common/observation.py, copied next to this file by the console

P = argparse.ArgumentParser()
P.add_argument('--role', choices=['planner', 'observer', 'evidence', 'ledger'], required=True)
A = P.parse_args()
OUT = Path('/evidence/runtime') / ('demo-' + A.role + '.jsonl')
CONTROL = Path('/control/demo.json')
from raw_retention import ObservationWriter,RotationManager
RAW_WRITER=ObservationWriter(OUT)
RAW_MANAGER=RotationManager(OUT.parent).start() if A.role=='observer' else None
if RAW_MANAGER is not None:
    import atexit
    atexit.register(RAW_MANAGER.close)
PUBLIC, RAW = '/run/duck/pail.sock', os.environ.get('PAIL_DEMO_RAW', '/run/duck/raw/robotd.sock')
GATE_LOG, EVIDENCE_SOCK, SEAM_CTL = '/run/duck/gate.ndjson', '/run/duck/evidence.sock', '/run/duck/state.ctl'
STOP_EARLY_S = 0.1   # keep one command period clear of the adapter's deadline (its clock started before this planner saw the first reply)
ZERO_S = 0.15        # zero-velocity commands sent INSIDE the permit before its deadline: robotd holds the last command for
#                      its deadman (~0.5 s) when a planner merely goes silent, which overshot a 90° turn to 102° (2026-09-16)
STOP_CMD_S = 0.5     # after a stop, command zero velocity this long: a stop is a command, not silence
HZ = 20.0


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


CLOCK_ID = clock_identity()
PRODUCER_ID = str(uuid.uuid4())
PRODUCER_SEQ = 0
FLEET_IDENTITY = {k: os.environ.get(v, '') for k, v in {
    'robot_id': 'PAIL_ROBOT_ID', 'run_id': 'PAIL_FLEET_RUN_ID',
    'deployment_id': 'PAIL_FLEET_DEPLOYMENT_ID', 'fleet_stream_id': 'PAIL_FLEET_STREAM_ID'}.items()}


RECORD_LOCK = threading.Lock()   # the upload thread records too; one sequence, whole lines


def record(event, **kw):
    global PRODUCER_SEQ
    with RECORD_LOCK:
        PRODUCER_SEQ += 1
        seq = PRODUCER_SEQ
        RAW_WRITER.append(dict(t=time.time(),mono=time.monotonic(),clock_id=CLOCK_ID,event=event,producer_instance_id=PRODUCER_ID,producer_seq=str(seq),**FLEET_IDENTITY,**kw))
    # Installer-bound, read-only observation input for the shared collector.
    # A velocity sample is software self-report, never physical stop proof.
    if A.role == 'observer' and FLEET_IDENTITY['run_id']:
        kind, value = None, None
        if event == 'motion_sample':
            a = kw['applied']
            kind = 'motion'
            value = {'state': 'OBSERVED_MOVING' if any(abs(v) > 1e-8 for v in a) else 'OBSERVED_ZERO',
                     'linear_mps': a[0], 'angular_rps': a[2], 'source_kind': 'simulation_applied_velocity',
                     'frame_id': FLEET_IDENTITY['fleet_stream_id'] + '/' + PRODUCER_ID}
        elif event == 'pose':
            kind = 'pose'
            value = {'state': 'OBSERVED', 'x_m': kw['x'], 'y_m': kw['y'], 'yaw_rad': kw['th'],
                     'frame_id': FLEET_IDENTITY['fleet_stream_id'] + '/' + PRODUCER_ID,
                     'source_kind': 'simulation_applied_velocity'}
        elif event == 'gate' and kw.get('state') in ('PERMIT', 'BLOCK'):
            kind, value = 'gate', {'state': kw['state']}
        if kind:
            write_observation(kind, value, seq)


# Upload (design 15): set on the observer when the fleet gives it a collector address and its
# own certificate. Records still go to the file; the collector of another machine gets them
# over the network, each made with the challenge of the collector's last answer.
PUSH_URL = os.environ.get('PAIL_OBSERVATION_PUSH_URL', '')
PUSHER = None
PUSH_LOCK = threading.Lock()
if PUSH_URL:
    PUSHER = observation.Pusher(observation.push_sender(PUSH_URL, os.environ['PAIL_OBSERVATION_PUSH_CA'],
                                                        os.environ['PAIL_OBSERVATION_PUSH_CERT'], os.environ['PAIL_OBSERVATION_PUSH_KEY']))


def push_loop():
    """Uploads in the background so that a slow or absent collector never holds the observer."""
    failing = False
    while True:
        time.sleep(0.1)
        with PUSH_LOCK:
            rows = PUSHER.begin(time.monotonic())
        if rows is None:
            continue
        # the network call runs outside the lock; the queue is changed only under it
        answer = PUSHER.upload(rows, FLEET_IDENTITY, PRODUCER_ID)
        with PUSH_LOCK:
            outcome = PUSHER.settle(rows, answer)
            queued, dropped = len(PUSHER.queue), PUSHER.dropped
        # a change of state is recorded, not every attempt
        if 'error' in outcome and not failing:
            failing = True
            record('push_failed', queued=queued, dropped=dropped, **outcome)
        elif 'error' not in outcome and failing:
            failing = False
            record('push_recovered', queued=queued, dropped=dropped, accepted=outcome.get('accepted'), replayed=outcome.get('replayed'))


def write_observation(kind, value, seq):
    row = observation.observation_row(FLEET_IDENTITY, kind, value, producer_id=PRODUCER_ID, seq=seq,
                                      clock_id=observation.clock_record_id(CLOCK_ID),
                                      wall_ms=int(time.time() * 1000), mono_ns=time.monotonic_ns())
    if PUSHER is not None:
        with PUSH_LOCK:
            row = PUSHER.stamp(row)
            PUSHER.enqueue(row)
    with (OUT.parent / 'observation.jsonl').open('a') as f:
        f.write(json.dumps(row, allow_nan=False) + '\n')


def report(kind, value):
    """A self-report that exists only as an observation record (liveness, permit)."""
    global PRODUCER_SEQ
    if A.role == 'observer' and FLEET_IDENTITY['run_id']:
        with RECORD_LOCK:
            PRODUCER_SEQ += 1
            seq = PRODUCER_SEQ
        write_observation(kind, value, seq)



def line(msg):
    return (json.dumps(msg) + '\n').encode()


class Control:
    def __init__(self):
        self.ctl = {'seq': -1, 'mode': 'idle'}
        self.unreadable = False

    def refresh(self):
        try:
            c = json.loads(CONTROL.read_text())
        except (OSError, ValueError) as ex:
            # on a macOS bind mount the console's atomic replace is occasionally seen torn for one
            # tick; the next read is whole. Only a persisting failure is worth a record.
            self.failures = getattr(self, 'failures', 0) + 1
            if self.failures == 4 and not self.unreadable:
                record('control_unreadable', detail=str(ex))
                self.unreadable = True
            return False
        self.failures = 0
        self.unreadable = False
        if c.get('seq') != self.ctl.get('seq'):
            self.ctl = c
            return True
        return False


# ---------------------------------------------------------------------------------------
# planner — the untrusted requester on the public socket
# ---------------------------------------------------------------------------------------
def classify_robot_reply(reply):
    # IDs are matched by the caller; an absent or malformed reply proves nothing.
    if not isinstance(reply,dict) or reply.get('jsonrpc')!='2.0':return 'UNCONFIRMED'
    if ('result' in reply)==('error' in reply):return 'UNCONFIRMED'
    if 'error' in reply:
        error=reply['error']
        if not isinstance(error,dict) or type(error.get('code')) is not int or not isinstance(error.get('message'),str):return 'UNCONFIRMED'
        if error['code']==-32001 and error['message']=='PAIL_COMMAND_BLOCKED':return 'BLOCKED'
        if error['code']==-32001 or error['message'].startswith('PAIL_'):return 'UNCONFIRMED'
    return 'REPLIED'


def command_acknowledged(reply):
    return classify_robot_reply(reply)=='REPLIED' and 'result' in reply


def skill_delivery_action(sent,reply,elapsed,since_sent):
    if not sent:return 'SEND' if elapsed<8 else 'UNKNOWN'
    kind=classify_robot_reply(reply)
    if kind=='REPLIED':return 'REPLIED'
    if elapsed>=8:return 'BLOCKED' if kind=='BLOCKED' else 'UNKNOWN'
    if kind=='BLOCKED' and since_sent>=.5:return 'RETRY'
    return 'WAIT'


def planner():
    C = Control()
    s = None
    rid = [100]
    replies = {}      # id -> response; pre-forward refusals are not robot answers

    from demo_connection import PlannerConnection, send_stamped, zero_window_open
    connection = PlannerConnection(PUBLIC, record)
    def connect():
        nonlocal s
        connection.connect()
        s = connection.sock
        replies.clear()

    def drain():
        for m in connection.drain():
            if 'id' in m:
                replies[m['id']] = m

    def send(method, params):
        rid[0] += 1
        connection.send({'jsonrpc': '2.0', 'id': rid[0], 'method': method, 'params': params})
        return rid[0]

    def move(linear, angular):
        rid = send('robot.move', {'vx': float(linear), 'vy': 0.0, 'vyaw': float(angular)})
        if linear == 0 and angular == 0:
            record('planner_zero', stop_id=C.ctl.get('stop_id'), request_id=rid)
        return rid

    connect()
    record('ready', role='planner', uid=os.getuid())
    started = step = 0
    step_since = None       # monotonic SEND time of the first answered (= first permitted) command of this step:
    #                         the adapter's step clock started when it permitted that command, which is
    #                         before its reply came back here (a reply-time clock ran late by up to a
    #                         round trip and, after a restart on Linux, let the last commands overrun)
    step_ids = {}           # command id -> monotonic send time, for the current step before it was permitted
    stop_until = 0.0
    skill_sent, skill_sent_at = None, 0.0
    hold_until = 0.0
    period = 1.0 / HZ
    while True:
        t0 = time.monotonic()
        try:
            drain()
        except (ConnectionError, OSError):
            record('disconnected')
            if C.ctl.get('mode')=='skill' and skill_sent is not None:
                record('skill_done',seq=C.ctl.get('seq'),reply=None,outcome='UNKNOWN',physical_execution='NOT_OBSERVED',detail='connection lost after a one-shot attempt; not resent')
                C.ctl=dict(C.ctl,mode='idle')
            time.sleep(1.0)
            try:
                connect()
            except OSError:
                continue
        before, before_mode = C.ctl.get('instruction'), C.ctl.get('mode')
        if C.refresh() and C.ctl.get('instruction') != before:
            started, step, step_since, step_ids, skill_sent, hold_until = time.monotonic(), 0, None, {}, None, 0.0
            record('instruction', seq=C.ctl.get('seq'), instruction=C.ctl.get('instruction'), mode=C.ctl.get('mode'), stop_id=C.ctl.get('stop_id'))
            if before_mode in ('plan', 'raw') and C.ctl.get('mode') == 'idle':
                stop_until = time.monotonic() + STOP_CMD_S  # a stop is a command, not silence
        mode = C.ctl.get('mode')
        now = time.monotonic()
        try:
            if mode == 'raw':
                r = C.ctl.get('raw') or {}
                if now - started < float(r.get('duration', 0)):
                    move(r.get('linear', 0), r.get('angular', 0))
                else:
                    record('raw_done', seq=C.ctl.get('seq'))
                    C.ctl = dict(C.ctl, mode='idle')
                    stop_until = now + STOP_CMD_S
            elif mode == 'skill':
                reply=replies.get(skill_sent)
                action=skill_delivery_action(skill_sent is not None,reply,now-started,now-skill_sent_at)
                if action in ('SEND','RETRY'):
                    if action=='RETRY':
                        record('skill_blocked',seq=C.ctl.get('seq'),skill=C.ctl.get('skill'),id=skill_sent,forwarded=False)
                    # Reserve the attempt before transport: a send exception can
                    # occur after the robot received bytes, so it is not retry permission.
                    skill_sent,skill_sent_at = rid[0]+1,now
                    record('skill_send_attempt',seq=C.ctl.get('seq'),skill=C.ctl.get('skill'),id=skill_sent)
                    sent_id = send('robot.do', {'skill': C.ctl.get('skill')})
                    assert sent_id==skill_sent
                    record('skill_sent', seq=C.ctl.get('seq'), skill=C.ctl.get('skill'), id=skill_sent)
                elif action=='REPLIED':
                    record('robot_reply',seq=C.ctl.get('seq'),skill=C.ctl.get('skill'),reply=reply.get('result'),error=reply.get('error'))
                    record('skill_done',seq=C.ctl.get('seq'),outcome='ROBOT_REPLIED',physical_execution='NOT_OBSERVED')
                    C.ctl = dict(C.ctl, mode='idle')
                elif action in ('BLOCKED','UNKNOWN'):
                    record('skill_done',seq=C.ctl.get('seq'),reply=None,outcome=action,physical_execution='NOT_OBSERVED',detail='delivery wait ended; an unknown execution is not retried')
                    C.ctl = dict(C.ctl, mode='idle')
            elif mode == 'plan':
                steps = C.ctl.get('steps') or []
                if step < len(steps):
                    st = steps[step]
                    answered = [i for i in step_ids if command_acknowledged(replies.get(i))]
                    if step_since is None and answered:
                        step_since = min(step_ids[i] for i in answered)
                        record('step_permitted', seq=C.ctl.get('seq'), step=step, token=st.get('token'), reply_lag_s=round(now - step_since, 3), first_reply_id=min(answered, key=lambda i: step_ids[i]), first_send_mono=step_since, reply_observed_mono=now)
                    if step_since is not None and now - step_since >= max(0.0, float(st['duration']) - STOP_EARLY_S - ZERO_S):
                        record('step_done', seq=C.ctl.get('seq'), step=step)
                        # motion ends ZERO_S before the permit's deadline margin; zero commands fill that
                        # window so the robot decelerates inside its permit (a command after the deadline
                        # is a step overrun the adapter refuses)
                        window_end = step_since + float(st['duration'])
                        step, step_since, step_ids = step + 1, None, {}
                        if step < len(steps):
                            stop_until = window_end - STOP_EARLY_S  # zero commands until the deadline, then the next step
                        hold_until = window_end + ZERO_S  # the next step's first command waits until the adapter has
                        #                                    consumed this step (its deadline plus one tick): a
                        #                          command sent earlier is judged under the old token (permitted, then
                        #                          refused as an overrun at the deadline)
                        if step >= len(steps):
                            record('plan_done', seq=C.ctl.get('seq'), plan_id=C.ctl.get('plan_id'))
                            C.ctl = dict(C.ctl, mode='idle')
                            # keep one command period clear of the adapter's deadline (its clock started
                            # a little before this planner saw the first reply); robotd's own deadman
                            # ramps the fake down when commands stop
                            stop_until = window_end - STOP_EARLY_S
                    if C.ctl.get('mode') == 'plan' and step < len(steps):
                        st = steps[step]
                        budget = sum(float(x['duration']) for x in steps) * 2 + 15
                        if now - started > budget:  # never publish forever on a plan the gate keeps refusing
                            record('plan_timeout', seq=C.ctl.get('seq'), plan_id=C.ctl.get('plan_id'))
                            C.ctl = dict(C.ctl, mode='idle')
                            stop_until = now + STOP_CMD_S
                        elif step_since is None:
                            # not permitted yet (previous step still being consumed, or refused):
                            # probe with the step's own command; blocked commands get no reply
                            if now >= hold_until:
                                linear = C.ctl.get('override_linear')
                                # the stamp is read before the send: the adapter's step clock cannot start earlier
                                request_id, sent_at = send_stamped(time.monotonic, lambda: move(st['linear'] if linear is None else linear, st['angular']))
                                step_ids[request_id] = sent_at
                        else:
                            linear = C.ctl.get('override_linear')
                            move(st['linear'] if linear is None else linear, st['angular'])
            if zero_window_open(time.monotonic, stop_until) and (mode == 'idle' or (mode == 'plan' and step_since is None and now < hold_until)):
                move(0.0, 0.0)
        except (ConnectionError, OSError) as ex:
            record('send_failed', detail=str(ex))
            if C.ctl.get('mode')=='skill' and skill_sent is not None:
                record('skill_done',seq=C.ctl.get('seq'),reply=None,outcome='UNKNOWN',physical_execution='NOT_OBSERVED',detail='one-shot send outcome uncertain; not resent')
                C.ctl=dict(C.ctl,mode='idle')
            s.close()
            time.sleep(0.5)
            try:
                connect()
            except OSError:
                pass
        dt = time.monotonic() - t0
        time.sleep(max(0.0, period - dt))


# ---------------------------------------------------------------------------------------
# observer — raw-socket subscriber (never a command) + gate log copier + seam control
# ---------------------------------------------------------------------------------------
def seam(op, **kw):
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as c:
            c.settimeout(2)
            c.connect(SEAM_CTL)
            c.sendall(line(dict(op=op, **kw)))
            return json.loads(c.makefile('rb').readline() or b'{}')
    except (OSError, ValueError) as ex:
        return {'ok': False, 'error': str(ex)}


def sample_interval(sample_t, now, last):
    """(dt, new_last) for one robot.state sample. `last` is (clock, value): the clock is 'sample' while the
    samples carry a finite, non-decreasing `t` of their own, 'wall' otherwise. A clock change, the first
    sample, or a `t` that went backwards (robotd restarted) integrates nothing for that sample. Pure
    function so the rule is testable without a socket."""
    usable = isinstance(sample_t, (int, float)) and not isinstance(sample_t, bool) and math.isfinite(sample_t)
    clock, value = ('sample', float(sample_t)) if usable else ('wall', now)
    if last is None or last[0] != clock or value < last[1]:
        return 0.0, (clock, value)
    return value - last[1], (clock, value)


def observer():
    C = Control()
    x = y = th = 0.0
    last_t = None
    pose_every = 0
    drive_at = 0.0
    gate_off = 0
    last_health = 0.0  # monotonic; gate_off is set below, after the log exists
    seam_state = None
    record('ready', role='observer', uid=os.getuid(), raw=RAW, position_source='simulation', push=bool(PUSHER))
    if PUSHER is not None:
        threading.Thread(target=push_loop, daemon=True).start()

    try:  # an observer that (re)starts reports from now on; the console already holds the past
        gate_off = os.stat(GATE_LOG).st_size
    except FileNotFoundError:
        gate_off = 0

    # Liveness and permit self-reports. The observer asks the adapter a QUERY (robot.health,
    # forwarded unjudged) on the public socket; it still sends no command anywhere.
    probe, alive, permit = observation.AdapterProbe(), observation.LivenessReporter('adapter'), observation.PermitReporter()
    public = {'s': None, 'buf': b'', 'retry': 0.0}

    def public_close():
        if public['s'] is not None:
            try:
                public['s'].close()
            except OSError:
                pass
        public['s'], public['buf'] = None, b''
        probe.disconnect()

    def self_report():
        now = time.monotonic()
        try:
            if public['s'] is None:
                if now < public['retry']:
                    return
                public['retry'] = now + 1.0
                c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                c.settimeout(0.5)
                c.connect(PUBLIC)
                c.sendall(line({'jsonrpc': '2.0', 'id': 1, 'method': 'hello', 'params': {'api_version': 44}}))
                c.setblocking(False)
                public['s'] = c
                probe.connect()
            request_id = probe.question(now)
            if request_id is not None:
                public['s'].sendall(line({'jsonrpc': '2.0', 'id': request_id, 'method': 'robot.health'}))
            try:
                while True:
                    chunk = public['s'].recv(65536)
                    if not chunk:
                        raise ConnectionError('adapter closed the public socket')
                    public['buf'] += chunk
                    if len(public['buf']) > 1 << 20:
                        raise ConnectionError('unterminated answer')
            except (BlockingIOError, InterruptedError):
                pass
            *rows, public['buf'] = public['buf'].split(b'\n')
            for raw in rows:
                try:
                    m = json.loads(raw)
                except ValueError:
                    continue
                if isinstance(m, dict) and ('result' in m or 'error' in m):
                    probe.answer(m.get('id'), now)
        except OSError:
            public_close()
        answers = probe.alive(now)
        value = alive.due(now, answers)
        if value:
            report('liveness', value)
        for value in permit.due(now, answers, C.ctl.get('steps')):
            report('permit', value)

    def copy_gate_log():
        nonlocal gate_off
        try:
            size = os.stat(GATE_LOG).st_size
        except FileNotFoundError:
            return
        if size < gate_off:  # the adapter restarted and rewrote the file
            gate_off = 0
            permit.adapter_restarted()
        if size <= gate_off:
            return
        with open(GATE_LOG, 'rb') as f:
            f.seek(gate_off)
            chunk = f.read(size - gate_off)
        cut = chunk.rfind(b'\n') + 1
        gate_off += cut
        for l in chunk[:cut].decode(errors='replace').splitlines():
            try:
                r = json.loads(l)
            except ValueError:
                continue
            permit.outcome(r)
            if r.get('kind') == 'outcome':
                record('gate', state=r.get('state'), reason=r.get('reason'), path=r.get('path'), detail=r.get('detail'),
                       token=r.get('token_id') or '', chain=r.get('chain_id') or '', forward=r.get('forward'), uid=r.get('uid'),
                       step_complete=r.get('step_complete'), fatal=r.get('fatal'), adapter_t_ms=r.get('t_ms'))
            elif r.get('kind') == 'stop':
                record('adapter_stop', reason=r.get('reason'), path=r.get('path'), adapter_t_ms=r.get('t_ms'))

    def apply_control():
        nonlocal seam_state
        want = C.ctl.get('safety', 'OK')
        if want != seam_state and os.path.exists(SEAM_CTL):
            r = seam('stale', on=(want == 'STALE'))
            record('safety_seam', level=want, seam=r)
            seam_state = want

    while True:
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(1.0)
            s.connect(RAW)
            s.sendall(line({'jsonrpc': '2.0', 'id': 1, 'method': 'hello', 'params': {'api_version': 44}}))
            s.sendall(line({'jsonrpc': '2.0', 'id': 2, 'method': 'robot.subscribe', 'params': {'hz': int(HZ)}}))
            f = s.makefile('rb')
            stream_id, sample_seq = uuid.uuid4().hex, 0
            record('connected', raw=RAW, stream_id=stream_id)
            while True:
                try:
                    raw = f.readline()
                except socket.timeout:
                    changed = C.refresh()  # the plan first: a permit is reported against its steps
                    copy_gate_log()
                    self_report()
                    if changed or seam_state is None:
                        apply_control()
                    continue
                if not raw:
                    break
                changed = C.refresh()
                copy_gate_log()
                self_report()
                if changed or seam_state is None:
                    apply_control()
                try:
                    m = json.loads(raw)
                except ValueError:
                    continue
                if m.get('method') != 'robot.state':
                    continue
                p = m.get('params') or {}
                mv = p.get('move') or {}
                ap, rq = mv.get('applied'), mv.get('requested')
                if not all(isinstance(v,list) and len(v)==3 and all(isinstance(n,(int,float)) and not isinstance(n,bool) and math.isfinite(n) for n in v) for v in (ap,rq)):
                    record('observation_invalid', reason='INVALID_MOTION_VECTOR', stream_id=stream_id)
                    continue
                sample_seq += 1
                record('motion_sample', stream_id=stream_id, sample_seq=sample_seq, requested=rq, applied=ap)
                now = time.monotonic()
                # The interval a sample's velocity is integrated over is the ROBOT's interval (the `t` robotd
                # stamps on the sample), not the time this process took to get to it: a burst of queued
                # samples processed after a stall used to charge the whole stall to the first (fastest)
                # sample and overstate the move (a 0.359 m scene R on a fleet, 2026-10-09). Wall time only when
                # the sample carries no usable clock.
                dt, last_t = sample_interval(p.get('t'), now, last_t)
                vx, vy, w = float(ap[0]), float(ap[1]), float(ap[2])
                th = math.atan2(math.sin(th + w * dt), math.cos(th + w * dt))
                x += (vx * math.cos(th) - vy * math.sin(th)) * dt
                y += (vx * math.sin(th) + vy * math.cos(th)) * dt
                if any(abs(float(v)) > 1e-8 for v in rq) and now - drive_at >= 0.1:
                    drive_at = now
                    record('drive', x=float(rq[0]), y=float(rq[1]), z=float(rq[2]), applied=[round(vx, 4), round(vy, 4), round(w, 4)],
                           limited_by=mv.get('limited_by') or [])
                pose_every = (pose_every + 1) % 2
                if pose_every == 0:
                    record('pose', x=round(x, 4), y=round(y, 4), th=round(th, 4), v=round(math.hypot(vx, vy), 4), w=round(w, 4),
                           requested=[round(float(v), 4) for v in rq], applied=[round(vx, 4), round(vy, 4), round(w, 4)],
                           limited_by=mv.get('limited_by') or [], source='simulation')
                sf = p.get('safety') or {}
                if time.monotonic() - last_health >= 5.0:
                    last_health = time.monotonic()
                    record('robot_state', fallen=sf.get('fallen'), limp=sf.get('limp'), loop=p.get('loop'))
        except OSError as ex:
            record('disconnected', detail=str(ex))
            # the robot feed is gone; whether the adapter still answers is a separate fact
            for _ in range(4):
                changed = C.refresh()
                copy_gate_log()
                self_report()
                if changed or seam_state is None:
                    apply_control()
                time.sleep(0.25)
        finally:
            try:
                s.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------------------
# evidence — synthetic identity reading on the adapter's evidence socket
# ---------------------------------------------------------------------------------------
def evidence():
    C = Control()
    record('ready', role='evidence', uid=os.getuid())
    s = None
    last_tag = None
    while True:
        C.refresh()
        tag = str(C.ctl.get('tag', 'box-12'))
        if tag != last_tag:
            record('tag', object_id=tag, source='NFC', synthetic=True)
            last_tag = tag
        try:
            if s is None:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(EVIDENCE_SOCK)
                record('connected', socket=EVIDENCE_SOCK)
            s.sendall(line({'source': 'NFC', 'object_id': tag, 'confidence': 0.99, 't': int(time.time() * 1000)}))  # t is integer milliseconds on this wire
        except OSError as ex:
            record('disconnected', detail=str(ex))
            try:
                s.close()
            except Exception:
                pass
            s = None
            time.sleep(1.0)
            continue
        time.sleep(0.2)


# ---------------------------------------------------------------------------------------
# ledger — byte mirror of the issuer's live journal for a host-side dashboard
# ---------------------------------------------------------------------------------------
def ledger():
    src, dst = Path('/state/private/blackbox'), Path('/evidence/ledger')
    dst.mkdir(parents=True, exist_ok=True)
    dst.chmod(0o755)
    seen = {}
    record('ready', role='ledger', source=str(src), mirror=str(dst))
    n = 0
    while True:
        copied = 0
        try:
            for p in src.rglob('*'):
                if p.is_symlink():
                    continue
                rel = p.relative_to(src)
                if p.is_dir():
                    d = dst / rel
                    d.mkdir(parents=True, exist_ok=True)
                    d.chmod(0o755)
                    continue
                st = p.stat()
                key = (st.st_size, st.st_mtime_ns)
                if seen.get(rel) == key:
                    continue
                target = dst / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                tmp = target.with_name(target.name + '.next')
                shutil.copyfile(p, tmp)
                tmp.chmod(0o644)
                tmp.replace(target)
                seen[rel] = key
                copied += 1
        except OSError as ex:
            record('mirror_error', detail=str(ex))
        n += 1
        if copied or n % 30 == 0:
            record('mirror', copied=copied, files=len(seen))
        time.sleep(1.0)


globals()[A.role]()
