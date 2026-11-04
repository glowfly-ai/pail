#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Drive every Microduck demo scene through the running console and judge it from the record.

  python3 examples/microduck/demo_scenes.py [--url http://127.0.0.1:8767] [--out results.json]

"Nothing moved" is never judged from silence alone: each refusal scene is followed by a
permitted move that the same observer (the raw-socket subscriber that integrates the
velocity robotd --fake reports as applied) must see. Positions are that integral, not a
robot measurement; this checks the software path, not a Microduck.
"""
import argparse, collections, json, math, re, signal, sys, time, urllib.error, urllib.request, uuid
from pathlib import Path
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'common'))
from run_record import RunRecord
from judge_events import JudgeLog
from stop_observation import summarize as summarize_stop

AP = argparse.ArgumentParser(description=__doc__)
AP.add_argument('--url', default='http://127.0.0.1:8767')
AP.add_argument('--out', help='new output file; never overwritten (default: timestamp + unique run id)')
AP.add_argument('--only', default='', help='comma separated scene ids')
AP.add_argument('--robot-id', default='', help='robot of a fleet console: requests go below /robot/<id>/ and commands carry a request id')
A = AP.parse_args()
if A.robot_id and not re.fullmatch(r'[A-Za-z0-9._-]{1,64}', A.robot_id):
    AP.error('--robot-id is a robot id of the fleet configuration')
BASE = A.url.rstrip('/') + ('/robot/' + A.robot_id if A.robot_id else '')
try:
    RUN = RunRecord(A.out, BASE, A.only)
except OSError as ex:
    print('Output refused; choose a NEW file: ' + str(ex), file=sys.stderr)
    raise SystemExit(2) from ex
A.out = str(RUN.path)
print('RUN_ID=%s OUT=%s' % (RUN.run_id, A.out), flush=True)
_original_excepthook = sys.excepthook

def _record_unhandled(kind, error, traceback):
    if not RUN.data['completed']:
        RUN.save(globals().get('RESULTS', []), completed=True, error='%s: %s' % (kind.__name__, error))
    _original_excepthook(kind, error, traceback)

sys.excepthook = _record_unhandled

def _terminate(signum, frame):
    raise KeyboardInterrupt('judge interrupted by signal %s' % signum)

signal.signal(signal.SIGTERM, _terminate)



def post(path, body=None):
    if A.robot_id and path == '/api/command':
        # a fleet accepts a command with a request id only; every command of the judge is a new one
        body = dict(body or {}, request_id=uuid.uuid4().hex)
    req = urllib.request.Request(BASE + path, data=json.dumps(body or {}).encode(), headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read())


def recovery_generation():
    """The fleet's fault generation of this robot (None without a fleet): a move after a confirmed recovery must
    not see it change — a second pause for the same restart cancels the plan under the operator's feet."""
    if not A.robot_id:
        return None
    with urllib.request.urlopen(BASE + '/api/state', timeout=10) as r:
        return (json.loads(r.read()).get('recovery') or {}).get('fault_generation')


def operator_confirms_recovery(f, key):
    """A fleet pauses a robot whose services came back (a restored issuer link, a restart) until the
    operator confirms — the page's button. In fleet mode the judge confirms as the operator would,
    and records it; without a fleet there is nothing to confirm. No command is sent before."""
    if not A.robot_id:
        return
    paused = None
    for _ in range(60):
        with urllib.request.urlopen(BASE + '/api/state', timeout=10) as r:
            paused = (json.loads(r.read()).get('recovery') or {}).get('paused')
        if paused:
            break
        time.sleep(0.5)
    if not paused:
        f[key] = 'NOT_PAUSED'
        return
    answer, refused = None, None
    for _ in range(30):   # the fleet refuses the confirmation while the robot's services are still settling
        try:
            answer = post('/api/recovery', {'confirmation': True})
            break
        except urllib.error.HTTPError as ex:
            refused = (ex.code, ex.read()[:200].decode(errors='replace'))
            time.sleep(3)
    else:
        raise AssertionError('the fleet did not take the operator confirmation: %s' % (refused,))
    for _ in range(60):
        with urllib.request.urlopen(BASE + '/api/state', timeout=10) as r:
            if not (json.loads(r.read()).get('recovery') or {}).get('paused'):
                break
        time.sleep(0.5)
    else:
        raise AssertionError('the fleet kept the robot paused after the operator confirmed: %s' % answer)
    f[key] = {'confirmed': True, 'answer': {k: answer.get(k) for k in ('ok', 'execution', 'robot_id')} if isinstance(answer, dict) else answer}


class Log(JudgeLog):
    def __init__(self):
        super().__init__(BASE, sink=RUN.append_events)

    def wait(self, i, what, timeout=20, pred=None, **kw):
        end = time.time() + timeout
        while time.time() < end:
            hits = [e for e in self.since(i, **kw) if pred is None or pred(e)]
            if hits:
                return hits
            time.sleep(.2)
        raise AssertionError('not observed within %ss: %s' % (timeout, what))

    def pose(self):
        p = self.since(0, event='pose')
        if not p:
            raise AssertionError('no pose from the observer')
        return p[-1]

    def drives(self, i):
        return self.since(i, event='drive')


L = Log()
RESULTS = []
CLOCK_FAILED = []
try:
    with urllib.request.urlopen(BASE + '/api/state', timeout=10) as _r:
        STATE = json.loads(_r.read())
except (OSError, ValueError) as ex:
    print('Console not reachable at '+BASE+': '+str(ex),file=sys.stderr,flush=True)
    RUN.save([], completed=True, error='Console state unavailable: '+str(ex))
    raise SystemExit(2) from ex
if 'limits' not in STATE and isinstance(STATE.get('robots'), list):
    # the fleet console answers for the whole fleet; a judge works on one robot (this used to be a KeyError)
    ids = [r.get('robot_id') for r in STATE['robots'] if isinstance(r, dict)]
    print('fleet console at %s: pass --robot-id (%s), one judge per robot' % (A.url, ', '.join(str(i) for i in ids) or 'no robot ready yet'), file=sys.stderr, flush=True)
    RUN.save([], completed=True, error='FLEET_CONSOLE_NEEDS_ROBOT_ID: ' + ', '.join(str(i) for i in ids))
    raise SystemExit(2)
LIMITS = STATE['limits']
RUN.save(RESULTS, scope='software path on robotd --fake; requested/applied state samples; no physical Microduck')
TARGET = STATE.get('target', 'box-12')
OVER_M = math.ceil(STATE['per_call_max_m']) + 2
OVER_S = round(round(OVER_M / STATE['cruise']['linear'], 2) + STATE.get('stop_window_s', 0.0), 2)   # the request includes the stop window


def scene(sid, title):
    def deco(fn):
        def run():
            if A.only and sid not in A.only.split(','):
                return
            started, facts = time.monotonic(), {}
            mark = L.mark()
            try:
                fn(facts)
                ok, err = True, None
            except AssertionError as ex:
                ok, err = False, str(ex)
            except urllib.error.HTTPError as ex:
                # the console refused an action: a failed scene, not a crashed judge (the TB3
                # judge already did this). The refusal body names the reason.
                try:
                    body = ex.read()[:300].decode(errors='replace')
                except OSError:
                    body = ''
                facts['http_refusal'] = dict(status=ex.code, url=getattr(ex, 'url', ''), body=body)
                ok, err = False, 'HTTP %s refused by the console: %s' % (ex.code, body or ex.reason)
            steps = L.since(mark, event='clock_step')
            if steps:
                facts['clock_steps'] = steps
                facts['error_before_clock_check'] = err
                ok, err = False, 'CLOCK_PREREQUISITE_FAILED: observer clock changed during this scene; no enforcement threshold was changed'
                CLOCK_FAILED.append(sid)
            if not ok:
                # What the gate said while the scene failed. A scene that reads as "no motion observed" is
                # often the gate refusing every command for one reason; name it instead of leaving the
                # recipient to dig through the events (2026-10-09: a VM time-sync agent stepped the wall
                # clock ~100 ms every 20 s, the gate's skew bound was crossed, and two full runs failed
                # 8/15 and 9/15 with thousands of ERR_CLOCK_DRIFT refusals that nothing summarised).
                refusals = collections.Counter(e.get('reason') for e in L.since(mark, event='gate') if e.get('state') in ('BLOCK', 'ESTOP'))
                facts['gate_refusals'] = dict(refusals.most_common(5))
                drift = refusals.get('ERR_CLOCK_DRIFT', 0)
                if drift and drift >= max(20, sum(refusals.values()) // 2):
                    err += (' | the gate refused %d commands with ERR_CLOCK_DRIFT during this scene: the adapter saw its wall clock step '
                            '(VM time synchronisation or an NTP step), not a policy refusal; restart the robot side (scene R or the console button) '
                            'once the clock is quiet and run the judge again; see DEMO.md section 8' % drift)
            facts['scene_event_range'] = dict(start_inclusive=mark, end_exclusive=len(L.events))
            RESULTS.append(dict(id=sid, title=title, passed=ok, error=err, facts=facts, seconds=round(time.monotonic() - started, 1)))
            print(('PASS ' if ok else 'FAIL ') + sid + ' ' + title + ('' if ok else ' — ' + err), flush=True)
            settle()
        run.sid = sid
        return run
    return deco


def settle():
    """End any running instruction and wait until nothing reaches the fake for 1.5 s."""
    post('/api/command', {'text': 'stop'})
    end = time.time() + 30
    while time.time() < end:
        i = L.mark()
        time.sleep(1.5)
        if not L.drives(i):
            return
    raise AssertionError('commands kept reaching the fake after stop')


def quiet(seconds=2.0):
    i = L.mark()
    time.sleep(seconds)
    return len(L.drives(i))


def move(text, facts, key, tolerance=0.15):
    """Submit a command that must be issued; wait until the plan completes; return displacement."""
    p0 = L.pose()
    i = L.mark()
    r = post('/api/command', {'text': text})
    assert r.get('accepted'), '%r was refused: %s' % (text, r.get('denial'))
    L.wait(i, 'step permitted for %r' % text, 25, event='step_permitted')
    total = sum(s['duration'] for s in r['steps'])
    L.wait(i, 'plan completion for %r' % text, total * 2 + 25, event='plan_done')
    time.sleep(1.5)  # the fake ramps down after the last command
    p1 = L.pose()
    d = math.hypot(p1['x'] - p0['x'], p1['y'] - p0['y'])
    dth = math.degrees(math.atan2(math.sin(p1['th'] - p0['th']), math.cos(p1['th'] - p0['th'])))
    permits = [e for e in L.since(i, event='gate', state='PERMIT') if e.get('path') == 'command']
    facts[key] = dict(text=text, tokens=len(r['tokens']), drives=len(L.drives(i)), moved_m=round(d, 3), turned_deg=round(dth, 1),
                      start=[p0['x'], p0['y'], p0['th']], end=[p1['x'], p1['y'], p1['th']],
                      issued_tokens=[t['id'] for t in r['tokens']], permitted_tokens=sorted({e.get('token') for e in permits if e.get('token')}))
    assert L.drives(i), 'no command reached the fake for %r' % text
    # M1-b: every PERMIT the adapter logged during this move names one of the tokens the issuer just signed
    unknown = [t for t in facts[key]['permitted_tokens'] if t not in facts[key]['issued_tokens']]
    assert not unknown, 'the adapter permitted under a token the console did not receive: %s' % unknown
    rec = L.wait(i, 'recorded move for %r' % text, 8, event='moved', plan=r.get('plan'))[-1]
    facts[key]['recorded'] = {k: rec.get(k) for k in ('moved_m', 'turned_deg', 'settled')}
    assert rec.get('moved_m') is not None and abs(rec['moved_m'] - d) < 0.05, 'recorded move %s disagrees with measured %.3f m' % (rec.get('moved_m'), d)
    facts[key]['constraint_refusals'] = len([e for e in L.since(i, event='gate', reason='ERR_CONSTRAINT') if e.get('path') == 'command'])
    assert facts[key]['constraint_refusals'] == 0, 'the adapter refused a command of a normal move (ERR_CONSTRAINT) for %r' % text
    return d, dth, p0, p1


def refused(text, facts, name, requested, maximum):
    p0 = L.pose()
    i = L.mark()
    r = post('/api/command', {'text': text})
    d = r.get('denial') or {}
    facts['refusal'] = dict(text=text, accepted=r.get('accepted'), code=d.get('code'), exceeded=d.get('exceeded'))
    assert not r.get('accepted'), '%r was issued' % text
    assert d.get('code') == 'ERR_ENVELOPE_EXCEEDED', 'code %s' % d.get('code')
    ex = [e for e in d.get('exceeded') or [] if e['name'] == name]
    assert ex and abs(float(ex[0]['requested']) - requested) < 1e-6 and abs(float(ex[0]['max']) - maximum) < 1e-6, 'exceeded %s' % d.get('exceeded')
    w = L.wait(i, 'warning event', 5, event='refused')[-1]
    assert w.get('warning') and w['warning'][0].get('ko') and w['warning'][0].get('en'), 'no bilingual warning'
    facts['warning'] = w['warning']
    n = quiet(3)
    p1 = L.pose()
    facts['after_refusal'] = dict(drives=n, pose_change_m=round(math.hypot(p1['x'] - p0['x'], p1['y'] - p0['y']), 4))
    assert n == 0 and facts['after_refusal']['pose_change_m'] < 0.005, 'something moved after a refusal'


def control_move(f, key='positive_control'):
    d, _, _, _ = move('forward 0.3 m', f, key)
    # 0.30–0.31 m on every recorded run (the fake's ramp is inside the stop window); a move cut
    # short by a step overrun measured 0.22 m (Linux, 2026-09-16) and must not pass here
    assert abs(d - 0.3) < 0.05, 'control moved %.3f m, want 0.30 ± 0.05' % d


@scene('6', 'drive without permission (fresh stack, no plan yet)')
def s6(f):
    i = L.mark()
    post('/api/raw', {'linear': 0.1, 'duration': 4})
    # Primary evidence: the command produced no drive. An adapter already in BLOCK ERR_NO_TOKEN logs no
    # new refusal for it (P35-L1), so a refusal event is secondary: when one arrives its reason must be a
    # no-permit reason.
    time.sleep(1)
    f['drives'] = quiet(2.5)
    assert f['drives'] == 0, 'a command reached the fake without a plan'
    refusals = [e for e in L.since(i, event='gate') if e.get('state') in ('BLOCK', 'ESTOP')]
    f['gate_refusals'] = len(refusals)
    # Recorded, not judged: ERR_NO_TOKEN on a fresh stack, ERR_ISSUER_UNREACHABLE while the Issuer link is impaired
    # (the preview.36 network-impairment replay refused this scene on exactly that reason; the fake had not moved).
    f['gate_refusal_reasons'] = sorted({str(e.get('reason')) for e in refusals})
    control_move(f)


@scene('1', 'forward 1 m within the limits')
def s1(f):
    d, dth, _, _ = move('forward 1 m', f, 'move')
    assert 0.7 < d < 1.05, 'moved %.3f m, want about 1.0 minus the fake ramp' % d
    assert abs(dth) < 5, 'turned %.1f°' % dth
    f['after_completion_drives'] = quiet(2.5)
    assert f['after_completion_drives'] == 0, 'commands kept reaching the fake after the step completed'


@scene('2', 'a distance above the per-call limit: refused, nothing moves, warning')
def s2(f):
    refused('forward %g m' % OVER_M, f, 'step.max_duration_s', OVER_S, LIMITS['step.max_duration_s'])
    control_move(f)


@scene('3', 'forward 1 m at 0.3 m/s is above the speed limit: refused')
def s3(f):
    refused('forward 1 m at 0.3 m/s', f, 'sls.linear_mps', 0.3, LIMITS['sls.linear_mps'])
    control_move(f)


@scene('4', 'left 90 deg turns in place')
def s4(f):
    d, dth, _, _ = move('left 90 deg', f, 'move')
    assert 60 < dth < 100 and d < 0.05, 'turned %.1f°, moved %.3f m' % (dth, d)


@scene('4b', 'back 0.5 m reverses')
def s4b(f):
    d, dth, p0, p1 = move('back 0.5 m', f, 'move')
    heading = (math.cos(p0['th']), math.sin(p0['th']))
    along = (p1['x'] - p0['x']) * heading[0] + (p1['y'] - p0['y']) * heading[1]
    f['along_heading_m'] = round(along, 3)
    assert -0.55 < along < -0.3, 'moved %.3f m along the heading, want about -0.5' % along


@scene('4c', 'left 1 m = turn 90° then 1 m, two tokens')
def s4c(f):
    d, dth, p0, p1 = move('left 1 m', f, 'move')
    assert f['move']['tokens'] == 2, 'tokens %s' % f['move']['tokens']
    left = (-math.sin(p0['th']), math.cos(p0['th']))
    side = (p1['x'] - p0['x']) * left[0] + (p1['y'] - p0['y']) * left[1]
    f['to_the_left_m'] = round(side, 3)
    assert 60 < dth < 100 and 0.6 < side < 1.05, 'turned %.1f°, %.3f m to the left' % (dth, side)


@scene('4d', 'wave: a skill token is issued, the adapter permits robot.do, the fake declines (policy not driving)')
def s4d(f):
    i = L.mark()
    r = post('/api/command', {'text': 'wave'})
    assert r.get('accepted'), 'skill plan refused: %s' % r.get('denial')
    f['token'] = {'id': r['tokens'][0]['id'], 'skill': r['tokens'][0].get('skill')}
    assert f['token']['skill'] == 'wave', 'the token does not name the skill: %s' % f['token']
    g = L.wait(i, 'adapter PERMIT for robot.do wave', 10, event='gate', state='PERMIT', pred=lambda e: e.get('path') == 'command')[0]
    f['permit'] = {k: g.get(k) for k in ('reason', 'token')}
    assert g.get('token') == f['token']['id'], 'permitted under %s, issued %s' % (g.get('token'), f['token']['id'])
    rep = L.wait(i, 'the robot answered robot.do', 10, event='robot_reply')[0]
    f['robot_reply'] = rep.get('reply')
    assert isinstance(rep.get('reply'), dict) and rep['reply'].get('accepted') is False, 'expected the fake to decline (no policy driving): %s' % rep.get('reply')
    f['drives'] = quiet(1.5)
    assert f['drives'] == 0, 'a twist reached the fake during a skill call'


@scene('5', 'planner exceeds its permit (0.3 m/s): adapter blocks every command and sends robot.stop, token stays usable')
def s5(f):
    i = L.mark()
    r = post('/api/command', {'text': 'forward 1 m'})
    assert r.get('accepted'), 'plan refused: %s' % r.get('denial')
    L.wait(i, 'first motion', 25, event='drive')
    j = L.mark()
    post('/api/rogue', {'linear': 0.3})
    L.wait(j, 'adapter ERR_CONSTRAINT', 10, event='gate', reason='ERR_CONSTRAINT')
    L.wait(j, 'adapter robot.stop', 5, event='adapter_stop')
    time.sleep(1.5)
    f['drives_while_rogue'] = quiet(2.5)
    f['max_speed_reaching_fake'] = max([abs(e['x']) for e in L.drives(j)] or [0])
    assert f['drives_while_rogue'] == 0 and f['max_speed_reaching_fake'] <= LIMITS['sls.linear_mps'] + 1e-9, 'a command above the permit reached the fake'
    k = L.mark()
    post('/api/rogue', {'linear': None})
    L.wait(k, 'motion resumes within the permit (same token)', 10, event='drive')
    f['resumed'] = True


@scene('7', 'wrong tag read: adapter refuses, the right tag restores')
def s7(f):
    post('/api/inputs', {'tag': 'other-box'})
    time.sleep(1)
    i = L.mark()
    r = post('/api/command', {'text': 'forward 0.5 m'})
    assert r.get('accepted'), 'plan refused: %s' % r.get('denial')
    L.wait(i, 'adapter ERR_TARGET_MISMATCH', 15, event='gate', reason='ERR_TARGET_MISMATCH')
    time.sleep(.5)
    f['drives_with_wrong_tag'] = quiet(2.5)
    assert f['drives_with_wrong_tag'] == 0, 'a command reached the fake while the tag did not match the token target'
    j = L.mark()
    post('/api/inputs', {'tag': TARGET})
    L.wait(j, 'motion after the right tag', 15, event='drive')
    f['restored'] = True
    time.sleep(.5)
    f['planner_restarts_on_feed_switch'] = len(L.since(j, source='planner', event='instruction'))
    assert f['planner_restarts_on_feed_switch'] == 0, 'switching the tag restarted the running plan'


@scene('8S', 'safety feed lost while moving: adapter blocks and stops; feed restored: motion resumes within the permit')
def s8s(f):
    i = L.mark()
    r = post('/api/command', {'text': 'forward 1 m'})
    assert r.get('accepted'), 'plan refused: %s' % r.get('denial')
    L.wait(i, 'first motion', 25, event='drive')
    j = L.mark()
    post('/api/inputs', {'safety': 'STALE'})
    g = L.wait(j, 'adapter refusal on stale safety', 8, event='gate', pred=lambda e: e.get('state') in ('BLOCK', 'ESTOP') and 'SAFETY' in (e.get('reason') or ''))[0]
    f['refusal'] = {k: g.get(k) for k in ('state', 'reason', 'path')}
    L.wait(j, 'adapter robot.stop', 5, event='adapter_stop')
    time.sleep(1.5)
    f['drives_while_stale'] = quiet(2)
    assert f['drives_while_stale'] == 0, 'commands kept reaching the fake while the safety feed was stale'
    k = L.mark()
    post('/api/inputs', {'safety': 'OK'})
    L.wait(k, 'motion after the feed is back', 15, event='drive')
    f['resumed_after_restore'] = True
    f['planner_restarts_on_feed_switch'] = len(L.since(j, source='planner', event='instruction'))
    assert f['planner_restarts_on_feed_switch'] == 0, 'switching the seam restarted the running plan'


@scene('8A', 'issuer link lost while moving: adapter fails closed within its grace ladder; link restored: motion resumes')
def s8a(f):
    i = L.mark()
    r = post('/api/command', {'text': 'forward 1 m'})
    assert r.get('accepted'), 'plan refused: %s' % r.get('denial')
    L.wait(i, 'first motion', 25, event='drive')
    j = L.mark()
    t0 = time.time()
    post('/api/fault', {'service': 'agent', 'action': 'stop'})
    # A fleet pauses the robot and writes idle the moment the fault is made, so the planner may stop
    # commanding before the agent is gone: then the refusal is the gate's own recheck of the active
    # token (BLOCK on the recheck path, adapter stop), not a refused command. Both are the gate
    # failing closed; the single-robot console only ever shows the command path.
    paths = ('command', 'recheck') if A.robot_id else ('command',)
    g = L.wait(j, 'adapter refusal after the agent stopped', 30, event='gate', pred=lambda e: e.get('state') == 'BLOCK' and e.get('path') in paths)[0]
    f['refusal'] = {k: g.get(k) for k in ('reason', 'path')}
    f['refusal_after_s'] = round(g['t'] - t0, 2)
    L.wait(j, 'adapter robot.stop', 10, event='adapter_stop')
    time.sleep(1.5)
    f['drives_while_down'] = quiet(2)
    assert f['drives_while_down'] == 0, 'commands kept reaching the fake while the issuer link was down'
    k = L.mark()
    post('/api/fault', {'service': 'agent', 'action': 'start'})
    try:
        L.wait(k, 'motion after the agent is back', 30, event='drive')
        f['resumed_after_restore'] = True
    except AssertionError:
        f['resumed_after_restore'] = False   # recorded: the step window may have expired while the link was down
    operator_confirms_recovery(f, 'fleet_recovery_after_restore')
    settle()
    control_move(f, 'after_link_restored')


@scene('S', 'stop while moving: the plan is cancelled at the issuer; the next plan runs on its own token')
def ss(f):
    i = L.mark()
    r = post('/api/command', {'text': 'forward 1 m'})
    assert r.get('accepted'), 'plan refused: %s' % r.get('denial')
    first_token = r['tokens'][0]['id']
    L.wait(i, 'first motion', 25, event='drive')
    time.sleep(1.0)
    j = L.mark()
    st = post('/api/command', {'text': 'stop'})
    ev = L.wait(j, 'stopped event', 5, event='stopped')[0]
    f['stop'] = dict(response=st.get('cancelled'), plan=ev.get('plan'), cancelled=ev.get('cancelled'))
    assert ev.get('plan') == r.get('plan') and ev.get('cancelled') is True, 'stop did not cancel the running plan at the issuer: %s' % f['stop']
    ack = L.wait(j, 'planner acknowledged this stop', 5, source='planner', event='instruction', mode='idle', stop_id=ev['stop_id'])[0]
    time.sleep(2)
    observed = L.since(j)
    f['stop_id'] = ev['stop_id']
    f['observation_event_range'] = dict(start_inclusive=j, end_exclusive=j+len(observed))
    try:
        f.update(summarize_stop(observed, ev['stop_id']))
    except ValueError as ex:
        raise AssertionError('stop observation invalid: ' + str(ex)) from ex
    assert f['requested_nonzero_samples_after_ack'] == 0, 'requested velocity stayed nonzero after stop acknowledgement: %s' % f
    try:
        g = L.wait(j, 'adapter without the cancelled permit', 10, event='gate', pred=lambda e: e.get('state') != 'PERMIT' or e.get('token') != first_token)[0]
        f['gate_after_stop'] = dict(state=g.get('state'), reason=g.get('reason'), raw_cross_clock_after_cancel_s=round(g['t'] - ev['t'], 3))  # wall-clock: two event stamps from the log, recorded as a raw cross-clock value
    except AssertionError:
        f['gate_after_stop'] = None
    k = L.mark()
    d, _, _, _ = move('forward 0.3 m', f, 'next')
    issued = L.since(k, event='issued')[0]
    permits = [e for e in L.since(k, event='gate', state='PERMIT') if e.get('path') == 'command' and e.get('token')]
    f['next']['permitted_token'] = permits[0].get('token') if permits else None
    f['next']['cancelled_plan_token'] = first_token
    assert permits and permits[0].get('token') == issued['tokens'][0]['id'], 'the next plan did not run on its own token: %s' % f['next']
    assert permits[0].get('token') != first_token, "the next plan ran on the cancelled plan's token"
    assert 0.15 < d < 0.4, 'moved %.3f m after stop, want roughly 0.3' % d


@scene('R', 'restart the robot side, then a permitted move works again')
def sr(f):
    i = L.mark()
    r = post('/api/restart_robot')
    assert r.get('ok'), 'restart failed: %s' % r
    L.wait(i, 'restart completed', 180, event='robot_restarted')
    # The console returns from the restart once every actor's `ready` is in the runtime files; the console's
    # tailer (50 ms poll) may publish that line to this feed a moment after `robot_restarted`. Wait for it
    # instead of reading the feed once ("the observer did not come back" on a fleet, 2026-10-09).
    L.wait(i, 'the observer back after the restart', 30, source='observer', event='ready')
    # The restarted fake starts its pose stream again at the origin. The latest pose in the feed can still be the one
    # from BEFORE the restart for a moment, and a move measured from it includes the reset jump (TB3 judge 2026-10-10:
    # recorded 0.295 m vs measured 0.416 m, start heading 175 deg): measure only from a pose produced after the restart.
    j = L.mark()
    L.wait(j, 'a pose from the restarted robot', 30, event='pose')
    operator_confirms_recovery(f, 'fleet_recovery_after_restart')
    gen = recovery_generation()
    try:
        control_move(f, 'after_restart')
    finally:
        if gen is not None:
            f['fault_generation'] = dict(before_move=gen, after_move=recovery_generation())
    if gen is not None and f['fault_generation']['after_move'] != gen:
        # 2026-10-10: the fleet's inventory pass reported the console's own restart as a NEW fault after the operator
        # had confirmed, paused the robot again and cancelled the plan just issued (the move stalled on ERR_NO_TOKEN)
        raise AssertionError('the fleet paused the robot AGAIN after the operator confirmed and the plan was issued: %s' % f['fault_generation'])


@scene('9', 'ledger verifies, and the dashboard answers a ledger query for this run')
def s9(f):
    r = post('/api/verify')
    f['output_tail'] = r.get('output', '').splitlines()[-2:]
    assert r.get('ok'), 'verify failed'
    f['dashboard'] = r.get('dashboard')
    if STATE.get('dashboard_url'):
        assert f['dashboard'] and f['dashboard'].get('ok'), 'dashboard ledger query failed: %s' % f['dashboard']


def main():
    try:
        urllib.request.urlopen(BASE + '/api/state', timeout=5).read()
    except OSError as ex:
        print('Console not reachable at %s (%s). Start it with: python3 examples/microduck/demo.py up' % (BASE, ex), file=sys.stderr)
        return 2
    suite = [s6, s1, s2, s3, s4, s4b, s4c, s4d, s5, s7, s8s, s8a, ss, sr, s9]
    RUN.data['expected_scene_ids'] = [s.sid for s in suite if not A.only or s.sid in A.only.split(',')]
    RUN.save(RESULTS)
    for s in suite:
        s()
        if CLOCK_FAILED:
            break  # Do not submit more plans after an invalid timing prerequisite.
    ok = bool(RESULTS) and all(r['passed'] for r in RESULTS)
    RUN.save(RESULTS, scope='software path on robotd --fake; requested/applied state samples; synthetic identity and safety; no physical Microduck', completed=True, error='CLOCK_PREREQUISITE_FAILED' if CLOCK_FAILED else None)
    print('RESULT=%s %d/%d OUT=%s' % ('PASS' if ok else 'FAIL', sum(r['passed'] for r in RESULTS), len(RESULTS), A.out))
    if CLOCK_FAILED:
        print('CLOCK_PREREQUISITE_FAILED in scenes %s; re-run with a NEW result file after restoring the runtime; thresholds unchanged' % ','.join(CLOCK_FAILED))
        return 2
    return 0 if ok else 1


if __name__ == '__main__':
    try:
        rc = main()
        if not RUN.data['completed']:
            RUN.save(RESULTS, completed=True, error='judge ended before completion (rc=%s)' % rc)
    except (Exception, KeyboardInterrupt) as ex:
        print('JUDGE_FAILED: '+str(ex),file=sys.stderr,flush=True)
        RUN.save(RESULTS, completed=True, error='%s: %s' % (type(ex).__name__, ex))
        raise
    sys.exit(rc)
