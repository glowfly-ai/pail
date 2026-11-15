#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Drive every demo scene through the running console and judge it from the event record.

  python3 examples/tb3/demo_scenes.py [--url http://127.0.0.1:8765] [--out results.json]

"Nothing moved" is never judged from silence alone: each refusal scene is followed by
a permitted move that the same observer (the simulated base) must see. Positions are
the simulation of what passed the gate; this checks the software path, not a robot.
"""
import uuid
import argparse, json, math, signal, sys, time, urllib.request
from pathlib import Path
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'common'))
from run_record import RunRecord
from judge_events import JudgeLog
from stop_observation import summarize as summarize_stop

AP = argparse.ArgumentParser(description=__doc__)
AP.add_argument('--url', default='http://127.0.0.1:8765')
AP.add_argument('--out', help='new output file; never overwritten (default: timestamp + unique run id)')
AP.add_argument('--only', default='', help='comma separated scene ids')
A = AP.parse_args()
BASE = A.url.rstrip('/')
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
    req = urllib.request.Request(BASE + path, data=json.dumps(body or {}).encode(), headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=330 if path == '/api/restart_robot' else 60) as r:
        return json.loads(r.read())


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
            raise AssertionError('no pose from the simulated base')
        return p[-1]

    def drives(self, i):
        return self.since(i, event='drive')


L = Log()
RESULTS = []
try:
    with urllib.request.urlopen(BASE + '/api/state', timeout=10) as _r:
        STATE = json.loads(_r.read())
except (OSError, ValueError) as ex:
    print('Console not reachable at '+BASE+': '+str(ex),file=sys.stderr,flush=True)
    RUN.save([], completed=True, error='Console state unavailable: '+str(ex))
    raise SystemExit(2) from ex
LIMITS = STATE['limits']
SIMULATED = STATE.get('position_source') == 'simulation'
RUN.save(RESULTS, scope='software simulated base' if SIMULATED else 'robot-side observations: '+str(STATE.get('position_source')))
# a distance the per-call limit cannot cover at cruise speed (3 m on the demo policy)
OVER_M = 3 if STATE['per_call_max_m'] < 3 else math.ceil(STATE['per_call_max_m']) + 2
OVER_S = round(OVER_M / STATE['cruise']['linear'], 2)
CLOCK_FAILED = []


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
            except urllib.error.HTTPError as ex:  # the console refused an action: a failed scene, not a crashed judge
                ok, err = False, 'console answered HTTP %d for %s: %s' % (ex.code, ex.url, ex.read().decode(errors='replace')[:300])
            steps = L.since(mark, event='clock_step')
            if steps:  # a wall-clock step makes the gate refuse everything: not this scene's verdict
                facts['clock_steps'] = steps
                facts['error_before_clock_check'] = err
                ok, err = False, 'CLOCK_PREREQUISITE_FAILED: robot-side clock jumped %s s during the scene' % steps[0].get('jump_s')
                CLOCK_FAILED.append(sid)
            facts['scene_event_range'] = dict(start_inclusive=mark, end_exclusive=len(L.events))
            RESULTS.append(dict(id=sid, title=title, passed=ok, error=err, facts=facts, seconds=round(time.monotonic() - started, 1)))
            print(('PASS ' if ok else 'FAIL ') + sid + ' ' + title + ('' if ok else ' — ' + err), flush=True)
            settle()
        run.sid = sid
        return run
    return deco


def settle():
    """End any running instruction and wait until the base reports no motion for 1.5 s."""
    post('/api/command', {'text': 'stop'})
    end = time.time() + 30
    while time.time() < end:
        i = L.mark()
        time.sleep(1.5)
        if not L.drives(i):
            return
    raise AssertionError('base kept moving after stop')


def quiet(seconds=2.0):
    i = L.mark()
    time.sleep(seconds)
    return len(L.drives(i))


def move(text, facts, key):
    """Submit a command that must be issued; wait until the plan completes; return displacement."""
    p0 = L.pose()
    i = L.mark()
    r = post('/api/command', {'text': text})
    assert r.get('accepted'), '%r was refused: %s' % (text, r.get('denial'))
    L.wait(i, 'step permitted for %r' % text, 20, event='step_permitted')
    total = sum(s['duration'] for s in r['steps'])
    L.wait(i, 'plan completion for %r' % text, total * 2 + 20, event='plan_done')
    time.sleep(1.0)
    p1 = L.pose()
    d = math.hypot(p1['x'] - p0['x'], p1['y'] - p0['y'])
    dth = math.degrees(math.atan2(math.sin(p1['th'] - p0['th']), math.cos(p1['th'] - p0['th'])))
    facts[key] = dict(text=text, tokens=len(r['tokens']), drives=len(L.drives(i)), moved_m=round(d, 3), turned_deg=round(dth, 1),
                      start=[p0['x'], p0['y'], p0['th']], end=[p1['x'], p1['y'], p1['th']])
    assert L.drives(i), 'no motion reached the base for %r' % text
    # the console's own record of the move (what the page shows, live or replayed) must agree
    # with this independent measurement from the same pose stream
    rec = L.wait(i, 'recorded move for %r' % text, 6, event='moved', plan=r.get('plan'))[-1]
    facts[key]['recorded'] = {k: rec.get(k) for k in ('moved_m', 'turned_deg', 'settled')}
    assert rec.get('moved_m') is not None and abs(rec['moved_m'] - d) < 0.03, 'recorded move %s disagrees with measured %.3f m' % (rec.get('moved_m'), d)
    # a well-behaved planner never commands past its permit: no step-overrun refusal on a normal move
    facts[key]['constraint_refusals'] = len(L.since(i, event='gate', reason='ERR_CONSTRAINT'))
    assert facts[key]['constraint_refusals'] == 0, 'the gate refused a command of a normal move (ERR_CONSTRAINT) for %r' % text
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


@scene('6', 'drive without permission (fresh stack, no plan yet)')
def s6(f):
    i = L.mark()
    post('/api/raw', {'linear': 0.1, 'duration': 4})
    # Primary evidence: the command produced no drive. A gate that was already in BLOCK ERR_NO_TOKEN
    # logs no new refusal for it (P35-L1: waiting for a transition failed a correct gate after a fault
    # injection), so a refusal event is secondary: when one arrives its reason must be a no-permit reason.
    time.sleep(1)
    f['drives'] = quiet(2.5)
    assert f['drives'] == 0, 'the base moved without a plan'
    refusals = [e for e in L.since(i, event='gate') if e.get('state') in ('BLOCK', 'ESTOP')]
    f['gate_refusals'] = len(refusals)
    # Recorded, not judged: ERR_NO_TOKEN on a fresh stack, ERR_ISSUER_UNREACHABLE while the Issuer link is impaired
    # (the preview.36 network-impairment replay refused this scene on exactly that reason; the base had not moved).
    f['gate_refusal_reasons'] = sorted({str(e.get('reason')) for e in refusals})
    # 0.2.2 F1: the raw drive (4 s) outlasts the 3.5 s above; the next scene's token is requested only after the
    # planner recorded the end of the raw drive (0.2.1 fleet robot-1: a leftover raw command started the new step early)
    L.wait(i, 'raw drive ended', 10, event='raw_done')
    # positive control: the same observer sees a permitted move
    d, _, _, _ = move('forward 0.3 m', f, 'positive_control')
    assert abs(d - 0.3) < 0.08, 'control moved %.3f m' % d


@scene('1', 'forward 1 m within the limits')
def s1(f):
    d, dth, _, _ = move('forward 1 m', f, 'move')
    assert abs(d - 1.0) < 0.15, 'moved %.3f m, want about 1.0' % d
    assert abs(dth) < 5, 'turned %.1f°' % dth
    f['after_completion_drives'] = quiet(2)
    assert f['after_completion_drives'] == 0, 'motion continued after the step completed'


@scene('2', 'a distance above the per-call limit: refused, nothing moves, warning')
def s2(f):
    refused('forward %g m' % OVER_M, f, 'step.max_duration_s', OVER_S, LIMITS['step.max_duration_s'])
    d, _, _, _ = move('forward 0.3 m', f, 'positive_control')
    assert abs(d - 0.3) < 0.08, 'control moved %.3f m, want about 0.3' % d


@scene('3', 'forward 1 m at 0.3 m/s is above the speed limit: refused')
def s3(f):
    refused('forward 1 m at 0.3 m/s', f, 'sls.linear_mps', 0.3, LIMITS['sls.linear_mps'])
    d, _, _, _ = move('forward 0.3 m', f, 'positive_control')
    assert abs(d - 0.3) < 0.08, 'control moved %.3f m, want about 0.3' % d


@scene('4', 'left 90 deg turns in place')
def s4(f):
    d, dth, _, _ = move('left 90 deg', f, 'move')
    assert abs(dth - 90) < 12 and d < 0.05, 'turned %.1f°, moved %.3f m' % (dth, d)


@scene('4b', 'back 0.5 m reverses')
def s4b(f):
    d, dth, p0, p1 = move('back 0.5 m', f, 'move')
    heading = (math.cos(p0['th']), math.sin(p0['th']))
    along = (p1['x'] - p0['x']) * heading[0] + (p1['y'] - p0['y']) * heading[1]
    f['along_heading_m'] = round(along, 3)
    assert abs(along + 0.5) < 0.08, 'moved %.3f m along the heading, want -0.5' % along


@scene('4c', 'left 1 m = turn 90° then 1 m, two tokens')
def s4c(f):
    d, dth, p0, p1 = move('left 1 m', f, 'move')
    assert f['move']['tokens'] == 2, 'tokens %s' % f['move']['tokens']
    left = (-math.sin(p0['th']), math.cos(p0['th']))
    side = (p1['x'] - p0['x']) * left[0] + (p1['y'] - p0['y']) * left[1]
    f['to_the_left_m'] = round(side, 3)
    assert abs(dth - 90) < 12 and abs(side - 1.0) < 0.15, 'turned %.1f°, %.3f m to the left' % (dth, side)


@scene('5', 'planner exceeds its permit (0.3 m/s): gate blocks every command, token stays usable')
def s5(f):
    i = L.mark()
    r = post('/api/command', {'text': 'forward 1 m'})
    assert r.get('accepted'), 'plan refused: %s' % r.get('denial')
    L.wait(i, 'first motion', 20, event='drive')
    j = L.mark()
    post('/api/rogue', {'linear': 0.3})
    L.wait(j, 'gate ERR_CONSTRAINT', 10, event='gate', reason='ERR_CONSTRAINT')
    time.sleep(1)
    f['drives_while_rogue'] = quiet(2.5)
    f['max_speed_reaching_base'] = max([abs(e['x']) for e in L.drives(j)] or [0])
    assert f['drives_while_rogue'] == 0 and f['max_speed_reaching_base'] <= 0.1 + 1e-9, 'a command above the permit reached the base'
    k = L.mark()
    post('/api/rogue', {'linear': None})
    L.wait(k, 'motion resumes within the permit (same token)', 10, event='drive')
    f['resumed'] = True


@scene('7', 'wrong tag read: gate refuses, right tag restores')
def s7(f):
    post('/api/inputs', {'tag': 'other-box'})
    time.sleep(1)
    i = L.mark()
    r = post('/api/command', {'text': 'forward 0.5 m'})
    assert r.get('accepted'), 'plan refused: %s' % r.get('denial')
    L.wait(i, 'gate ERR_TARGET_MISMATCH', 15, event='gate', reason='ERR_TARGET_MISMATCH')
    time.sleep(.5)
    f['drives_with_wrong_tag'] = quiet(2.5)
    assert f['drives_with_wrong_tag'] == 0, 'the base moved while the tag did not match the token target'
    j = L.mark()
    post('/api/inputs', {'tag': 'sample-box'})
    L.wait(j, 'motion after the right tag', 15, event='drive')
    f['restored'] = True
    # a feed switch is not a new task: the planner must not have restarted its plan
    # (counted from the switch itself — the plan's own submission is one instruction before it)
    time.sleep(.5)
    f['planner_restarts_on_feed_switch'] = len(L.since(j, source='planner', event='instruction'))
    assert f['planner_restarts_on_feed_switch'] == 0, 'switching the tag restarted the running plan'


@scene('8', 'safety UNSAFE while moving: stop, the interrupted plan never resumes; a new plan runs once safety is OK (unlock is a no-op: no forgery lock)')
def s8(f):
    i = L.mark()
    r = post('/api/command', {'text': 'forward 1 m'})
    assert r.get('accepted'), 'plan refused: %s' % r.get('denial')
    L.wait(i, 'first motion', 20, event='drive')
    j = L.mark()
    post('/api/inputs', {'safety': 'UNSAFE'})
    L.wait(j, 'gate ESTOP', 5, event='gate', state='ESTOP')
    time.sleep(.5)
    f['drives_after_unsafe'] = quiet(2)
    assert f['drives_after_unsafe'] == 0, 'the base kept moving after safety went UNSAFE'
    post('/api/inputs', {'safety': 'OK'})
    f['drives_after_ok_without_unlock'] = quiet(3)
    f['planner_restarts_on_feed_switch'] = len(L.since(j, source='planner', event='instruction'))
    assert f['planner_restarts_on_feed_switch'] == 0, 'switching the safety level restarted the running plan'
    assert f['drives_after_ok_without_unlock'] == 0, 'motion resumed without an operator'
    u = post('/api/unlock')
    f['unlock'] = u
    assert u.get('accepted'), 'unlock refused: %s' % u
    time.sleep(1)
    d, _, _, _ = move('forward 0.3 m', f, 'after_unlock')
    assert abs(d - 0.3) < 0.08, 'control moved %.3f m, want about 0.3' % d


@scene('S', 'stop while moving: the plan is cancelled at the issuer; the next plan runs on its own token')
def ss(f):
    i = L.mark()
    r = post('/api/command', {'text': 'forward 1 m'})
    assert r.get('accepted'), 'plan refused: %s' % r.get('denial')
    first_token = r['tokens'][0]['id']
    L.wait(i, 'first motion', 20, event='drive')
    time.sleep(1.0)
    j = L.mark()
    st = post('/api/command', {'text': 'stop'})
    ev = L.wait(j, 'stopped event', 5, event='stopped')[0]
    f['stop'] = dict(response=st.get('cancelled'), plan=ev.get('plan'), cancelled=ev.get('cancelled'))
    assert ev.get('plan') == r.get('plan') and ev.get('cancelled') is True, 'stop did not cancel the running plan at the issuer: %s' % f['stop']
    # The stop propagates: console → instruction file → planner (one command period). Commands
    # already in flight when the planner reads 'idle' are the planner's, not the gate's, to
    # explain — so the judgment starts when the robot side acknowledged the stop, and the raw
    # count from the console's own timestamp is recorded beside it.
    ack = L.wait(j, 'planner acknowledged the stop', 5, source='planner', event='instruction', mode='idle', stop_id=ev['stop_id'])[0]
    time.sleep(2)
    observed = L.since(j)
    f['stop_id'] = ev['stop_id']
    f['observation_event_range'] = dict(start_inclusive=j, end_exclusive=j+len(observed))
    try:
        f.update(summarize_stop(observed, ev['stop_id']))
    except ValueError as ex:
        raise AssertionError('stop observation invalid: ' + str(ex)) from ex
    assert f['drives_after_stop'] == 0, 'the base kept moving after the robot side acknowledged the stop'
    # recorded, not judged: when the gate stopped reporting the cancelled plan's permit
    # (on a robot with the agent mirror this is the mirror's refresh, not a beacon)
    try:
        g = L.wait(j, 'gate without the cancelled permit', 10, event='gate', pred=lambda e: e.get('state') != 'PERMIT' or e.get('token') != first_token)[0]
        f['gate_after_stop'] = dict(state=g.get('state'), reason=g.get('reason'), raw_cross_clock_after_cancel_s=round(g['t'] - ev['t'], 3))  # wall-clock: two event stamps from the log, recorded as a raw cross-clock value
    except AssertionError:
        f['gate_after_stop'] = None
    # Before 2026-09-15 stop only idled the planner: the cancelled plan's remaining step window
    # stayed live at the issuer and the next plan could be run on the previous plan's token.
    k = L.mark()
    d, _, _, _ = move('forward 0.3 m', f, 'next')
    issued = L.since(k, event='issued')[0]
    permitted = L.since(k, event='step_permitted')
    f['next']['permitted_token'] = permitted[0].get('token') if permitted else None
    f['next']['cancelled_plan_token'] = first_token
    assert permitted and permitted[0].get('token') == issued['tokens'][0]['id'], 'the next plan did not run on its own token: %s' % f['next']
    assert permitted[0].get('token') != first_token, 'the next plan ran on the cancelled plan\'s token'
    assert abs(d - 0.3) < 0.08, 'moved %.3f m after stop, want about 0.3' % d


@scene('R', 'restart the robot side, then a permitted move works again')
def sr(f):
    i = L.mark()
    r = post('/api/restart_robot', {'operation_id': uuid.uuid4().hex})
    assert r.get('ok'), 'restart failed: %s' % r
    L.wait(i, 'restart completed', 120, event='robot_restarted')
    if SIMULATED:  # the simulated base restarts with the robot side; a real base driver stays up
        assert L.since(i, source='base', event='ready'), 'the simulated base did not come back'
    # The restarted base starts its pose stream again at the origin. The latest pose in the feed can still be the one
    # from BEFORE the restart for a moment, and a move measured from it includes the reset jump (2026-10-10, this scene:
    # recorded 0.295 m vs measured 0.416 m, start [0.03, -0.32, 175 deg]): measure only from a pose produced after it.
    j = L.mark()
    L.wait(j, 'a pose from the restarted robot', 30, event='pose')
    d, _, _, _ = move('forward 0.3 m', f, 'after_restart')
    assert abs(d - 0.3) < 0.08, 'moved %.3f m after restart' % d


@scene('9', 'ledger verifies')
def s9(f):
    r = post('/api/verify')
    f['output_tail'] = r.get('output', '').splitlines()[-2:]
    assert r.get('ok'), 'verify failed'


def main():
    try:
        urllib.request.urlopen(BASE + '/api/state', timeout=5).read()
    except OSError as ex:
        print('Console not reachable at %s (%s). Start it with: python3 examples/tb3/demo.py up' % (BASE, ex), file=sys.stderr)
        return 2
    suite = [s6, s1, s2, s3, s4, s4b, s4c, s5, s7, s8, ss, sr, s9]
    RUN.data['expected_scene_ids'] = [s.sid for s in suite if not A.only or s.sid in A.only.split(',')]
    RUN.save(RESULTS)
    # Readiness is a prerequisite, not a verdict: on hardware the first pose arrives only after the base driver and
    # the encoder observer are up (8.8 s after RIG_UP in one preview.14 evaluation). Starting scene 6 before that
    # recorded "no pose" as a product FAIL. Wait a bounded time; if no pose comes, end as NOT_READY (rc 3).
    if not SIMULATED:   # the simulated base streams poses from its first tick; only a robot-side source can be late
        try:
            L.wait(0, 'a first pose from the base before any scene', 45, event='pose')
        except AssertionError as ex:
            RUN.save(RESULTS, completed=True, error='NOT_READY: ' + str(ex))
            print('RESULT=NOT_READY 0/%d OUT=%s' % (len(RUN.data['expected_scene_ids']), A.out))
            print('NOT_READY: the base produced no pose within 45 s — wait for the driver/encoders (HARDWARE.md §9) and run again; no scene was judged')
            return 3
    for s in suite:
        s()
        if CLOCK_FAILED:
            break  # Do not submit more plans after an invalid timing prerequisite.
    ok = bool(RESULTS) and all(r['passed'] for r in RESULTS)
    scope = ('software path with a simulated base; synthetic identity and safety feeds; not a robot measurement' if SIMULATED
             else 'real robot side, positions from %s; synthetic identity and safety feeds' % STATE.get('position_source'))
    RUN.save(RESULTS, scope=scope, completed=True, error='CLOCK_PREREQUISITE_FAILED' if CLOCK_FAILED else None)
    print('RESULT=%s %d/%d OUT=%s' % ('PASS' if ok else 'FAIL', sum(r['passed'] for r in RESULTS), len(RESULTS), A.out))
    if CLOCK_FAILED:
        print('CLOCK_PREREQUISITE_FAILED in scenes %s — restart the robot side and run again; thresholds were not changed' % ','.join(CLOCK_FAILED))
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
