#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""TB3 live demo on the FLOOR — drives the hardware console (console_hw.py) through the floor
scenes. Only with the operator's clear-floor statement (HARDWARE.md, section 6).

Space agreed with the operator: 1.5 m ahead, 0.5 m behind the start, operator beside the
robot. Only straight moves along the start heading and turns in place. Before every
command the projected position along the start heading must stay inside [-0.45, +1.45] m;
otherwise the run stops without sending it. Speeds never exceed the policy (0.1 m/s).
Distances are wheel-encoder odometry: on a floor they include any wheel slip unseen.

  python3 examples/tb3/hardware/floor_run.py --out results.json
"""
import argparse, json, math, sys, time, urllib.request

AP = argparse.ArgumentParser()
AP.add_argument('--url', default='http://127.0.0.1:8765')
AP.add_argument('--out', required=True)
AP.add_argument('--only', default='', help='comma separated step ids (F2,F8b); default all')
A = AP.parse_args()
B = A.url.rstrip('/')
AHEAD, BEHIND = 1.45, -0.45


def post(path, body=None):
    r = urllib.request.Request(B + path, data=json.dumps(body or {}).encode(), headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(r, timeout=60) as f:
        return json.loads(f.read())


EV, NEXT = [], [0]


def pull():
    while True:
        with urllib.request.urlopen(B + '/api/events?from=%d' % NEXT[0], timeout=30) as f:
            g = json.loads(f.read())
        EV.extend(g['events'])
        NEXT[0] += len(g['events'])
        if len(g['events']) < 2000:
            return


def mark():
    pull()
    return len(EV)


def since(i, **kw):
    pull()
    return [e for e in EV[i:] if all(e.get(k) == v for k, v in kw.items())]


def wait(i, what, timeout, pred=lambda e: True, **kw):
    end = time.time() + timeout
    while time.time() < end:
        h = [e for e in since(i, **kw) if pred(e)]
        if h:
            return h
        time.sleep(.2)
    raise AssertionError('not observed within %ss: %s' % (timeout, what))


def pose():
    p = since(0, event='pose')
    if not p or time.time() - p[-1]['t'] > 2:  # wall-clock: freshness of a pose stamp written by the robot side
        raise AssertionError('encoder pose is not fresh')
    return p[-1]


pull()
P0 = pose()
C0, S0 = math.cos(P0['th']), math.sin(P0['th'])


def along(p):
    return (p['x'] - P0['x']) * C0 + (p['y'] - P0['y']) * S0


def heading_deg(p):
    return math.degrees(math.atan2(math.sin(p['th'] - P0['th']), math.cos(p['th'] - P0['th'])))


def guard(worst_forward=0.0, worst_back=0.0):
    s = along(pose())
    if abs(heading_deg(pose())) > 20:
        raise SystemExit('ABORT: heading %.0f° from the start line — straight moves would leave the agreed space' % heading_deg(pose()))
    if s + worst_forward > AHEAD or s - worst_back < BEHIND:
        raise SystemExit('ABORT: projected position %.2f..%.2f m leaves [%.2f, %.2f]' % (s - worst_back, s + worst_forward, BEHIND, AHEAD))
    return s


def quiet(sec):
    i = mark()
    p0 = pose()
    time.sleep(sec)
    p1 = pose()
    return len(since(i, event='drive')), round(math.hypot(p1['x'] - p0['x'], p1['y'] - p0['y']), 4)


def stop():
    post('/api/command', {'text': 'stop'})
    for _ in range(20):
        n, d = quiet(1.2)
        if n == 0 and d < 0.002:
            return
    raise SystemExit('ABORT: robot did not come to rest after stop')


def move(text, cmd_m):
    p0 = pose()
    i = mark()
    t0 = time.monotonic()
    r = post('/api/command', {'text': text})
    assert r.get('accepted'), '%s refused: %s' % (text, r.get('denial'))
    wait(i, 'permit for %s' % text, 20, event='step_permitted')
    total = sum(s['duration'] for s in r['steps'])
    wait(i, 'completion of %s' % text, total * 2 + 20, event='plan_done')
    time.sleep(1.5)
    p1 = pose()
    return dict(text=text, commanded_m=cmd_m, encoder_along_m=round(along(p1) - along(p0), 3),
                encoder_dist_m=round(math.hypot(p1['x'] - p0['x'], p1['y'] - p0['y']), 3),
                heading_change_deg=round(heading_deg(p1) - heading_deg(p0), 1), seconds=round(time.monotonic() - t0, 1),
                drives=len(since(i, event='drive')), constraint_refusals=len(since(i, event='gate', reason='ERR_CONSTRAINT')))


def home():
    s = along(pose())
    if abs(s) < 0.03:
        return None
    text = ('back %.2f m' % s) if s > 0 else ('forward %.2f m' % -s)
    return move(text, -s)


R = []


def step(sid, title, fn):
    f = {}
    try:
        fn(f)
        ok, err = True, None
    except AssertionError as ex:
        ok, err = False, str(ex)
    R.append(dict(id=sid, title=title, passed=ok, error=err, facts=f, along_after_m=round(along(pose()), 3)))
    print(('PASS ' if ok else 'FAIL ') + sid + ' ' + title + ('' if ok else ' — ' + err) + '  [at %.2f m]' % along(pose()), flush=True)
    stop()


def f0(f):
    post('/api/inputs', {'tag': 'sample-box', 'safety': 'OK'})
    f['drives'], f['moved_m'] = quiet(2)
    assert f['drives'] == 0 and f['moved_m'] < 0.005, 'robot not at rest'


def f1(f):
    guard(0.45)
    i = mark()
    post('/api/raw', {'linear': 0.1, 'duration': 3})
    wait(i, 'refusal for lack of a permit', 8, event='gate', pred=lambda e: e.get('reason') in ('ERR_NO_TOKEN', 'ERR_TOKEN_CONSUMED', 'ERR_EXPIRED'))
    time.sleep(.5)
    f['drives'], f['moved_m'] = quiet(2.5)
    assert f['drives'] == 0 and f['moved_m'] < 0.005, 'the robot moved without a plan'


def f2(f):
    guard(1.0)
    f['forward'] = move('forward 1 m', 1.0)
    assert f['forward']['drives'] > 0 and abs(f['forward']['encoder_along_m'] - 1.0) < 0.15, f['forward']
    f['back'] = move('back 1 m', -1.0)
    assert abs(f['back']['encoder_along_m'] + 1.0) < 0.15, f['back']


def refused(text, name):
    def run(f):
        guard(0.0)
        p0 = pose()
        r = post('/api/command', {'text': text})
        d = r.get('denial') or {}
        f['denial'] = d
        assert not r.get('accepted') and d.get('code') == 'ERR_ENVELOPE_EXCEEDED' and any(e['name'] == name for e in d.get('exceeded', [])), d
        f['drives'], f['moved_m'] = quiet(3)
        assert f['drives'] == 0 and f['moved_m'] < 0.005, 'the robot moved after a refusal'
        guard(0.3)
        f['control'] = move('forward 0.3 m', 0.3)
        assert f['control']['drives'] > 0, 'control move did not move'
        f['home'] = home()
    return run


def f5(f):
    guard(1.0)
    i = mark()
    assert post('/api/command', {'text': 'forward 1 m'}).get('accepted')
    wait(i, 'first motion', 20, event='drive')
    time.sleep(1.0)
    j = mark()
    post('/api/rogue', {'linear': 0.3})
    wait(j, 'gate ERR_CONSTRAINT', 8, event='gate', reason='ERR_CONSTRAINT')
    time.sleep(.8)
    f['drives_while_rogue'], f['moved_while_rogue_m'] = quiet(2)
    f['max_speed_at_driver'] = max([abs(e['x']) for e in since(j, event='drive')] or [0])
    assert f['drives_while_rogue'] == 0 and f['max_speed_at_driver'] <= 0.1 + 1e-9, f
    k = mark()
    post('/api/rogue', {'linear': None})
    wait(k, 'resume within the permit', 8, event='drive')
    time.sleep(1.0)
    stop()
    f['home'] = home()


def f6(f):
    f['left'] = move('left 90 deg', 0.0)
    f['right'] = move('right 90 deg', 0.0)
    assert abs(f['left']['heading_change_deg'] - 90) < 15 and abs(f['right']['heading_change_deg'] + 90) < 15, (f['left'], f['right'])
    assert f['left']['encoder_dist_m'] < 0.05 and f['right']['encoder_dist_m'] < 0.05, 'a turn in place translated'


def f7(f):
    guard(0.3)
    post('/api/inputs', {'tag': 'other-box'})
    time.sleep(1)
    i = mark()
    assert post('/api/command', {'text': 'forward 0.3 m'}).get('accepted')
    wait(i, 'gate ERR_TARGET_MISMATCH', 15, event='gate', reason='ERR_TARGET_MISMATCH')
    f['drives_wrong_tag'], f['moved_wrong_tag_m'] = quiet(2.5)
    assert f['drives_wrong_tag'] == 0 and f['moved_wrong_tag_m'] < 0.005, f
    j = mark()
    post('/api/inputs', {'tag': 'sample-box'})
    wait(j, 'motion after the right tag', 15, event='drive')
    time.sleep(4)
    stop()
    f['home'] = home()


def f8(f):
    guard(1.0)
    i = mark()
    assert post('/api/command', {'text': 'forward 1 m'}).get('accepted')
    wait(i, 'first motion', 20, event='drive')
    time.sleep(2.0)
    p_cmd = pose()
    j = mark()
    t_unsafe = time.time()
    post('/api/inputs', {'safety': 'UNSAFE'})
    e = wait(j, 'gate ESTOP', 5, event='gate', state='ESTOP')[0]
    f['estop_after_input_s'] = round(e['t'] - t_unsafe, 3)
    time.sleep(2.0)
    p_rest = pose()
    f['travel_after_unsafe_input_m'] = round(math.hypot(p_rest['x'] - p_cmd['x'], p_rest['y'] - p_cmd['y']), 3)
    drv = since(j, event='drive')
    f['last_drive_after_estop_s'] = round(max([d['t'] for d in drv] or [e['t']]) - e['t'], 3)
    f['drives_after_estop_2s'], f['moved_after_estop_2s_m'] = quiet(2)
    assert f['drives_after_estop_2s'] == 0 and f['moved_after_estop_2s_m'] < 0.005, f
    post('/api/inputs', {'safety': 'OK'})
    f['drives_ok_no_unlock'], f['moved_ok_no_unlock_m'] = quiet(3)
    assert f['drives_ok_no_unlock'] == 0 and f['moved_ok_no_unlock_m'] < 0.005, 'motion resumed without an operator'
    u = post('/api/unlock')
    f['unlock'] = u
    assert u.get('accepted'), u
    time.sleep(1)
    f['home'] = home()


def f8b(f):
    """Stop while moving: the plan is cancelled at the issuer and the next plan runs on its own token."""
    guard(1.0)
    i = mark()
    r = post('/api/command', {'text': 'forward 1 m'})
    assert r.get('accepted'), r.get('denial')
    first_token = r['tokens'][0]['id']
    wait(i, 'first motion', 20, event='drive')
    time.sleep(2.0)
    j = mark()
    t_stop = time.time()
    st = post('/api/command', {'text': 'stop'})
    ev = wait(j, 'stopped event', 5, event='stopped')[0]
    f['stop'] = dict(response=st.get('cancelled'), plan=ev.get('plan'), cancelled=ev.get('cancelled'), console_s=round(ev['t'] - t_stop, 3))
    assert ev.get('plan') == r.get('plan') and ev.get('cancelled') is True, 'stop did not cancel the plan at the issuer: %s' % f['stop']
    # A real base decelerates from 0.1 m/s after the zero command (the ESTOP scene F8 measures
    # about 0.045 m); what must not happen is the first floor run's shape — 0.87 m more, until
    # the step window expired. Judged like F8: no drive command after the stop, travel well
    # under a step's worth, and at rest by the end of the window.
    f['drives_after_stop'], f['travel_after_stop_m'] = quiet(2)
    assert f['drives_after_stop'] == 0, 'the planner kept commanding after stop: %s' % f
    assert f['travel_after_stop_m'] < 0.10, 'the robot kept driving after stop (%.3f m) — the cancel did not reach the gateway' % f['travel_after_stop_m']
    f['drives_at_rest'], f['moved_at_rest_m'] = quiet(1)
    assert f['drives_at_rest'] == 0 and f['moved_at_rest_m'] < 0.005, 'not at rest 2 s after stop: %s' % f
    # recorded, not judged: the gate emits no event while the planner is idle, so a gate line
    # here (if any) is the zero command being refused on the cancelled token
    g = since(j, event='gate')
    f['gate_after_cancel'] = dict(state=g[0].get('state'), reason=g[0].get('reason'), after_stop_s=round(g[0]['t'] - t_stop, 3)) if g else None
    guard(0.3)
    k = mark()
    f['next'] = move('forward 0.3 m', 0.3)
    issued = since(k, event='issued')[0]
    permitted = since(k, event='step_permitted')
    f['next']['permitted_token'] = permitted[0].get('token') if permitted else None
    assert permitted and permitted[0].get('token') == issued['tokens'][0]['id'] and permitted[0].get('token') != first_token, \
        'the next plan did not run on its own token: %s' % f['next']
    f['home'] = home()


def f9(f):
    r = post('/api/verify')
    f['tail'] = r.get('output', '').splitlines()[-2:]
    assert r.get('ok'), 'ledger did not verify'


def main():
    print('start pose along=0 heading=0 (encoders at x=%.3f y=%.3f th=%.3f)' % (P0['x'], P0['y'], P0['th']), flush=True)
    for sid, title, fn in [x for x in [('F0', 'at rest', f0), ('F1', 'drive without permission: no motion', f1),
                           ('F2', 'forward 1 m, then back 1 m', f2),
                           ('F3', 'forward 5 m: refused, no motion, then 0.3 m control', refused('forward 5 m', 'step.max_duration_s')),
                           ('F4', '1 m at 0.3 m/s: refused, no motion, then 0.3 m control', refused('forward 1 m at 0.3 m/s', 'sls.linear_mps')),
                           ('F5', 'planner speeds up to 0.3 m/s: gate blocks, resumes within permit', f5),
                           ('F6', 'left 90 deg, right 90 deg in place', f6),
                           ('F7', 'wrong tag: no motion; right tag: moves', f7),
                           ('F8', 'UNSAFE while moving: stop distance, no auto resume, unlock', f8),
                           ('F8b', 'stop while moving: cancelled at the issuer, next plan on its own token', f8b),
                           ('F9', 'ledger verifies', f9)] if not A.only or x[0] in A.only.split(',')]:
        step(sid, title, fn)
    ok = all(r['passed'] for r in R)
    with open(A.out, 'w') as fh:
        json.dump(dict(passed=ok, placement='floor', space_m=[BEHIND, AHEAD], distances='wheel-encoder odometry (no tape measurement)', steps=R), fh, indent=2, ensure_ascii=False)
    print('RESULT=%s %d/%d' % ('PASS' if ok else 'FAIL', sum(r['passed'] for r in R), len(R)))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
