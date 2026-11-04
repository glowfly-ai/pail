#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Issuer-outage fault injection across an E-STOP, driven through the demo console.

Works against the software TurtleBot3 demo (`evaluation.py tb3`, simulated base) and
against the hardware console (`hardware/console_hw.py`, real robot, wheels raised).
The Issuer container is paused on the operator PC with `docker pause`, which keeps its
sockets open: a request sent while it is paused is delayed, not lost, and is processed
when the container resumes. That is the model under which a revocation report must
still take effect.

Two sequences, chosen with --mode:

  permit   The robot is moving under a live permit. Pause the Issuer, then safety
           UNSAFE -> OK while it is paused, keep it paused for --pause seconds, resume.
           Expected: no drive command reaches the base after OK; the gate refuses the
           interrupted chain with ERR_REVOKED fatal_latched; the Issuer ledger holds the
           revoking ESTOP once.

  outage   The robot is moving; pause the Issuer and wait --wait-block seconds so the
           gate has already lost its permit (BLOCK ERR_ISSUER_UNREACHABLE); then UNSAFE.
           The last gate record before UNSAFE must be that refusal, or the verdict is
           PRECONDITION_NOT_MET (exit 3): a step that is still running keeps its permit
           until its delegated window is exhausted. Multiple steps may already be delegated;
           no fixed --wait-block or two-step instruction guarantees this precondition on hardware
           -> OK, and resume the Issuer --ok-hold seconds later. Expected: the same —
           the chain whose step was interrupted is never permitted again.

Both print one JSON line and append it to --out: the number of non-zero drive commands
forwarded to the base after OK (must be 0), the gate decisions after the injection
point, and the planner events. Read the Issuer container log for the ledger lines:
`docker logs <issuer> 2>&1 | grep decision=ESTOP`.

usage:
  fault_inject.py --mode permit --console http://127.0.0.1:8765 --state /tmp/pail-hw-console --issuer pailhw-issuer --pause 30
  fault_inject.py --mode outage --console http://127.0.0.1:8876 --state /tmp/p-sw --issuer <demo issuer container> --wait-block 4 --ok-hold 0.5

--issuer is the Issuer container's name on this PC. The hardware rig's is `pailhw-issuer`
(issuer_host.sh). The software demo names its containers per run; find the Issuer with
  docker ps --format '{{.Names}}' | grep issuer          # e.g. pail-tb3-demo-<release>-<id>-issuer-1

The console state is the directory given to console_hw.py or evaluation.py (its
evidence/runtime holds the mirrored participant logs). Stop the robot and let it settle
before the first run; the script sends `stop` itself and waits three seconds.
"""
import argparse
import json
import os
import shlex
import subprocess
import sys
import time
import urllib.request


def docker_command(argv, robot_ssh, remote_containers):
    """Route only an explicit container operand, never a script/string match."""
    if not robot_ssh or not remote_containers:
        return argv
    action=argv[1] if len(argv)>1 else ''
    index={'exec':2, 'inspect':4, 'start':2, 'restart':2}.get(action)
    if action=='exec' and len(argv)>2 and argv[2]=='-d': index=3
    if index is not None and len(argv)>index and argv[index] in remote_containers:
        return ['ssh','-o','BatchMode=yes','-o','ConnectTimeout=10','--',robot_ssh,shlex.join(argv)]
    return argv


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--mode', choices=('permit', 'outage', 'agent-crash'), required=True)
    ap.add_argument('--agent', default=None, help='agent-crash: container running pail_robot_agent (default: --issuer, the split entrypoint of the demos)')
    ap.add_argument('--robot-ssh', help='SSH destination for --agent and --robot only; Issuer stays local')
    ap.add_argument('--robot', default=None, help='agent-crash: the gate container; when given, the gate is SIGKILLed and restarted inside it too')
    ap.add_argument('--kill-after', type=float, default=2.0, help='agent-crash: seconds after UNSAFE before the agent is SIGKILLed')
    ap.add_argument('--ledger-wait', type=float, default=20.0, help='agent-crash: seconds to wait for the Issuer to record the ESTOP after it resumes')
    ap.add_argument('--console', required=True, help='console base URL, e.g. http://127.0.0.1:8765')
    ap.add_argument('--state', required=True, help='console state directory (holds evidence/runtime)')
    ap.add_argument('--issuer', required=True, help='Issuer container name on this PC (docker pause/unpause)')
    ap.add_argument('--instruction', default='forward 1 m')
    ap.add_argument('--pause', type=float, default=12.0, help='permit mode: total seconds the Issuer stays paused')
    ap.add_argument('--wait-block', type=float, default=4.0, help='outage mode: seconds between pause and UNSAFE')
    ap.add_argument('--ok-hold', type=float, default=0.5, help='outage mode: seconds between OK and unpause')
    ap.add_argument('--observe', type=float, default=10.0, help='seconds to watch after the Issuer resumes')
    ap.add_argument('--label', default=None)
    ap.add_argument('--out', default='fault_inject.jsonl')
    a = ap.parse_args()
    if a.robot_ssh and (not a.agent or a.agent == a.issuer or a.robot == a.issuer or a.robot_ssh.startswith('-')):
        ap.error('--robot-ssh requires an explicit remote --agent distinct from the local --issuer')
    remote = {a.agent, a.robot} - {None} if a.robot_ssh else set()
    def runner(argv, **kwargs):
        return subprocess.run(docker_command(argv, a.robot_ssh, remote), **kwargs)
    rt = os.path.join(a.state, 'evidence', 'runtime')
    if not os.path.isdir(rt):
        raise SystemExit('refused: %s has no evidence/runtime (is this the console state directory?)' % a.state)
    label = a.label or ('%s-%gs' % (a.mode, a.pause if a.mode == 'permit' else a.wait_block))

    def post(path, body):
        req = urllib.request.Request(a.console + path, data=json.dumps(body).encode(), headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.loads(r.read())

    def rows(name):
        p = os.path.join(rt, name)
        out = []
        if not os.path.exists(p):
            return out
        with open(p) as f:
            for line in f:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
        return out

    # Hardware console: the drive observer mirrors what the vendor driver received (sample_mono).
    # Software demo: the simulated base logs every drive command it received (mono).
    def drives_after(t_mono):
        hw = [e for e in rows('demo-drive.jsonl') if e.get('event') == 'drive_observer']
        if hw:
            return [e for e in hw if (abs(e.get('x', 0)) > 1e-6 or abs(e.get('z', 0)) > 1e-6) and e.get('sample_mono', e['mono']) > t_mono]
        return [e for e in rows('demo-base.jsonl') if e.get('event') == 'drive' and (abs(e.get('x', 0)) > 1e-6 or abs(e.get('z', 0)) > 1e-6) and e['mono'] > t_mono]

    def last_mono():
        base = rows('demo-base.jsonl')[-50:]
        if not base:
            raise SystemExit('refused: no demo-base.jsonl rows yet — is the stack up and mirrored?')
        return max(e['mono'] for e in base)

    def docker(*args):
        runner(['docker', *args], check=True, timeout=60)

    if a.mode == 'agent-crash':
        return agent_crash(a, label, post, rows, drives_after, last_mono, docker, runner)
    post('/api/command', {'text': 'stop'})
    time.sleep(3)
    m_start = last_mono()
    accepted = post('/api/command', {'text': a.instruction}).get('accepted')
    t0 = time.monotonic()
    while time.monotonic() - t0 < 25 and not drives_after(m_start):
        time.sleep(0.05)
    if not drives_after(m_start):
        res = dict(label=label, mode=a.mode, error='no forwarded motion within 25 s', accepted=accepted)
        print(json.dumps(res)); open(a.out, 'a').write(json.dumps(res) + '\n'); return 2
    time.sleep(0.5 if a.mode == 'outage' else 1.0)
    m0 = last_mono()
    docker('pause', a.issuer)
    t_pause = time.monotonic()
    paused = True
    try:
        precondition = None
        if a.mode == 'outage':
            time.sleep(a.wait_block)
            # The row this mode documents is "E-STOP with no live permit": the gate must already be refusing with
            # BLOCK ERR_ISSUER_UNREACHABLE when UNSAFE arrives. On a real base a running step keeps its permit until
            # a delegated window ends; even multiple steps may already be delegated (three hardware runs took the
            # permit path and were still called PASS). The last gate record before UNSAFE is therefore part of the
            # verdict: when it is not that refusal, the run is PRECONDITION_NOT_MET, whatever happened after OK.
            last = [e for e in rows('demo-planner.jsonl') if e.get('event') == 'gate' and e['mono'] > m0]
            last = last[-1] if last else None
            precondition = bool(last and last.get('state') == 'BLOCK' and last.get('reason') == 'ERR_ISSUER_UNREACHABLE')
        post('/api/inputs', {'safety': 'UNSAFE'})
        time.sleep(1.0 if a.mode == 'outage' else 1.5)
        m_ok = last_mono()
        post('/api/inputs', {'safety': 'OK'})
        if a.mode == 'outage':
            time.sleep(a.ok_hold)
        else:
            time.sleep(4.0)
            rest = a.pause - (time.monotonic() - t_pause)
            if rest > 0:
                time.sleep(rest)
        during = len(drives_after(m_ok + 0.3))
        docker('unpause', a.issuer)
        paused = False
        t_resume = time.monotonic()
        time.sleep(a.observe)
    finally:
        if paused:
            docker('unpause', a.issuer)
    gates = [(round(e['mono'] - m0, 3), e.get('state'), e.get('reason'), (e.get('token') or '')[:8], (e.get('detail') or '')[:80])
             for e in rows('demo-planner.jsonl') if e.get('event') == 'gate' and e['mono'] > m0]
    planner = [(round(e['mono'] - m0, 2), e['event'], (e.get('token') or '')[:8])
               for e in rows('demo-planner.jsonl') if e['mono'] > m0 - 12 and e.get('event') in ('instruction', 'step_permitted', 'step_done', 'plan_done', 'plan_clock_aborted')]
    res = dict(label=label, mode=a.mode, instruction=a.instruction, accepted=accepted, issuer_paused_s=round(t_resume - t_pause, 1),
               drives_after_ok_while_paused=during, drives_after_ok_total=len(drives_after(m_ok + 0.3)),
               verdict=('PRECONDITION_NOT_MET' if precondition is False else 'PASS' if not drives_after(m_ok + 0.3) else 'FAIL'),
               precondition_gate_state_at_unsafe=(None if precondition is None else ('BLOCK ERR_ISSUER_UNREACHABLE' if precondition else (last and '%s %s' % (last.get('state'), last.get('reason'))) or 'no gate record')),
               gates=gates[:16], planner=planner[:12])
    print(json.dumps(res))
    with open(a.out, 'a') as f:
        f.write(json.dumps(res) + '\n')
    return 0 if res['verdict'] == 'PASS' else 3 if res['verdict'] == 'PRECONDITION_NOT_MET' else 1


# Linux keeps at most 15 bytes of a process name in /proc/<pid>/comm (TASK_COMM_LEN 16 with the NUL), so
# `pail_robot_agent` reads back as `pail_robot_agen`. The preview.26 contaminated-host replay compared the full name,
# matched no process (signalled=0) and refused the injection; the comparison uses what the kernel stores.
COMM_LEN = 15


def signal_process(container, comm, sig, shell='sh', runner=None):
    """Send `sig` to every process named `comm` inside `container` with the shell builtin kill (the runtime images
    carry no kill binary; preview.25 evaluation §7). `comm` is compared as the kernel stores it (COMM_LEN bytes)."""
    runner = runner or subprocess.run
    script = 'n=0; for d in /proc/[0-9]*; do if [ "$(cat $d/comm 2>/dev/null)" = %s ]; then kill -%s ${d#/proc/} && n=$((n+1)); fi; done; echo signalled=$n' % (comm[:COMM_LEN], sig)
    r = runner(['docker', 'exec', container, shell, '-c', script], capture_output=True, text=True, timeout=30)
    if r.returncode or 'signalled=0' in r.stdout:
        raise RuntimeError('signal %s to %s in %s: rc=%d %s %s' % (sig, comm, container, r.returncode, r.stdout.strip()[-120:], r.stderr.strip()[-120:]))


def container_running(name, runner=None):
    runner = runner or subprocess.run
    r = runner(['docker', 'inspect', '--format', '{{.State.Running}}', name], capture_output=True, text=True, timeout=30)
    return r.returncode == 0 and r.stdout.strip() == 'true'


def agent_crash(a, label, post, rows, drives_after, last_mono, docker, runner=None):
    """agent-crash (preview.25 evaluation P25-M2): the robot moves; pail_cloud is SIGSTOPped (the Issuer cannot
    answer); UNSAFE; --kill-after seconds later the agent is SIGKILLed — in the demos it shares the Issuer
    container (split entrypoint, `wait -n`), so the container exits and is started again; with --robot the gate
    is SIGKILLed and restarted inside its container too; then OK while the planner still holds the interrupted
    instruction. Two verdict parts: no non-zero drive after OK (safety) AND the Issuer records the ESTOP of the
    interrupted token after it resumes (evidence) — the part that was lost 6 of 8 times before the fatal
    write-ahead and the durable queue of the TB3 demo (LEDGER_MISSING is a FAIL, not a note)."""
    runner = runner or subprocess.run
    agent = a.agent or a.issuer
    post('/api/command', {'text': 'stop'})
    time.sleep(3)
    m_start = last_mono()
    accepted = post('/api/command', {'text': a.instruction}).get('accepted')
    t0 = time.monotonic()
    while time.monotonic() - t0 < 25 and not drives_after(m_start):
        time.sleep(0.05)
    if not drives_after(m_start):
        res = dict(label=label, mode=a.mode, error='no forwarded motion within 25 s', accepted=accepted)
        print(json.dumps(res)); open(a.out, 'a').write(json.dumps(res) + '\n'); return 2
    time.sleep(1.0)
    m0 = last_mono()
    token = next(((e.get('token') or '') for e in reversed(rows('demo-planner.jsonl')) if e.get('event') == 'gate' and e.get('state') == 'PERMIT'), '')
    t_wall0 = time.time()
    stopped = True
    unsafe = False
    signal_process(a.issuer, 'pail_cloud', 'STOP')
    try:
        post('/api/inputs', {'safety': 'UNSAFE'})
        unsafe = True
        time.sleep(a.kill_after)
        # the agent dies with its fatal unconfirmed (the Issuer is stopped); in the split container this ends the container
        signal_process(agent, 'pail_robot_agent', 'KILL', runner=runner)
        stopped = agent != a.issuer  # a remote/separate agent cannot resume the local Issuer
        deadline = time.monotonic() + 30
        while container_running(agent, runner=runner) and time.monotonic() < deadline:
            time.sleep(0.2)
        if container_running(agent, runner=runner):
            # separate agent container (hardware rig): the Issuer is still stopped — resume it so the restarted agent can report
            if stopped:
                signal_process(a.issuer, 'pail_cloud', 'CONT')
                stopped = False
            docker('restart', agent)
        else:
            docker('start', agent)
        if stopped:
            signal_process(a.issuer, 'pail_cloud', 'CONT')
            stopped = False
        if a.robot:
            signal_process(a.robot, 'pep_gate_node', 'KILL', shell='bash', runner=runner)
            time.sleep(0.5)
            runner(['docker', 'exec', '-d', a.robot, 'bash', '-c', 'source /opt/ros/humble/setup.bash && source /opt/pail_ws/install/setup.bash && exec /usr/local/bin/pep_gate_entrypoint.sh'], check=True, timeout=30)
        time.sleep(1.5)
        m_ok = last_mono()
        post('/api/inputs', {'safety': 'OK'})
        unsafe = False
        time.sleep(a.observe)
    finally:
        if stopped:
            try:
                signal_process(a.issuer, 'pail_cloud', 'CONT')
            except RuntimeError:
                pass
        if unsafe:
            # a refused run must not leave the demo UNSAFE: the next injection on the same demo would then see
            # "no forwarded motion within 25 s" (preview.26 contaminated replay, agent-crash-2 after a refused agent-crash-1)
            try:
                post('/api/inputs', {'safety': 'OK'})
            except Exception:
                pass
    # evidence: the Issuer's receipt of the ESTOP for the interrupted token, after the crash
    ledger = None
    deadline = time.monotonic() + a.ledger_wait
    while time.monotonic() < deadline and not ledger:
        r = subprocess.run(['docker', 'logs', '--since', time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(t_wall0)), a.issuer], capture_output=True, text=True, timeout=30)
        for line in (r.stdout + r.stderr).splitlines():
            if 'TokenService.ReportDecision' in line and 'decision=ESTOP' in line and (not token or 'token_id=' + token in line):
                ledger = line.strip()[:200]
                break
        if not ledger:
            time.sleep(1.0)
    drives = len(drives_after(m_ok + 0.3))
    gates = [(round(e['mono'] - m0, 3), e.get('state'), e.get('reason'), (e.get('token') or '')[:8], (e.get('detail') or '')[:80])
             for e in rows('demo-planner.jsonl') if e.get('event') == 'gate' and e['mono'] > m0]
    verdict = 'PASS' if drives == 0 and ledger else ('FAIL' if drives else 'LEDGER_MISSING')
    res = dict(label=label, mode=a.mode, instruction=a.instruction, accepted=accepted, kill_after_s=a.kill_after, gate_restarted=bool(a.robot),
               interrupted_token=token[:8], drives_after_ok_total=drives, issuer_recorded_estop=ledger, verdict=verdict, gates=gates[:16])
    print(json.dumps(res))
    with open(a.out, 'a') as f:
        f.write(json.dumps(res) + '\n')
    return 0 if verdict == 'PASS' else 1


if __name__ == '__main__':
    # a failure ends with a named refusal line, never a bare traceback (class pin C2)
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError) as exc:
        print('FAULT_INJECT_REFUSED: ' + str(exc), file=sys.stderr, flush=True)
        sys.exit(2)
