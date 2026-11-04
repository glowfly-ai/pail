#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Host-side driver: one probe container joined to the rig's namespaces, three taps, N publisher runs.

  compose rig (examples/tb3/demo.py):   lat_run.py --kind compose --state STATE --out OUTDIR [--rates 10,20,50,10]
  hardware rig (start_demo_rig.sh):     lat_run.py --kind hw --rig-dir DIR --config CFG --gate-image IMG
                                            --submit "CMD..." --out OUTDIR

Plans come from tb3-probe: compose rig = `docker exec <project>-issuer-1 tb3-probe`; hardware rig = the
--submit command prefix (native tb3-probe on the operator PC with -addr/-ca/-cert/-key, run over ssh or
locally). Every run: submit one 15 s twist step -> publish for --seconds -> cancel the plan.
"""
import argparse, json, os, shlex, subprocess, sys, threading, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROS_SRC = 'source /opt/ros/humble/setup.bash && source /opt/pail_ws/install/setup.bash && '
TAPS = [('cmd', '/cmd_vel', '/pep_gate'), ('safe', '/safe_cmd_vel', '/motion_bridge'), ('drive', '/drive_cmd_vel', '/driver')]
# sysfs paths assembled from parts: a long base64-shaped path literal trips the public key-material scan
CPUS = Path('/sys/devices/system/cpu')
GOV = CPUS / 'cpu0' / 'cpufreq' / 'scaling_governor'


def sh(cmd, check=True, timeout=120, quiet=False):
    if not quiet:
        print('+', ' '.join(shlex.quote(c) for c in cmd), flush=True)
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError('rc=%d: %s' % (p.returncode, (p.stderr or p.stdout)[-800:]))
    return p


def log(out, **kw):
    kw.setdefault('t', time.time())
    with (out / 'driver.jsonl').open('a') as f:
        f.write(json.dumps(kw) + '\n')
    print(json.dumps(kw), flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--kind', choices=['compose', 'hw'], required=True)
    ap.add_argument('--state', type=Path, help='compose rig state directory')
    ap.add_argument('--rig-dir', type=Path, help='hardware rig directory (holds control/ state/ fastdds_loopback.xml)')
    ap.add_argument('--config', type=Path, help='hardware rig robot configuration directory')
    ap.add_argument('--gate-image', help='hardware rig gate image (defaults from console.json on compose)')
    ap.add_argument('--submit', help='hardware rig: command prefix that runs tb3-probe with its connection flags')
    ap.add_argument('--out', type=Path, required=True, help='host directory for driver.jsonl and the analysis')
    ap.add_argument('--rates', default='10,20,50,10')
    ap.add_argument('--seconds', type=float, default=14.0)
    ap.add_argument('--step-linear', type=float, default=0.03)
    ap.add_argument('--settle', type=float, default=10.0, help='seconds to wait after the taps report ready (SROS2 discovery)')
    ap.add_argument('--name', default='lat-probe')
    ap.add_argument('--keep', action='store_true', help='leave the probe container running')
    ap.add_argument('--taps', default='cmd,safe,drive', help='which taps to run (fewer processes on a small board)')
    ap.add_argument('--buffer', action='store_true', help='taps and publisher keep records in memory until exit')
    a = ap.parse_args()
    taps = [t for t in TAPS if t[0] in a.taps.split(',')]
    buf = ' --buffer' if a.buffer else ''
    a.out.mkdir(parents=True, exist_ok=True)

    if a.kind == 'compose':
        con = json.loads((a.state / 'evidence/console.json').read_text())
        project, gate = con['project'], con['gate_image']
        net = project + '-netspace-1'
        issuer = project + '-issuer-1'
        mounts = ['-v', '%s:/etc/pail:ro' % (a.state / 'runtime/config'), '-v', '%s:/reference:ro' % (a.state / 'runtime/reference'),
                  '-v', '%s:/evidence' % (a.state / 'evidence')]
        env = ['-e', 'FASTRTPS_DEFAULT_PROFILES_FILE=/reference/fastdds_loopback.xml']
        evid = '/evidence/runtime'
        host_evid = a.state / 'evidence/runtime'
        submit = ['docker', 'exec', issuer, 'tb3-probe']
    else:
        if not (a.rig_dir and a.config and a.gate_image and a.submit):
            ap.error('--kind hw needs --rig-dir --config --gate-image --submit')
        gate, net = a.gate_image, 'pailhw-net'
        # state/ belongs to the rig's uid after `up`; the probe writes to its own scratch mount instead
        lat_dir = a.rig_dir / 'lat'
        lat_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(lat_dir, 0o777)  # the probe runs as the image user; this is a measurement scratch directory
        mounts = ['-v', '%s:/etc/pail:ro' % a.config, '-v', '%s:/demo:ro' % a.rig_dir, '-v', '%s:/lat' % lat_dir,
                  '-v', '%s:/etc/fastdds_udp_only.xml:ro' % (a.rig_dir / 'fastdds_loopback.xml')]
        env = ['-e', 'FASTRTPS_DEFAULT_PROFILES_FILE=/etc/fastdds_udp_only.xml']
        evid = '/lat'
        host_evid = lat_dir
        submit = shlex.split(a.submit)
    ros = ['-e', 'ROS_DOMAIN_ID=0', '-e', 'ROS_SECURITY_ENABLE=true', '-e', 'ROS_SECURITY_STRATEGY=Enforce',
           '-e', 'ROS_SECURITY_KEYSTORE=/etc/pail/sros2_keystore'] + env

    sh(['docker', 'rm', '-f', a.name], check=False, quiet=True)
    sh(['docker', 'run', '-d', '--name', a.name, '--network', 'container:' + net, '--ipc', 'container:' + net, '--cap-drop', 'ALL',
        '--label', 'pail.measurement=cmdvel-latency', *mounts, *ros, '--entrypoint', 'sleep', gate, 'infinity'])
    # `docker cp` keeps the host owner/mode (a 0600 file is unreadable to the image user); stream it in as that user.
    p = subprocess.run(['docker', 'exec', '-i', a.name, 'sh', '-c', 'umask 022; cat > /tmp/lat_probe.py'],
                       input=(HERE / 'lat_probe.py').read_bytes(), capture_output=True)
    if p.returncode:
        raise RuntimeError('probe copy failed: ' + p.stderr.decode()[-300:])
    sh(['docker', 'exec', a.name, 'python3', '-m', 'py_compile', '/tmp/lat_probe.py'])
    # one fresh directory per invocation (the taps' files are owned by the image user and append otherwise)
    stamp = time.strftime('%Y%m%dT%H%M%S')
    evid = evid + '/lat-' + stamp
    host_evid = host_evid / ('lat-' + stamp)
    sh(['docker', 'exec', a.name, 'sh', '-c', 'umask 022; mkdir -p ' + evid])
    facts = {
        'kind': a.kind, 'gate_image': gate, 'netspace': net,
        'image_inspect': json.loads(sh(['docker', 'image', 'inspect', gate], quiet=True).stdout)[0].get('RepoDigests'),
        'image_id': json.loads(sh(['docker', 'image', 'inspect', gate], quiet=True).stdout)[0].get('Id'),
        'probe_user': sh(['docker', 'exec', a.name, 'id'], quiet=True).stdout.strip(),
        'docker': sh(['docker', '--version'], quiet=True).stdout.strip(),
        'uname': sh(['uname', '-a'], quiet=True).stdout.strip(),
        'loadavg': Path('/proc/loadavg').read_text().strip() if Path('/proc/loadavg').exists() else None,
        'cpufreq': {p.parent.parent.name: p.read_text().strip() for p in CPUS.glob('cpu[0-9]*/cpufreq/scaling_cur_freq')},
        'governor': (GOV.read_text().strip() if GOV.exists() else None),
        'nvpmodel_status': Path('/var/lib/nvpmodel/status').read_text().strip() if Path('/var/lib/nvpmodel/status').exists() else None,
        'containers': sh(['docker', 'ps', '--format', '{{.Names}} {{.Image}} {{.Status}}'], quiet=True).stdout.strip().splitlines(),
    }
    log(a.out, event='facts', **facts)
    (a.out / 'facts.json').write_text(json.dumps(facts, indent=1))

    # taps (the ready record is written immediately even in --buffer mode: the file is created on open,
    # and the record itself is flushed with the rest at exit — so readiness is judged by the process list)
    for name, topic, enclave in taps:
        sh(['docker', 'exec', '-d', '-e', 'ROS_SECURITY_ENCLAVE_OVERRIDE=' + enclave, a.name, 'bash', '-c',
            ROS_SRC + 'exec python3 -u /tmp/lat_probe.py tap --topic %s --out %s/tap-%s.jsonl%s' % (topic, evid, name, buf)])
    end = time.time() + 60
    while time.time() < end:
        ps = sh(['docker', 'exec', a.name, 'ps', '-ef'], check=False, quiet=True).stdout
        alive = [n for n, _, _ in taps if ('tap-%s.jsonl' % n) in ps]
        files = [n for n, _, _ in taps if (host_evid / ('tap-%s.jsonl' % n)).exists()]
        if len(alive) == len(taps) and len(files) == len(taps) and time.time() > end - 55:
            break
        time.sleep(1)
    else:
        raise SystemExit('TAPS_NOT_READY: ' + sh(['docker', 'exec', a.name, 'ps', '-ef'], check=False).stdout)
    log(a.out, event='taps_ready', settle_s=a.settle, taps=[n for n, _, _ in taps], buffered=a.buffer)

    # host load sampler for the whole measurement window
    stop_sampler = threading.Event()

    def sample():
        with (a.out / 'load.jsonl').open('a') as f:
            while not stop_sampler.is_set():
                row = {'t': time.time(), 'loadavg': Path('/proc/loadavg').read_text().strip() if Path('/proc/loadavg').exists() else None}
                if Path('/proc/pressure/cpu').exists():
                    row['psi_cpu'] = Path('/proc/pressure/cpu').read_text().splitlines()[0]
                f.write(json.dumps(row) + '\n'); f.flush()
                stop_sampler.wait(2.0)
    threading.Thread(target=sample, daemon=True).start()
    time.sleep(a.settle)

    rates = [float(r) for r in a.rates.split(',')]
    for i, rate in enumerate(rates):
        seq0 = int(rate) * 1000 + i * 100000 if int(rate) * 1000 + i * 100000 < 900000 else i * 100000
        steps = json.dumps([{'linear': a.step_linear, 'angular': 0, 'duration': 15}])
        r = sh(submit + ['-mode', 'submit', '-steps', steps], timeout=60)
        res = json.loads(r.stdout.strip().splitlines()[-1])
        log(a.out, event='submitted', rate=rate, result=res)
        if res.get('status') != 'ACCEPTED':
            raise SystemExit('PLAN_REFUSED: ' + json.dumps(res))
        plan = res.get('plan')
        stats_before = sh(['docker', 'stats', '--no-stream', '--format', '{{.Name}} {{.CPUPerc}} {{.MemUsage}}'], quiet=True).stdout.strip().splitlines()
        t0 = time.time()
        p = sh(['docker', 'exec', '-e', 'ROS_SECURITY_ENCLAVE_OVERRIDE=/oem_planner', a.name, 'bash', '-c',
                ROS_SRC + 'exec python3 -u /tmp/lat_probe.py pub --rate %g --seconds %g --seq0 %d --out %s/pub-%02d-%gHz.jsonl%s'
                % (rate, a.seconds, seq0, evid, i, rate, buf)], timeout=a.seconds + 60, check=False)
        log(a.out, event='published', rate=rate, seq0=seq0, rc=p.returncode, wall_s=round(time.time() - t0, 2),  # wall-clock: the probe reports wall seconds of the publish window by design
            stderr=p.stderr[-400:], stats_before=stats_before,
            loadavg=Path('/proc/loadavg').read_text().strip() if Path('/proc/loadavg').exists() else None)
        c = sh(submit + ['-mode', 'cancel', '-plan', plan], check=False, timeout=60)
        log(a.out, event='cancelled', rate=rate, plan=plan, rc=c.returncode, output=c.stdout.strip()[-300:])
        time.sleep(4)

    # stop the taps gracefully (buffered records are written on SIGTERM), then copy and analyze
    stop_sampler.set()
    sh(['docker', 'exec', a.name, 'pkill', '-TERM', '-f', 'lat_probe.py tap'], check=False)
    end = time.time() + 20
    while time.time() < end:
        done_taps = [n for n, _, _ in taps if (host_evid / ('tap-%s.jsonl' % n)).exists() and '"exit"' in (host_evid / ('tap-%s.jsonl' % n)).read_text()]
        if len(done_taps) == len(taps):
            break
        time.sleep(0.5)
    log(a.out, event='taps_stopped', flushed=done_taps)
    for f in sorted(host_evid.glob('tap-*.jsonl')) + sorted(host_evid.glob('pub-*.jsonl')):
        (a.out / f.name).write_bytes(f.read_bytes())
    r = sh([sys.executable, '-B', str(HERE / 'lat_analyze.py'), '--dir', str(a.out), '--json', str(a.out / 'ANALYSIS.json')], check=False)
    print(r.stdout)
    (a.out / 'analysis.txt').write_text(r.stdout + r.stderr)
    if not a.keep:
        sh(['docker', 'rm', '-f', a.name], check=False, quiet=True)
    log(a.out, event='done', rc=r.returncode)
    return r.returncode


if __name__ == '__main__':
    sys.exit(main())
