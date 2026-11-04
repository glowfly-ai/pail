#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Join the probe records (pub + three taps) by seq and report latency and jitter per run.

  lat_analyze.py --dir RUN_DIR [--warmup 1.0] [--json OUT]

RUN_DIR holds pub-<rate>.jsonl, tap-cmd.jsonl, tap-safe.jsonl, tap-drive.jsonl. Taps run for the
whole session; the pub file bounds each run (start/done events). Latencies are differences of
CLOCK_MONOTONIC read in different processes of the same container (same kernel clock).

  hop     = tap(cmd)   - pub          publisher -> a direct subscriber (reference DDS hop + Python)
  gate    = tap(safe)  - tap(cmd)     gate decision + republish + one DDS hop
  bridge  = tap(drive) - tap(safe)    bridge forward + one DDS hop
  added   = tap(drive) - tap(cmd)     what the driver sees later than a direct subscriber would
  jitter  = interval between consecutive arrivals on a tap vs the nominal period
"""
import argparse, json, math, statistics, sys
from pathlib import Path


def load(path):
    rows = []
    if not Path(path).exists():  # a tap that was not run (e.g. two-tap mode on a small board)
        return rows
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def pct(xs, p):
    if not xs:
        return None
    s = sorted(xs)
    k = (len(s) - 1) * p / 100.0
    lo, hi = math.floor(k), math.ceil(k)
    return s[lo] if lo == hi else s[lo] + (s[hi] - s[lo]) * (k - lo)


def stats_ms(xs_ns):
    xs = [x / 1e6 for x in xs_ns]
    if not xs:
        return {'n': 0}
    return {'n': len(xs), 'min': round(min(xs), 3), 'p50': round(pct(xs, 50), 3), 'p90': round(pct(xs, 90), 3),
            'p99': round(pct(xs, 99), 3), 'max': round(max(xs), 3), 'mean': round(statistics.fmean(xs), 3),
            'stdev': round(statistics.pstdev(xs), 3) if len(xs) > 1 else 0.0}


def intervals(ts_ns):
    return [b - a for a, b in zip(ts_ns, ts_ns[1:])]


def analyze_run(pub_rows, taps, warmup_s):
    start = next(r for r in pub_rows if r.get('event') == 'start')
    done = next((r for r in pub_rows if r.get('event') == 'done'), None)
    rate = start['rate']
    period_ns = 1e9 / rate
    sent = {r['seq']: r['mono_ns'] for r in pub_rows if 'seq' in r}
    if not sent:
        return {'rate': rate, 'error': 'no published samples'}
    t_first, t_last = min(sent.values()), max(sent.values())
    by = {}
    for name, rows in taps.items():
        by[name] = {r['seq']: r['mono_ns'] for r in rows
                    if 'seq' in r and r['seq'] in sent and t_first - 1e9 <= r['mono_ns'] <= t_last + 5e9}
    # Steady state begins after the gate's first PERMIT: commands sent before the token reached the
    # gate are refused by design (ERR_NO_TOKEN) and are reported separately, not as loss.
    first_drive = min(by['drive'], key=lambda s: sent[s]) if by['drive'] else None
    t_permit = sent[first_drive] if first_drive is not None else t_first
    cut = max(t_first, t_permit) + warmup_s * 1e9
    seqs = sorted(s for s, t in sent.items() if t >= cut)
    out = {'rate_hz': rate, 'published': len(sent), 'after_warmup': len(seqs), 'warmup_s': warmup_s,
           'seconds': start.get('seconds'), 'done': done is not None,
           'first_delivery_after_s': round((t_permit - t_first) / 1e9, 3) if first_drive is not None else None,
           'sent_before_first_delivery': sum(1 for s, t in sent.items() if t < t_permit),
           'first_delivered_seq': first_drive,
           'first_delivered_gate_ms': (round((by['safe'][first_drive] - by['cmd'][first_drive]) / 1e6, 3)
                                       if first_drive in by['safe'] and first_drive in by['cmd'] else None),
           'received': {name: sum(1 for s in seqs if s in by[name]) for name in by},
           'lost_at_drive': [s for s in seqs if s not in by.get('drive', {})][:50]}
    out['lost_at_drive_count'] = sum(1 for s in seqs if s not in by.get('drive', {}))
    out['unexpected_on_drive'] = sum(1 for r in taps.get('drive', []) if r.get('seq') == -1 and t_first <= r['mono_ns'] <= t_last + 2e9)

    def lat(a, b):
        return [by[b][s] - by[a][s] for s in seqs if s in by[a] and s in by[b]]
    out['latency_ms'] = {
        'hop_pub_to_cmd': stats_ms([by['cmd'][s] - sent[s] for s in seqs if s in by['cmd']]),
        'gate_cmd_to_safe': stats_ms(lat('cmd', 'safe')),
        'bridge_safe_to_drive': stats_ms(lat('safe', 'drive')),
        'added_cmd_to_drive': stats_ms(lat('cmd', 'drive')),
        'end_to_end_pub_to_drive': stats_ms([by['drive'][s] - sent[s] for s in seqs if s in by['drive']]),
    }
    jit = {}
    for name in ('cmd', 'safe', 'drive'):
        ts = [by[name][s] for s in seqs if s in by[name]]
        iv = intervals(ts)
        dev = [abs(x - period_ns) for x in iv]
        jit[name] = {'interval_ms': stats_ms(iv), 'abs_dev_from_period_ms': stats_ms(dev)}
    ts = [sent[s] for s in seqs]
    iv = intervals(ts)
    jit['pub'] = {'interval_ms': stats_ms(iv), 'abs_dev_from_period_ms': stats_ms([abs(x - period_ns) for x in iv])}
    out['jitter'] = jit
    # order preservation on the drive tap
    drive_seq_order = [s for s in sorted(by['drive'], key=lambda s: by['drive'][s]) if s in set(seqs)]
    out['reordered_on_drive'] = sum(1 for a, b in zip(drive_seq_order, drive_seq_order[1:]) if b < a)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dir', type=Path, required=True)
    ap.add_argument('--warmup', type=float, default=1.0)
    ap.add_argument('--json', type=Path)
    a = ap.parse_args()
    taps = {k: load(a.dir / ('tap-%s.jsonl' % k)) for k in ('cmd', 'safe', 'drive')}
    result = {'dir': str(a.dir), 'runs': []}
    for pub in sorted(a.dir.glob('pub-*.jsonl')):
        rows = load(pub)
        try:
            r = analyze_run(rows, taps, a.warmup)
        except StopIteration:
            r = {'file': pub.name, 'error': 'no start event'}
        r['file'] = pub.name
        result['runs'].append(r)
    txt = json.dumps(result, indent=1)
    if a.json:
        a.json.write_text(txt)
    for r in result['runs']:
        if 'error' in r:
            print(r['file'], 'ERROR', r['error'])
            continue
        L = r['latency_ms']
        print('%s rate=%g Hz steady sent=%d drive=%d lost=%d reorder=%d | first delivery after %s s (%d refused before it), first delivered gate=%s ms'
              % (r['file'], r['rate_hz'], r['after_warmup'], r['received']['drive'], r['lost_at_drive_count'], r['reordered_on_drive'],
                 r['first_delivery_after_s'], r['sent_before_first_delivery'], r['first_delivered_gate_ms']))
        for k in ('hop_pub_to_cmd', 'gate_cmd_to_safe', 'bridge_safe_to_drive', 'added_cmd_to_drive', 'end_to_end_pub_to_drive'):
            s = L[k]
            if s['n']:
                print('  %-26s p50=%7.3f p90=%7.3f p99=%7.3f max=%7.3f ms (n=%d)' % (k, s['p50'], s['p90'], s['p99'], s['max'], s['n']))
        for k in ('cmd', 'drive'):
            j = r['jitter'][k]['abs_dev_from_period_ms']
            i = r['jitter'][k]['interval_ms']
            if j['n']:
                print('  jitter@%-5s |dt-T| p50=%6.3f p99=%6.3f max=%6.3f ms ; interval stdev=%6.3f ms' % (k, j['p50'], j['p99'], j['max'], i['stdev']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
