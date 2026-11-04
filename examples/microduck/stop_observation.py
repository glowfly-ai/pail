# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Microduck stop verdicts use received state samples, not a count of wire commands."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'common'))
from observation import finite, stop_context, robot_rows, stationary_observation

GRACE_S = 0.1  # unchanged: two 50 ms planner periods, not TB3's 0.15 s
MAX_SAMPLE_GAP_S = 0.25  # observation coverage, not an actuator-response allowance


def vector(value):
    if not isinstance(value, list) or len(value) != 3 or not all(finite(v) for v in value):
        raise ValueError('missing or invalid requested/applied state vector')
    return value


def nonzero(value):
    return any(abs(v) > 1e-8 for v in vector(value))


def summarize(events, stop_id):
    req, dispatch, done, ack, result = stop_context(events, stop_id)
    clock, t0 = ack['clock_id'], ack['mono']
    rows = robot_rows(events, ('motion_sample', 'pose', 'planner_zero', 'observation_invalid'), clock)
    if any(e['event'] == 'observation_invalid' for e in rows):
        raise ValueError('invalid robot.state observation during stop')
    all_samples = [e for e in rows if e['event'] == 'motion_sample']
    for e in all_samples:
        vector(e.get('requested')); vector(e.get('applied'))
        if not finite(e.get('received_mono')) or e.get('received_clock_id') != req['clock_id']:
            raise ValueError('state sample has no valid console receipt time')
    samples = sorted((e for e in all_samples if e['mono'] >= t0), key=lambda e:e['mono'])
    if not samples or samples[0]['mono']-t0 > MAX_SAMPLE_GAP_S or samples[-1]['mono']-t0 < 1.0:
        raise ValueError('state observer did not cover the post-ack window')
    stream = samples[0].get('stream_id')
    if not stream or any(e.get('stream_id') != stream for e in samples):
        raise ValueError('observer stream changed or missing during stop')
    previous = None
    for e in samples:
        vector(e.get('requested')); vector(e.get('applied'))
        if not finite(e.get('received_mono')) or e.get('received_clock_id') != req['clock_id']:
            raise ValueError('state sample has no valid console receipt time')
        if not isinstance(e.get('sample_seq'), int) or isinstance(e['sample_seq'], bool):
            raise ValueError('missing state sample sequence')
        if previous is not None:
            gap = e['mono']-previous['mono']
            if gap <= 0 or gap > MAX_SAMPLE_GAP_S or e['sample_seq'] != previous['sample_seq']+1:
                raise ValueError('gapped, stale or repeated state observations')
        previous = e
    if nonzero(samples[-1]['requested']) or nonzero(samples[-1]['applied']):
        raise ValueError('last observed requested/applied velocity is still nonzero')
    after = [e for e in samples if e['mono'] > t0 + GRACE_S]
    requested = [e for e in after if nonzero(e['requested'])]
    applied = [e for e in after if nonzero(e['applied'])]
    result.update(post_ack_grace_s=GRACE_S, maximum_sample_gap_s=MAX_SAMPLE_GAP_S,
                  observation_window_after_ack_s=round(samples[-1]['mono']-t0, 6),
                  motion_samples=len(samples), observer_stream_id=stream,
                  requested_nonzero_samples_after_ack=len(requested),
                  applied_nonzero_samples_after_ack=len(applied),
                  counts_are='received robot.state samples, not RPC commands',
                  requested_nonzero_samples_received_after_request=sum(nonzero(e['requested']) and e['received_mono'] > req['mono'] for e in all_samples),
                  requested_nonzero_samples_received_after_cancel_response=sum(nonzero(e['requested']) and e['received_mono'] > done['mono'] for e in all_samples))
    def first(predicate):
        hits = [e['mono']-t0 for e in samples if predicate(e)]
        return round(min(hits), 6) if hits else None
    result['ack_to_zero_requested_state_s'] = first(lambda e:not nonzero(e['requested']))
    result['ack_to_zero_applied_state_s'] = first(lambda e:not nonzero(e['applied']))
    zeros = [e['mono']-t0 for e in rows if e['event']=='planner_zero' and e.get('stop_id')==stop_id and e['mono']>=t0]
    result['ack_to_planner_zero_s'] = round(min(zeros),6) if zeros else None
    result['planner_zero_reason'] = None if zeros else 'NO_MATCHING_ZERO_PUBLICATION'
    result['stationary_pose_observation'] = stationary_observation([e for e in rows if e['event']=='pose'],t0)
    result['pose_source'] = 'integral of fake applied velocity; not wheel odometry'
    return result
