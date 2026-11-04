# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Stop observations: correlate instructions, never compare different hosts' clocks."""
import math
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'common'))
from observation import stop_context, robot_rows, stationary_observation


def summarize(events, stop_id):
    req, dispatch, done, ack, result = stop_context(events, stop_id)
    clock, t0 = ack['clock_id'], ack['mono']
    rows = robot_rows(events, ('drive', 'drive_state', 'drive_observer', 'pose', 'planner_zero'), clock)
    states = [e for e in rows if e['event'] == 'drive_observer' and e['mono'] >= t0]
    if any(not math.isfinite(e.get('sample_mono', float('nan'))) or e['sample_mono'] > e['mono'] for e in states):
        raise ValueError('invalid last-command observation timestamp')
    if not states or max(e['mono'] for e in states) < t0 + 1.0:
        raise ValueError('drive observer did not cover the post-ack window')
    latest = max(states, key=lambda e:e['mono'])
    if abs(latest['x']) > 1e-8 or abs(latest['z']) > 1e-8:
        raise ValueError('last command at the drive observer is still nonzero')
    drives = [e for e in rows if e['event'] == 'drive']
    after_ack = [e for e in drives if e['mono'] > t0 + 0.15]
    result.update(drives_after_stop=len(after_ack), post_ack_grace_s=0.15,
                  drives_received_after_request=sum(e['received_mono'] > req['mono'] for e in drives),
                  drives_received_after_cancel_response=sum(e['received_mono'] > done['mono'] for e in drives),
                  observer_heartbeat_is_not_a_new_command=True,
                  observation_window_after_ack_s=round(max(e['mono'] for e in states)-t0, 6))
    delivery = dispatch.get('delivery')
    if delivery:
        a, b = delivery['published_before_mono'], delivery['published_after_mono']
        result['drives_after_publication_interval'] = [sum(e['mono'] > b for e in drives), sum(e['mono'] > a for e in drives)]
    def first_delay(kind, predicate):
        hits = [e['mono']-t0 for e in rows if e['event'] == kind and e['mono'] >= t0 and predicate(e)]
        return round(min(hits), 6) if hits else None
    result['ack_to_planner_zero_s'] = first_delay('planner_zero', lambda e: e.get('stop_id') == stop_id)
    result['ack_to_observed_zero_command_s'] = first_delay('drive_state', lambda e: e['x'] == 0 and e['z'] == 0)
    stationary = stationary_observation([e for e in rows if e['event'] == 'pose'], t0)
    result['ack_to_stationary_odometry_confirmation_s'] = stationary['value_s']
    result['stationary_odometry_observation'] = stationary
    return result
