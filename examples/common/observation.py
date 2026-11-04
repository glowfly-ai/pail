# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Transport-neutral clock, correlation and optional motion-observation rules."""
import hashlib
import json
import math


def finite(value):
    return not isinstance(value, bool) and isinstance(value, (int, float)) and math.isfinite(value)


def stop_context(events, stop_id):
    if not isinstance(stop_id, str) or not stop_id:
        raise ValueError('missing stop id')
    if any(e.get('event') == 'clock_step' for e in events):
        raise ValueError('CLOCK_PREREQUISITE_FAILED: clock discontinuity during stop observation')
    def one(kind, **fields):
        rows = [e for e in events if e.get('event') == kind and all(e.get(k) == v for k, v in fields.items())]
        if len(rows) != 1:
            raise ValueError('need exactly one %s for this stop, got %d' % (kind, len(rows)))
        return rows[0]
    req = one('stop_requested', stop_id=stop_id)
    dispatch = one('stop_dispatched', stop_id=stop_id)
    done = one('stopped', stop_id=stop_id)
    ack = one('instruction', stop_id=stop_id, source='planner', mode='idle')
    if ack.get('instruction') != dispatch.get('instruction'):
        raise ValueError('acknowledged a different instruction')
    clock = ack.get('clock_id')
    if not clock or clock == 'unavailable':
        raise ValueError('robot monotonic clock identity unavailable')
    host = req.get('clock_id')
    if not host or any(x.get('clock_id') != host for x in (dispatch, done)) or ack.get('received_clock_id') != host:
        raise ValueError('console request and acknowledgement receipt clocks differ or are missing')
    times = [req.get('mono'), dispatch.get('mono'), done.get('mono'), ack.get('received_mono'), ack.get('mono')]
    if not all(finite(t) for t in times):
        raise ValueError('non-finite or missing monotonic timestamp')
    if not req['mono'] <= dispatch['mono'] <= done['mono'] or ack['received_mono'] < req['mono']:
        raise ValueError('invalid console event ordering')
    if not all(finite(x.get('t')) for x in (req, ack)):
        raise ValueError('invalid diagnostic wall-clock timestamp')
    result = dict(stop_id=stop_id, robot_clock_id=clock, console_clock_id=host,
                  stop_ack_after_s=round(ack['received_mono']-req['mono'], 6),
                  stop_ack_basis='console-monotonic request to received ack; upper bound includes log transport',
                  stop_cancel_round_trip_s=round(done['mono']-dispatch['mono'], 6),
                  control_delivery_round_trip_s=round(dispatch['mono']-req['mono'], 6),
                  raw_cross_clock_ack_delta_s=round(ack['t']-req['t'], 6), physical_stop_time_measured=False)  # wall-clock: the raw cross-clock delta is recorded beside the monotonic one on purpose (rc13)
    delivery = dispatch.get('delivery')
    if delivery:
        if delivery.get('clock_id') != clock:
            raise ValueError('control publication and planner clocks differ')
        a, b = delivery.get('published_before_mono'), delivery.get('published_after_mono')
        if not all(finite(x) for x in (a, b)) or a > b or ack['mono'] < a:
            raise ValueError('invalid publication interval')
        result['publication_to_ack_s'] = [round(max(0., ack['mono']-b), 6), round(ack['mono']-a, 6)]
        result['publication_to_ack_reason'] = None
    else:
        result['publication_to_ack_s'] = None
        result['publication_to_ack_reason'] = 'NO_ROBOT_CLOCK_PUBLICATION_MARKER'
    return req, dispatch, done, ack, result


def robot_rows(events, kinds, clock):
    rows = [e for e in events if e.get('event') in kinds]
    if any(e.get('clock_id') != clock for e in rows):
        raise ValueError('robot clock identity changed or missing; do not count silence as stopped')
    if any(not finite(e.get('mono')) for e in rows):
        raise ValueError('non-finite robot timestamp')
    return rows


def stationary_observation(poses, ack_mono, *, max_gap_s=0.25):
    """An observed stationary interval, never a physical braking time or a silence inference."""
    rows = sorted((e for e in poses if e['mono'] >= ack_mono), key=lambda e:e['mono'])
    def result(value=None, reason=None):
        return dict(value_s=value, status='MEASURED' if value is not None else 'NOT_MEASURED',
                    reason=reason, required_stationary_span_s=0.5, maximum_sample_gap_s=max_gap_s,
                    position_tolerance=1e-4, samples=len(rows))
    if not rows:
        return result(reason='NO_POSE_SAMPLES')
    if any(not finite(e.get(k)) for e in rows for k in ('x','y','th')):
        return result(reason='INVALID_POSE')
    start = last = rows[0]
    gaps = False
    for e in rows[1:]:
        dt = e['mono']-last['mono']
        if dt <= 0:
            return result(reason='NON_INCREASING_POSE_TIME')
        if dt > max_gap_s:
            gaps = True
            start = e
        elif any(abs(e[k]-start[k]) > 1e-4 for k in ('x','y','th')):
            start = e
        elif e['mono']-start['mono'] >= 0.5-1e-9:
            return result(round(e['mono']-ack_mono, 6))
        last = e
    if rows[-1]['mono']-rows[0]['mono'] < 0.5-1e-9:
        return result(reason='INSUFFICIENT_POSE_SPAN')
    return result(reason='POSE_GAPS' if gaps else 'NO_STATIONARY_INTERVAL_OBSERVED')


# ---------------------------------------------------------------------------------------
# Observation record version 2: liveness and permit self-reports.
# Pure rules, no socket and no clock of their own: the caller passes what it saw and when.
# ---------------------------------------------------------------------------------------
RECORD_VERSION = 2
RECORD_KINDS = ('plan', 'gate', 'permit', 'motion', 'pose', 'liveness')
LIVENESS_COMPONENTS = ('adapter', 'observer')
REPORT_PERIOD_S = 1.0          # liveness and held-permit reports
ADAPTER_QUESTION_PERIOD_S = 0.5
ADAPTER_ANSWER_WINDOW_S = 1.0  # an answer older than this is not "the adapter answers"
MAX_STEPS = 1024
CLOCK_BINDING = 'shared_kernel_monotonic'   # what a source map may ask for; the collector decides


def clock_record_id(identity):
    """Name of the monotonic clock in a record: a hash of boot id and time namespace offset.

    The collector computes the same name for ITS clock and compares. A producer that could
    not read its identity hashes the word it fell back to; no collector has that name."""
    if not isinstance(identity, str) or not identity:
        raise ValueError('clock identity is a non-empty string')
    return 'mono-' + hashlib.sha256(identity.encode()).hexdigest()


def observation_row(identity, kind, value, *, producer_id, seq, clock_id, wall_ms, mono_ns):
    """One version 2 line for the collector. Refuses what the collector would refuse."""
    if kind not in RECORD_KINDS:
        raise ValueError('unknown observation kind ' + repr(kind))
    value = dict(value)
    if value.setdefault('physical_stop_proven', False) is not False:
        raise ValueError('an observation never proves a physical stop')
    if (kind == 'liveness') != ('component' in value) or value.get('component', 'adapter') not in LIVENESS_COMPONENTS:
        raise ValueError('component belongs to liveness records and is one of ' + repr(LIVENESS_COMPONENTS))
    if kind == 'liveness' and value.get('state') != 'ALIVE':
        raise ValueError('ALIVE is the only liveness value: a stopped component cannot report itself')
    if ('step_index' in value) != ('step_count' in value):
        raise ValueError('step_index and step_count come together')
    if 'step_index' in value:
        i, n = value['step_index'], value['step_count']
        if kind not in ('permit', 'plan') or any(isinstance(v, bool) or not isinstance(v, int) for v in (i, n)) or not 1 <= i <= n <= MAX_STEPS:
            raise ValueError('invalid step position')
    if isinstance(mono_ns, bool) or not isinstance(mono_ns, int) or mono_ns <= 0 or mono_ns >= 1 << 63:
        raise ValueError('invalid monotonic time')
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ValueError('invalid sequence')
    return {'schema_version': RECORD_VERSION, 'deployment_id': identity['deployment_id'],
            'robot_id': identity['robot_id'], 'identity': identity['robot_id'],
            'owner': identity['run_id'], 'run_id': identity['run_id'], 'kind': kind,
            'producer_instance_id': producer_id, 'stream_id': identity['fleet_stream_id'],
            'producer_seq': str(seq), 'observed_at_ms': int(wall_ms), 'observed_mono_ns': str(mono_ns),
            'clock_id': clock_id, 'replayed': False, 'value': value}


class AdapterProbe:
    """Question and answer on the adapter's public socket, as seen by the observer.

    "The adapter answers" means: connected, and an answer to one of OUR questions arrived
    within the window. A connection alone is not an answer, and neither is an old answer.
    """
    def __init__(self, period=ADAPTER_QUESTION_PERIOD_S, window=ADAPTER_ANSWER_WINDOW_S):
        self.period, self.window = period, window
        self.connected = False
        self.asked = {}
        self.last_question = self.last_answer = None
        self.next_id = 1000

    def connect(self):
        self.connected, self.asked, self.last_question, self.last_answer = True, {}, None, None

    def disconnect(self):
        self.connected, self.asked, self.last_answer = False, {}, None

    def question(self, now):
        """Returns the id to ask with, or None when no question is due."""
        if not self.connected or (self.last_question is not None and 0 <= now - self.last_question < self.period):
            return None
        self.next_id += 1
        self.last_question = now
        self.asked[self.next_id] = now
        for old in [k for k, t in self.asked.items() if now - t > 4 * self.window or now < t]:
            del self.asked[old]
        return self.next_id

    def answer(self, request_id, now):
        """An answer counts only for a question that was asked on this connection."""
        if isinstance(request_id, bool) or request_id not in self.asked:
            return False
        del self.asked[request_id]
        self.last_answer = now
        return True

    def alive(self, now):
        return bool(self.connected and self.last_answer is not None and 0 <= now - self.last_answer <= self.window)


class LivenessReporter:
    """ALIVE once per period while the adapter answers; nothing at all otherwise."""
    def __init__(self, component='adapter', period=REPORT_PERIOD_S):
        if component not in LIVENESS_COMPONENTS:
            raise ValueError('unknown component')
        self.component, self.period, self.last = component, period, None

    def due(self, now, adapter_answers):
        if not adapter_answers:
            return None
        if self.last is not None and 0 <= now - self.last < self.period:
            return None
        self.last = now
        return {'state': 'ALIVE', 'component': self.component, 'physical_stop_proven': False}


class PermitReporter:
    """Permit self-report from the adapter's own gate outcomes.

    RECEIVED repeats once per period while the last outcome says a permit is held and the
    adapter answers. EXPIRED is written once, on the transition. When the adapter does not
    answer nothing is written: the collector turns the facet STALE by itself.
    """
    def __init__(self, period=REPORT_PERIOD_S):
        self.period = period
        self.held = False
        self.token = ''
        self.last = None
        self.pending_expired = False

    def outcome(self, row):
        """One `outcome` or `stop` line of the adapter's gate log."""
        if not isinstance(row, dict):
            return
        if row.get('kind') == 'outcome' and row.get('permit_active') is True:
            # the adapter's own statement; a refused command inside a held permit keeps it held
            self.held, self.pending_expired = True, False
            if isinstance(row.get('token_id'), str) and row['token_id']:
                self.token = row['token_id']
        elif row.get('kind') in ('outcome', 'stop') and self.held:
            self.held, self.pending_expired, self.token = False, True, ''

    def adapter_restarted(self):
        if self.held:
            self.held, self.pending_expired = False, True

    def due(self, now, adapter_answers, steps=None):
        """Values to write now, oldest first."""
        out = []
        if self.pending_expired:
            self.pending_expired = False
            self.last = None
            out.append({'state': 'EXPIRED', 'physical_stop_proven': False})
        if self.held and adapter_answers and (self.last is None or not 0 <= now - self.last < self.period):
            self.last = now
            value = {'state': 'RECEIVED', 'physical_stop_proven': False}
            position = step_position(steps, self.token)
            if position:
                value['step_index'], value['step_count'] = position
            out.append(value)
        return out


def step_position(steps, token):
    """(index from 1, count) of the step this token belongs to, or None when it is not known."""
    if not token or not isinstance(steps, list) or not 1 <= len(steps) <= MAX_STEPS:
        return None
    hits = [i for i, s in enumerate(steps) if isinstance(s, dict) and s.get('token') == token]
    return (hits[0] + 1, len(steps)) if len(hits) == 1 else None


# ---------------------------------------------------------------------------------------
# Observation upload with a challenge (design 15): a robot on another machine sends its
# records to the collector; the collector answers with a challenge it will judge by its
# own clock. A record made after the answer carries that challenge. Pure rules; the
# network call is passed in.
# ---------------------------------------------------------------------------------------
# The age bound the collector can give a record is (upload period .. 2 x period) + transit:
# a record carries the challenge of the answer BEFORE the upload that carries the record,
# and it is read up to one period after that upload. 0.2 s keeps the bound at 0.2-0.5 s,
# well inside the 1 s limit of motion and pose (measured 2026-09-30; 0.5 s gave 0.5-1.03 s).
PUSH_PERIOD_S = 0.2
PUSH_MAX_RECORDS = 256
PUSH_MAX_BYTES = 1 << 20
PUSH_QUEUE_LIMIT = 4096


class Pusher:
    """Keeps what is to be uploaded and the challenge of the last answer.

    A record is stamped with the current challenge when it is MADE (stamp), so that it can
    only have been made after the challenge was issued. Records are queued and sent in
    order, at most PUSH_MAX_RECORDS or PUSH_MAX_BYTES per upload. When the collector cannot
    be reached, the challenge is dropped: what is queued and what is made until an answer
    comes goes up without a challenge and marked replayed, so the collector takes it as
    history and never as the current state. The queue is bounded; what does not fit is
    dropped and counted, never sent out of order. Nothing here touches authorization."""
    def __init__(self, send, period=PUSH_PERIOD_S, limit=PUSH_QUEUE_LIMIT):
        self.send = send   # send(body_bytes) -> (status, answer_dict); may raise
        self.period, self.limit = period, limit
        self.queue = []
        self.challenge = None
        self.connected = False
        self.dropped = 0
        self.last_attempt = None
        self.stats = {'uploads': 0, 'accepted': 0, 'rejected': 0, 'replayed': 0, 'failures': 0, 'rejected_reasons': {}}

    def stamp(self, row):
        """The record as it is made: with the current challenge, or as replayed while the collector is out of reach."""
        if self.challenge:
            return dict(row, challenge=self.challenge)
        if self.last_attempt is not None and not self.connected:
            return dict(row, replayed=True)
        return dict(row)

    def enqueue(self, row):
        if len(self.queue) >= self.limit:
            del self.queue[0]
            self.dropped += 1
        self.queue.append(row)

    def due(self, now):
        return bool(self.queue) and (self.last_attempt is None or now - self.last_attempt >= self.period or now < self.last_attempt)

    def batch(self):
        rows, used = [], 0
        for row in self.queue:
            size = len(json.dumps(row, allow_nan=False)) + 1
            if len(rows) == PUSH_MAX_RECORDS or used + size > PUSH_MAX_BYTES - 512:
                break
            rows.append(row)
            used += size
        return rows

    def begin(self, now):
        """The rows of the upload that is due now, or None. They stay queued until settle()."""
        if not self.due(now):
            return None
        self.last_attempt = now
        return self.batch()

    def upload(self, rows, identity, producer_id):
        """The network call for one batch. No state of the pusher changes here (a thread may run it)."""
        body = json.dumps({'schema_version': 1, 'robot_id': identity['robot_id'], 'producer_instance_id': producer_id, 'records': rows}, allow_nan=False).encode()
        try:
            status, answer = self.send(body)
        except Exception as ex:   # the network, the certificate, the collector: all the same to the robot
            return {'error': type(ex).__name__ + ': ' + str(ex)[:200]}
        if status != 200 or not isinstance(answer, dict) or not isinstance(answer.get('challenge'), str) or not answer['challenge']:
            return {'error': 'PUSH_STATUS_' + str(status), 'answer': answer if isinstance(answer, dict) else None}
        return answer

    def settle(self, rows, answer):
        """Apply the collector's answer to the queue and the challenge."""
        if 'error' in answer:
            self.failure()
            return answer
        if self.queue[:len(rows)] == rows:
            del self.queue[:len(rows)]
        self.challenge, self.connected = answer['challenge'], True
        self.stats['uploads'] += 1
        self.stats['accepted'] += int(answer.get('accepted') or 0)
        self.stats['replayed'] += int(answer.get('replayed') or 0)
        for r in answer.get('rejected') or []:
            self.stats['rejected'] += 1
            reason = str(r.get('reason'))[:64]
            self.stats['rejected_reasons'][reason] = self.stats['rejected_reasons'].get(reason, 0) + 1
        return answer

    def tick(self, now, identity, producer_id):
        """One upload when due, all in one thread. Returns the collector's answer, an error record, or None."""
        rows = self.begin(now)
        if rows is None:
            return None
        return self.settle(rows, self.upload(rows, identity, producer_id))

    def failure(self):
        self.stats['failures'] += 1
        self.connected, self.challenge = False, None
        self.queue = [dict(row, replayed=True) for row in self.queue]
        for row in self.queue:
            row.pop('challenge', None)


def push_sender(url, ca, cert, key, timeout=2.0):
    """HTTPS POST with the robot's own certificate; the collector's certificate must chain to `ca`.

    One connection is kept between uploads (a handshake per upload would cost more than the
    upload). A connection the collector closed while idle is replaced once, before the request
    is counted as failed: the collector had not read the request, so nothing is sent twice."""
    import http.client
    import ssl
    import urllib.parse
    context = ssl.create_default_context(cafile=ca)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(cert, key)
    target = urllib.parse.urlsplit(url)
    kept = {'conn': None}

    def send(body):
        for attempt in (0, 1):
            conn = kept['conn'] or http.client.HTTPSConnection(target.hostname, target.port or 443, context=context, timeout=timeout)
            kept['conn'] = None
            try:
                conn.request('POST', target.path, body=body, headers={'Content-Type': 'application/json'})
                r = conn.getresponse()
                data = r.read()
            except (http.client.RemoteDisconnected, ConnectionResetError, BrokenPipeError):
                conn.close()
                if attempt:
                    raise
                continue   # the idle connection was closed under us: once more on a new one
            except Exception:
                conn.close()
                raise
            kept['conn'] = conn
            if r.status == 200:
                return r.status, json.loads(data)
            return r.status, {'error': data[:200].decode(errors='replace')}
    return send
