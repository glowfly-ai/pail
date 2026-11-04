# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Bounded console observation primitives; no command or authorization authority.

One log per console process (shared by all robots). Bytes are serialized before
locking; pages copy only immutable byte references under the lock and decode
outside it. HTTP/history/SSE adapters own authentication and live barriers.
"""
import base64
from collections import deque
import hashlib
import json
import math
import re
import threading
import uuid

MAX_EVENTS = 5000
MAX_BYTES = 16 * 1024 * 1024
MAX_EVENT_BYTES = 64 * 1024
MAX_LINE_BYTES = 1024 * 1024
READ_CHUNK_BYTES = 256 * 1024
MAX_PAGE_BYTES = 1024 * 1024
MAX_PAGE_EVENTS = 1000
MAX_CURSOR_BYTES = 512
UINT64_MAX = (1 << 64) - 1


class EventLogError(ValueError):
    def __init__(self, code, status=400, **details):
        super().__init__(code)
        self.code, self.status = code, status
        self.details = dict(error=code, **details)


def _json(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
                      separators=(',', ':'), sort_keys=True).encode('ascii')


def _object(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError('duplicate key')
        out[k] = v
    return out


def _reject_constant(value):
    raise ValueError('non-finite JSON')


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError('non-finite JSON')
    return number


def _preflight(value):
    # Bound individual encoder chunks before JSONEncoder allocates escaped strings
    # or a sorted key array. Every visited scalar/container needs at least one
    # encoded byte, so this early rejection cannot exclude a <=64 KiB event.
    remaining = MAX_EVENT_BYTES
    def visit(node):
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or (isinstance(node, str) and len(node) > MAX_EVENT_BYTES):
            raise EventLogError('payload_oversize')
        if isinstance(node, dict):
            for key, item in node.items():
                visit(key)
                visit(item)
        elif isinstance(node, (list, tuple)):
            for item in node:
                visit(item)
    visit(value)


def _seq(value):
    if not isinstance(value, str) or not re.fullmatch(r'0|[1-9][0-9]{0,19}', value):
        raise EventLogError('INVALID_CURSOR')
    n = int(value)
    if n > UINT64_MAX:
        raise EventLogError('INVALID_CURSOR')
    return n


def _filters(value):
    value = {} if value is None else value
    if (not isinstance(value, dict) or
            set(value) - {'robot_id', 'source', 'event'} or
            any(not isinstance(v, str) or not v or len(v.encode('utf-8')) > 256
                for v in value.values())):
        raise EventLogError('INVALID_FILTER')
    value = dict(value)
    return value, hashlib.sha256(_json(value)).hexdigest()


def _cursor(epoch, after, digest):
    return base64.urlsafe_b64encode(_json(dict(version=1, epoch=epoch,
        after_seq=str(after), filter_digest=digest))).rstrip(b'=').decode('ascii')


def _decode(token, digest):
    try:
        if (not isinstance(token, str) or not 0 < len(token) <= MAX_CURSOR_BYTES
                or not re.fullmatch(r'[A-Za-z0-9_-]+', token)):
            raise ValueError('encoding')
        raw = base64.b64decode(token + '=' * (-len(token) % 4), altchars=b'-_', validate=True)
        if base64.urlsafe_b64encode(raw).rstrip(b'=').decode() != token:
            raise ValueError('noncanonical base64')
        obj = json.loads(raw, object_pairs_hook=_object, parse_constant=_reject_constant, parse_float=_finite_float)
        if (not isinstance(obj, dict) or set(obj) != {'version','epoch','after_seq','filter_digest'}
                or type(obj['version']) is not int or obj['version'] != 1
                or not isinstance(obj['epoch'], str)
                or str(uuid.UUID(obj['epoch'])) != obj['epoch']
                or not isinstance(obj['filter_digest'], str)
                or not re.fullmatch('[0-9a-f]{64}', obj['filter_digest'])):
            raise ValueError('schema')
        after = _seq(obj['after_seq'])
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise EventLogError('INVALID_CURSOR') from exc
    if obj['filter_digest'] != digest:
        raise EventLogError('FILTER_CHANGED')
    return obj['epoch'], after


class BoundedEventLog:
    """Fixed process budget. append() returns an absolute sequence as a string."""
    def __init__(self):
        self.epoch = str(uuid.uuid4())
        self._rows = deque()
        self._bytes = self._high = self._oversize = 0
        self._lock = threading.Lock()

    def append(self, event):
        if not isinstance(event, dict):
            raise EventLogError('INVALID_EVENT')
        try:
            _preflight(event)
            # iterencode avoids allocating an unbounded serialized aggregate.
            parts, size = [], 0
            encoder = json.JSONEncoder(ensure_ascii=True, allow_nan=False,
                                      separators=(',', ':'), sort_keys=True)
            for part in encoder.iterencode(event):
                size += len(part)
                if size > MAX_EVENT_BYTES:
                    raise EventLogError('payload_oversize', encoded_bytes_at_least=size)
                parts.append(part)
            encoded = ''.join(parts).encode('ascii')
        except (TypeError, ValueError, RecursionError) as exc:
            if isinstance(exc, EventLogError):
                if exc.code == 'payload_oversize':
                    with self._lock:
                        self._oversize += 1
                raise
            raise EventLogError('INVALID_EVENT') from exc
        with self._lock:
            if self._high == UINT64_MAX:
                raise EventLogError('SEQUENCE_EXHAUSTED', 503)
            self._high += 1
            self._rows.append((self._high, encoded))
            self._bytes += len(encoded)
            while len(self._rows) > MAX_EVENTS or self._bytes > MAX_BYTES:
                self._bytes -= len(self._rows.popleft()[1])
            return str(self._high)

    def _bounds(self):
        return dict(current_epoch=self.epoch,
                    low_seq=str(self._rows[0][0] if self._rows else self._high + 1),
                    high_seq=str(self._high), snapshot_url='/api/v2/snapshot')

    def snapshot(self, filters=None):
        _, digest = _filters(filters)
        with self._lock:
            info = self._bounds()
            high = self._high
            info.update(count=len(self._rows), serialized_bytes=self._bytes,
                        payload_oversize_count=self._oversize)
        info['cursor'] = _cursor(info['current_epoch'], high, digest)
        return info

    def page(self, cursor=None, *, filters=None, limit=200, after_seq=None):
        """after_seq is the v1 same-epoch path, never an array index.

        Empty filtered pages preserve the input cursor. high_seq is informational,
        not permission to skip unreturned records. v1 cannot detect an old epoch;
        clients requiring restart detection must use the opaque v2 cursor.
        """
        filters, digest = _filters(filters)
        if type(limit) is not int or not 1 <= limit <= MAX_PAGE_EVENTS:
            raise EventLogError('INVALID_LIMIT')
        if cursor is not None and after_seq is not None:
            raise EventLogError('INVALID_CURSOR')
        epoch, after = self.epoch, 0
        if cursor is not None:
            epoch, after = _decode(cursor, digest)
        elif after_seq is not None:
            after = _seq(after_seq)
        with self._lock:
            bounds = self._bounds()
            low, high = int(bounds['low_seq']), self._high
            if epoch != self.epoch:
                raise EventLogError('EPOCH_CHANGED', 409, **bounds,
                                    gap={'after_seq': str(after), 'through_seq': str(high)})
            if after < low - 1:
                raise EventLogError('CURSOR_EXPIRED', 409, **bounds,
                                    gap={'from_seq':str(after+1), 'through_seq':str(low-1)})
            if after > high:
                raise EventLogError('CURSOR_AHEAD', 400, **bounds)
            # At most 5000 references / 16 MiB; no JSON work or I/O under lock.
            candidates = tuple((seq, raw) for seq, raw in self._rows if seq > after)
        events, sequences, used = [], [], 2
        # Reserve more than the maximum metadata/cursor/sequence framing. The
        # full compact JSON response, not only the payload array, stays <=1 MiB.
        page_used = 2048
        for seq, raw in candidates:
            event = json.loads(raw)
            if any(event.get(k) != v for k, v in filters.items()):
                continue
            extra = len(raw) + (1 if events else 0)
            framed = extra + len(str(seq)) + 3
            if len(events) == limit or page_used + framed > MAX_PAGE_BYTES:
                break
            events.append(event)
            sequences.append(str(seq))
            used += extra
            page_used += framed
        end = int(sequences[-1]) if sequences else after
        return dict(bounds, events=events, sequences=sequences, next=str(end),
                    next_cursor=_cursor(epoch, end, digest), event_bytes=used)


class BoundedJSONLines:
    """Incremental binary JSONL decoder. EOF is not a completed line.

    Caller owns file identity/rotation and starts a new decoder for each file.
    feed accepts at most one read chunk. Faults contain logical file ID + byte
    origin, never raw payload or a host path. Oversize lines report once on
    crossing the cap and discard until newline without growing the buffer.
    """
    def __init__(self, file_id, offset=0):
        self.file_id = str(uuid.UUID(file_id))
        if type(offset) is not int or not 0 <= offset <= UINT64_MAX:
            raise ValueError('invalid offset')
        self.offset = self.line_start = offset
        self._buffer = bytearray()
        self._discard = False
        self.fault_count = 0

    @property
    def buffered_bytes(self):
        return len(self._buffer)

    def _fault(self, code, origin):
        self.fault_count += 1
        return dict(error=code, origin=dict(file_id=self.file_id, offset=str(origin)),
                    count=1)

    def read(self, stream):
        """One bounded read; the caller schedules subsequent reads fairly."""
        return self.feed(stream.read(READ_CHUNK_BYTES))

    def feed(self, chunk):
        if not isinstance(chunk, bytes) or len(chunk) > READ_CHUNK_BYTES:
            raise ValueError('binary chunk exceeds read limit')
        rows, faults, pos = [], [], 0
        while pos < len(chunk):
            newline = chunk.find(b'\n', pos)
            stop = len(chunk) if newline < 0 else newline
            piece = chunk[pos:stop]
            if not self._discard:
                if len(self._buffer) + len(piece) > MAX_LINE_BYTES:
                    faults.append(self._fault('line_oversize', self.line_start))
                    self._buffer.clear()
                    self._discard = True
                else:
                    self._buffer.extend(piece)
            consumed = stop - pos + (newline >= 0)
            self.offset += consumed
            pos += consumed
            if newline >= 0:
                if not self._discard:
                    try:
                        event = json.loads(bytes(self._buffer).decode('utf-8'),
                                           object_pairs_hook=_object,
                                           parse_constant=_reject_constant, parse_float=_finite_float)
                        if not isinstance(event, dict):
                            raise ValueError('event must be an object')
                        rows.append(dict(event=event, origin=dict(
                            file_id=self.file_id, offset=str(self.line_start))))
                    except (ValueError, UnicodeError, RecursionError):
                        faults.append(self._fault('invalid_json', self.line_start))
                self._buffer.clear()
                self._discard = False
                self.line_start = self.offset
        return rows, faults

    def finish(self):
        """Call only for a confirmed closed/truncated/replaced file, not live EOF."""
        faults = []
        if self._buffer:
            faults.append(self._fault('partial_line', self.line_start))
        self._buffer.clear()
        self._discard = False
        self.line_start = self.offset
        return faults
