# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Event reader for the scene judges over the console's bounded v1 event API.

The console keeps a bounded event log, so `GET /api/events?from=0` is refused with 409
once the first events have been evicted. A judge that starts against a console that has
been running for a while therefore starts at the oldest event still held. A gap after
the judge has started reading is different: events it needed are gone, and it stops.
"""
import json
import urllib.error
import urllib.request


class EventGap(AssertionError):
    """The console evicted events this judge had not read yet."""


RESYNC_KEEP = 300      # events before the live edge a late-starting judge still reads (the newest pose is among them)
RESYNC_LIMIT = 10      # a feed that evicts faster than one request round trip, ten times in a row, is reported as a gap


class JudgeLog:
    def __init__(self, base, sink=None, timeout=30):
        self.base, self.sink, self.timeout = base, sink, timeout
        self.events, self.next = [], 0
        self.resync = None  # set when the judge had to start past evicted events (with how often it had to)

    def _page(self):
        try:
            with urllib.request.urlopen('%s/api/events?from=%d' % (self.base, self.next), timeout=self.timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as ex:
            if ex.code != 409:
                raise
            body = json.loads(ex.read() or b'{}')
            resyncs = (self.resync or {}).get('resyncs', 0)
            if self.events or resyncs >= RESYNC_LIMIT or 'low_seq' not in body:
                raise EventGap('console event log gap (%s): events %s were evicted before this judge '
                               'read them; start a new judge run' % (body.get('error'), body.get('gap'))) from ex
            # A judge that has read nothing has lost nothing. Earlier the cursor was put exactly on the
            # eviction edge (low_seq-1), so on a full, moving feed (a fleet: ~40 events/s) the very next request
            # could already be behind the edge again and the judge failed before its first scene (measured once
            # in 20 back-to-back fleet R runs, 2026-10-09). Start near the live edge instead: the scenes mark
            # their own start, and only the newest pose from before it is needed.
            low, high = int(body['low_seq']), int(body.get('high_seq') or body['low_seq'])
            self.next = max(low - 1, high - RESYNC_KEEP)
            self.resync = dict(error=body.get('error'), low_seq=body['low_seq'], high_seq=body.get('high_seq'),
                               started_after_seq=self.next, resyncs=resyncs + 1)
            return None

    def pull(self):
        while True:
            got = self._page()
            if got is None:
                continue
            if self.sink is not None:
                self.sink(got['events'])
            self.events += got['events']
            self.next = int(got['next'])
            if not got['events'] or self.next >= int(got.get('high_seq', self.next)):
                return

    def mark(self):
        self.pull()
        return len(self.events)

    def since(self, i, **kw):
        self.pull()
        return [e for e in self.events[i:] if all(e.get(k) == v for k, v in kw.items())]
