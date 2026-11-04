// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package telemetry

import (
	"errors"
	"sync"
	"time"
)

const IngressBytes = 4 << 20
const IngressItems = 256

type queuedRaw struct {
	line []byte
	now  time.Time
}

// Ingress decouples UDP/tick producers from disk stalls. The byte reservation
// includes the in-flight item. Overflow is counted, not blocked or unbounded.
type Ingress struct {
	mu            sync.Mutex
	store         *Store
	queue         chan queuedRaw
	done          chan struct{}
	bytes         int
	closed        bool
	base, dropped uint64
	first, last   int64
	onError       func(error)
}

func NewIngress(s *Store, onError func(error)) *Ingress {
	q := &Ingress{store: s, queue: make(chan queuedRaw, IngressItems), done: make(chan struct{}), base: s.Health().IngressLossCount, onError: onError}
	go q.run()
	return q
}
func (q *Ingress) AppendLine(line []byte, now time.Time) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return errors.New("INGRESS_CLOSED")
	}
	code := "INGRESS_FULL"
	if len(line)+1 > RawLineBytes {
		code = "INPUT_LINE_OVERSIZE"
	}
	if len(line)+1 > RawLineBytes || q.bytes+len(line)+1 > IngressBytes || len(q.queue) == cap(q.queue) {
		q.dropped++
		q.last = now.UnixMilli()
		if q.first == 0 {
			q.first = q.last
		}
		return errors.New(code)
	}
	b := append([]byte(nil), line...)
	q.bytes += len(b) + 1
	q.queue <- queuedRaw{b, now}
	return nil
}
func (q *Ingress) losses() (uint64, int64, int64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.base + q.dropped, q.first, q.last
}
func (q *Ingress) Health() StorageHealth {
	total, first, last := q.losses()
	h := q.store.Health()
	if total > h.IngressLossCount {
		h.LossCount += total - h.IngressLossCount
		h.IngressLossCount = total
		h.State = "OBSERVATION_LOSS"
		h.LastError = "INGRESS_FULL"
		h.LastErrorMs = last
		if h.FirstErrorMs == 0 {
			h.FirstErrorMs = first
		}
	}
	return h
}
func (q *Ingress) recordLoss() {
	total, first, last := q.losses()
	if e := q.store.RecordIngressLoss(total, first, last); e != nil && q.onError != nil {
		q.onError(e)
	}
}
func (q *Ingress) run() {
	defer close(q.done)
	for item := range q.queue {
		q.recordLoss()
		if e := q.store.AppendLine(item.line, item.now); e != nil && q.onError != nil {
			q.onError(e)
		}
		q.mu.Lock()
		q.bytes -= len(item.line) + 1
		q.mu.Unlock()
	}
	q.recordLoss()
}
func (q *Ingress) Close() {
	q.mu.Lock()
	if !q.closed {
		q.closed = true
		close(q.queue)
	}
	q.mu.Unlock()
	<-q.done
}
