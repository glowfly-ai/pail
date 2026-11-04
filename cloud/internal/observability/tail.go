// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package observability

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"syscall"
	"time"
)

// Tail reads only installer-selected regular files. The initial EOF and every
// replacement are live barriers; neither file history nor partial startup
// lines may turn into a new current-state sample after collector restart.
type Tail struct {
	collector *Collector
	provider  Provider
	file      *os.File
	info      os.FileInfo
	offset    int64
	pending   []byte
	discard   bool
}

func NewTail(c *Collector, p Provider) (*Tail, error) {
	if p.Kind != "normalized_jsonl" {
		return nil, errors.New("UNSUPPORTED_TAIL")
	}
	t := &Tail{collector: c, provider: p}
	return t, t.open()
}
func (t *Tail) open() error {
	fi, e := os.Lstat(t.provider.PathRef)
	if e != nil || !fi.Mode().IsRegular() {
		return errors.New("SOURCE_UNAVAILABLE")
	}
	f, e := os.OpenFile(t.provider.PathRef, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return errors.New("SOURCE_UNAVAILABLE")
	}
	actual, e := f.Stat()
	if e != nil || !actual.Mode().IsRegular() || !os.SameFile(fi, actual) {
		f.Close()
		return errors.New("SOURCE_REPLACED")
	}
	if t.file != nil {
		t.file.Close()
	}
	t.file = f
	t.info = actual
	t.offset = actual.Size()
	t.pending = nil
	t.discard = false
	if t.offset > 0 {
		b := []byte{0}
		if _, e = f.ReadAt(b, t.offset-1); e != nil {
			return e
		}
		t.discard = b[0] != '\n'
	}
	t.collector.Fault(t.provider.ProviderID, "LIVE_BARRIER_WAIT")
	return nil
}
func (t *Tail) Close() {
	if t.file != nil {
		t.file.Close()
	}
}
func (t *Tail) Poll() error {
	fi, e := os.Lstat(t.provider.PathRef)
	if e != nil || !fi.Mode().IsRegular() {
		t.collector.Fault(t.provider.ProviderID, "SOURCE_UNAVAILABLE")
		return errors.New("SOURCE_UNAVAILABLE")
	}
	if t.file == nil || !os.SameFile(t.info, fi) || fi.Size() < t.offset {
		if e = t.open(); e != nil {
			t.collector.Fault(t.provider.ProviderID, "SOURCE_UNAVAILABLE")
		}
		return e
	}
	b := make([]byte, 256<<10)
	n, e := t.file.ReadAt(b, t.offset)
	if e != nil && e != io.EOF {
		t.collector.Fault(t.provider.ProviderID, "SOURCE_READ_ERROR")
		return errors.New("SOURCE_READ_ERROR")
	}
	t.offset += int64(n)
	b = b[:n]
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		part := b
		if i >= 0 {
			part = b[:i]
		}
		if !t.discard {
			if len(t.pending)+len(part) > MaxEvent {
				t.pending = nil
				t.discard = true
				t.collector.Fault(t.provider.ProviderID, "PAYLOAD_OVERSIZE")
			} else {
				t.pending = append(t.pending, part...)
			}
		}
		if i < 0 {
			break
		}
		b = b[i+1:]
		if !t.discard && len(t.pending) > 0 {
			var ev Event
			if e = StrictJSON(t.pending, &ev); e != nil {
				t.collector.Fault(t.provider.ProviderID, "INVALID")
			} else {
				_ = t.collector.Observe(t.provider.ProviderID, ev)
			}
		}
		t.pending = nil
		t.discard = false
	}
	return nil
}

// RunFiles uses a single bounded polling worker; HTTP never opens raw files.
func (c *Collector) RunFiles(ctx context.Context) {
	tails := []*Tail{}
	for _, p := range c.config.Providers {
		if p.Kind == "normalized_jsonl" {
			t, e := NewTail(c, p)
			if e != nil {
				c.Fault(p.ProviderID, "SOURCE_UNAVAILABLE")
			}
			tails = append(tails, t)
		}
	}
	defer func() {
		for _, t := range tails {
			t.Close()
		}
	}()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, t := range tails {
				_ = t.Poll()
			}
		}
	}
}
