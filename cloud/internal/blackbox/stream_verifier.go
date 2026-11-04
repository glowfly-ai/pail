// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package blackbox

// StreamVerifier is the incremental (frame-boundary-agnostic) counterpart of
// WalkDir for HA replication (HA LLD §4.4): the standby feeds raw shipped
// bytes and every record is chain-verified before it is acknowledged. Same
// rules as reader.go — segment header participates in the chain, per-record
// prev/this hashes, cross-segment tail inheritance with empty segments
// transparent. A partial record simply stays buffered until more bytes arrive.
//
// The very first segment fed may have any seq (a standby may receive history
// that does not start at seq 1); its header prev_segment_tail_hash is adopted
// as the trust anchor — verification is anchored at the first shipped segment.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

type StreamVerifier struct {
	emit func(Record) error

	first      bool // no segment header parsed yet: adopt its prev tail
	expectTail [32]byte
	prev       [32]byte
	segSeq     uint64
	started    bool // current segment's header parsed
	hasRecords bool
	buf        []byte
	records    int
}

func NewStreamVerifier(emit func(Record) error) *StreamVerifier {
	return &StreamVerifier{emit: emit, first: true}
}

// Records returns the number of chain-verified records emitted so far.
func (v *StreamVerifier) Records() int { return v.records }

// Pending returns the number of buffered bytes not yet forming a complete
// header/record (a torn tail while the stream is open).
func (v *StreamVerifier) Pending() int { return len(v.buf) }

// HeadHex returns a short fingerprint of the current chain head.
func (v *StreamVerifier) HeadHex() string { return hex.EncodeToString(v.prev[:8]) }

// BeginSegment starts a new segment. The previous segment must have ended on
// a record boundary — a torn tail is only acceptable at the very end of the
// stream, never before a successor segment exists.
func (v *StreamVerifier) BeginSegment(seq uint64) error {
	if len(v.buf) != 0 {
		return fmt.Errorf("stream verifier: torn record at end of segment %d (%d pending bytes)", v.segSeq, len(v.buf))
	}
	if !v.first {
		if !v.started {
			return fmt.Errorf("stream verifier: segment %d ended before its header", v.segSeq)
		}
		if seq != v.segSeq+1 {
			return fmt.Errorf("stream verifier: segment seq %d after %d (gap)", seq, v.segSeq)
		}
		if v.hasRecords {
			v.expectTail = v.prev
		}
	}
	v.segSeq = seq
	v.started = false
	v.hasRecords = false
	return nil
}

// Feed appends raw bytes and verifies/emits every complete record. Any chain
// violation returns an error; the caller must NOT ack the frame.
func (v *StreamVerifier) Feed(data []byte) error {
	v.buf = append(v.buf, data...)
	if !v.started {
		if len(v.buf) < segHeaderSize {
			return nil
		}
		hdr := v.buf[:segHeaderSize]
		if string(hdr[0:4]) != segMagic {
			return fmt.Errorf("stream verifier: bad segment magic %q", hdr[0:4])
		}
		if ver := binary.LittleEndian.Uint32(hdr[4:8]); ver != segVersion {
			return fmt.Errorf("stream verifier: unsupported segment version=%d", ver)
		}
		if got := binary.LittleEndian.Uint64(hdr[8:16]); got != v.segSeq {
			return fmt.Errorf("stream verifier: header seq=%d, want %d", got, v.segSeq)
		}
		if v.first {
			copy(v.expectTail[:], hdr[16:48])
			v.first = false
		}
		if !bytes.Equal(hdr[16:48], v.expectTail[:]) {
			return fmt.Errorf("stream verifier: prev_segment_tail_hash mismatch in segment %d (chain broken across segments)", v.segSeq)
		}
		v.prev = sha256.Sum256(hdr)
		v.buf = v.buf[segHeaderSize:]
		v.started = true
	}
	for {
		if len(v.buf) < 20 {
			return nil
		}
		rhdr := v.buf[0:16]
		if ver := binary.LittleEndian.Uint32(rhdr[0:4]); ver != recVersion {
			return fmt.Errorf("stream verifier: unsupported record version=%d in segment %d", ver, v.segSeq)
		}
		payloadLen := int(binary.LittleEndian.Uint32(v.buf[16:20]))
		total := 20 + payloadLen + 64
		if len(v.buf) < total {
			return nil
		}
		payload := v.buf[20 : 20+payloadLen]
		prevStored := v.buf[20+payloadLen : 20+payloadLen+32]
		thisStored := v.buf[20+payloadLen+32 : total]
		if !bytes.Equal(prevStored, v.prev[:]) {
			return fmt.Errorf("stream verifier: prev_hash mismatch in segment %d (chain broken)", v.segSeq)
		}
		h := sha256.New()
		h.Write(rhdr)
		h.Write(payload)
		h.Write(v.prev[:])
		if !bytes.Equal(h.Sum(nil), thisStored) {
			return fmt.Errorf("stream verifier: this_hash mismatch in segment %d (record tampered)", v.segSeq)
		}
		rec := Record{
			SegmentSeq: v.segSeq,
			Type:       binary.LittleEndian.Uint32(rhdr[4:8]),
			UnixMs:     binary.LittleEndian.Uint64(rhdr[8:16]),
			Payload:    append([]byte(nil), payload...),
		}
		copy(v.prev[:], thisStored)
		v.hasRecords = true
		v.records++
		v.buf = v.buf[total:]
		if v.emit != nil {
			if err := v.emit(rec); err != nil {
				return err
			}
		}
	}
}
