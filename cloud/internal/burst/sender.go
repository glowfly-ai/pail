// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package burst

import (
	"net"
	"sync/atomic"
	"time"
)

type Sender struct {
	addr string
	seq  atomic.Uint32
}

func New(addr string) *Sender { return &Sender{addr: addr} }

// NextSeq returns a fresh burst_seq. The same value must be reused for all
// retransmissions of one event so receivers can deduplicate.
func (s *Sender) NextSeq() uint32 { return s.seq.Add(1) }

// burstSchedule per LLD-v2 §6: 5 transmissions at 0/50/200/500/1000ms.
var burstSchedule = []time.Duration{0, 50 * time.Millisecond, 200 * time.Millisecond, 500 * time.Millisecond, 1000 * time.Millisecond}

// SendBurst transmits the packet on the §6 schedule in a background
// goroutine (UDP is fire-and-forget; loss is compensated by repetition).
func (s *Sender) SendBurst(packet []byte) {
	go func() {
		start := time.Now()
		for _, d := range burstSchedule {
			if wait := d - time.Since(start); wait > 0 {
				time.Sleep(wait)
			}
			_ = s.Send(packet)
		}
	}()
}

func (s *Sender) Send(packet []byte) error {
	udpAddr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write(packet)
	return err
}
