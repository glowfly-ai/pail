// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package observability

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"
)

// Observations pushed over the network (design 15). A robot on another machine
// uploads its records; the collector answers with a challenge, a random value it
// remembers with the moment it issued it. A record that echoes the challenge was
// made after that moment: its age is at most now - issue time, judged by the
// collector's own clock. The robot's clock is never read for this.
const PushKind = "normalized_push"
const PushTrust = "authenticated_self_report"
const ChallengeBytes = 16
const ChallengeLife = 10 * time.Second
const ChallengesKept = 4
const PushMaxRecords = 256
const PushMaxBytes = 1 << 20

type challenge struct {
	value    string
	issued   time.Time
	producer string
	used     bool
}

// PushResult is what the collector answers an upload with.
type PushResult struct {
	Accepted  int            `json:"accepted"`
	Rejected  []PushRejected `json:"rejected"`
	Challenge string         `json:"challenge"`
	// ChallengeLifeMS says how long the challenge is good for, by the collector's clock.
	ChallengeLifeMS int64 `json:"challenge_life_ms"`
	// Replayed records are accepted as history and never as the current state.
	Replayed int `json:"replayed"`
}
type PushRejected struct {
	Seq    string `json:"producer_seq"`
	Reason string `json:"reason"`
}

// issuedAt is how Observe learns the issue time of a verified challenge: Push
// verifies and records it here, keyed by the record it belongs to, just before
// it calls Observe. Nothing outside Push ever finds an entry.
func (c *Collector) issuedAt(e Event) time.Time {
	if c.pushIssued == nil || e.Challenge == "" {
		return time.Time{}
	}
	return c.pushIssued[e.Challenge]
}

func newChallenge(now time.Time, producer string) (challenge, error) {
	b := make([]byte, ChallengeBytes)
	if _, err := rand.Read(b); err != nil {
		return challenge{}, errors.New("CHALLENGE_ENTROPY")
	}
	return challenge{value: base64.RawURLEncoding.EncodeToString(b), issued: now, producer: producer}, nil
}

// issue gives a robot's producer a new challenge and keeps the newest few.
func (c *Collector) issue(robot, producer string, now time.Time) (string, error) {
	if c.challenges == nil {
		c.challenges = map[string][]challenge{}
	}
	ch, err := newChallenge(now, producer)
	if err != nil {
		return "", err
	}
	ring := append(c.challenges[robot], ch)
	if len(ring) > ChallengesKept {
		ring = ring[len(ring)-ChallengesKept:]
	}
	c.challenges[robot] = ring
	return ch.value, nil
}

// verify judges an echoed challenge for a robot's producer: it must be one the
// collector issued to this robot and this producer, not yet used, and no older
// than its life. The first record of an upload uses it up: every record of the
// upload shares it, and it is spent when the upload ends (see Push).
func (c *Collector) verify(robot, producer, value string, now time.Time) (time.Time, string) {
	for i := range c.challenges[robot] {
		ch := &c.challenges[robot][i]
		if ch.value != value {
			continue
		}
		switch {
		case ch.producer != producer:
			return time.Time{}, "CHALLENGE_OTHER_PRODUCER"
		case ch.used:
			return time.Time{}, "CHALLENGE_USED"
		case now.Sub(ch.issued) < 0 || now.Sub(ch.issued) > ChallengeLife:
			return time.Time{}, "CHALLENGE_EXPIRED"
		}
		return ch.issued, ""
	}
	return time.Time{}, "CHALLENGE_UNKNOWN"
}

func (c *Collector) spend(robot, value string) {
	for i := range c.challenges[robot] {
		if c.challenges[robot][i].value == value {
			c.challenges[robot][i].used = true
		}
	}
}

// Push takes one upload of a robot's push provider: the records in order, each
// judged as any record is (identity, kind, sequence), and each with its
// challenge judged by the collector's clock. A record with a wrong challenge is
// refused and counted; a record without one is taken as receiver_only, current
// or replayed as it says. The answer carries the next challenge.
func (c *Collector) Push(id, producer string, records []Event) (PushResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	p := c.providers[id]
	if p == nil || p.config.Kind != PushKind {
		return PushResult{}, errors.New("UNKNOWN_PROVIDER")
	}
	if len(records) > PushMaxRecords {
		return PushResult{}, errors.New("PUSH_TOO_MANY_RECORDS")
	}
	if !validUUID(producer) {
		return PushResult{}, errors.New("PUSH_PRODUCER")
	}
	out := PushResult{Rejected: []PushRejected{}, ChallengeLifeMS: ChallengeLife.Milliseconds()}
	spent := map[string]bool{}
	for _, e := range records {
		if e.Producer != producer {
			out.Rejected = append(out.Rejected, PushRejected{Seq: e.Seq, Reason: "PUSH_PRODUCER_MISMATCH"})
			c.fault(p, "PUSH_PRODUCER_MISMATCH")
			continue
		}
		if e.Challenge != "" {
			issued, reason := c.verify(p.config.RobotID, producer, e.Challenge, now)
			if reason != "" && !(reason == "CHALLENGE_USED" && spent[e.Challenge]) {
				out.Rejected = append(out.Rejected, PushRejected{Seq: e.Seq, Reason: reason})
				c.fault(p, reason)
				continue
			}
			if reason == "CHALLENGE_USED" {
				issued = c.issuedOf(p.config.RobotID, e.Challenge) // spent by an earlier record of this same upload
			}
			if c.pushIssued == nil {
				c.pushIssued = map[string]time.Time{}
			}
			c.pushIssued[e.Challenge] = issued
		}
		err := c.observeLocked(id, e, now)
		delete(c.pushIssued, e.Challenge)
		if err != nil {
			out.Rejected = append(out.Rejected, PushRejected{Seq: e.Seq, Reason: err.Error()})
			continue
		}
		if e.Challenge != "" {
			spent[e.Challenge] = true
		}
		if e.Replayed {
			out.Replayed++
		} else {
			out.Accepted++
		}
	}
	for value := range spent {
		c.spend(p.config.RobotID, value)
	}
	next, err := c.issue(p.config.RobotID, producer, now)
	if err != nil {
		return PushResult{}, err
	}
	out.Challenge = next
	return out, nil
}

// PushProvider names the push source declared for a robot of this deployment.
func (c *Collector) PushProvider(robot string) (string, bool) {
	for _, p := range c.config.Providers {
		if p.Kind == PushKind && p.RobotID == robot && p.DeploymentID == c.config.DeploymentID {
			return p.ProviderID, true
		}
	}
	return "", false
}

func (c *Collector) issuedOf(robot, value string) time.Time {
	for _, ch := range c.challenges[robot] {
		if ch.value == value {
			return ch.issued
		}
	}
	return time.Time{}
}

func (c *Collector) fault(p *providerState, reason string) {
	p.errors++
	p.lastError = reason
}

// judgeChallenge decides a record that echoed a verified challenge: its age is at
// most now - issue time, by the collector's clock. Within the kind's limit it is
// FRESH on that basis; beyond it, STALE. What the robot wrote as its own time is
// not read here at all (design 14.3): a robot with a wrong clock is judged as one
// with a right clock, and so is a robot that lies about the time.
func judgeChallenge(s *slot, kind string, ttl time.Duration, now time.Time, f *Facet) {
	// The issue precedes the receipt, and the caller has already judged a receipt
	// that lies in the future (CLOCK_UNCERTAIN): the bound cannot be negative here.
	upper := now.Sub(s.issued)
	f.FreshnessBasis = "challenge_bound"
	f.AgeUpperMS = ptr(upper.Milliseconds())
	if upper >= ttl {
		f.Quality = "STALE"
		f.Reason = "OBSERVATION_OLD"
		return
	}
	f.Quality = "FRESH"
	f.Reason = "CHALLENGE_BOUND"
}
