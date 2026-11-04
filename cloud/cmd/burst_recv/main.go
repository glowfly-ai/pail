// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"time"

	"github.com/glowfly/pail/services/internal/burst"
	"github.com/glowfly/pail/services/internal/crypto"
	"github.com/glowfly/pail/services/internal/deploysec"
)

// burst_recv listens for PAIL burst packets and emits one JSON line per event.
//
// v2 (120B): signature over pkt[0:56] is verified against the issuer keyring;
// duplicates (same robot_id_hash + burst_seq) from the 5-shot retransmission
// schedule are suppressed after the first copy.
// v1 (32B, unsigned as-built format): accepted but always valid=false
// ("unauthenticated", compatibility grace per LLD-v2 §6).

type keyringKey struct {
	id  string
	pub ed25519.PublicKey
}

// defaultDedupWindow bounds how long a (valid, robot, seq) key suppresses
// re-arrivals. Derived, not invented (D §7.4, N-11): the §6 retransmission
// schedule ends at 1000ms, so 5x that span covers every scheduled duplicate
// with delivery jitter to spare. A window without expiry has two failures —
// the set grows for as long as the process lives, and a sender that reuses
// burst_seq after a restart is ignored forever. The window is observed in the
// startup log, not in the seal: sealing it is the next freeze window's call
// (RQ-3 closed this window's seal surface).
const defaultDedupWindow = 5 * time.Second

// dedup suppresses re-arrivals of a key inside a freshness window keyed on
// first receipt time. Entries past the window are pruned on every call, so the
// set is bounded by distinct events per window, not by uptime. The timestamp
// is not refreshed by duplicates: a key that keeps arriving re-emits once per
// window instead of being silenced for as long as the flood lasts.
type dedup struct {
	window time.Duration
	seen   map[string]time.Time
}

func newDedup(window time.Duration) *dedup {
	return &dedup{window: window, seen: map[string]time.Time{}}
}

// first reports whether key is new inside the window and records it if so.
func (d *dedup) first(key string, now time.Time) bool {
	for k, t := range d.seen {
		if now.Sub(t) > d.window {
			delete(d.seen, k)
		}
	}
	if _, ok := d.seen[key]; ok {
		return false
	}
	d.seen[key] = now
	return true
}

type eventJSON struct {
	Ver         int    `json:"ver"`
	Event       string `json:"event"`
	EventCode   byte   `json:"event_code"`
	Reason      uint16 `json:"reason"`
	UnixMs      uint64 `json:"unix_ms"`
	RobotIDHash string `json:"robot_id_hash,omitempty"`
	TokenHash   string `json:"token_hash"`
	BurstSeq    uint32 `json:"burst_seq,omitempty"`
	Valid       bool   `json:"valid"`
	KeyID       string `json:"key_id,omitempty"`
	Note        string `json:"note,omitempty"`
}

// issuerKeys loads the burst verifier's trust anchors through the one keyring
// path every PAIL process uses (`B6-6`, implementation contract).
//
// This file used to parse keyring.json itself. A second loader is not a copy of
// the first, it is a place where a rule fixed in one is still absent in the
// other: the local parser folded a missing role into "issuer" long after the
// canonical loader stopped doing so (`S15`), and it read the unsigned file with
// no way to ask for the signed bundle. Both were invisible from here.
//
// The path argument is the legacy unsigned keyring; which source is actually
// trusted is PAIL_KEYRING_MODE's decision, and the mode is returned so the
// caller can say out loud what it trusted.
func issuerKeys(legacyPath string) ([]keyringKey, string, error) {
	kr, mode, err := crypto.LoadTrustedKeyringFromEnv(legacyPath)
	if err != nil {
		return nil, mode, err
	}
	byID, err := kr.PublicKeysByRole("issuer")
	if err != nil {
		return nil, mode, err
	}
	if len(byID) == 0 {
		return nil, mode, fmt.Errorf("keyring %s has no issuer-role key", legacyPath)
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids) // map order would make the reported key_id vary per run
	keys := make([]keyringKey, 0, len(ids))
	for _, id := range ids {
		keys = append(keys, keyringKey{id: id, pub: byID[id]})
	}
	return keys, mode, nil
}

func main() {
	var (
		listen = flag.String("listen", "127.0.0.1:46000", "UDP listen addr")
		count  = flag.Int("count", 0, "exit after N packets (0 = run forever); duplicates count too")
		window = flag.Duration("dedup-window", defaultDedupWindow,
			"freshness window for duplicate suppression (receipt time)")
	)
	flag.Parse()
	if *window <= 0 {
		// A zero or negative window is not "no dedup", it is a configuration
		// that suppresses nothing while still claiming to — refuse it.
		fmt.Fprintf(os.Stderr, "dedup-window must be positive, got %v\n", *window)
		os.Exit(1)
	}

	// The keyring path comes from PAIL_KEYRING, not from a flag of this
	// binary's own: S8 scans that env var, and a flag the scanner cannot see
	// would let the process trust one file while the check cleared another.
	keyringPath := os.Getenv("PAIL_KEYRING")
	if keyringPath == "" {
		keyringPath = deploysec.DefaultKeyringPath
	}
	deploysec.Preflight("burst_recv")
	// S19 : private key modes, beside Preflight and not
	// inside it — Preflight downgrades to a banner under PAIL_PROFILE=dev.
	deploysec.EnforceKeyModes("burst_recv")

	keys, mode, err := issuerKeys(keyringPath)
	if err != nil {
		deploysec.RefuseConfig("burst_recv",
			fmt.Errorf("keyring trust path (mode=%s): %w", mode, err))
	}

	addr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve: %v\n", err)
		os.Exit(1)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	// The window is observed here, not sealed (D §7.4) — this line is the one
	// place its live value can be read back.
	fmt.Fprintf(os.Stderr, "burst_recv listening on %s (keyring mode=%s issuer keys: %d dedup window=%v)\n",
		*listen, mode, len(keys), *window)

	seen := newDedup(*window) // valid|robot_id_hash|burst_seq dedup
	enc := json.NewEncoder(os.Stdout)
	buf := make([]byte, 2048)
	received := 0

	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read: %v\n", err)
			os.Exit(1)
		}
		pkt := buf[:n]
		received++

		switch {
		case n == burst.V2PacketSize && string(pkt[0:4]) == "PAIL" && pkt[4] == 2:
			ev := eventJSON{
				Ver:         2,
				EventCode:   pkt[5],
				Event:       burst.EventName(pkt[5]),
				Reason:      binary.LittleEndian.Uint16(pkt[6:8]),
				UnixMs:      binary.LittleEndian.Uint64(pkt[8:16]),
				RobotIDHash: hex.EncodeToString(pkt[16:32]),
				TokenHash:   hex.EncodeToString(pkt[32:48]),
				BurstSeq:    binary.LittleEndian.Uint32(pkt[48:52]),
			}
			for _, k := range keys {
				if burst.VerifyPacketV2(k.pub, pkt) {
					ev.Valid = true
					ev.KeyID = k.id
					break
				}
			}
			if !ev.Valid {
				ev.Note = "signature invalid (forged or unknown issuer)"
			}
			// validity is part of the key so a forged packet can never
			// pre-claim a (robot, seq) slot and suppress the real event
			dedupKey := fmt.Sprintf("%v|%s|%d", ev.Valid, ev.RobotIDHash, ev.BurstSeq)
			if !seen.first(dedupKey, time.Now()) {
				// duplicate of an already-emitted event inside the window: suppress
				break
			}
			enc.Encode(ev)

		case n == 32 && string(pkt[0:4]) == "PAIL" && pkt[4] == 1:
			// as-built v1: no signature, no robot id, no seq — never "valid"
			enc.Encode(eventJSON{
				Ver:       1,
				EventCode: pkt[5],
				Event:     burst.EventName(pkt[5]),
				TokenHash: hex.EncodeToString(pkt[6:22]),
				Reason:    binary.LittleEndian.Uint16(pkt[22:24]),
				UnixMs:    binary.LittleEndian.Uint64(pkt[24:32]),
				Valid:     false,
				Note:      "unauthenticated (v1 compatibility)",
			})

		default:
			enc.Encode(eventJSON{Valid: false, Note: fmt.Sprintf("malformed packet (%d bytes)", n)})
		}

		if *count > 0 && received >= *count {
			return
		}
	}
}
