// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// Command bo2_anchor_probe drives the PRODUCTION anchor client (anchor.Agent
// + the HTTP store constructed exactly like the service mains) against a live
// Anchor SaaS front door. The chain snapshot is synthetic, but the upload path
// under test — record build, Ed25519 signing, HTTP PUT, offline queue, drain —
// is the real production code. It exists to demonstrate and then verify the
// BO-2 transport-credential (bearer) behavior of the client.
//
// Modes:
//
//	-keygen                  print PRIV=<b64 seed> / PUB=<b64 pub> and exit
//	(default)                run: env PAIL_ANCHOR_URL [PAIL_ANCHOR_TOKEN],
//	                         flags -priv-file -keyid -robot -queue -ticks -base
//
// The seed travels by file path (-priv-file), never argv (AF-9, F-AN-16):
// argv is readable by every same-host process via ps/procfs.
//
// -base sets the chain record count the synthetic chain starts AFTER, so a
// second probe run can continue the same robot's monotonic count sequence
// (the SaaS rejects count rewinds with 409, like the real persistent chain
// never rewinds).
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/glowfly/pail/services/internal/anchor"
)

type seedSigner struct {
	priv  ed25519.PrivateKey
	keyID string
}

func (s *seedSigner) Sign(msg []byte) ([]byte, error) { return ed25519.Sign(s.priv, msg), nil }
func (s *seedSigner) KeyID() string                   { return s.keyID }
func (s *seedSigner) Public() ed25519.PublicKey       { return s.priv.Public().(ed25519.PublicKey) }

// fakeChain is a Snapshotter whose record count advances on every snapshot,
// so each Tick emits a fresh anchor record (Keepalive=0 legacy emission).
type fakeChain struct{ n uint64 }

func (f *fakeChain) Snapshot() ([32]byte, uint64, uint64) {
	f.n++
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], f.n)
	return sha256.Sum256(b[:]), 1, f.n
}

func queueCount(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() {
			n++
		}
	}
	return n
}

func main() {
	keygen := flag.Bool("keygen", false, "generate ed25519 keypair, print PRIV/PUB base64")
	privFile := flag.String("priv-file", "", "path to file holding base64 ed25519 seed (32B)")
	keyID := flag.String("keyid", "bo2-key-1", "issuer key id")
	robot := flag.String("robot", "robot-1", "robot id")
	queue := flag.String("queue", "", "offline queue dir")
	ticks := flag.Int("ticks", 5, "number of anchor ticks")
	base := flag.Uint64("base", 0, "chain record count to continue after")
	intervalMs := flag.Int("interval_ms", 0, "sleep between ticks (long-running robot simulation)")
	flag.Parse()

	if *keygen {
		pub, pk, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("PRIV=%s\n", base64.StdEncoding.EncodeToString(pk.Seed()))
		fmt.Printf("PUB=%s\n", base64.StdEncoding.EncodeToString(pub))
		return
	}

	if *privFile == "" {
		fmt.Fprintln(os.Stderr, "-priv-file required")
		os.Exit(1)
	}
	rawSeed, err := os.ReadFile(*privFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read -priv-file: %v\n", err)
		os.Exit(1)
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(rawSeed)))
	if err != nil || len(seed) != ed25519.SeedSize {
		fmt.Fprintln(os.Stderr, "bad -priv-file: need base64 32-byte ed25519 seed")
		os.Exit(1)
	}
	if *queue == "" {
		fmt.Fprintln(os.Stderr, "-queue required")
		os.Exit(1)
	}
	store, desc := anchor.StoreFromEnv()
	if store == nil {
		fmt.Fprintln(os.Stderr, "set PAIL_ANCHOR_URL (or PAIL_ANCHOR_DIR)")
		os.Exit(1)
	}
	fmt.Printf("STORE=%s\n", desc)

	a := &anchor.Agent{
		Source:   &fakeChain{n: *base},
		Signer:   &seedSigner{priv: ed25519.NewKeyFromSeed(seed), keyID: *keyID},
		RobotID:  *robot,
		Store:    store,
		QueueDir: *queue,
		Logf:     func(format string, v ...any) { fmt.Printf(format+"\n", v...) },
	}
	for i := 1; i <= *ticks; i++ {
		a.Tick()
		fmt.Printf("TICK=%d QUEUE=%d\n", i, queueCount(*queue))
		if *intervalMs > 0 && i < *ticks {
			time.Sleep(time.Duration(*intervalMs) * time.Millisecond)
		}
	}
	fmt.Printf("QUEUE_FINAL=%d\n", queueCount(*queue))
}
