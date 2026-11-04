// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

// ev_crash_probe — G-EVI-11 crash-survival probe (implementation contract, E-10-12~14).
//
// Drives the REAL production packages (internal/blackbox writer/reader,
// internal/burst sender) across a process-boundary crash — the bo2 pattern:
// the probe is scaffolding, the behavior under test is the SUT's.
//
//	-mode run     open blackbox dir, emit N events (signed burst + chained
//	              record each), print CONFIRMED, then linger appending
//	              heartbeat records until killed (-9 lands mid-write).
//	-mode verify  replay the dir through the production reader (WalkDir) and
//	              report its verdict: RECORDS / TORN_TAIL, or CHAIN_ERROR.
//	              Torn tail is NOT an error — a truncated final record is the
//	              normal trace of a crash, not tampering (E-10-14).
import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/glowfly/pail/services/internal/blackbox"
	"github.com/glowfly/pail/services/internal/burst"
	devcrypto "github.com/glowfly/pail/services/internal/crypto"
	"github.com/glowfly/pail/services/internal/deploysec"
	"github.com/glowfly/pail/services/internal/signer"
)

func main() {
	var (
		mode    = flag.String("mode", "", "run | verify")
		dir     = flag.String("dir", "/tmp/ev1/bb", "blackbox segment dir")
		addr    = flag.String("addr", "127.0.0.1:46001", "burst UDP addr")
		keyfile = flag.String("keyfile", "", "issuer ed25519 key JSON")
		n       = flag.Int("n", 5, "events to emit before CONFIRMED")
		robot   = flag.String("robot", "robot-ev1", "robot id")
		linger  = flag.Bool("linger", true, "keep appending heartbeats after CONFIRMED")
	)
	flag.Parse()

	switch *mode {
	case "run":
		run(*dir, *addr, *keyfile, *n, *robot, *linger)
	case "verify":
		verify(*dir)
	default:
		fmt.Fprintln(os.Stderr, "need -mode run|verify")
		os.Exit(2)
	}
}

func run(dir, addr, keyfile string, n int, robot string, linger bool) {
	// `S17` (§3.7). 하네스 도구라고 면제하지 않는다 — 이 프로브가 서명하는 기록은
	// 프로덕션 리더가 읽고, 하드코딩된 id 는 **그 기록이 어느 키의 것인지를 도구가
	// 대신 정하게** 한다.
	keyID := os.Getenv("PAIL_ISSUER_KEY_ID")
	if err := deploysec.RequireIssuerKeyID(keyID, "PAIL_ISSUER_KEY_ID"); err != nil {
		deploysec.RefuseConfig("ev_crash_probe", err)
	}
	// Test harness: load the probe key if provisioned, else mint one explicitly.
	kp, err := devcrypto.LoadEd25519KeypairJSON(keyfile, keyID)
	if errors.Is(err, devcrypto.ErrKeyFileNotFound) {
		kp, err = devcrypto.GenerateEd25519KeypairJSON(keyfile, keyID)
	}
	if err != nil {
		fatal("keyfile: %v", err)
	}
	w, err := blackbox.OpenDir(dir, blackbox.Config{Signer: signer.NewLocal(kp)})
	if err != nil {
		fatal("blackbox open: %v", err)
	}
	s := burst.New(addr)
	for i := 1; i <= n; i++ {
		seq := s.NextSeq()
		now := uint64(time.Now().UnixMilli())
		th := burst.TokenHash16(fmt.Sprintf("ev1-token-%d", i))
		pkt := burst.BuildPacketV2(kp.Private, burst.EventEstop, 0x13, now, robot, th, seq)
		s.SendBurst(pkt)
		payload := []byte(fmt.Sprintf(`{"kind":"EV1_EVENT","i":%d,"burst_seq":%d}`, i, seq))
		if err := w.Append(blackbox.RecordGateDecision, now, payload); err != nil {
			fatal("append: %v", err)
		}
		fmt.Printf("EVENT i=%d seq=%d\n", i, seq)
	}
	head, segSeq, cnt := w.Snapshot()
	fmt.Printf("CONFIRMED n=%d records=%d seg=%d head=%s\n",
		n, cnt, segSeq, hex.EncodeToString(head[:8]))
	if !linger {
		return // deliberately no Close: crash probes never exit cleanly
	}
	// In-flight writes for the kill to land in: unconfirmed heartbeats.
	for {
		time.Sleep(50 * time.Millisecond)
		now := uint64(time.Now().UnixMilli())
		_ = w.Append(blackbox.RecordGateDecision, now, []byte(`{"kind":"EV1_HEARTBEAT"}`))
	}
}

func verify(dir string) {
	records := 0
	torn, err := blackbox.WalkDir(dir, func(r blackbox.Record) error {
		records++
		return nil
	})
	if err != nil {
		fmt.Printf("CHAIN_ERROR: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("RECORDS=%d TORN_TAIL=%v\n", records, torn)
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "FATAL: "+format+"\n", a...)
	os.Exit(1)
}
