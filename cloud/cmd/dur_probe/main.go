// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

// dur_probe — implementation contract (`DUR-L6`) 전원 상실 fault-injection 하네스의 구동부.
//
// `ev_crash_probe` 의 형제다. 다른 점은 만드는 형상이다: `kill -9` 는 write(2) 를
// 반으로 자르지 못하므로(그 시스템콜은 프로세스 죽음에 대해 원자적이다) 전원
// 상실이 남기는 바이트 형상은 하네스가 **파일에 직접** 만든다. 여기서 하는 일은
// 그 형상을 만든 뒤 **프로덕션 경로**(blackbox.OpenDir / blackbox.WalkDir)에
// 묻는 것뿐이다 — 판정자는 이 도구가 아니라 SUT 다.
//
//	-mode write   OpenDir → n건 append → Close. 정상 종료(=fsync)까지 간다.
//	-mode fill    append 를 오류가 날 때까지. 실물 ENOSPC 용(DUR-01).
//	-mode open    OpenDir → Close 만. 기동 경로의 판정을 그대로 노출한다.
//	              rc=0 기동 성공 / rc=3 기동 거부. **거부는 오류가 아니라 결과다**
//	              — rc=1(도구 자신의 실패)과 같은 값으로 내면 "거부됐다"와
//	              "재보지도 못했다"가 같은 바이트가 된다(H-B2).
//	-mode verify  프로덕션 리더로 재생하고 복구 레코드(32)를 세어 서명까지 검증한다.
//
// 이 도구는 트리를 변형시키지 않는다 — 절단·변조는 셸이 truncate/dd 로 한다.
// 알 수 없는 인자는 무시하지 않는다(flag 기본 동작이 rc=2 로 거부한다).

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/glowfly/pail/services/internal/blackbox"
	devcrypto "github.com/glowfly/pail/services/internal/crypto"
	"github.com/glowfly/pail/services/internal/deploysec"
	"github.com/glowfly/pail/services/internal/signer"
)

func main() {
	var (
		mode    = flag.String("mode", "", "write | fill | open | verify")
		dir     = flag.String("dir", "/tmp/dur1/bb", "blackbox segment dir")
		keyfile = flag.String("keyfile", "", "issuer ed25519 key JSON")
		n       = flag.Int("n", 5, "records to append (-mode write)")
		payload = flag.Int("payload", 64, "payload bytes per record")
		maxFill = flag.Int("max", 100000, "append attempt ceiling (-mode fill)")
	)
	flag.Parse()
	if flag.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "unexpected positional argument(s): %v\n", flag.Args())
		os.Exit(2)
	}

	switch *mode {
	case "write":
		write(*dir, *keyfile, *n, *payload)
	case "fill":
		fill(*dir, *keyfile, *payload, *maxFill)
	case "open":
		open(*dir, *keyfile)
	case "verify":
		verify(*dir, *keyfile)
	default:
		fmt.Fprintln(os.Stderr, "need -mode write|fill|open|verify")
		os.Exit(2)
	}
}

// keypair — `S17`(§3.7). 하네스 도구라고 면제하지 않는다: 이 프로브가 서명하는
// 기록은 프로덕션 리더가 읽고, 하드코딩된 id 는 그 기록이 어느 키의 것인지를
// 도구가 대신 정하게 한다.
func keypair(keyfile string) *devcrypto.Keypair {
	keyID := os.Getenv("PAIL_ISSUER_KEY_ID")
	if err := deploysec.RequireIssuerKeyID(keyID, "PAIL_ISSUER_KEY_ID"); err != nil {
		deploysec.RefuseConfig("dur_probe", err)
	}
	kp, err := devcrypto.LoadEd25519KeypairJSON(keyfile, keyID)
	if errors.Is(err, devcrypto.ErrKeyFileNotFound) {
		kp, err = devcrypto.GenerateEd25519KeypairJSON(keyfile, keyID)
	}
	if err != nil {
		fatal("keyfile: %v", err)
	}
	return kp
}

func openWriter(dir, keyfile string) (*blackbox.Writer, error) {
	return blackbox.OpenDir(dir, blackbox.Config{Signer: signer.NewLocal(keypair(keyfile))})
}

func body(i, size int) []byte {
	p := []byte(fmt.Sprintf(`{"kind":"DUR_EVENT","i":%d}`, i))
	if len(p) >= size {
		return p
	}
	return append(p, bytes.Repeat([]byte("."), size-len(p))...)
}

func write(dir, keyfile string, n, payload int) {
	w, err := openWriter(dir, keyfile)
	if err != nil {
		fmt.Printf("OPEN=refused err=%v\n", err)
		os.Exit(3)
	}
	for i := 1; i <= n; i++ {
		if err := w.Append(blackbox.RecordGateDecision, uint64(time.Now().UnixMilli()), body(i, payload)); err != nil {
			fatal("append %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		fatal("close: %v", err)
	}
	fmt.Printf("OPEN=ok WROTE=%d PAYLOAD=%d\n", n, payload)
}

// fill 은 append 가 실패할 때까지 밀어 넣는다. 세는 것은 **성공한 append 수**이고,
// 그 수가 이 모드의 전부다: 재기동 뒤 레코드가 그보다 적으면 어딘가에서 append 가
// 성공을 반환하고도 바이트를 남기지 않은 것이다(거짓 성공).
func fill(dir, keyfile string, payload, max int) {
	w, err := openWriter(dir, keyfile)
	if err != nil {
		fmt.Printf("OPEN=refused err=%v\n", err)
		os.Exit(3)
	}
	acked := 0
	var first error
	for i := 1; i <= max; i++ {
		if err := w.Append(blackbox.RecordGateDecision, uint64(time.Now().UnixMilli()), body(i, payload)); err != nil {
			first = err
			break
		}
		acked++
	}
	// Close 는 실패할 수 있다(fsync 가 ENOSPC 를 여기서 낼 수 있다). 그것도 사실이라
	// 적는다 — 삼키면 "닫혔다"와 "닫히지 않았다"가 같은 침묵이 된다.
	cerr := w.Close()
	fmt.Printf("ACKED=%d CLOSE_ERR=%v FIRST_ERR=%v\n", acked, cerr, first)
	if first == nil {
		fmt.Printf("NO_ENOSPC=true (max=%d 까지 밀었으나 append 가 한 번도 실패하지 않았다)\n", max)
		os.Exit(4)
	}
}

func open(dir, keyfile string) {
	w, err := openWriter(dir, keyfile)
	if err != nil {
		fmt.Printf("OPEN=refused err=%v\n", err)
		os.Exit(3)
	}
	if err := w.Close(); err != nil {
		fatal("close: %v", err)
	}
	fmt.Println("OPEN=ok")
}

// verify 는 프로덕션 리더로 재생하고, 복구 선언(레코드 32)을 **서명까지** 검증한다.
// 세기만 하면 "복구 레코드가 있다"와 "복구 레코드처럼 생긴 바이트가 있다"가 같은
// 값이 된다 — 이 레코드를 서명한 이유가 정확히 그것이다.
func verify(dir, keyfile string) {
	records, recovery := 0, 0
	var discarded uint64
	sigOK := true
	pub := keypair(keyfile).Public

	// events 를 따로 센다. 전체 레코드 수에는 체크포인트도 섞이므로 "acked 한 만큼
	// 살아남았는가"를 records 로 재면 두 값이 다른 이유가 여러 개가 되고, 그러면
	// 거짓 성공과 체크포인트 삽입이 같은 숫자 차이로 도착한다(H-B2).
	events := 0
	torn, err := blackbox.WalkDir(dir, func(r blackbox.Record) error {
		records++
		if r.Type == blackbox.RecordGateDecision {
			events++
		}
		if r.Type != blackbox.RecordRecoveryTruncate {
			return nil
		}
		recovery++
		if len(r.Payload) != blackbox.RecoveryTruncatePayloadLen {
			sigOK = false
			fmt.Printf("RECOVERY_BAD_LEN=%d\n", len(r.Payload))
			return nil
		}
		d := binary.BigEndian.Uint64(r.Payload[0:8])
		tail := r.Payload[8:40]
		seg := binary.BigEndian.Uint64(r.Payload[40:48])
		ms := binary.BigEndian.Uint64(r.Payload[48:56])
		sig := r.Payload[56:120]
		discarded += d
		if !ed25519.Verify(pub, blackbox.RecoveryTruncateSignedInput(d, tail, seg, ms), sig) {
			sigOK = false
			fmt.Printf("RECOVERY_SIG_BAD seg=%d discarded=%d\n", seg, d)
			return nil
		}
		fmt.Printf("RECOVERY seg=%d discarded=%d unix_ms=%d\n", seg, d, ms)
		return nil
	})
	if err != nil {
		fmt.Printf("CHAIN_ERROR: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("RECORDS=%d EVENTS=%d TORN_TAIL=%v RECOVERY=%d DISCARDED=%d SIG_OK=%v\n",
		records, events, torn, recovery, discarded, sigOK)
	if !sigOK {
		os.Exit(1)
	}
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "FATAL: "+format+"\n", a...)
	os.Exit(1)
}
