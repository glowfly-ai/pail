// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package telemetry

import (
	"crypto/ed25519"
	"fmt"
	"time"
)

// Dispatcher routes one received UDP datagram to the ingester that understands
// it and returns the JSONL line to append.
//
// 라우팅과 직렬화가 한 자리에 있는 이유는 `D11` 이다 — 미러는 게이트 수신기
// 옆 **같은 수집 포트**로 보내므로 한 소켓에 두 형식이 도착한다. 두 판단을
// 갈라 두면 매직은 permit 인데 burst 로 적히는 조합이 조용히 산다.
type Dispatcher struct {
	burst  *Ingester
	mirror *MirrorIngester
}

func NewDispatcher(burstKeys, mirrorKeys []ed25519.PublicKey) *Dispatcher {
	return &Dispatcher{
		burst:  NewIngester(burstKeys),
		mirror: NewMirrorIngester(mirrorKeys),
	}
}

// Observe routes by magic.
//
// 매직 문자열을 인제스터와 여기서 각각 읽는 것은 사본이지만 **틀리는 방향이
// 닫혀 있다**: 여기의 리터럴이 어긋나면 인제스터가 자기 검사로 거부해 오류가
// 되고, 잘못된 칸에 조용히 적히는 경로는 생기지 않는다.
//
// 모르는 매직은 어느 파서에도 넘기지 않는다. 넘기면 그 파서의 "bad
// magic/version" 이 **무엇이 도착했는지**를 덮어, 알 수 없는 트래픽과 상대
// 형식의 도착이 같은 문구로 기록된다.
func (d *Dispatcher) Observe(pkt []byte, now time.Time) ([]byte, Record, error) {
	if len(pkt) < 4 {
		return nil, Record{}, fmt.Errorf("datagram %d byte(s): magic 을 읽을 수 없다", len(pkt))
	}
	switch string(pkt[0:4]) {
	case "PAIL":
		rec, err := d.burst.Observe(pkt, now)
		if err != nil {
			return nil, Record{}, err
		}
		line, err := rec.MarshalBurst()
		if err != nil {
			return nil, Record{}, err
		}
		return line, rec, nil
	case "PMIR":
		rec, err := d.mirror.Observe(pkt, now)
		if err != nil {
			return nil, Record{}, err
		}
		line, err := rec.MarshalPermit()
		if err != nil {
			return nil, Record{}, err
		}
		return line, rec, nil
	}
	return nil, Record{}, fmt.Errorf("unknown magic %q", pkt[0:4])
}
