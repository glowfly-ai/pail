// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

//go:build red_lldb

// implementation contract / B3-C7 — 버스트 `token_hash16` 스펙 경고의 존재 검사.
//
// §2.6 의 결정은 "유도식을 바꾸지 않는다"였다. 유도식은 6벌 중복이고 어떤
// 판정에도 쓰이지 않으므로, 고치면 판정 경로의 이득 없이 canon 동결 창만
// 넓어진다(R1/RB-6). 대신 **약점을 밝히는 문단**이 스펙에 있어야 한다 —
// 밝히지 않은 약점이 밝힌 약점보다 나쁘다(H7).
//
// 그런데 주석으로만 존재하는 경고는 조용히 지워진다. 이 검사는 그 문단을
// 지우는 일을 실패로 만든다. 즉 여기서 GREEN 이 뜻하는 것은 "구현이 옳다"가
// 아니라 **"제3자가 읽는 세 표면이 이 값의 한계를 말하고 있다"** 이다.
//
// 세 표면을 모두 보는 이유: 제3자 구현자가 한 곳만 읽을 수 있기 때문이다.
// 와이어 형식(packet_v2.go)만 읽는 사람, 릴레이 경계(agent_relay.proto)만
// 읽는 사람, 문서(as-built §6.1)만 읽는 사람이 각각 있다.
//
// 실행: go test -tags red_lldb -run TestB3C7 ./internal/burst -v
package burst

import (
	"encoding/hex"
	"github.com/glowfly/pail/services/internal/testlayout"
	"os"
	"strings"
	"testing"
)

// specSurface 는 경고를 실어야 하는 표면 하나다. want 의 각 항목은 그 표면이
// 반드시 말해야 하는 명제를 대표하는 문구다. 문구 자체가 아니라 **명제**가
// 요구사항이므로, 표면의 언어(영/한)에 맞춰 다르게 적는다.
type specSurface struct {
	path string
	desc string
	want []string
}

func TestB3C7_TokenHash16WarningPresentInSpec(t *testing.T) {
	surfaces := []specSurface{
		{
			path: "services/pail_services_go/internal/burst/packet_v2.go",
			desc: "와이어 형식 정본",
			want: []string{
				"not an identity claim",
				"MUST NOT",
				"authorization decision",
				"consumption_key",
			},
		},
		{
			path: "proto/agent_relay.proto",
			desc: "릴레이 경계",
			want: []string{
				"NOT an identity claim",
				"authorization decision",
				"consumption_key",
			},
		},
		{
			path: "oss/spec/ARCHITECTURE.md",
			desc: "public architecture reference",
			want: []string{
				"not an identity claim",
				"authorization decision",
				"consumption_key",
			},
		},
	}

	for _, s := range surfaces {
		b, err := os.ReadFile(testlayout.Path(t, s.path))
		if err != nil {
			t.Fatalf("%s(%s): 읽기 실패 — 경고를 실을 표면 자체가 없다: %v", s.path, s.desc, err)
		}
		body := string(b)
		for _, w := range s.want {
			if !strings.Contains(body, w) {
				t.Errorf("%s(%s): 스펙 경고에서 %q 가 사라졌다 — §2.6 은 유도식을 안 고치는 대신 "+
					"이 문단을 요구했다. 문단이 없으면 제3자 구현체가 이 값을 신원으로 쓴다(H7).",
					s.path, s.desc, w)
			}
		}
	}
	// 실패한 뒤에도 GREEN 을 찍으면 그 줄은 증거가 아니라 소음이다.
	if t.Failed() {
		return
	}
	t.Logf("GREEN: 세 표면(%d) 전부가 token_hash16 을 상관 힌트로 한정하고 판정 사용을 금지한다", len(surfaces))
}

// TestB3C7_DerivationDeliberatelyUnchanged — §2.6 의 결정은 무변경이다.
// 누가 "고치는 김에" 손대면 6벌 canon 변경으로 번진다(RB-6). 유도식이
// 바뀌면 여기서 걸리고, 걸린 사람은 §2.6 을 다시 읽게 된다.
func TestB3C7_DerivationDeliberatelyUnchanged(t *testing.T) {
	got := TokenHash16("tok-abc")
	// sha256("tok-abc")[:16]. Go 로 산출하지 않았다 — `printf 'tok-abc' |
	// shasum -a 256` 로 이 패키지 밖에서 얻었다. 구현으로 기대값을 만들면
	// 이 검사는 대조가 아니라 구현이 자기 자신과 같음을 확인하는 항등식이 된다.
	const want = "0b9f31c5403adf5a5676eafcf2ed391d"
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("token_hash16 유도식이 바뀌었다 — §2.6 은 무변경을 결정했고, "+
			"바꾸면 6벌 전부가 canon 변경 대상이 된다(R1/RB-6).\n  got  %x\n  want %s", got, want)
	}
	t.Logf("GREEN: 유도식 sha256(token_id)[:16] 무변경 (%x)", got)
}
