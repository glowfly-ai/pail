// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// `B9-4` 행위 유닛 .
//
// 고치는 것: payload 가 미지 필드를 **조용히 버린다.** 그래서 `status: "revoked"`
// 같은 폐기 표시를 더하는 순간 구판 리더는 그것을 못 본 채 **키를 유효하다고
// 판단한다** — 폐기 표시를 더하는 것이 폐기를 무시하는 경로를 함께 만드는 셈이다.
// §4.2 가 `status` 필드를 기각하고 부재 기반 폐기를 유지한 근거가 이것이고,
// 그 결정은 파서가 앞으로 모르는 필드를 **거부**한다는 전제 위에 선다.
//
// 죽는 자리를 각각 잰다(`H-B9`) — payload 상위 · 항목 안 · 봉투 · 뒤에 붙은
// 잉여 바이트. 한 유닛으로 접으면 넷 중 하나가 열려도 나머지 셋이 초록을 만든다.

func rootKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// signPayload 는 `BuildBundle` 을 **거치지 않고** 봉투를 만든다. 파서를 재려면
// 서명이 유효해야 하는데, `BuildBundle` 은 서명 전에 같은 파서를 부르므로 깨진
// payload 를 그 길로는 실어 보낼 수 없다. 공격자는 그 제약을 받지 않는다.
func signPayload(t *testing.T, priv ed25519.PrivateKey, payload []byte) []byte {
	t.Helper()
	env := BundleEnvelope{
		SchemaVersion: BundleSchemaVersion,
		PayloadB64:    base64.StdEncoding.EncodeToString(payload),
		RootKeyID:     "root-1",
		RootSigB64:    base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload)),
	}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func wantReject(t *testing.T, what string, bundle []byte, pub ed25519.PublicKey) {
	t.Helper()
	p, _, err := VerifyBundle(bundle, pub)
	if err == nil {
		t.Fatalf("%s: 번들이 수용됐다 (%+v). 모르는 것이 조용히 버려지면 "+
			"폐기 표시가 실려도 키는 유효한 채로 남는다", what, p)
	}
	// 사유까지 재는 이유: 서명 불일치로 죽으면 파서가 열린 채여도 초록이 된다.
	// `after top-level value` 는 지금의 `json.Unmarshal` 이 내는 문구고 `trailing` 은
	// 엄격 파싱으로 옮긴 뒤의 문구다 — **둘 다 받는다.** 잉여 바이트 검사는 지금
	// 이미 서 있는 성질이라 이 두 줄은 새 결함이 아니라 **회귀 가드**이며, 좁게
	// 적으면 고쳐야 할 것이 없는데도 붉어져 진짜 세 건을 가린다.
	for _, ok := range []string{"unknown field", "trailing", "after top-level value"} {
		if strings.Contains(err.Error(), ok) {
			return
		}
	}
	t.Fatalf("%s: 거부됐지만 사유가 다르다: %v", what, err)
}

func TestBundleRejectsUnknownPayloadField(t *testing.T) {
	pub, priv := rootKeys(t)
	payload := makePayload(t, 7, futureUnix())
	// 폐기 표시를 실제로 얹는다 — §4.2 가 기각한 그 필드다.
	tampered := strings.Replace(string(payload), `{"bundle_version"`,
		`{"status":"revoked","bundle_version"`, 1)
	wantReject(t, "payload 상위 미지 필드", signPayload(t, priv, []byte(tampered)), pub)
}

func TestBundleRejectsUnknownEntryField(t *testing.T) {
	pub, priv := rootKeys(t)
	payload := makePayload(t, 7, futureUnix())
	// 항목 **안**의 미지 필드. 상위만 막으면 여기가 열린 채 남고, 폐기 표시는
	// 애초에 키마다 붙는 것이라 이쪽이 더 자연스러운 입구다.
	tampered := strings.Replace(string(payload), `{"key_id"`,
		`{"status":"revoked","key_id"`, 1)
	wantReject(t, "keys[] 항목의 미지 필드", signPayload(t, priv, []byte(tampered)), pub)
}

func TestBundleRejectsUnknownEnvelopeField(t *testing.T) {
	pub, priv := rootKeys(t)
	bundle := signPayload(t, priv, makePayload(t, 7, futureUnix()))
	// 봉투는 **전송이 만지는 바깥쪽**이다. 여기서 모르는 것을 버리면 payload 를
	// 아무리 엄격하게 봐도 서명이 덮지 않는 자리에 필드를 실을 수 있다.
	tampered := strings.Replace(string(bundle), `{"schema_version"`,
		`{"note":"ignore me","schema_version"`, 1)
	wantReject(t, "봉투의 미지 필드", []byte(tampered), pub)
}

func TestBundleRejectsTrailingContent(t *testing.T) {
	pub, priv := rootKeys(t)
	payload := makePayload(t, 7, futureUnix())

	// `json.Unmarshal` 은 값 뒤의 잉여 바이트를 거부하지만 `json.Decoder` 는
	// 한 값만 읽고 멈춘다. 엄격 파싱으로 옮기면서 이 검사를 함께 옮기지 않으면
	// **구멍을 막으면서 다른 구멍을 낸다.** 두 겹 다 잰다.
	t.Run("payload", func(t *testing.T) {
		wantReject(t, "payload 뒤 잉여", signPayload(t, priv,
			append(append([]byte{}, payload...), []byte(` {"bundle_version":9}`)...)), pub)
	})
	t.Run("envelope", func(t *testing.T) {
		bundle := signPayload(t, priv, payload)
		wantReject(t, "봉투 뒤 잉여", append(bundle, []byte(" {}")...), pub)
	})
}

// 양성 대조. 정확한 필드만 실린 번들은 통과해야 한다 — 그러지 않으면 이것은
// 게이트가 아니라 벽이고, 그때는 위 넷이 전부 초록인 채 **아무 번들도 실을 수
// 없다.** `BuildBundle` 이 만든 것과 손으로 서명한 것을 함께 잰다.
func TestBundleAcceptsExactFields(t *testing.T) {
	pub, priv := rootKeys(t)
	payload := makePayload(t, 7, futureUnix())

	built, err := BuildBundle(priv, "root-1", payload)
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}
	for name, bundle := range map[string][]byte{
		"BuildBundle": built,
		"손 서명":        signPayload(t, priv, payload),
	} {
		p, raw, err := VerifyBundle(bundle, pub)
		if err != nil {
			t.Fatalf("%s: 정상 번들이 거부됐다: %v", name, err)
		}
		if p.BundleVersion != 7 || len(p.Keys) != 1 || len(raw) == 0 {
			t.Fatalf("%s: 실린 값이 다르다: %+v", name, p)
		}
	}
}

// §4.4 의 마이그레이션 지렛대는 판을 올리면 구판 리더가 **거부한다**는 것인데,
// 형식 변경은 대개 필드 추가를 함께 데려온다. 엄격 파싱이 판 검사보다 먼저 서면
// 그 번들은 `unknown field` 로 죽고 — 안전하기는 하되 — 읽는 쪽은 자기가 구판이라
// 는 사실을 알 길이 없다. 거부는 같고 **고칠 수 있는가**가 다르다. 그래서 사유까지
// 잰다(커밋16 이 `S16`~`S16e` 를 사유 id 로 가른 것과 같은 이유).
func TestBundleReportsSchemaVersionBeforeUnknownField(t *testing.T) {
	pub, priv := rootKeys(t)
	bundle := signPayload(t, priv, makePayload(t, 7, futureUnix()))
	tampered := strings.Replace(string(bundle), `{"schema_version":1`,
		`{"schema_version":2,"rotation_hint":"v3"`, 1)
	if tampered == string(bundle) {
		t.Fatal("픽스처가 봉투를 건드리지 못했다 — 이 테스트는 아무것도 재지 않았다")
	}
	_, _, err := VerifyBundle([]byte(tampered), pub)
	if err == nil {
		t.Fatal("판이 다른 번들이 수용됐다")
	}
	if !strings.Contains(err.Error(), "schema_version") {
		t.Fatalf("판을 말하지 않는다: %v", err)
	}
	if strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("미지 필드가 판 진단을 가렸다: %v", err)
	}
}
