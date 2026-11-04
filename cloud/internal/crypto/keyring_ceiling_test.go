// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// `B9-3` 행위 유닛 — 폐기 도달 **상한의 첫째 항**(번들 유효 창)이 설정으로
// 존재하고, 미설정이 통과가 아닌지.
//
// 상한은 `번들 유효 창 + 폴링 주기`다. 여기서는 앞항만 잰다 — 뒷항은
// `cmd/pail_robot_agent` 에 있고 그쪽 유닛이 따로 잰다(`H-B9`).
//
// 세 자리를 나눠 잰다: 환경에서 못 읽음(`S20b`) · 적재 경로가 상한을 안 물음
// (`S20b`) · 물었는데 창이 넘음(`S20`). 하나로 접으면 "상한을 안 물었다"와
// "물었고 통과했다"가 같은 초록이 된다.
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"path/filepath"
	"testing"
	"time"

	"github.com/glowfly/pail/services/internal/deploysec"
)

// TestBundlePolicyFromEnvRefusesUnset — 무제한을 기본값으로 두지 않는다(`U-B5`).
func TestBundlePolicyFromEnvRefusesUnset(t *testing.T) {
	t.Setenv(EnvBundleMaxLifetime, "")
	_, err := BundlePolicyFromEnv()
	wantRule(t, err, "S20b")
}

// TestBundlePolicyFromEnvRefusesNonPositive — 0 과 음수와 쓰레기. 0 을 "무제한"
// 으로 읽으면 상한을 끄는 방법이 상한을 고르는 방법과 같은 자리에 생긴다.
func TestBundlePolicyFromEnvRefusesNonPositive(t *testing.T) {
	for _, raw := range []string{"0", "-1", "abc", "7d", "3.5"} {
		t.Setenv(EnvBundleMaxLifetime, raw)
		_, err := BundlePolicyFromEnv()
		wantRule(t, err, "S20b")
	}
}

// TestBundlePolicyFromEnvAcceptsSeconds — 양성 대조. 이것이 없으면 위 둘은
// "항상 거부한다"로도 초록이고, 그때 이것은 게이트가 아니라 벽이다.
func TestBundlePolicyFromEnvAcceptsSeconds(t *testing.T) {
	t.Setenv(EnvBundleMaxLifetime, "604800")
	pol, err := BundlePolicyFromEnv()
	if err != nil {
		t.Fatalf("정상 값이 거부됐다: %v", err)
	}
	if pol.MaxLifetime != 7*24*time.Hour {
		t.Fatalf("MaxLifetime=%s, want 168h", pol.MaxLifetime)
	}
}

// ceilingBundle 은 지금부터 window 만큼 유효한 서명 번들을 놓고 경로를 준다.
func ceilingBundle(t *testing.T, window time.Duration) (string, string, ed25519.PublicKey) {
	t.Helper()
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	b, err := BuildBundle(rootPriv, "root-1", makePayload(t, 1, time.Now().Add(window).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "keyring_bundle.json")
	writeFile(t, p, b)
	return p, filepath.Join(dir, "state.json"), rootPub
}

// TestLoadBundleRefusesWindowOverCeiling — `S20`. 루트가 제대로 서명한 번들인데
// 유효 창이 상한을 넘었다. 이것 하나만 깨서 잰다 — 서명·판·롤백은 모두 정상이다.
func TestLoadBundleRefusesWindowOverCeiling(t *testing.T) {
	path, state, rootPub := ceilingBundle(t, 30*24*time.Hour)
	_, err := LoadKeyringBundle(path, rootPub, state, BundlePolicy{MaxLifetime: 7 * 24 * time.Hour})
	wantRule(t, err, "S20")
}

// TestLoadBundleAcceptsWindowUnderCeiling — 양성 대조. 같은 리그에서 창만
// 줄이면 실려야 한다. 없으면 위 시험은 "번들을 아예 못 싣는다"로도 초록이다.
func TestLoadBundleAcceptsWindowUnderCeiling(t *testing.T) {
	path, state, rootPub := ceilingBundle(t, 24*time.Hour)
	if _, err := LoadKeyringBundle(path, rootPub, state, BundlePolicy{MaxLifetime: 7 * 24 * time.Hour}); err != nil {
		t.Fatalf("상한 안의 번들이 거부됐다: %v", err)
	}
}

// TestLoadBundleRefusesUndeclaredCeiling — 적재 경로가 상한을 **묻지 않은**
// 경우. 영값 정책은 "무제한"이 아니라 "선언 안 함"이고 `S20b` 다(`H-B2`).
// 이것이 없으면 새 호출자가 `BundlePolicy{}` 를 넘겨도 조용히 통과한다.
func TestLoadBundleRefusesUndeclaredCeiling(t *testing.T) {
	path, state, rootPub := ceilingBundle(t, 24*time.Hour)
	_, err := LoadKeyringBundle(path, rootPub, state, BundlePolicy{})
	wantRule(t, err, "S20b")
}

// TestLoadedBundleCarriesFreshness — 적재된 keyring 이 시간축 게이트를 실제로
// 들고 나오는지. 상한 검사만 통과하고 만료 출처가 비면 그 뒤 `Check` 는 `S20f`
// 로 죽고, 그 죽음은 적재 시점에서 보이지 않는다.
func TestLoadedBundleCarriesFreshness(t *testing.T) {
	path, state, rootPub := ceilingBundle(t, 24*time.Hour)
	kr, err := LoadKeyringBundle(path, rootPub, state, BundlePolicy{MaxLifetime: 7 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("적재: %v", err)
	}
	f, err := kr.Freshness()
	if err != nil {
		t.Fatalf("적재된 번들에서 시간축 게이트를 못 꺼낸다: %v", err)
	}
	if err := f.Check(); err != nil {
		t.Fatalf("방금 실은 번들이 만료로 판정됐다: %v", err)
	}
	// 만료 뒤에는 같은 게이트가 멈춘다 — 적재는 이미 끝났고 프로세스는 살아 있다.
	if err := f.CheckAt(time.Now().Add(25 * time.Hour)); deploysec.RuleID(err) != "S20d" {
		t.Fatalf("적재 뒤 만료가 강제되지 않는다: %v", err)
	}
}

// TestUnsignedDevKeyringCarriesFreshness — 무서명 dev 경로도 출처를 댄다.
// 대지 않으면 dev 전체가 `S20f` 로 멈추고, 그것은 게이트가 아니라 벽이다.
func TestUnsignedDevKeyringCarriesFreshness(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "keyring.json"), []byte(
		`{"keys":[{"key_id":"dev-key-1","ed25519_public_key_base64":"`+
			base64.StdEncoding.EncodeToString(mustPub(t))+`","role":"issuer"}]}`))
	kr, err := LoadKeyring(filepath.Join(dir, "keyring.json"))
	if err != nil {
		t.Fatalf("적재: %v", err)
	}
	f, err := kr.Freshness()
	if err != nil {
		t.Fatalf("무서명 keyring 이 출처를 대지 않는다: %v", err)
	}
	if err := f.Check(); err != nil {
		t.Fatalf("무서명 dev 경로가 멈췄다: %v", err)
	}
}
