// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// `B9-3` 행위 유닛 — 폐기 도달 상한의 **둘째 항**(폴링 주기)과 그 항을 쓸모 있게
// 만드는 적용 수단이 설정으로 존재하고, 미설정이 통과가 아닌지.
//
// 앞항(번들 유효 창)은 `internal/crypto` 쪽 유닛이 잰다. 둘을 한 자리에서 재면
// 한 항이 열려도 다른 항이 초록을 만든다(`H-B9`).
//
// 판정은 사유 문구가 아니라 `deploysec.RuleID` 로 한다.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/glowfly/pail/services/internal/deploysec"
)

// reachEnv 는 풀러가 켜지는 최소 환경을 놓는다. 각 시험은 여기서 **한 항목만**
// 비워 자기 규칙을 잰다.
func reachEnv(t *testing.T) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rootPub := filepath.Join(dir, "root_pub.b64")
	if err := os.WriteFile(rootPub, []byte(base64.StdEncoding.EncodeToString(pub)), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PAIL_ROOT_PUBKEY_FILE", rootPub)
	t.Setenv("PAIL_KEYRING_BUNDLE", filepath.Join(dir, "keyring_bundle.json"))
	t.Setenv(EnvKeyringPollSec, "300")
	t.Setenv(EnvGateRestartCmd, "true")
}

func wantPullerRule(t *testing.T, id string) {
	t.Helper()
	k, err := newKeyringPullerFromEnv(nil, "robot-1")
	if err == nil {
		t.Fatalf("거부되어야 한다 (%s) — puller=%v 를 돌려줬다", id, k != nil)
	}
	if got := deploysec.RuleID(err); got != id {
		t.Fatalf("rule=%q, want %q (err=%v)", got, id, err)
	}
}

// TestPullerRefusesUnsetPollInterval — `S20c`. 6h 기본값을 지운 자리다. 기본값이
// 있으면 "6시간으로 정했다"와 "폴링을 생각해 본 적 없다"가 같은 배포가 된다.
func TestPullerRefusesUnsetPollInterval(t *testing.T) {
	reachEnv(t)
	t.Setenv(EnvKeyringPollSec, "")
	wantPullerRule(t, "S20c")
}

// TestPullerRefusesBadPollInterval — 초 단위 정수가 아닌 것. 파싱 실패를
// 기본값으로 접으면 오타 하나가 상한을 조용히 바꾼다.
func TestPullerRefusesBadPollInterval(t *testing.T) {
	for _, raw := range []string{"-1", "6h", "abc", "3.5"} {
		reachEnv(t)
		t.Setenv(EnvKeyringPollSec, raw)
		wantPullerRule(t, "S20c")
	}
}

// TestPullerRefusesMissingRestartCmd — `S20e`/`B-R3`. 풀러는 켜졌는데 새 번들을
// 적용할 수단이 없다. 예전에는 이것이 로그 한 줄이었고, 그 줄은 번들이 놓인
// 뒤에만 찍혀서 아무도 안 읽으면 폐기가 영원히 도달하지 않았다.
func TestPullerRefusesMissingRestartCmd(t *testing.T) {
	reachEnv(t)
	t.Setenv(EnvGateRestartCmd, "")
	wantPullerRule(t, "S20e")
	// 공백만 있는 것도 같다 — 있는 것처럼 보이지만 실행할 것이 없다.
	t.Setenv(EnvGateRestartCmd, "   ")
	wantPullerRule(t, "S20e")
}

// TestPullerEnabledWithFullConfig — 양성 대조. 셋이 다 있으면 풀러가 서야 한다.
// 없으면 위 셋은 "풀러가 절대 안 켜진다"로도 초록이고, 그때 이것은 게이트가
// 아니라 벽이다.
func TestPullerEnabledWithFullConfig(t *testing.T) {
	reachEnv(t)
	k, err := newKeyringPullerFromEnv(nil, "robot-1")
	if err != nil {
		t.Fatalf("완전한 설정이 거부됐다: %v", err)
	}
	if k == nil {
		t.Fatal("풀러가 nil 이다 — 설정이 다 있는데 폴링이 꺼졌다")
	}
	if k.interval != 300*time.Second {
		t.Fatalf("interval=%s, want 5m", k.interval)
	}
	if k.restartCmd != "true" {
		t.Fatalf("restartCmd=%q — 적용 수단이 전달되지 않았다", k.restartCmd)
	}
}

// TestPullerExplicitZeroDisables — `0` 은 **의도적 비활성화**다. 미설정과
// 구별되어야 한다 — 구별되지 않으면 폴링을 끄는 유일한 방법이 기동 거부가 된다.
// 이때는 적용 수단이 없어도 거부하지 않는다(적용할 것이 안 오므로).
func TestPullerExplicitZeroDisables(t *testing.T) {
	reachEnv(t)
	t.Setenv(EnvKeyringPollSec, "0")
	t.Setenv(EnvGateRestartCmd, "")
	k, err := newKeyringPullerFromEnv(nil, "robot-1")
	if err != nil {
		t.Fatalf("명시적 0 이 거부됐다: %v", err)
	}
	if k != nil {
		t.Fatal("poll=0 인데 풀러가 섰다")
	}
}

// TestPullerNoRootKeyStaysOff — 루트 공개키가 없으면 풀은 애초에 성립하지
// 않는다. 이 자리에서 폴링 주기를 요구하면 풀을 안 쓰는 배포가 쓰지도 않을 값을
// 고르라는 요구를 받고, 그렇게 고른 값은 아무 상한도 뜻하지 않는다.
func TestPullerNoRootKeyStaysOff(t *testing.T) {
	reachEnv(t)
	t.Setenv("PAIL_ROOT_PUBKEY_FILE", "")
	t.Setenv(EnvKeyringPollSec, "")
	t.Setenv(EnvGateRestartCmd, "")
	k, err := newKeyringPullerFromEnv(nil, "robot-1")
	if err != nil {
		t.Fatalf("루트 키 없는 배포가 거부됐다: %v", err)
	}
	if k != nil {
		t.Fatal("루트 공개키가 없는데 풀러가 섰다 — 검증 못 할 바이트를 게이트에 놓게 된다")
	}
}
