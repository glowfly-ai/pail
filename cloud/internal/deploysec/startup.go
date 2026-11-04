// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package deploysec

import (
	"errors"
	"fmt"
	"os"
)

// §3.7  기동 거부 규칙 S15~S20. `implementation contract` 의 S0~S10 에 이어
// 붙이되, 한 가지가 다르다: **프로파일이 면제하지 않는다.**
//
// S0~S10 은 "보호가 꺼져 있다"를 재고, `PAIL_PROFILE=dev` 는 "이 보호 없이
// 돌리겠다"는 운영자의 선언이므로 거부가 배너로 내려간다. S15~S20 이 재는 것은
// 그것이 아니라 **설정이 형식으로 깨졌다**이다 — role 없는 keyring 항목은 끄고
// 켤 수 있는 보호가 아니라 판독 불가능한 입력이다.
//
// dev 에서만 통과시키면 결과가 뒤집힌다: keyring 과 키 파일이 실제로 만들어지는
// 곳이 dev 이므로, 깨진 형식은 dev 에서 조용히 생겨 프로덕션으로 그대로 간다.
// 그때 프로덕션의 거부는 "만든 사람"이 아니라 "배포한 사람" 앞에서 터진다.
//
// 규약: 거부는 `exit 78`(`EX_CONFIG`, `implementation contract` `S11`)이고, stderr 한 줄에
// **규칙 id 와 사유**가 함께 나온다. 둘 중 하나만 있으면 운영자는 무엇을 고쳐야
// 할지(id 없이) 또는 왜 고쳐야 할지(사유 없이)를 모른다.

// ConfigError 는 §3.7 규칙 하나의 위반이다. id 를 문자열에 녹이지 않고 필드로
// 두는 이유는 하나다 — 하네스가 사유 문구의 표현이 바뀌어도 규칙의 생사를
// 계속 관측할 수 있어야 하기 때문이다.
type ConfigError struct {
	ID  string
	Msg string
}

func (e *ConfigError) Error() string { return e.ID + ": " + e.Msg }

// Cfg 는 §3.7 위반 하나를 만든다.
func Cfg(id, format string, a ...interface{}) error {
	return &ConfigError{ID: id, Msg: fmt.Sprintf(format, a...)}
}

// RuleID 는 err 사슬에서 §3.7 규칙 id 를 꺼낸다. 규칙이 아닌 오류면 "".
func RuleID(err error) string {
	var ce *ConfigError
	if errors.As(err, &ce) {
		return ce.ID
	}
	return ""
}

// RefuseConfig 는 사유를 stderr 에 적고 78 로 죽는다.
//
// `log.Fatalf` 를 쓰지 않는다. 그쪽은 1 로 죽고, 1 은 "설정이 틀렸다"와 "코드가
// 터졌다"를 같은 값으로 만든다. 오케스트레이터가 둘을 구분하지 못하면 설정
// 오류에도 재시작 루프를 돈다.
func RefuseConfig(component string, err error) {
	RefuseConfigAll(component, []error{err})
}

// RefuseConfigAll 은 위반이 여러 건일 때 **전부 적고** 한 번 죽는다. 첫 건에서
// 죽으면 운영자는 세 개를 고치려고 세 번 재시작한다 — 거부가 무엇을 고쳐야
// 하는지 말하지 않는 것과 같은 결함의 분할판이다.
//
// errs 가 비면 아무것도 하지 않는다. 만족한 경우에 죽지 않는 것을 여기서 한 번
// 정해두면 호출자마다 조건을 다시 적지 않아도 된다.
func RefuseConfigAll(component string, errs []error) {
	if len(errs) == 0 {
		return
	}
	for _, err := range errs {
		fmt.Fprintf(os.Stderr, "PAIL STARTUP REFUSED: %v [component=%s]\n", err, component)
	}
	os.Exit(ExitConfig)
}

// RequireIssuerKeyID 는 `S17` 이다. 4지점(§1.5)이 각자 자기 기본값을 들고 있던
// 것을 하나로 모은다 — 지점이 넷이어도 규칙은 하나이고, 두 벌이면 한 벌만
// 고쳐진다(`B1-6` 과 같은 논거).
//
// src 는 값이 어디서 왔어야 하는지를 적는다(환경변수 이름·플래그 이름). 사유
// 문자열이 "설정하라"까지 말하지 않으면 운영자는 무엇을 설정할지 모른다.
func RequireIssuerKeyID(v, src string) error {
	if v == "" {
		return Cfg("S17", "issuer: key id not configured (set %s)", src)
	}
	return nil
}

// ProfileIsDev reports PAIL_PROFILE=dev — the one profile where a missing
// requester registry (S22) is a banner instead of a refusal. Read from the
// environment at call time, like the other profile-sensitive checks here, so
// a test can set it without rebuilding.
func ProfileIsDev() bool { return os.Getenv("PAIL_PROFILE") == "dev" }
