// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package signer

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	devcrypto "github.com/glowfly/pail/services/internal/crypto"
)

// Local 어댑터: 서명이 공개키로 검증되고 KeyID/Public이 키쌍과 일치.
func TestLocalSignVerify(t *testing.T) {
	kp, err := devcrypto.NewDevKeypair("test-key-1")
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	s := NewLocal(kp)
	msg := []byte("pail-d5-signer")
	sig, err := s.Sign(msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("sig size=%d", len(sig))
	}
	if !ed25519.Verify(s.Public(), msg, sig) {
		t.Fatal("signature must verify with Public()")
	}
	if s.KeyID() != "test-key-1" {
		t.Fatalf("key id=%q", s.KeyID())
	}
	// 사전-D5 직접 서명과 바이트 동일 (기능 등가).
	if want := ed25519.Sign(kp.Private, msg); string(want) != string(sig) {
		t.Fatal("Local.Sign must equal direct ed25519.Sign")
	}
}

// FromEnv 기본값(local): 명시적으로 생성된 키파일을 로드 후 서명 가능.
func TestFromEnvLocalDefault(t *testing.T) {
	t.Setenv("PAIL_SIGNER", "")
	path := filepath.Join(t.TempDir(), "issuer_ed25519.json")
	// F-KEY-23: FromEnv 는 더 이상 키를 만들지 않는다 — 프로비저닝이 먼저 생성한다.
	if _, err := devcrypto.GenerateEd25519KeypairJSON(path, "dev-key-1"); err != nil {
		t.Fatalf("provision: %v", err)
	}
	s, err := FromEnv(path, "dev-key-1")
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if s.KeyID() != "dev-key-1" {
		t.Fatalf("key id=%q", s.KeyID())
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("keyfile missing: %v", err)
	}
	sig, err := s.Sign([]byte("m"))
	if err != nil || !ed25519.Verify(s.Public(), []byte("m"), sig) {
		t.Fatalf("sign/verify: err=%v", err)
	}
}

// F-KEY-23 배선: 프로덕션 서명자(FromEnv local)는 키파일이 없으면 **거부**하고
// 아무것도 만들지 않는다. 이 유닛이 RB-10 변형 증명의 배선 죽음(어느 프로덕션
// 호출자를 Generate 로 되돌리면 여기서 붉어진다)을 잰다.
func TestFromEnvLocalRefusesAbsentKeyfile(t *testing.T) {
	t.Setenv("PAIL_SIGNER", "")
	path := filepath.Join(t.TempDir(), "absent_issuer_ed25519.json")
	_, err := FromEnv(path, "dev-key-1")
	if err == nil {
		t.Fatal("FromEnv(local) must refuse an absent keyfile (no auto-create)")
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Fatal("FromEnv(local) must NOT create the keyfile on absence")
	}
}

// FromEnv kms: 트랜스포트 미구현 → 기동 거부 (fail-closed).
func TestFromEnvKMSRefuses(t *testing.T) {
	t.Setenv("PAIL_SIGNER", "kms")
	if _, err := FromEnv(filepath.Join(t.TempDir(), "k.json"), "dev-key-1"); err == nil {
		t.Fatal("kms mode must refuse to start")
	}
}

// FromEnv 미지 모드: 에러.
func TestFromEnvUnknownMode(t *testing.T) {
	t.Setenv("PAIL_SIGNER", "tpm")
	if _, err := FromEnv(filepath.Join(t.TempDir(), "k.json"), "dev-key-1"); err == nil {
		t.Fatal("unknown mode must error")
	}
}

// KMS 골격: Sign은 명시적 에러 (콜러 fail-closed 경로 검증용).
func TestKMSSkeletonSignErrors(t *testing.T) {
	k := &KMS{Endpoint: "https://kms.invalid", KeyName: "issuer-1"}
	if _, err := k.Sign([]byte("m")); err == nil {
		t.Fatal("skeleton Sign must error")
	}
}
