// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	devcrypto "github.com/glowfly/pail/services/internal/crypto"
)

type keyringFile struct {
	Keys []keyringEntry `json:"keys"`
}

type keyringEntry struct {
	KeyID        string `json:"key_id"`
	PublicKeyB64 string `json:"ed25519_public_key_base64"`
	Role         string `json:"role,omitempty"`
}

func writeKeyring(t *testing.T, entries ...keyringEntry) string {
	t.Helper()
	b, err := json.Marshal(keyringFile{Keys: entries})
	if err != nil {
		t.Fatalf("marshal keyring: %v", err)
	}
	path := filepath.Join(t.TempDir(), "keyring.json")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatalf("write keyring: %v", err)
	}
	return path
}

// selfCheck runs the self-check the way production does after `B6-6`: the
// keyring comes from crypto.LoadTrustedKeyringFromEnv, not from a reader
// private to this package. unsigned-dev is declared out loud — before `B6-6`
// this opt-in did not exist here, and the unsigned file was read either way.
func selfCheck(t *testing.T, s Signer, path string) error {
	t.Helper()
	t.Setenv("PAIL_KEYRING_MODE", "unsigned-dev")
	kr, mode, err := devcrypto.LoadTrustedKeyringFromEnv(path)
	if err != nil {
		return err
	}
	return VerifyAgainstKeys(s, kr, mode)
}

func genPub(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	return pub
}

// KM1-1: KMS(가짜 트랜스포트) Public 캐시가 keyring과 일치 → self-check 통과.
func TestSelfCheckMatchPasses(t *testing.T) {
	pub := genPub(t)
	s := &KMS{Endpoint: "https://vault.invalid", KeyName: "issuer-1", pub: pub}
	if got := s.Public(); string(got) != string(pub) {
		t.Fatal("KMS.Public must return the cached key")
	}
	path := writeKeyring(t, keyringEntry{
		KeyID: "issuer-1", PublicKeyB64: base64.StdEncoding.EncodeToString(pub), Role: "issuer",
	})
	if err := selfCheck(t, s, path); err != nil {
		t.Fatalf("matching key must pass self-check: %v", err)
	}
}

// KM1-1: keyring이 같은 key_id로 다른 공개키를 신뢰 → 시작 거부 분기.
func TestSelfCheckPubkeyMismatchRefuses(t *testing.T) {
	s := &KMS{Endpoint: "https://vault.invalid", KeyName: "issuer-1", pub: genPub(t)}
	path := writeKeyring(t, keyringEntry{
		KeyID: "issuer-1", PublicKeyB64: base64.StdEncoding.EncodeToString(genPub(t)), Role: "issuer",
	})
	if err := selfCheck(t, s, path); err == nil {
		t.Fatal("keyring/signer pubkey mismatch must refuse start")
	}
}

// KM1-1: keyring에 해당 key_id 부재 → 시작 거부.
func TestSelfCheckMissingKeyIDRefuses(t *testing.T) {
	s := &KMS{Endpoint: "https://vault.invalid", KeyName: "issuer-1", pub: genPub(t)}
	path := writeKeyring(t, keyringEntry{
		KeyID: "other-key", PublicKeyB64: base64.StdEncoding.EncodeToString(genPub(t)), Role: "issuer",
	})
	if err := selfCheck(t, s, path); err == nil {
		t.Fatal("missing key_id in keyring must refuse start")
	}
}

// KM1-1: role=operator만 있는 항목은 issuer 대조에 쓰이지 않음.
func TestSelfCheckOperatorRoleNotTrusted(t *testing.T) {
	pub := genPub(t)
	s := &KMS{Endpoint: "https://vault.invalid", KeyName: "issuer-1", pub: pub}
	path := writeKeyring(t, keyringEntry{
		KeyID: "issuer-1", PublicKeyB64: base64.StdEncoding.EncodeToString(pub), Role: "operator",
	})
	if err := selfCheck(t, s, path); err == nil {
		t.Fatal("operator-role entry must not satisfy issuer self-check")
	}
}

// KM1-1: keyring 파일 자체가 없으면 대조 불가 → 시작 거부 (fail-closed).
func TestSelfCheckUnreadableKeyringRefuses(t *testing.T) {
	s := &KMS{Endpoint: "https://vault.invalid", KeyName: "issuer-1", pub: genPub(t)}
	if err := selfCheck(t, s, filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Fatal("unreadable keyring must refuse start")
	}
}

// `B6-6`: self-check 의 keyring 은 모드 선택자를 지난다. 기본(번들) 모드에서
// 무서명 파일이 **읽히지 않는 것**이 그 증거다 — 지워진 경로는 완벽하게 유효한
// 무서명 keyring 을 그냥 읽었고, 그때 모드 설정은 아무 힘도 없었다.
func TestSelfCheckRefusesUnsignedKeyringInBundleMode(t *testing.T) {
	pub := genPub(t)
	path := writeKeyring(t, keyringEntry{
		KeyID: "issuer-1", PublicKeyB64: base64.StdEncoding.EncodeToString(pub), Role: "issuer",
	})
	t.Setenv("PAIL_KEYRING_MODE", "")
	t.Setenv("PAIL_ROOT_PUBKEY_FILE", "")
	kr, mode, err := devcrypto.LoadTrustedKeyringFromEnv(path)
	if err == nil {
		t.Fatalf("bundle mode must not read the unsigned keyring (mode=%s keys=%d)", mode, len(kr.Keys))
	}
}

// KM1-1: Local signer도 동일 self-check 경로로 통과.
func TestSelfCheckLocalSigner(t *testing.T) {
	t.Setenv("PAIL_SIGNER", "")
	kf := filepath.Join(t.TempDir(), "issuer_ed25519.json")
	// F-KEY-23: 프로비저닝이 키를 먼저 만든다; FromEnv 는 로드만 한다.
	if _, err := devcrypto.GenerateEd25519KeypairJSON(kf, "dev-key-1"); err != nil {
		t.Fatalf("provision: %v", err)
	}
	s, err := FromEnv(kf, "dev-key-1")
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	path := writeKeyring(t, keyringEntry{
		KeyID: "dev-key-1", PublicKeyB64: base64.StdEncoding.EncodeToString(s.Public()), Role: "issuer",
	})
	if err := selfCheck(t, s, path); err != nil {
		t.Fatalf("local signer matching keyring must pass: %v", err)
	}
}
