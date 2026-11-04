// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

// TestNewDevKeypair: 키 생성이 성공하고 KeyID가 올바르게 설정되는지 확인.
func TestNewDevKeypair(t *testing.T) {
	kp, err := NewDevKeypair("test-key-1")
	if err != nil {
		t.Fatalf("NewDevKeypair failed: %v", err)
	}
	if kp.KeyID != "test-key-1" {
		t.Errorf("KeyID mismatch: got %q want %q", kp.KeyID, "test-key-1")
	}
	if len(kp.Public) == 0 {
		t.Error("Public key is empty")
	}
	if len(kp.Private) == 0 {
		t.Error("Private key is empty")
	}
}

// TestSignVerify: 서명한 메시지를 올바른 pubkey로 검증 성공, 다른 pubkey로 검증 실패.
func TestSignVerify(t *testing.T) {
	kp, err := NewDevKeypair("test-key-sign")
	if err != nil {
		t.Fatalf("NewDevKeypair: %v", err)
	}

	msg := []byte("action_token_bytes_placeholder")
	sig := Sign(kp.Private, msg)

	if !Verify(kp.Public, msg, sig) {
		t.Error("Verify returned false for valid signature")
	}

	// 메시지 1바이트 변조 → 검증 실패해야 함
	tampered := make([]byte, len(msg))
	copy(tampered, msg)
	tampered[0] ^= 0xFF
	if Verify(kp.Public, tampered, sig) {
		t.Error("Verify returned true for tampered message (expected false)")
	}

	// 서명 1바이트 변조 → 검증 실패해야 함
	tamperedSig := make([]byte, len(sig))
	copy(tamperedSig, sig)
	tamperedSig[0] ^= 0xFF
	if Verify(kp.Public, msg, tamperedSig) {
		t.Error("Verify returned true for tampered signature (expected false)")
	}
}

// TestPublicKeyBase64: base64 인코딩이 비어있지 않고 디코딩 가능한지 확인.
func TestPublicKeyBase64(t *testing.T) {
	kp, err := NewDevKeypair("test-key-b64")
	if err != nil {
		t.Fatalf("NewDevKeypair: %v", err)
	}
	b64 := PublicKeyBase64(kp.Public)
	if b64 == "" {
		t.Error("PublicKeyBase64 returned empty string")
	}
}

// TestGenerateEd25519KeypairJSON_Create: 명시적 생성만 파일을 만든다.
func TestGenerateEd25519KeypairJSON_Create(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys", "issuer.json")

	kp, err := GenerateEd25519KeypairJSON(path, "dev-key-1")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if kp.KeyID != "dev-key-1" {
		t.Errorf("KeyID: got %q want %q", kp.KeyID, "dev-key-1")
	}
	// 파일이 생성되어야 함
	if _, err := os.Stat(path); err != nil {
		t.Errorf("keyfile not created: %v", err)
	}
	// 권한 확인 (0600)
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Errorf("keyfile perm: got %o want %o", info.Mode().Perm(), 0600)
	}
}

// TestLoadEd25519KeypairJSON_Load: Generate 로 만든 파일을 Load 하면 같은 키.
func TestLoadEd25519KeypairJSON_Load(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "issuer.json")

	kp1, err := GenerateEd25519KeypairJSON(path, "dev-key-1")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	kp2, err := LoadEd25519KeypairJSON(path, "dev-key-1")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if string(kp1.Public) != string(kp2.Public) {
		t.Error("Loaded public key differs from created public key")
	}
	if string(kp1.Private) != string(kp2.Private) {
		t.Error("Loaded private key differs from created private key")
	}
}

// TestLoadEd25519KeypairJSON_KeyIDMismatch: key_id 불일치 시 에러.
func TestLoadEd25519KeypairJSON_KeyIDMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "issuer.json")

	if _, err := GenerateEd25519KeypairJSON(path, "dev-key-1"); err != nil {
		t.Fatalf("generate: %v", err)
	}
	_, err := LoadEd25519KeypairJSON(path, "dev-key-2")
	if err == nil {
		t.Error("Expected error on key_id mismatch, got nil")
	}
}
