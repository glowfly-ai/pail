// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// fakeTransit mocks the two Transit endpoints with a real ed25519 key so
// returned signatures actually verify.
type fakeTransit struct {
	pub        ed25519.PublicKey
	priv       ed25519.PrivateKey
	keyType    string
	latestVer  int
	signVer    int // version stamped on signatures (rotation drift when != latestVer)
	wantToken  string
	fail5xx    int32 // remaining requests to answer 500 (for retry test)
	deny403    bool
	signCalls  int32
	totalCalls int32
}

func newFakeTransit(t *testing.T) *fakeTransit {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	return &fakeTransit{pub: pub, priv: priv, keyType: "ed25519", latestVer: 1, signVer: 1, wantToken: "test-token"}
}

func (f *fakeTransit) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&f.totalCalls, 1)
		if atomic.LoadInt32(&f.fail5xx) > 0 {
			atomic.AddInt32(&f.fail5xx, -1)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if r.Header.Get("X-Vault-Token") != f.wantToken || f.deny403 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/transit/keys/issuer-key":
			resp := map[string]any{"data": map[string]any{
				"type":           f.keyType,
				"latest_version": f.latestVer,
				"keys": map[string]any{
					fmt.Sprint(f.latestVer): map[string]any{"public_key": base64.StdEncoding.EncodeToString(f.pub)},
				},
			}}
			json.NewEncoder(w).Encode(resp)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/transit/sign/issuer-key":
			atomic.AddInt32(&f.signCalls, 1)
			var req struct {
				Input string `json:"input"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			msg, err := base64.StdEncoding.DecodeString(req.Input)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			sig := ed25519.Sign(f.priv, msg)
			resp := map[string]any{"data": map[string]any{
				"signature": fmt.Sprintf("vault:v%d:%s", f.signVer, base64.StdEncoding.EncodeToString(sig)),
			}}
			json.NewEncoder(w).Encode(resp)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func vaultEnv(t *testing.T, addr string) {
	t.Helper()
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("test-token\n"), 0600); err != nil {
		t.Fatalf("token file: %v", err)
	}
	t.Setenv("PAIL_SIGNER", "vault")
	t.Setenv("PAIL_VAULT_ADDR", addr)
	t.Setenv("PAIL_VAULT_KEY_NAME", "issuer-key")
	t.Setenv("PAIL_VAULT_TOKEN_FILE", tokenFile)
	t.Setenv("PAIL_VAULT_TIMEOUT_MS", "2000")
}

// 초기화: 공개키 조회·캐시 성립 + 서명이 그 공개키로 검증됨 (e2e 계약).
func TestVaultInitAndSignVerifies(t *testing.T) {
	f := newFakeTransit(t)
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	vaultEnv(t, srv.URL)

	s, err := FromEnv("", "prod-issuer-1")
	if err != nil {
		t.Fatalf("FromEnv vault: %v", err)
	}
	if s.KeyID() != "prod-issuer-1" {
		t.Fatalf("key id=%q", s.KeyID())
	}
	if string(s.Public()) != string(f.pub) {
		t.Fatal("Public() must equal transit public key")
	}
	msg := []byte("pail-km1-vault")
	sig, err := s.Sign(msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !ed25519.Verify(s.Public(), msg, sig) {
		t.Fatal("signature must verify under cached Public()")
	}
}

// 금고 다운(연결 불가): 초기화 자체가 실패 = 프로세스 시작 거부.
func TestVaultDownRefusesInit(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	addr := srv.URL
	srv.Close() // 즉시 닫아 연결 거부 유도
	vaultEnv(t, addr)
	t.Setenv("PAIL_VAULT_TIMEOUT_MS", "300")
	if _, err := FromEnv("", "prod-issuer-1"); err == nil {
		t.Fatal("vault down must refuse process start")
	}
}

// 서명 중 금고 다운: Sign 에러 (발급 거부), 폴백 없음.
func TestVaultDownDuringSignErrors(t *testing.T) {
	f := newFakeTransit(t)
	srv := httptest.NewServer(f.handler(t))
	vaultEnv(t, srv.URL)
	t.Setenv("PAIL_VAULT_TIMEOUT_MS", "300")
	s, err := FromEnv("", "prod-issuer-1")
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	srv.Close()
	if _, err := s.Sign([]byte("m")); err == nil {
		t.Fatal("sign while vault down must error")
	}
}

// 재시도 1회: 첫 요청 500 → 재시도 성공. 500 두 번이면 실패(재시도 1회 한정).
func TestVaultSingleRetry(t *testing.T) {
	f := newFakeTransit(t)
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	vaultEnv(t, srv.URL)
	s, err := FromEnv("", "prod-issuer-1")
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	atomic.StoreInt32(&f.fail5xx, 1)
	if _, err := s.Sign([]byte("m")); err != nil {
		t.Fatalf("one 500 then success must pass (single retry): %v", err)
	}
	atomic.StoreInt32(&f.fail5xx, 2)
	if _, err := s.Sign([]byte("m")); err == nil {
		t.Fatal("two 500s must fail — retry is limited to one")
	}
}

// 키 버전 고정: transit 키가 회전되어 vault:v2 서명이 오면 거부.
func TestVaultVersionPinRefusesRotatedKey(t *testing.T) {
	f := newFakeTransit(t)
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	vaultEnv(t, srv.URL)
	s, err := FromEnv("", "prod-issuer-1")
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	f.signVer = 2 // 회전 흉내: keyring은 여전히 v1 공개키
	if _, err := s.Sign([]byte("m")); err == nil {
		t.Fatal("rotated transit key (v2 sig vs pinned v1) must refuse to sign")
	}
}

// 403 (토큰 만료/정책): 발급 거부, 자동 재인증 없음.
func TestVault403Refuses(t *testing.T) {
	f := newFakeTransit(t)
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	vaultEnv(t, srv.URL)
	s, err := FromEnv("", "prod-issuer-1")
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	f.deny403 = true
	if _, err := s.Sign([]byte("m")); err == nil {
		t.Fatal("403 must refuse issuance")
	}
}

// ed25519가 아닌 transit 키: 초기화 거부.
func TestVaultWrongKeyTypeRefuses(t *testing.T) {
	f := newFakeTransit(t)
	f.keyType = "ecdsa-p256"
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	vaultEnv(t, srv.URL)
	if _, err := FromEnv("", "prod-issuer-1"); err == nil {
		t.Fatal("non-ed25519 transit key must refuse init")
	}
}

// env 누락: 시작 거부.
func TestVaultMissingEnvRefuses(t *testing.T) {
	t.Setenv("PAIL_SIGNER", "vault")
	t.Setenv("PAIL_VAULT_ADDR", "")
	t.Setenv("PAIL_VAULT_KEY_NAME", "")
	t.Setenv("PAIL_VAULT_TOKEN_FILE", "")
	if _, err := FromEnv("", "prod-issuer-1"); err == nil {
		t.Fatal("missing vault env must refuse start")
	}
}
