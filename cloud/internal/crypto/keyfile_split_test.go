// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package crypto

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// B6-4 행위 유닛 — 규칙: Load 는 부재 시 **거부하고 아무것도 만들지 않는다**
// (F-KEY-23 / S18). 구성물(심볼)의 소멸이 아니라 실행이 근거다(H-B5). 이 유닛이
// 붉어지는 변형은 "Load 안에 자동 생성을 되살린다"이다.
func TestKeyfileLoadAbsentRefuses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "issuer_ed25519.json")

	_, err := LoadEd25519KeypairJSON(path, "dev-key-1")
	if err == nil {
		t.Fatal("Load on absent keyfile must return an error, not create one")
	}
	if !errors.Is(err, ErrKeyFileNotFound) {
		t.Fatalf("absent keyfile must be ErrKeyFileNotFound, got: %v", err)
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Fatal("Load must NOT create the keyfile (auto-generation removed)")
	}
	// 두 번째 호출도 여전히 만들지 않는다 — 자동 생성 계수 0.
	if _, err := LoadEd25519KeypairJSON(path, "dev-key-1"); !errors.Is(err, ErrKeyFileNotFound) {
		t.Fatalf("second Load must still refuse, got: %v", err)
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Fatal("keyfile must remain absent after repeated Load")
	}
}

// B6-4/B6-5 행위 유닛 — 규칙: Generate 는 명시적으로 로드 가능한 키파일을
// 0600 으로 만든다. B6-5(fsync 후 rename)의 코드 경로는 keyfile.go 의 Sync()
// 호출로 서고, 러너의 구조 검사가 그 부재를 따로 잡는다(fsync 변형).
func TestKeyfileGenerateDurable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "issuer_ed25519.json")

	gen, err := GenerateEd25519KeypairJSON(path, "dev-key-1")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("keyfile not created: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("keyfile perm: got %o want 0600", info.Mode().Perm())
	}
	// tmp 잔해가 남지 않는다 — rename 이 완료됐다.
	if _, err := os.Stat(path + ".tmp"); err == nil {
		t.Fatal("temp file must not survive a completed Generate")
	}
	// 양성 대조: 방금 만든 파일을 Load 하면 같은 키가 나온다.
	loaded, err := LoadEd25519KeypairJSON(path, "dev-key-1")
	if err != nil {
		t.Fatalf("Load after Generate: %v", err)
	}
	if !gen.Public.Equal(loaded.Public) || string(gen.Private) != string(loaded.Private) {
		t.Fatal("Load after Generate returned a different key")
	}
	if loaded.KeyID != "dev-key-1" {
		t.Fatalf("key id: got %q want dev-key-1", loaded.KeyID)
	}
}
