// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/glowfly/pail/services/internal/deploysec"
)

// `S15`  의 순수 규칙 몫. **기동 거부**의 증거는 여기가 아니라
// `tests/tools/red_ossb_b.py` 의 `RB-7` 이 재는 바이너리 rc=78 이다 — 이 파일은
// 규칙이 **세 입구 전부**에서 살아 있음을 잰다.
//
// 입구를 셋으로 나눠 재는 이유: 한 곳만 재면 나머지 두 경로로 들어온 role 없는
// 항목이 검사를 지나지 않는다. 특히 번들 경로는 항목이 **루트 서명을 받은 채로**
// 들어오므로, 거기서 접히면 fail-open 이 서명의 권위를 등에 업는다.

const wantS15Msg = `has no role`

func assertS15(t *testing.T, where string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: role 없는 항목이 통과했다 (S15 기대)", where)
	}
	if id := deploysec.RuleID(err); id != "S15" {
		t.Fatalf("%s: rule id %q (S15 기대) — err=%v", where, id, err)
	}
	if !strings.Contains(err.Error(), wantS15Msg) {
		t.Fatalf("%s: 사유 문자열에 %q 가 없다 — err=%v", where, wantS15Msg, err)
	}
}

func rolelessKeyring(t *testing.T) *Keyring {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &Keyring{Keys: []KeyringEntry{
		{KeyID: "no-role-1", PublicKeyB64: base64.StdEncoding.EncodeToString(pub)},
	}}
}

// 입구 1 — 파일 적재기.
func TestS15LoadKeyringRefusesMissingRole(t *testing.T) {
	kr := rolelessKeyring(t)
	b, err := json.Marshal(kr)
	if err != nil {
		t.Fatal(err)
	}
	// `omitempty` 가 남아 있으면 이 marshal 이 role 필드를 아예 빼고, 그래도
	// 읽는 쪽은 죽는다 — 즉 **쓰는 도구는 성공을 보고하고 실패는 배포한 사람
	// 앞에서 터진다.** 그래서 태그에서 지웠고, 여기서 필드의 존재를 확인한다.
	if !strings.Contains(string(b), `"role"`) {
		t.Fatalf("marshal 이 role 필드를 생략했다 (omitempty 회귀): %s", b)
	}
	path := filepath.Join(t.TempDir(), "keyring.json")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	_, err = LoadKeyring(path)
	assertS15(t, "LoadKeyring", err)
}

// 입구 2 — 손으로 조립한 구조체(적재기를 지나지 않는 경로).
func TestS15PublicKeysByRoleRefusesMissingRole(t *testing.T) {
	kr := rolelessKeyring(t)
	// 묻는 역할이 무엇이든 거부한다. `issuer` 만 물어보는 프로세스에서 role 없는
	// 항목이 살아남으면, 그것이 다음 사람이 `burst` 를 물을 때 자격이 된다.
	for _, role := range []string{"issuer", "operator", "burst"} {
		_, err := kr.PublicKeysByRole(role)
		assertS15(t, "PublicKeysByRole("+role+")", err)
	}
}

// 입구 3 — 루트 서명을 받은 번들.
func TestS15BundleRefusesMissingRole(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kr := rolelessKeyring(t)
	payload, err := json.Marshal(BundlePayload{
		BundleVersion: 1,
		IssuedAtUnix:  time.Now().Unix(),
		ExpiresAtUnix: time.Now().Add(24 * time.Hour).Unix(),
		Keys:          kr.Keys,
	})
	if err != nil {
		t.Fatal(err)
	}
	// 서명 시점에 죽는다 — 잘못된 번들이 **만들어지지 않는다**. 여기서 통과시키면
	// 거부는 배포 현장으로 미뤄지고, 그때는 서명이 이미 붙어 있다.
	_, err = BuildBundle(rootPriv, "root-1", payload)
	assertS15(t, "BuildBundle", err)

	// 그래도 서명된 번들이 손에 들어온 경우(다른 도구가 만든 것)를 위해 검증
	// 경로도 잰다. 서명은 유효한데 내용이 규칙을 어기는 상태를 만든다.
	env := BundleEnvelope{
		SchemaVersion: 1,
		RootKeyID:     "root-1",
		PayloadB64:    base64.StdEncoding.EncodeToString(payload),
		RootSigB64:    base64.StdEncoding.EncodeToString(ed25519.Sign(rootPriv, payload)),
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = VerifyBundle(raw, rootPub)
	assertS15(t, "VerifyBundle", err)
}

// 규칙을 만족하면 위반이 0 이어야 한다. 이것이 없으면 게이트가 아니라 벽이다.
func TestS15SatisfiedPasses(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kr := &Keyring{Keys: []KeyringEntry{
		{KeyID: "iss-1", PublicKeyB64: base64.StdEncoding.EncodeToString(pub), Role: "issuer"},
		{KeyID: "op-1", PublicKeyB64: base64.StdEncoding.EncodeToString(pub), Role: "operator"},
	}}
	if err := kr.ValidateRoles(); err != nil {
		t.Fatalf("role 이 전부 명시된 keyring 이 거부됐다: %v", err)
	}
	got, err := kr.PublicKeysByRole("issuer")
	if err != nil {
		t.Fatalf("PublicKeysByRole: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("issuer 키 %d개 (1 기대) — 역할 필터가 깨졌다", len(got))
	}
	if _, ok := got["iss-1"]; !ok {
		t.Fatalf("issuer 키가 iss-1 이 아니다: %v", got)
	}
}
