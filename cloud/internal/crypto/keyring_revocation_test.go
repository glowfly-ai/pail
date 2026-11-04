// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/glowfly/pail/services/internal/deploysec"
)

// PAIL-CASE: RevokedKeyIsAValue (`C-B16`, implementation contract)
//
// 이 파일이 재는 것은 폐기된 키가 **거부된다** 가 아니다 — 그것은 목록에서
// 지우기만 해도 참이 된다. 재는 것은 그 거부가 「모르는 키」와 **다른 값**으로
// 도달한다는 것이다(`H-B2`). 두 자리를 함께 본다: 적재기(`revoked_keys` 를
// 읽는가)와 소비자(`operator.Guard` 는 별도 배터리).

func pubB64(t *testing.T) (string, ed25519.PublicKey) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(pub), pub
}

// 적재기가 `revoked_keys` 를 읽는다(`C16-C1`).
func TestKeyringLoadsRevokedArray(t *testing.T) {
	a, _ := pubB64(t)
	r, _ := pubB64(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")
	writeFile(t, path, []byte(`{"keys":[{"key_id":"op-key-1","ed25519_public_key_base64":"`+a+`","role":"operator"}],`+
		`"revoked_keys":[{"key_id":"op-key-0","ed25519_public_key_base64":"`+r+`","role":"operator"}]}`))

	kr, err := LoadKeyring(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	active, err := kr.PublicKeysByRole("operator")
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := kr.RevokedKeysByRole("operator")
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 || active["op-key-1"] == nil {
		t.Fatalf("active: %v", active)
	}
	if len(revoked) != 1 || revoked["op-key-0"] == nil {
		t.Fatalf("revoked list must reach the consumer as a value, got %v", revoked)
	}
}

// 폐기 배열이 없는 keyring 은 그대로 적재된다 — 부재가 정상 배치다.
func TestKeyringWithoutRevokedArrayLoads(t *testing.T) {
	a, _ := pubB64(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")
	writeFile(t, path, []byte(`{"keys":[{"key_id":"op-key-1","ed25519_public_key_base64":"`+a+`","role":"operator"}]}`))
	kr, err := LoadKeyring(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	revoked, err := kr.RevokedKeysByRole("operator")
	if err != nil {
		t.Fatal(err)
	}
	if len(revoked) != 0 {
		t.Fatalf("want empty revoked set, got %v", revoked)
	}
}

// role 없는 폐기 항목도 `S15` 로 거부한다. 관용하면 폐기 목록이 **역할 없는
// 이름의 보관소**가 되고 그 이름이 어느 검증자에게 가야 하는지 아무도 모른다.
func TestKeyringRevokedEntryNeedsRole(t *testing.T) {
	a, _ := pubB64(t)
	r, _ := pubB64(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")
	writeFile(t, path, []byte(`{"keys":[{"key_id":"op-key-1","ed25519_public_key_base64":"`+a+`","role":"operator"}],`+
		`"revoked_keys":[{"key_id":"op-key-0","ed25519_public_key_base64":"`+r+`"}]}`))
	_, err := LoadKeyring(path)
	if err == nil {
		t.Fatal("revoked entry without a role must refuse the load")
	}
	if got := deploysec.RuleID(err); got != "S15" {
		t.Fatalf("rule id = %q, want S15 (err: %v)", got, err)
	}
}

// `C16-C4`: 같은 key_id 가 양쪽에 있으면 거부한다. 관용하고 "활성이 이긴다" 로
// 정하면 폐기 선언을 게재한 사람이 자기 선언이 무효라는 것을 알 방법이 없다.
func TestKeyringOverlapRefused(t *testing.T) {
	a, _ := pubB64(t)
	r, _ := pubB64(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")
	writeFile(t, path, []byte(`{"keys":[{"key_id":"op-key-1","ed25519_public_key_base64":"`+a+`","role":"operator"}],`+
		`"revoked_keys":[{"key_id":"op-key-1","ed25519_public_key_base64":"`+r+`","role":"operator"}]}`))
	_, err := LoadKeyring(path)
	if err == nil {
		t.Fatal("a key_id in both lists must refuse the load")
	}
	if got := deploysec.RuleID(err); got != "S15b" {
		t.Fatalf("rule id = %q, want S15b (err: %v)", got, err)
	}
}

// 겹침은 **역할 필터보다 앞에서** 잰다. 뒤에서 재면 역할이 갈린 겹침이
// 통과하고, 그때 두 검증자는 같은 이름에 대해 반대 판정을 내린다.
func TestKeyringOverlapAcrossRolesRefused(t *testing.T) {
	a, _ := pubB64(t)
	r, _ := pubB64(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")
	writeFile(t, path, []byte(`{"keys":[{"key_id":"k1","ed25519_public_key_base64":"`+a+`","role":"issuer"}],`+
		`"revoked_keys":[{"key_id":"k1","ed25519_public_key_base64":"`+r+`","role":"operator"}]}`))
	if _, err := LoadKeyring(path); deploysec.RuleID(err) != "S15b" {
		t.Fatalf("overlap split across roles must still refuse, got %v", err)
	}
	// 손으로 조립한 keyring 도 같은 문으로 거부되어야 한다 — 적재기를 지나지
	// 않는 경로가 있기 때문이다.
	kr := &Keyring{
		Keys:        []KeyringEntry{{KeyID: "k1", PublicKeyB64: a, Role: "issuer"}},
		RevokedKeys: []KeyringEntry{{KeyID: "k1", PublicKeyB64: r, Role: "operator"}},
	}
	if _, err := kr.PublicKeysByRole("issuer"); deploysec.RuleID(err) != "S15b" {
		t.Fatalf("hand-built keyring must refuse too, got %v", err)
	}
	if _, err := kr.RevokedKeysByRole("operator"); deploysec.RuleID(err) != "S15b" {
		t.Fatalf("hand-built keyring must refuse on the revoked side too, got %v", err)
	}
}

// `C16-C2`: 폐기는 **서명된 payload 안에서** 실려 오고, 적재된 keyring 이 그것을
// 그대로 나른다. 봉투에 실리면 떼어내도 루트 서명이 깨지지 않는다.
func TestBundleCarriesRevokedKeys(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	a, _ := pubB64(t)
	r, _ := pubB64(t)
	p := BundlePayload{
		BundleVersion: 11,
		IssuedAtUnix:  time.Now().Unix(),
		ExpiresAtUnix: futureUnix(),
		Keys:          []KeyringEntry{{KeyID: "prod-issuer-1", PublicKeyB64: a, Role: "issuer"}},
		RevokedKeys:   []KeyringEntry{{KeyID: "prod-issuer-0", PublicKeyB64: r, Role: "issuer"}},
	}
	pb, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	bundle, err := BuildBundle(rootPriv, "root-1", pb)
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(dir, "keyring_bundle.json")
	writeFile(t, bundlePath, bundle)

	kr, err := LoadKeyringBundle(bundlePath, rootPub, filepath.Join(dir, "state.json"), testBundlePolicy)
	if err != nil {
		t.Fatalf("bundle with revoked_keys must load: %v", err)
	}
	revoked, err := kr.RevokedKeysByRole("issuer")
	if err != nil {
		t.Fatal(err)
	}
	if len(revoked) != 1 || revoked["prod-issuer-0"] == nil {
		t.Fatalf("bundle revocation did not reach the keyring: %v", revoked)
	}
}

// 번들 안의 겹침도 거부한다 — 만드는 자리와 읽는 자리 **양쪽에서**.
//
// 서명이 맞았다는 것은 **누가 썼는지**를 말할 뿐 그 내용이 일관된다는 뜻이
// 아니다. 그래서 `BuildBundle` 이 거부하는 것만으로는 부족하다: 그 검사는 우리
// 도구를 쓴 사람에게만 걸리고, 서명 키를 가진 다른 도구가 만든 번들은 그 문을
// 지나지 않는다. 적재 경로를 재려면 봉투를 손으로 조립해야 한다.
func TestBundleOverlapRefused(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	a, _ := pubB64(t)
	r, _ := pubB64(t)
	p := BundlePayload{
		BundleVersion: 12,
		IssuedAtUnix:  time.Now().Unix(),
		ExpiresAtUnix: futureUnix(),
		Keys:          []KeyringEntry{{KeyID: "dup", PublicKeyB64: a, Role: "issuer"}},
		RevokedKeys:   []KeyringEntry{{KeyID: "dup", PublicKeyB64: r, Role: "issuer"}},
	}
	pb, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildBundle(rootPriv, "root-1", pb); deploysec.RuleID(err) != "S15b" {
		t.Fatalf("BuildBundle must refuse to sign an overlapping payload, got %v", err)
	}

	env := BundleEnvelope{
		SchemaVersion: BundleSchemaVersion,
		PayloadB64:    base64.StdEncoding.EncodeToString(pb),
		RootKeyID:     "root-1",
		RootSigB64:    base64.StdEncoding.EncodeToString(ed25519.Sign(rootPriv, pb)),
	}
	eb, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "keyring_bundle.json")
	writeFile(t, bundlePath, eb)
	_, err = LoadKeyringBundle(bundlePath, rootPub, filepath.Join(dir, "state.json"), testBundlePolicy)
	if deploysec.RuleID(err) != "S15b" {
		t.Fatalf("overlap inside a validly signed bundle must refuse at load, got %v", err)
	}
}

// 형식 대칭. `RevokedKeys` 가 비면 필드 자체가 나가지 않아야 한다 — nil 을
// `"revoked_keys":null` 로 내보내면 C++ 적재기가 그것을 배열 아닌 값으로 읽어
// 거부한다(같은 바이트를 두 언어가 다르게 읽는 자리).
func TestEmptyRevocationIsOmittedNotNull(t *testing.T) {
	b, err := json.Marshal(BundlePayload{BundleVersion: 1, Keys: []KeyringEntry{}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "revoked_keys") {
		t.Fatalf("empty revocation must not emit the field at all: %s", b)
	}
	kb, err := json.Marshal(Keyring{Keys: []KeyringEntry{}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(kb), "revoked_keys") {
		t.Fatalf("empty revocation must not emit the field at all: %s", kb)
	}
}
