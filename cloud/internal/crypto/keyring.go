// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/glowfly/pail/services/internal/deploysec"
)

// Keyring JSON schema (config/keys/keyring.json). M9 (LLD-v2 §7.2) added the
// "role" field ("issuer" | "operator" | "burst") as optional and folded an
// empty role to issuer. `implementation contract` removes that fold: role is required
// and an entry without one refuses the start (`S15`).
//
// 접힘을 지우는 이유는 호환이 아니라 자격이다 — role 이 비면 **발급자 자격이
// "명시되지 않음"에서 자동으로 생긴다.** 기본값을 issuer 가 아닌 다른 값으로
// 바꾸는 선택지는 `implementation contract` 이 이미 기각했다: 기본값이 무엇이든
// "명시되지 않음"이 조용히 어떤 자격이 되는 구조는 같다(fail-silent).
//
// 구판 호환을 두지 않는 근거는 공개 전이라 제3자 구판 리더가 없다는 것이다.
//
// `omitempty` 도 함께 지운다. 남겨두면 이 구조체로 keyring 을 **써내는** 쪽이
// role="" 인 항목을 필드 없이 내보내고, 그 파일은 읽는 쪽에서 `S15` 로 죽는다 —
// 만든 도구는 성공을 보고하고 실패는 배포한 사람 앞에서 터진다.
//
// The pubkey field name ed25519_public_key_base64 is canonical — the C++ PEP
// scans for it.
type KeyringEntry struct {
	KeyID        string `json:"key_id"`
	PublicKeyB64 string `json:"ed25519_public_key_base64"`
	Role         string `json:"role"`
}

type Keyring struct {
	Keys []KeyringEntry `json:"keys"`

	// `C-B16` : 폐기된 키의 **공개 절반**. 신뢰 집합이 아니다 —
	// 여기 실린 키로 서명이 맞아떨어져도 판정은 언제나 거부다. 갖고 있는 이유는
	// 그 거부가 "모르는 키"와 **다른 값**이 되게 하는 것 하나뿐이다.
	//
	// `keys` **밖**의 별도 배열인 것은 취향이 아니라 **구판이 틀리는 방향**을
	// 정하는 선택이다(`C16-C1`). 이 배열을 모르는 구판 리더는 그 키를 활성
	// 목록에서 찾지 못해 거부한다 — 부재 기반 폐기(`implementation contract`)가 그대로
	// 유지된다. 폐기 표시를 `keys` 안의 `status` 필드로 두면 반대로 기운다:
	// 필드를 모르는 리더는 그것을 버리고 키를 계속 신뢰한다(fail-open).
	//
	// omitempty 는 여기서만 예외적으로 옳다. `KeyringEntry.Role` 에서 지운 이유
	// (쓰는 쪽이 빈 값을 생략하면 읽는 쪽이 죽는다)가 여기엔 없다 — 부재가
	// **정상 배치**이고 양쪽 적재기가 부재를 받아들인다. 반대로 nil 을 `null` 로
	// 내보내면 C++ 적재기가 그것을 배열 아닌 값으로 읽어 거부한다.
	RevokedKeys []KeyringEntry `json:"revoked_keys,omitempty"`

	// 만료 근거는 적재 경로가 채운다(`B-R2`, §4.3). 필드를 내보내지 않는 이유는
	// 둘이다 — keyring.json 의 형식을 건드리지 않고, **아무도 채우지 않은 값이
	// 거부**가 되게 하기 위해서다. `&Keyring{Keys: ...}` 의 영값은 "만료를 확인한
	// 적 없음"이고 `Freshness` 는 그것을 `S20f` 로 돌려준다(`H-B2`).
	expiresAtUnix   int64
	expirySource    string
	loadedTrustJSON string
}

// Freshness 는 이 keyring 의 시간축 게이트를 만든다. 적재 경로가 만료를 대입하지
// 않았으면 오류다 — 새 적재 경로가 생겼을 때 그 누락이 **통과가 아니라 거부**로
// 나타나야 한다.
func (kr *Keyring) Freshness() (*TrustFreshness, error) {
	switch kr.expirySource {
	case expirySourceUnsignedDev:
		return TrustFreshnessUnsignedDev(), nil
	case expirySourceBundle:
		return TrustFreshnessFromBundle(kr.expiresAtUnix)
	}
	return nil, deploysec.Cfg("S20f",
		"trust anchor: keyring loaded without declaring an expiry source — %d key(s) from an unknown-freshness path",
		len(kr.Keys))
}

// ValidateRoles is `S15`: every entry must name its role.
//
// 적재 시점에 건다. `PublicKeysByRole` 에만 걸면 검사는 **묻는 역할에 대해서만**
// 도는데, 아무도 burst 를 묻지 않는 프로세스에서는 role 없는 항목이 끝까지
// 살아 있다가 다음 사람이 그 역할을 물을 때 자격이 된다.
func (kr *Keyring) ValidateRoles() error {
	for _, e := range kr.Keys {
		if e.Role == "" {
			return deploysec.Cfg("S15", "keyring: entry %q has no role", e.KeyID)
		}
	}
	// 폐기 항목도 role 을 댄다. 대지 않으면 폐기 목록이 **역할 없는 이름의
	// 보관소**가 되고, 그 이름이 어느 검증자에게 도달해야 하는지 아무도 모른다.
	for _, e := range kr.RevokedKeys {
		if e.Role == "" {
			return deploysec.Cfg("S15", "keyring: revoked entry %q has no role", e.KeyID)
		}
	}
	return nil
}

// ValidateRevocation is `S15b` (`C16-C4`): a key_id must not be in both lists.
//
// 겹침을 여기서 한 번 거부하기 때문에 검증자들은 **순서만** 정하면 된다. 양쪽
// 에서 판정하면 같은 규칙이 두 자리에 살고, 한쪽만 고쳐지는 날이 온다.
//
// 겹침을 관용하고 "활성이 이긴다"로 정하는 선택지는 기각했다. 그 규칙에서는
// 폐기 선언을 게재한 사람이 자기 선언이 무효라는 것을 알 방법이 없다 — 파일은
// 그의 의도를 그대로 담고 있고 아무도 거부하지 않는다.
func (kr *Keyring) ValidateRevocation() error {
	if len(kr.RevokedKeys) == 0 {
		return nil
	}
	active := make(map[string]struct{}, len(kr.Keys))
	for _, e := range kr.Keys {
		active[e.KeyID] = struct{}{}
	}
	for _, e := range kr.RevokedKeys {
		if _, dup := active[e.KeyID]; dup {
			return deploysec.Cfg("S15b", "keyring: key_id %q is both active and revoked", e.KeyID)
		}
	}
	return nil
}

func LoadKeyring(path string) (*Keyring, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keyring read: %w", err)
	}
	var kr Keyring
	if err := json.Unmarshal(b, &kr); err != nil {
		return nil, fmt.Errorf("keyring unmarshal: %w", err)
	}
	if err := kr.ValidateRoles(); err != nil {
		return nil, err
	}
	if err := kr.ValidateRevocation(); err != nil {
		return nil, err
	}
	// 무서명 keyring 에는 만료가 없다. 없는 것을 있다고 꾸미지 않되, **이름을
	// 대게** 한다 — 그래야 `Freshness` 가 "만료 없음"과 "확인한 적 없음"을 가른다.
	kr.expirySource = expirySourceUnsignedDev
	kr.loadedTrustJSON = `{"schema_version":1,"loaded_mode":"unsigned-dev","load_verdict":"UNSIGNED_DEVELOPMENT","expiry_applicability":"NOT_APPLICABLE"}`
	return &kr, nil
}

// PublicKeysByRole returns key_id -> pubkey for entries matching role.
//
// 적재기가 이미 `S15` 를 걸지만 여기서도 건다. 이 메서드는 파일을 거치지 않고
// 손으로 조립한 `Keyring` 에도 불리고, 그 경로는 적재기의 검사를 지나지 않는다.
// 두 자리 모두에서 거부해야 "어느 문으로 들어와도 자격은 명시되어야 한다"가
// 참이 된다.
func (kr *Keyring) PublicKeysByRole(role string) (map[string]ed25519.PublicKey, error) {
	if err := kr.ValidateRevocation(); err != nil {
		return nil, err
	}
	return keysByRole(kr.Keys, role)
}

// RevokedKeysByRole 은 폐기된 키의 공개 절반을 같은 형태로 돌려준다.
//
// `PublicKeysByRole` 과 **짝으로** 부르는 것이 규율이다. 활성만 받아 가는 호출
// 자는 폐기를 "모르는 키"로 보게 되고, 그것이 `C-B16` 이 닫으려는 결함이다.
// 짝을 강제하는 자리는 여기가 아니라 소비자의 생성자다 — `operator.NewGuard`
// 는 두 맵을 **인자로** 받아, 폐기를 넘기지 않는 호출부가 컴파일되지 않는다.
func (kr *Keyring) RevokedKeysByRole(role string) (map[string]ed25519.PublicKey, error) {
	if err := kr.ValidateRevocation(); err != nil {
		return nil, err
	}
	return keysByRole(kr.RevokedKeys, role)
}

func keysByRole(entries []KeyringEntry, role string) (map[string]ed25519.PublicKey, error) {
	out := map[string]ed25519.PublicKey{}
	for _, e := range entries {
		if e.Role == "" {
			return nil, deploysec.Cfg("S15", "keyring: entry %q has no role", e.KeyID)
		}
		if e.Role != role {
			continue
		}
		pub, err := base64.StdEncoding.DecodeString(e.PublicKeyB64)
		if err != nil {
			return nil, fmt.Errorf("keyring %s: decode pubkey: %w", e.KeyID, err)
		}
		if len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("keyring %s: invalid pubkey size %d", e.KeyID, len(pub))
		}
		out[e.KeyID] = ed25519.PublicKey(pub)
	}
	return out, nil
}

// LoadedTrustJSON is a copy of metadata captured by the successful loader.
// It never opens the configured path and never asserts current authorization.
func (kr *Keyring) LoadedTrustJSON() string {
	if kr == nil || kr.loadedTrustJSON == "" {
		return `{"schema_version":1,"load_verdict":"NOT_OBSERVED"}`
	}
	return kr.loadedTrustJSON
}
