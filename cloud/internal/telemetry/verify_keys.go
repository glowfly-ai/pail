// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package telemetry

import (
	"crypto/ed25519"
	"fmt"
	"sort"

	"github.com/glowfly/pail/services/internal/crypto"
)

// VerifyKeys selects the trust-anchor set for burst signature verification
// from a loaded keyring. Bursts are signed by the robot-agent's own key
// (role "burst"); the issuer role is only the pre-split fallback for
// combined binaries — the same rule the PVS mirror (`keymod.burst_pub`)
// applies. Returns the keys and the role they were taken from.
//
// 실측 2026-09-02: issuer-role만 들고 있던 telemetryd 가 정품 burst 패킷을
// `sig=bad` 로 적었다 — 위조 경보가 키 선택 결함을 가리는 형태(H-B2 역상).
func VerifyKeys(kr *crypto.Keyring) ([]ed25519.PublicKey, string, error) {
	byID, err := kr.PublicKeysByRole("burst")
	if err != nil {
		return nil, "", err
	}
	if len(byID) > 0 {
		return sortedKeys(byID), "burst", nil
	}
	byID, err = kr.PublicKeysByRole("issuer")
	if err != nil {
		return nil, "", err
	}
	if len(byID) == 0 {
		return nil, "", fmt.Errorf("keyring has neither burst- nor issuer-role key")
	}
	return sortedKeys(byID), "issuer", nil
}

// VerifyMirrorKeys selects the trust-anchor set for permit-mirror packets.
//
// VerifyKeys 와 달리 **폴백이 없다**. burst 는 예외 사건 감사 채널이라
// 구판 결합 바이너리 호환(issuer 폴백)이 값이 있었지만, permit 미러는 DB-2
// 에서 처음 생기는 채널이라 호환할 구판이 없다 — 폴백은 편의가 아니라
// 역할 분리의 소실이다. 아무 신뢰 키나 permit 생존을 증언할 수 있으면 화면의
// 초록은 누구의 증언인지를 잃는다.
func VerifyMirrorKeys(kr *crypto.Keyring) ([]ed25519.PublicKey, string, error) {
	byID, err := kr.PublicKeysByRole("mirror")
	if err != nil {
		return nil, "", err
	}
	if len(byID) == 0 {
		return nil, "", fmt.Errorf("keyring has no mirror-role key")
	}
	return sortedKeys(byID), "mirror", nil
}

func sortedKeys(byID map[string]ed25519.PublicKey) []ed25519.PublicKey {
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	keys := make([]ed25519.PublicKey, 0, len(ids))
	for _, id := range ids {
		keys = append(keys, byID[id])
	}
	return keys
}
