// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package util

import "testing"

// DN0 ①(유닛 티어): 게이트가 실제로 발행하는 BLOCK 사유가 버스트 사전에
// 등재되어 있지 않아 0xFF(미매핑)로 낙하한다는 RED 증거.
func TestDN0_RED_GateReasonsCollapseToUnmapped(t *testing.T) {
	// pep_gate_node.cpp / crypto/strict_verify.cpp 가 ReportDecision 으로
	// 실제 발행하는 사유들.
	emitted := []string{
		"ERR_NO_TOKEN", "ERR_TOKEN_CONSUMED", "ERR_NO_EVIDENCE",
		"ERR_ACTION_MISMATCH", "ERR_CONSTRAINT", "ERR_SAFETY_STALE",
		"ERR_GRPC_DISABLED", "ERR_EXPIRED", "ERR_NOT_YET_VALID",
		"ERR_SCHEMA", "ERR_UNKNOWN_KEY_ID", "ERR_VERIFY",
		"ERR_ROBOT_ID_MISMATCH", "ERR_BAD_TOKEN", "ERR_TOKEN_PARSE",
		"ERR_BAD_SIGNATURE_SIZE", "ERR_BAD_TIME_WINDOW",
		"ERR_TOKEN_VIEW_INCOMPLETE", "ERR_REVOKED", "ERR_CRYPTO_INIT",
		// 이슈어가 스스로 넣는 사유
		"ERR_OVER_LEASE", "ERR_UNEXPLAINED_PROGRESS",
	}
	lost := 0
	for _, r := range emitted {
		if v := ReasonStringToUint16(r); v == 0xFF {
			t.Logf("LOST: %-28s -> 0x%02X (unmapped)", r, v)
			lost++
		} else {
			t.Logf("  ok: %-28s -> 0x%02X", r, v)
		}
	}
	t.Logf("총 %d종 중 %d종이 0xFF로 소실", len(emitted), lost)
	if lost > 0 {
		t.Fatalf("DN0 RED 확인: 게이트 발행 사유 %d종이 버스트 사전에 없어 0xFF로 소실된다", lost)
	}
}
