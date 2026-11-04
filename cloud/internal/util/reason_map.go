// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package util

import "github.com/glowfly/pail/services/internal/reason"

// ReasonStringToUint16 은 사유 문자열을 버스트 패킷 값으로 바꾼다.
//
// 사전은 internal/reason 이 단독으로 보유한다. 여기에 두 번째 표를 두면 게이트가 발행하는
// 사유와 북바운드가 해석하는 사유가 갈라진다(O-14). 시그니처는 기존 호출 지점 5곳을 위해
// 유지한다. util -> reason 단방향 의존이다.
func ReasonStringToUint16(r string) uint16 { return reason.ValueOf(r) }
