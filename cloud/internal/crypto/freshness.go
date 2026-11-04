// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// 신뢰 기점의 **시간축** 유효성 (`B-R1`/`B-R2`, implementation contract).
//
// §1.4 가 실측한 것은 만료가 **적재 시점에만** 검사된다는 것이었다. 그러면 폐기
// 도달에 상한이 없다 — 번들을 갱신해도 게이트가 재시작되지 않으면 이미 적재된
// 키는 계속 유효하고, 사람이 재시작하지 않으면 영원히다.
//
// 상한을 만드는 것은 재시작이 아니라 **쓰는 시점의 재검사**다. 프로세스가 아무리
// 오래 살아 있어도 만료 시각을 넘긴 신뢰 기점 위에서는 발급·검증이 멈춘다. 그래서
// 도달 시간의 천장이 `번들 유효 창 + 폴링 주기`로 닫힌다.
//
// 주기적 감시(`Watch`)는 그 위에 얹는 **관측**이지 강제가 아니다. 강제를 감시에
// 걸면 프로세스가 놀고 있던 동안 틱이 밀린 만큼 만료된 기점이 살아 있게 된다.
// 반대로 감시가 없으면 놀고 있는 프로세스의 만료는 다음 요청이 올 때까지 아무
// 로그에도 안 나타난다. 둘 다 필요하고, **판정은 한 벌**(`Check`)이다.
package crypto

import (
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"github.com/glowfly/pail/services/internal/deploysec"
)

// FreshnessWatchInterval 은 **관측** 주기다. 설정으로 빼지 않는 이유는 이 값이
// 폐기 도달 상한에 들어가지 않기 때문이다 — 상한은 `번들 만료 주기 + 폴링 주기`로
// 닫히고, 그것을 닫는 것은 사용 시점의 `Check` 다. 이 틱은 놀고 있는 프로세스의
// 만료가 로그에 나타나게 할 뿐이므로, 고를 것이 없는 값을 고르라고 요구하면
// 설정 항목만 늘고 판단은 안 는다.
const FreshnessWatchInterval = 5 * time.Minute

// 만료 근거의 출처. 빈 문자열이 **기본값이자 거부 사유**인 것이 요점이다 —
// `&Keyring{Keys: ...}` 로 만든 값은 "만료를 확인한 적 없음"이고, 그것은 통과가
// 아니라 `S20f` 다(`H-B2`). 만료가 없는 경로를 쓰려면 이름을 대야 한다.
const (
	expirySourceBundle      = "bundle"
	expirySourceUnsignedDev = "unsigned-dev"
)

// TrustFreshness 는 적재된 신뢰 기점 하나의 시간축 상태다.
//
// 생성자를 둘로 나눈 이유는 `haveExpiry bool` 을 두면 **미확인과 만료 없음이 같은
// 값**이 되기 때문이다. 이름을 대지 않으면 만들 수 없게 한다.
type TrustFreshness struct {
	expiresAtUnix int64
	source        string
	// expired 는 `Watch` 가 관측한 마지막 상태다. 판정에 쓰지 않는다 — 읽는 쪽이
	// 이걸 보면 감시 주기만큼 만료가 늦게 발견된다. 로그·상태 표시 전용.
	observedExpired atomic.Bool
}

// TrustFreshnessFromBundle 은 서명된 번들에서 온 만료다.
//
// `expiresAtUnix <= 0` 은 만들지 못한다. 번들 payload 는 이미 그 값을 요구하므로
// 여기 0 이 오면 적재 경로 어딘가가 만료를 잃어버린 것이고, 그것을 "만료 없음"으로
// 접으면 잃어버린 사실이 통과로 나타난다.
func TrustFreshnessFromBundle(expiresAtUnix int64) (*TrustFreshness, error) {
	if expiresAtUnix <= 0 {
		return nil, deploysec.Cfg("S20f",
			"trust anchor: bundle mode but no expiry reached the freshness gate (expires_at_unix=%d) — unexamined is not unexpiring",
			expiresAtUnix)
	}
	return &TrustFreshness{expiresAtUnix: expiresAtUnix, source: expirySourceBundle}, nil
}

// TrustFreshnessUnsignedDev 는 `PAIL_KEYRING_MODE=unsigned-dev` 경로다. 무서명
// keyring 에는 만료가 **없다** — 없는 것을 있다고 꾸미지 않고, 대신 그 사실이
// 이름과 로그에 남는다. 이 경로를 여는 것은 이미 `LoadTrustedKeyringFromEnv` 의
// 명시적 선언이고, 여기서 다시 거부하면 dev 가 통째로 멈춘다.
func TrustFreshnessUnsignedDev() *TrustFreshness {
	return &TrustFreshness{source: expirySourceUnsignedDev}
}

// CheckAt 은 판정 한 벌이다. `Check` 와 `Watch` 가 같은 것을 부른다.
func (f *TrustFreshness) CheckAt(now time.Time) error {
	if f == nil {
		return deploysec.Cfg("S20f",
			"trust anchor: no freshness gate installed — the check did not run, and a check that did not run is not a check that passed")
	}
	switch f.source {
	case expirySourceUnsignedDev:
		return nil
	case expirySourceBundle:
		if n := now.Unix(); n >= f.expiresAtUnix {
			return deploysec.Cfg("S20d",
				"trust anchor: expired (now=%d >= expires_at=%d, %s past) — refusing to keep verifying on it",
				n, f.expiresAtUnix, time.Duration(n-f.expiresAtUnix)*time.Second)
		}
		return nil
	}
	// 출처가 비었다 = 아무도 만료를 대입한 적이 없다. `default:` 로 접지 않고
	// 여기까지 흘려 보내는 이유는, 새 적재 경로가 생겼을 때 그것이 통과가 아니라
	// 거부로 나타나야 하기 때문이다.
	return deploysec.Cfg("S20f",
		"trust anchor: expiry source not declared (source=%q) — a keyring that never said when it dies is not fresh",
		f.source)
}

// Check 은 지금 시각으로 판정한다. 요청 경로가 부르는 것.
func (f *TrustFreshness) Check() error { return f.CheckAt(time.Now()) }

// Describe 는 기동 로그 한 줄이다. 만료가 **없는** 경로도 소리 내어 말한다.
func (f *TrustFreshness) Describe() string {
	if f == nil {
		return "trust freshness: NOT INSTALLED"
	}
	switch f.source {
	case expirySourceUnsignedDev:
		return "trust freshness: none (unsigned-dev keyring has no expiry)"
	case expirySourceBundle:
		return fmt.Sprintf("trust freshness: expires_at=%s (in %s)",
			time.Unix(f.expiresAtUnix, 0).UTC().Format(time.RFC3339),
			time.Until(time.Unix(f.expiresAtUnix, 0)).Truncate(time.Second))
	}
	return fmt.Sprintf("trust freshness: UNDECLARED (source=%q)", f.source)
}

// ObservedExpired 는 `Watch` 가 마지막으로 본 상태다. 표시 전용.
func (f *TrustFreshness) ObservedExpired() bool {
	return f != nil && f.observedExpired.Load()
}

// InstallTrustFreshness 는 적재된 keyring 에서 시간축 게이트를 꺼내 기동 로그에
// 적고 주기적 감시를 띄운다. 두 mains 가 각자 조립하면 한쪽만 감시를 빠뜨릴 수
// 있고, 빠뜨린 쪽은 **아무 로그도 안 낸다** — 없는 것이 없는 것처럼 보인다.
//
// 게이트를 못 꺼내면 기동 거부다. 만료를 확인할 수 없는 발급자는 폐기 도달 상한을
// 주장할 수 없고, 주장할 수 없는 상한은 상한이 아니다.
func InstallTrustFreshness(component string, kr *Keyring) *TrustFreshness {
	f, err := kr.Freshness()
	if err != nil {
		deploysec.RefuseConfig(component, err)
	}
	log.Print(f.Describe())
	go f.Watch(FreshnessWatchInterval, nil, func(err error) {
		log.Printf("WARNING: %v — issuance is refused from here on", err)
	})
	return f
}

// Watch 는 `B-R1` 의 **주기적** 재검사다. 놀고 있는 프로세스에서도 만료가 로그에
// 나타나게 하는 것이 전부이고, 강제는 하지 않는다(강제는 `Check` 가 요청마다).
//
// stop 이 닫히면 끝난다. 만료를 처음 관측한 틱에서 한 번만 적고, 그 뒤로는
// 조용하다 — 6 시간마다 같은 줄을 쌓으면 그 줄은 읽히지 않는다.
func (f *TrustFreshness) Watch(interval time.Duration, stop <-chan struct{}, onExpired func(error)) {
	if f == nil || interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			err := f.CheckAt(now)
			if err == nil {
				f.observedExpired.Store(false)
				continue
			}
			if !f.observedExpired.Swap(true) && onExpired != nil {
				onExpired(err)
			}
		}
	}
}
