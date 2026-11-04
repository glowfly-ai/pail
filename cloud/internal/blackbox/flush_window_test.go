// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// flush_window_test.go — G-PRF-01 절1(거동) 의 계측. implementation contract
//
// 공표문이 「미플러시 창」이라는 수를 싣는다. 그 수가 실제 거동과 같은지는
// 여기서만 정해진다 — 공표문 쪽에서는 셀 수 없다.
//
// **빌드 태그가 없다.** x30_sync_test.go 가 같은 시임을 이미 세고 있지만 그 파일은
// `//go:build red_lldb` 뒤에 있어 평소 스위트에서 한 번도 돌지 않는다 —
// 「관측점이 있는 것」과 「그것이 도는 것」은 다른 값이다. 공표한 수를 지키는
// 관측점은 태그 없이 돌아야 한다.
//
// 재는 것:
//  1. 미플러시 창의 최대치 — fsync 사이에 몇 개의 레코드가 페이지 캐시에 쌓이는가.
//     **호출 경계가 아니라 순간**을 센다: k 번째 Append 안에서 fsync 가 불릴 때
//     그 k 번째 레코드는 이미 파일에 써진 채다. 전원이 그 사이에 끊기면 그것도
//     함께 잃는다.
//  2. fsync 가 불리는 자리가 체크포인트뿐인가.
//  3. 쓰기가 멈춘 뒤 남는 잔여(F-PRF-1 의 크기).
package blackbox

import (
	"os"
	"sync"
	"testing"
	"time"
)

// flushProbe 는 syncFn 시임을 가로채 «몇 번째 레코드에서 fsync 가 났는가» 를
// 기록한다. appended 를 Append **호출 전에** 올리는 것이 요점이다 — 그래야
// 진행 중인 레코드가 창에 포함된다.
//
// mu 는 장식이 아니다: 유휴 디바운스(F-PRF-1 수정)가 들어온 뒤로 syncFn 은
// **타이머 고루틴**에서도 불린다. 잠그지 않으면 `-race` 아래에서 붉어지고,
// -race 없이는 조용히 어긋난 수를 낸다 — 후자가 더 나쁘다.
type flushProbe struct {
	mu       sync.Mutex
	appended int
	at       []int // 각 syncFn 호출 시점의 appended 값
}

func (p *flushProbe) install(w *Writer) {
	inner := w.syncFn
	w.syncFn = func(f *os.File) error {
		p.mu.Lock()
		p.at = append(p.at, p.appended)
		p.mu.Unlock()
		return inner(f)
	}
}

func (p *flushProbe) bump() {
	p.mu.Lock()
	p.appended++
	p.mu.Unlock()
}

// windows 는 연속한 fsync 사이에 쌓인 레코드 수. 첫 창은 0 부터 센다.
func (p *flushProbe) windows() []int {
	p.mu.Lock()
	defer p.mu.Unlock()
	out, prev := make([]int, 0, len(p.at)), 0
	for _, a := range p.at {
		out = append(out, a-prev)
		prev = a
	}
	return out
}

func (p *flushProbe) maxWindow() int {
	m := 0
	for _, w := range p.windows() {
		if w > m {
			m = w
		}
	}
	return m
}

// residual: 마지막 fsync 이후 써졌고 아직 내구화되지 않은 레코드 수.
func (p *flushProbe) residual() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.at) == 0 {
		return p.appended
	}
	return p.appended - p.at[len(p.at)-1]
}

func (p *flushProbe) drive(t *testing.T, w *Writer, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		p.bump()
		if err := w.Append(RecordGateDecision, uint64(time.Now().UnixMilli()), []byte("x")); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
}

// openProbed 는 기본으로 유휴 디바운스를 **끈다**(IdleFlushAfter: -1).
// 창을 재는 네 테스트가 재려는 것은 체크포인트 트리거이고, 디바운스가 켜져 있으면
// 느린 CI 에서 fsync 하나가 더 끼어들어 창이 줄어든다 — 그 초록은 「상한을
// 지켰다」가 아니라 「재려던 것을 재지 못했다」다(H-B9 의 픽스처판).
// 디바운스를 재는 테스트는 자기가 명시적으로 값을 준다.
func openProbed(t *testing.T, cfg Config) (*Writer, *flushProbe) {
	t.Helper()
	if cfg.IdleFlushAfter == 0 {
		cfg.IdleFlushAfter = -1
	}
	w, err := OpenDir(t.TempDir(), cfg)
	if err != nil {
		t.Fatalf("OpenDir: %v", err)
	}
	p := &flushProbe{}
	p.install(w)
	return w, p
}

// TestFlushWindow_RecordsTrigger: 레코드 트리거만 켠 상태의 미플러시 창.
// 공표문의 min() 첫 항이 이 수다.
//
// 🚨 착수 때 설계서 §5 는 이 항을 `CheckpointEveryRecords − 1` 로 적고 있었다.
// 재 보니 **N** 이다(N=4 에서 4, N=16 에서 16). 창은 Append 호출 **경계**가 아니라
// **순간**에 정해진다 — N 번째 레코드는 파일에 써진 뒤 같은 호출 안에서 fsync 를
// 만나므로, 그 사이에 전원이 끊기면 N 개를 잃는다. 두 N 으로 재는 이유는 한 점
// 으로는 「N」과 「N−1」을 가를 수 없어서가 아니라, 상수로 굳은 값과 N 에 붙어
// 움직이는 값을 가르기 위해서다.
//
// 코드가 아니라 문서가 틀렸다는 점이 중요하다 — cmd/perf_spec 은 이미 N 을
// 공표하고 있었다. 재지 않고 문서에 맞췄다면 **공표 수를 틀리게 고쳤을 것이다.**
func TestFlushWindow_RecordsTrigger(t *testing.T) {
	for _, every := range []int{4, 16} {
		w, p := openProbed(t, Config{
			Signer:                 testSigner(testKey(t)),
			CheckpointEveryRecords: every,
			CheckpointEvery:        24 * time.Hour, // 시간 트리거는 꺼 둔다
			MaxSegmentBytes:        1 << 30,        // 회전도 꺼 둔다
		})
		p.drive(t, w, every*5)
		got, windows := p.maxWindow(), p.windows()
		w.Close()

		if got != every {
			t.Errorf("N=%d: 미플러시 창 최대 %d 레코드, 공표한 상한 %d. 창=%v",
				every, got, every, windows)
		}
	}
}

// TestFlushWindow_TimeTriggerBites: min() 둘째 항 `f · CheckpointEvery`.
//
// 벽시계를 쓰지만 흔들리지 않는다. 트리거가 타이머가 아니라 Append 안의
// `time.Since(lastCkpt)` 이기 때문이다 — 드라이버가 멈추면 다음 Append 에서
// 경과 시간이 더 커져 체크포인트가 **레코드 기준으로는 더 일찍** 난다. 즉 지연은
// 창을 **줄이는** 방향으로만 작용한다. 상한만 재는 것이 안전한 이유다.
func TestFlushWindow_TimeTriggerBites(t *testing.T) {
	const (
		every    = 100 * time.Millisecond
		interval = 5 * time.Millisecond
		n        = 100 // 약 0.5 초 = 체크포인트 다섯 번어치
	)
	w, p := openProbed(t, Config{
		Signer:                 testSigner(testKey(t)),
		CheckpointEveryRecords: 1 << 30, // 레코드 트리거는 꺼 둔다
		CheckpointEvery:        every,
		MaxSegmentBytes:        1 << 30, // 회전도 꺼 둔다
	})
	for i := 0; i < n; i++ {
		p.bump()
		if err := w.Append(RecordGateDecision, uint64(time.Now().UnixMilli()), []byte("x")); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		time.Sleep(interval)
	}
	got, windows := p.maxWindow(), p.windows()
	w.Close()

	if len(windows) == 0 {
		t.Fatalf("시간 트리거가 한 번도 안 물었다 — min() 의 둘째 항이 거동에 없다")
	}
	bound := int(every/interval) + 1 // f·T, 경계 레코드 1개 여유
	if got > bound {
		t.Errorf("미플러시 창 최대 %d 레코드 > f·T 상한 %d. 창=%v", got, bound, windows)
	}
	t.Logf("시간 트리거 %d 회, 창=%v (상한 %d)", len(windows), windows, bound)
}

// TestFlushWindow_FsyncSites: 공표문은 「정상 운전 중 fsync 는 체크포인트에서만
// 일어난다」고 적고 있었다. **거짓이다** — 세그먼트 회전도 fsync 한다
// (writer.go:434, DUR-L5). 체크포인트를 끄고 세그먼트만 돌리면 fsync 가 난다.
//
// 이 방향은 안전하다(추가 flush 는 창을 줄인다). 그래서 고칠 것은 코드가 아니라
// **문장**이다. 하지만 조용히 두면 안 된다 — 공표문의 「~에서만」은 다음 사람이
// 「회전 로직을 만져도 내구성엔 영향 없다」로 읽는 문장이다.
func TestFlushWindow_FsyncSites(t *testing.T) {
	w, p := openProbed(t, Config{
		Signer:                 testSigner(testKey(t)),
		CheckpointEveryRecords: 1 << 30, // 체크포인트 없음
		CheckpointEvery:        24 * time.Hour,
		MaxSegmentBytes:        4096, // 회전은 자주
	})
	p.drive(t, w, 400)
	rotations, windows := len(p.at), p.windows()
	w.Close()

	if rotations == 0 {
		t.Fatalf("회전이 fsync 를 부르지 않는다 — 회전 시 내구화(DUR-L5)가 사라졌다")
	}
	// 회전은 창을 **줄이는** 방향이다. 다른 트리거가 하나도 없는 이 배치에서
	// 회전이 flush 하지 않았다면 400 개가 한 창에 그대로 쌓였을 것이다.
	if got := p.maxWindow(); got >= 400 {
		t.Errorf("창 최대 %d 레코드 — 회전 fsync 가 창을 줄이지 못했다", got)
	}
	t.Logf("회전 fsync %d 회 (체크포인트 0 회). 창=%v — 「체크포인트에서만」은 거짓이고, "+
		"회전은 창을 줄이는 방향이라 상한은 깨지 않는다.", rotations, windows)
}

// TestFlushWindow_IdleResidual: 디바운스가 물기 **전**의 잔여. 즉 체크포인트
// 트리거만으로 남는 양이고, F-PRF-1 이 무한으로 방치하던 바로 그 레코드들이다.
// 디바운스를 끈 채 재는 이유가 여기 있다 — 이 수가 0 이 되면 다음 테스트
// (TestIdleFlush_BoundedWindow)가 아무것도 재지 않게 된다.
func TestFlushWindow_IdleResidual(t *testing.T) {
	w, p := openProbed(t, Config{
		Signer:                 testSigner(testKey(t)),
		CheckpointEveryRecords: 8,
		CheckpointEvery:        24 * time.Hour,
		MaxSegmentBytes:        1 << 30,
		IdleFlushAfter:         -1,
	})
	p.drive(t, w, 11) // 8 에서 한 번 flush, 3 개가 남는다
	got := p.residual()
	w.Close()

	t.Logf("디바운스 없이 남는 잔여 = %d 레코드 — F-PRF-1 이 무기한 방치하던 양.", got)
	if got == 0 {
		t.Errorf("잔여가 0 이다 — 이 테스트가 유휴 잔여를 재지 못하고 있다")
	}
}

// TestIdleFlush_BoundedWindow: F-PRF-1 의 수정. 쓰기가 멈추면 잔여가 사라지는가.
//
// 🚨 이 테스트는 수정 **전에 먼저 붉었다**(`잔여 3 레코드`). 그 붉음이 없었다면
// 여기 초록은 「고쳤다」가 아니라 「원래 그랬다」와 구분되지 않는다.
//
// 세 값을 함께 본다: 잔여 0 · fires ≥ 1 · flushes ≥ 1. 잔여만 보면 타이머가
// 죽었는데 우연히 다른 트리거가 물어 준 경우를 통과시킨다(H-B2).
func TestIdleFlush_BoundedWindow(t *testing.T) {
	const idle = 50 * time.Millisecond
	w, p := openProbed(t, Config{
		Signer:                 testSigner(testKey(t)),
		CheckpointEveryRecords: 1 << 30, // 레코드 트리거 없음
		CheckpointEvery:        24 * time.Hour,
		MaxSegmentBytes:        1 << 30, // 회전 없음
		IdleFlushAfter:         idle,
	})
	defer w.Close()
	p.drive(t, w, 3)
	time.Sleep(6 * idle)

	fires, flushes, err := w.IdleFlushStats()
	if err != nil {
		t.Fatalf("배경 fsync 가 실패했다: %v", err)
	}
	if got := p.residual(); got != 0 {
		t.Errorf("쓰기가 멈춘 뒤 %v 가 지나도 잔여 %d 레코드가 내구화되지 않았다 (fires=%d flushes=%d)",
			6*idle, got, fires, flushes)
	}
	if fires == 0 {
		t.Errorf("콜백이 한 번도 깨지 않았다 — 타이머가 장전되지 않았거나 죽었다")
	}
	if flushes == 0 {
		t.Errorf("콜백은 %d 회 깼는데 fsync 까지 간 적이 없다 — 꼬리 쫓기 가드가 항상 물고 있다", fires)
	}
	// 디바운스는 유휴 전이당 한 번이다. 여러 번 발화하면 티커로 퇴화한 것이고,
	// 그때 「운전 중 비용 0」이라는 공표가 거짓이 된다.
	if flushes > 1 {
		t.Errorf("유휴 전이 한 번에 fsync 가 %d 회 — 디바운스가 티커로 퇴화했다", flushes)
	}
}

// TestIdleFlush_SilentDuringTraffic: 디바운스는 **운전 중에 발화하면 안 된다**.
//
// 이것이 티커가 아니라 디바운스를 고른 이유 전체다. 참조 워크로드의 가장 느린
// 쓰기 간격(WL-1 = 10 Hz = 100 ms)보다 훨씬 촘촘한 흐름을 흘리면서, 디바운스
// 기한을 그 간격보다 길게 잡는다 — 매 Append 가 기한을 밀어내므로 콜백은 끝까지
// 미래에 머문다.
//
// fires 를 함께 재는 것이 요점이다. flushes==0 만 보면 「발화했지만 꼬리 쫓기
// 가드가 막았다」와 「아예 깨지 않았다」가 같은 0 이 된다 — 앞의 것은 정상이고
// 뒤의 것도 정상이지만, **타이머가 wedge 된 것**도 같은 0 이다(H-B2).
func TestIdleFlush_SilentDuringTraffic(t *testing.T) {
	const (
		idle     = 200 * time.Millisecond
		interval = 20 * time.Millisecond
		n        = 40 // 0.8 초 — 기한의 네 배를 흐른다
	)
	w, p := openProbed(t, Config{
		Signer:                 testSigner(testKey(t)),
		CheckpointEveryRecords: 1 << 30,
		CheckpointEvery:        24 * time.Hour,
		MaxSegmentBytes:        1 << 30,
		IdleFlushAfter:         idle,
	})
	defer w.Close()
	for i := 0; i < n; i++ {
		p.bump()
		if err := w.Append(RecordGateDecision, uint64(time.Now().UnixMilli()), []byte("x")); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		time.Sleep(interval)
	}
	_, flushes, err := w.IdleFlushStats()
	if err != nil {
		t.Fatalf("배경 fsync 가 실패했다: %v", err)
	}
	if flushes != 0 {
		t.Errorf("끊기지 않은 %v 짜리 흐름 중에 유휴 fsync 가 %d 회 났다 — 디바운스가 재장전되지 않는다",
			time.Duration(n)*interval, flushes)
	}

	// 이제 흐름을 끊으면 정확히 한 번 물어야 한다. 이 절이 없으면 위 초록은
	// 「발화하지 않았다」와 「타이머가 애초에 없다」를 구분하지 못한다.
	time.Sleep(4 * idle)
	fires, flushes, err := w.IdleFlushStats()
	if err != nil {
		t.Fatalf("배경 fsync 가 실패했다: %v", err)
	}
	if flushes != 1 {
		t.Errorf("흐름이 끊긴 뒤 유휴 fsync 가 %d 회 (fires=%d) — 정확히 1 회여야 한다", flushes, fires)
	}
	if got := p.residual(); got != 0 {
		t.Errorf("흐름이 끊긴 뒤 잔여 %d 레코드", got)
	}
}
