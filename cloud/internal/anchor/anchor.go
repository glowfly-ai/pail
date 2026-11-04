// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// Package anchor implements the M9 anchor agent (LLD-v2 §7.1): every interval
// it checks the blackbox chain position and uploads a signed AnchorRecord to
// an external append-only store. Upload failure queues the record locally and
// NEVER blocks token issuance — the agent runs in its own goroutine and only
// takes a brief snapshot of the blackbox writer state.
//
// Emission policy: a changed snapshot is anchored at the next tick (evidence
// freshness). When Keepalive > 0 (production default), an unchanged snapshot
// is re-anchored only once per Keepalive window — a liveness proof that
// distinguishes "idle" from "dead or suppressed". Keepalive == 0 keeps the
// legacy every-tick emission (demo/verification environments).
package anchor

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	mrand "math/rand"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/glowfly/pail/services/internal/canon"
	"github.com/glowfly/pail/services/internal/signer"
)

// Record is the uploaded AnchorRecord (JSON). sig covers the deterministic
// canon string, so any holder of the issuer pubkey can audit an anchor.
type Record struct {
	RobotID     string `json:"robot_id"`
	KeyID       string `json:"key_id"`
	HeadHashHex string `json:"head_hash_hex"`
	SegmentSeq  uint64 `json:"segment_seq"`
	RecordCount uint64 `json:"record_count"`
	UnixMs      int64  `json:"unix_ms"`
	SigB64      string `json:"ed25519_sig_base64"`
}

func anchorCanon(headHashHex string, segSeq, recCount uint64, unixMs int64) []byte {
	return []byte(fmt.Sprintf(canon.AnchorV1+"%s:%d:%d:%d", headHashHex, segSeq, recCount, unixMs))
}

func BuildRecord(sg signer.Signer, robotID string, head [32]byte, segSeq, recCount uint64, unixMs int64) (Record, error) {
	hh := hex.EncodeToString(head[:])
	sig, err := sg.Sign(anchorCanon(hh, segSeq, recCount, unixMs))
	if err != nil {
		return Record{}, fmt.Errorf("anchor sign: %w", err)
	}
	return Record{
		RobotID:     robotID,
		KeyID:       sg.KeyID(),
		HeadHashHex: hh,
		SegmentSeq:  segSeq,
		RecordCount: recCount,
		UnixMs:      unixMs,
		SigB64:      base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// VerifyRecord lets an external auditor check an anchor signature.
func VerifyRecord(pub ed25519.PublicKey, r Record) bool {
	sig, err := base64.StdEncoding.DecodeString(r.SigB64)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, anchorCanon(r.HeadHashHex, r.SegmentSeq, r.RecordCount, r.UnixMs), sig)
}

// Snapshotter is implemented by blackbox.Writer.
type Snapshotter interface {
	Snapshot() (headHash [32]byte, segmentSeq uint64, recordCount uint64)
}

type Agent struct {
	Source   Snapshotter
	Signer   signer.Signer
	RobotID  string
	Store    Store
	QueueDir string
	Interval time.Duration
	// Keepalive > 0 enables change-driven emission: unchanged snapshots are
	// skipped until Keepalive has elapsed since the last emitted record.
	// 0 = emit every tick (legacy behavior).
	Keepalive time.Duration
	Logf      func(format string, v ...any)

	// BA-3: thundering-herd and outage damping. Jitter spreads the tick phase
	// and length (each wait is Interval*(1 ± Jitter*u), u uniform; the first
	// wait is Interval*u so a fleet booted together does not anchor
	// together); 0 = fixed ticker. BackoffMax > 0 backs off STORE ATTEMPTS
	// after a failure (Interval*2^n, full jitter, capped at BackoffMax); the
	// record of every tick is still built and queued locally, so evidence
	// cadence is unchanged and only the pressure on a down store is. A
	// success resets the backoff. 0 = attempt on every tick (legacy).
	Jitter     float64
	BackoffMax time.Duration
	// Rand and Now are seams for tests; nil = math/rand, time.Now.
	Rand func() float64
	Now  func() time.Time
	// backoff state: consecutive failed attempts and the earliest next attempt.
	failStreak int
	retryAt    time.Time

	// ticks makes record names unique even when two ticks land on the same
	// unix_ms with an unchanged snapshot (otherwise queue files collide).
	ticks uint64

	// last emitted snapshot state. Queued-on-failure counts as emitted — the
	// record exists locally and will drain. A record that reached *neither*
	// the store nor the queue does NOT count: see markEmitted.
	//
	// 이 주석은 원래 "queued-on-failure counts as emitted ... so no evidence is
	// lost" 였다. 그 문장은 큐잉이 성공했을 때만 참인데 코드는 실패했을 때도
	// 같은 표시를 세우고 있었다 — **주석이 코드를 실제보다 안전하게 그리는**
	// 형태다(`E-W5`). `C-B18` 에서 코드를 문장에 맞췄다.
	emitted   bool
	lastHead  [32]byte
	lastSeq   uint64
	lastCount uint64
	lastEmit  time.Time

	// dropped 는 업로드도 큐잉도 못 해 **사라진** 레코드 수다. 로그가 아니라
	// 값으로 두는 이유는 로그가 회전하기 때문이다 — 디스크가 가득 찬 상황은
	// 로그가 가장 먼저 잘리는 상황이기도 하다.
	dropped     uint64
	lastDropErr string
}

// Dropped 는 (사라진 레코드 수, 마지막 사유) 다. 0 과 "" 는 "사라진 것이
// 없다"이지 "확인하지 않았다"가 아니다 — 이 값은 Tick 이 매번 지나는 경로에서만
// 움직인다.
func (a *Agent) Dropped() (uint64, string) { return a.dropped, a.lastDropErr }

// markEmitted 는 레코드가 **어딘가에 durable 해진 뒤에만** 불린다.
//
// 이 자리가 `C-B18` 의 전부다. 여기를 Tick 앞쪽으로 되돌리면 실패한 쓰기가 다시
// 성공으로 적히고, 그때 꺼지는 것은 재시도만이 아니라 **keepalive 재발신**이다 —
// 앵커 저장소에서 "로봇이 조용하다"와 "로봇이 못 쓰고 있다"를 가르는 유일한 신호.
func (a *Agent) markEmitted(head [32]byte, seq, count uint64, now time.Time) {
	a.emitted, a.lastHead, a.lastSeq, a.lastCount, a.lastEmit = true, head, seq, count, now
}

// drop 은 유실을 기록한다. 표시를 세우지 않으므로 다음 틱이 같은 스냅샷을 다시
// 발신한다 — 유실이 재시도로 이어진다.
func (a *Agent) drop(name string, err error) {
	a.dropped++
	a.lastDropErr = err.Error()
	a.logf("anchor: record %s reached neither store nor queue (dropped=%d): %v", name, a.dropped, err)
}

func (a *Agent) logf(format string, v ...any) {
	if a.Logf != nil {
		a.Logf(format, v...)
		return
	}
	log.Printf(format, v...)
}

func (a *Agent) interval() time.Duration {
	if a.Interval <= 0 {
		return 60 * time.Second
	}
	return a.Interval
}

func (a *Agent) rand() float64 {
	if a.Rand != nil {
		return a.Rand()
	}
	return mrand.Float64()
}

func (a *Agent) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// initialDelay is the first wait: a random phase inside one interval when
// jitter is on, so agents started together do not tick together.
func (a *Agent) initialDelay() time.Duration {
	if a.Jitter <= 0 {
		return a.interval()
	}
	return time.Duration(float64(a.interval()) * a.rand())
}

// nextDelay is the wait between ticks: Interval*(1 + Jitter*(2u-1)).
func (a *Agent) nextDelay() time.Duration {
	iv := a.interval()
	if a.Jitter <= 0 {
		return iv
	}
	return time.Duration(float64(iv) * (1 + a.Jitter*(2*a.rand()-1)))
}

// Run ticks until ctx ends. The wait is re-drawn every tick (see nextDelay);
// with Jitter == 0 this is the fixed cadence it always was.
func (a *Agent) Run(ctx context.Context) {
	t := time.NewTimer(a.initialDelay())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.Tick()
			t.Reset(a.nextDelay())
		}
	}
}

// storeAttemptAllowed reports whether the store may be tried now; during a
// backoff window the tick queues locally instead (the queue drains in order
// once attempts resume).
func (a *Agent) storeAttemptAllowed(now time.Time) bool {
	return a.BackoffMax <= 0 || a.failStreak == 0 || !now.Before(a.retryAt)
}

// noteStoreFailure lengthens the backoff: Interval*2^streak with full jitter
// (uniform in [0, cap]), capped at BackoffMax. Full jitter, not a fixed
// multiple, is what breaks a fleet's synchronized retries.
func (a *Agent) noteStoreFailure(now time.Time) {
	if a.BackoffMax <= 0 {
		return
	}
	a.failStreak++
	capD := a.interval()
	for i := 1; i < a.failStreak && capD < a.BackoffMax; i++ {
		capD *= 2
	}
	if capD > a.BackoffMax {
		capD = a.BackoffMax
	}
	wait := time.Duration(float64(capD) * a.rand())
	a.retryAt = now.Add(wait)
	a.logf("anchor: store attempt %d failed; backing off %s (cap %s, max %s)", a.failStreak, wait.Round(time.Millisecond), capD, a.BackoffMax)
}

func (a *Agent) noteStoreSuccess() {
	if a.failStreak > 0 {
		a.logf("anchor: store reachable again after %d failed attempt(s); backoff reset", a.failStreak)
	}
	a.failStreak, a.retryAt = 0, time.Time{}
}

// BackoffState is observable for tests and status: consecutive failures and
// when the next attempt may happen (zero when not backing off).
func (a *Agent) BackoffState() (failStreak int, retryAt time.Time) { return a.failStreak, a.retryAt }

// Tick builds and uploads one anchor record. Queued backlog is drained first
// (oldest first): monotonic anchor repositories reject count rewinds, so a
// newer record sealing before the backlog would brick every queued record
// with a permanent conflict. While backlog remains, the current record joins
// the queue instead of being uploaded out of order. Errors are logged, never
// propagated — anchoring must not block issuance (LLD-v2 §7.1).
// With Keepalive > 0, an unchanged snapshot inside the keepalive window is
// skipped (change-driven emission).
func (a *Agent) Tick() {
	head, seq, count := a.Source.Snapshot()
	now := a.now()
	if a.Keepalive > 0 && a.emitted &&
		head == a.lastHead && seq == a.lastSeq && count == a.lastCount &&
		now.Sub(a.lastEmit) < a.Keepalive {
		return
	}
	rec, err := BuildRecord(a.Signer, a.RobotID, head, seq, count, now.UnixMilli())
	if err != nil {
		a.logf("anchor: %v", err)
		return
	}
	data, err := json.Marshal(rec)
	if err != nil {
		a.logf("anchor: marshal: %v", err)
		return
	}
	// zero-padded unix_ms keeps lexicographic order == chronological order
	a.ticks++
	name := fmt.Sprintf("anchor_%013d_%06d_%08d_%08d.json", rec.UnixMs, a.ticks, seq, count)
	if !a.storeAttemptAllowed(now) {
		// BA-3: inside a backoff window the store is not touched; the record
		// is kept locally and drains in order when attempts resume.
		a.logf("anchor: backoff until %s, queueing %s", a.retryAt.Format(time.RFC3339Nano), name)
		if err := a.queue(name, data); err != nil {
			a.drop(name, err)
			return
		}
		a.markEmitted(head, seq, count, now)
		return
	}
	if !a.drainQueue() {
		a.logf("anchor: backlog remains, queueing %s to preserve order", name)
		if err := a.queue(name, data); err != nil {
			a.drop(name, err)
			return
		}
		a.markEmitted(head, seq, count, now)
		return
	}
	if err := a.Store.Put(name, data); err != nil {
		a.logf("anchor: upload failed, queueing %s: %v", name, err)
		a.noteStoreFailure(now)
		if qerr := a.queue(name, data); qerr != nil {
			a.drop(name, qerr)
			return
		}
	} else {
		a.noteStoreSuccess()
	}
	a.markEmitted(head, seq, count, now)
}

// queue 는 오류를 돌려준다. 예전에는 로그만 남기고 삼켰는데, 그러면 부르는
// 쪽에서 **큐에 들어간 것과 사라진 것이 같은 반환값**(없음)이 된다 — 그 위에
// 세운 방출 표시가 `C-B18` 이었다.
func (a *Agent) queue(name string, data []byte) error {
	if err := os.MkdirAll(a.QueueDir, 0o700); err != nil {
		a.logf("anchor: queue mkdir: %v", err)
		return err
	}
	if err := os.WriteFile(filepath.Join(a.QueueDir, name), data, 0o600); err != nil {
		a.logf("anchor: queue write: %v", err)
		return err
	}
	return nil
}

// drainQueue retries queued records oldest-first, stopping at the first
// failure (the store is presumably still down). Returns true when no backlog
// remains afterwards.
func (a *Agent) drainQueue() bool {
	entries, err := os.ReadDir(a.QueueDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return true // no queue dir yet = nothing queued
		}
		// 읽지 못한 큐는 빈 큐가 아니다 (H-B2): 권한·I/O 오류를 '백로그
		// 없음'으로 접으면 앵커링 완료로 보고된다. 모름 = 드레인 미완.
		a.logf("anchor: queue readdir: %v", err)
		return false
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		path := filepath.Join(a.QueueDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			a.logf("anchor: queue read %s: %v", name, err)
			continue
		}
		if err := a.Store.Put(name, data); err != nil {
			a.logf("anchor: queue retry %s failed: %v", name, err)
			a.noteStoreFailure(a.now())
			return false
		}
		a.noteStoreSuccess()
		if err := os.Remove(path); err != nil {
			a.logf("anchor: queue remove %s: %v", name, err)
		}
		a.logf("anchor: queued record uploaded %s", name)
	}
	return true
}
