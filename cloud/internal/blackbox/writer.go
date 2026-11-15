// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package blackbox

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/glowfly/pail/services/internal/signer"
)

// Segment-based append-only hash-chained blackbox per LLD-v2 §5.2/§5.3.
//
// File name: pail_blackbox.<seq:08d>.seg
// Segment header (fixed 56B):
//   magic(4)='PBSG' | ver(u32)=2 | segment_seq(u64)
//   | prev_segment_tail_hash(32) | created_unix_ms(u64)
// Records keep the as-built layout: version|type|unix_ms|payload_len|payload|prev_hash|this_hash.
// The first record of a segment chains to sha256(segment header), so the
// header itself is tamper-evident.
//
// Process start always opens a NEW segment, inheriting the latest segment's
// final record this_hash as prev_segment_tail_hash (zeros for the very first
// segment). This keeps --check-chain continuity across restarts.

const (
	segMagic      = "PBSG"
	segVersion    = 2
	segHeaderSize = 4 + 4 + 8 + 32 + 8
	recVersion    = 1

	// SegmentHeaderSize is the byte length of a complete segment header — the
	// smallest prefix of a segment a verifier may trust when the segment holds
	// no complete record yet (ledgerq frontier, review 15/21).
	SegmentHeaderSize = segHeaderSize

	DefaultMaxSegmentBytes        = int64(64) << 20
	DefaultMaxSegmentAge          = 24 * time.Hour
	DefaultCheckpointEveryRecords = 1000
	DefaultCheckpointEvery        = 60 * time.Second

	// DefaultIdleFlushAfter bounds the unflushed window when writes STOP.
	//
	// [F-PRF-1] 체크포인트 트리거는 `Append` 안에만 있다. 쓰기가 멈추면 마지막
	// 레코드들이 페이지 캐시에 무기한 남는다 — 그리고 쓰기가 멈추는 이유는 대개
	// 로봇이 섰기 때문이고, 로봇이 서는 이유는 대개 사고다. 즉 유실될 확률이
	// 가장 높은 레코드가 인과적으로 가장 필요한 레코드다.
	//
	// 값은 발명이 아니라 참조 워크로드에서 유도한다: 가장 느린 참조 프로파일이
	// WL-1 의 10 Hz(쓰기 간격 100 ms)이므로 그 10 배를 잡는다. 운전 중에는
	// 절대 발화하지 않고(디바운스가 매 Append 마다 재장전된다), 발화는 유휴로
	// 넘어가는 전이마다 정확히 한 번이다.
	DefaultIdleFlushAfter = 1 * time.Second
)

type Config struct {
	MaxSegmentBytes        int64
	MaxSegmentAge          time.Duration
	CheckpointEveryRecords int
	CheckpointEvery        time.Duration
	// IdleFlushAfter bounds the unflushed window after writes stop (F-PRF-1).
	// Zero takes DefaultIdleFlushAfter — a zero Config must not silently mean
	// "no idle durability", because that is exactly the shape of the defect.
	// Negative disables it, and that choice is then explicit in the caller.
	IdleFlushAfter time.Duration
	// Signer signs CHECKPOINT head hashes (LLD-v2 §5.3). Required:
	// an unsigned blackbox cannot be attested, so fail closed at open.
	// A signing failure (e.g. remote KMS down) fails the append (issuer-first).
	Signer signer.Signer
	// OnCheckpoint, if set, fires after a CHECKPOINT record is appended
	// (burst v2 trigger, LLD-v2 §6). Called with the writer lock held —
	// must not call back into the Writer.
	OnCheckpoint func(headHash [32]byte, recordCount uint64)
	// Ship, if set, synchronously forwards every byte written to the segment
	// files (header and records alike, HA LLD §4.2) — called with the writer
	// lock held, in write order. A Ship error from a RECORD write fails the
	// append (sync commit: grants are refused without a standby ack). A Ship
	// error from a segment HEADER write is tolerated: the header is already in
	// the local segment file and the leader's catch-up resends it from there,
	// while the very next record append still fails until the session is live.
	Ship func(segmentSeq uint64, offset uint64, data []byte) error
}

func (c *Config) applyDefaults() {
	if c.MaxSegmentBytes <= 0 {
		c.MaxSegmentBytes = DefaultMaxSegmentBytes
	}
	if c.MaxSegmentAge <= 0 {
		c.MaxSegmentAge = DefaultMaxSegmentAge
	}
	if c.CheckpointEveryRecords <= 0 {
		c.CheckpointEveryRecords = DefaultCheckpointEveryRecords
	}
	if c.CheckpointEvery <= 0 {
		c.CheckpointEvery = DefaultCheckpointEvery
	}
	// 0 만 기본값을 받는다. 음수는 "끈다"는 호출자의 명시적 선택이므로 그대로 둔다
	// — 다른 필드처럼 `<= 0` 으로 뭉뚱그리면 끄는 방법이 사라진다.
	if c.IdleFlushAfter == 0 {
		c.IdleFlushAfter = DefaultIdleFlushAfter
	}
}

type Writer struct {
	// mu serializes appends: concurrent gRPC handlers sharing one Writer
	// would otherwise race on prevHash and corrupt the chain.
	mu  sync.Mutex
	dir string
	cfg Config

	f          *os.File
	prevHash   [32]byte
	segSeq     uint64
	segCreated time.Time
	segBytes   int64
	segRecords uint64
	// segStartTail is the prev_segment_tail_hash this segment was created
	// with. If the segment is still empty at rotation time, THIS is the tail
	// the next segment must inherit (empty segments are transparent to chain
	// inheritance — reader walkSegment and OpenDir share one scan, scan.go),
	// not sha256(this segment's header).
	segStartTail [32]byte

	sinceCkptRecords int
	lastCkpt         time.Time

	// [F-PRF-1] 유휴 디바운스. 티커가 아니라 매 Append 마다 재장전되는 타이머다 —
	// 운전 중에는 발화할 수 없고, 비용은 유휴 전이당 fsync 한 번이다.
	idleTimer *time.Timer
	lastWrite time.Time
	closed    bool
	// idleFires 는 콜백이 깨어난 횟수, idleFlushes 는 실제로 fsync 까지 간 횟수다.
	// 하나로 합치면 「유휴가 없어 할 일이 없었다」와 「타이머가 아예 안 돌았다」가
	// 같은 0 이 된다(H-B2). Docker Desktop macOS/arm64 에서 time.Ticker 가 wedge
	// 되는 것을 실제로 본 적이 있으므로 이 구분은 가정이 아니다.
	idleFires      uint64
	idleFlushes    uint64
	durableAppends uint64
	// idleErr 는 배경 fsync 의 실패다. 콜백에는 돌려줄 곳이 없으므로 여기 담아
	// **다음 Append 가 반환한다** — writeCheckpoint 의 fail-closed 자세와 같다.
	// 삼키면 「내구화됐다」와 「내구화 시도가 실패했다」가 같은 침묵이 된다.
	idleErr error
	// [SEC-H07] idleSealErr is an idle checkpoint that could not be written
	// (signer down, standby gone) and is still owed. Unlike idleErr it is not
	// terminal: the next Append retries the checkpoint first and refuses its
	// record only while that retry keeps failing. idleSeals counts the idle
	// checkpoints that landed.
	idleSealErr error
	idleSeals   uint64

	// [OR3/X30] Durability seam. Production calls (*os.File).Sync; the unit
	// harness counts calls, because "did fsync run" is the only durability
	// question answerable without machine-level crash injection (§2.9).
	// Never nil after OpenDir.
	syncFn func(*os.File) error
	// [DUR-L5] Directory durability seam, deliberately SEPARATE from syncFn.
	// File contents surviving is not the file surviving: without a directory
	// fsync the new segment's name can be absent after a power loss, and the
	// chain then has a hole the reader reports as broken. internal/crypto/
	// keyfile.go already knew this pattern; the blackbox did not.
	//
	// Separate because one seam counting both would leave a deform unable to say
	// WHICH durability point it disabled (H-B9). Never nil after OpenDir.
	syncDirFn func(*os.File) error
}

func segmentName(seq uint64) string { return fmt.Sprintf("pail_blackbox.%08d.seg", seq) }

// OpenDir opens the blackbox directory and starts a new segment.
func OpenDir(dir string, cfg Config) (*Writer, error) {
	cfg.applyDefaults()
	if cfg.Signer == nil {
		return nil, errors.New("blackbox: checkpoint signer required (fail-closed)")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("blackbox: mkdir %s: %w", dir, err)
	}

	latestSeq, latestPath, err := latestSegment(dir)
	if err != nil {
		return nil, fmt.Errorf("blackbox: scan %s: %w", dir, err)
	}

	w := &Writer{
		dir:       dir,
		cfg:       cfg,
		segSeq:    latestSeq,
		lastCkpt:  time.Now(),
		syncFn:    func(f *os.File) error { return f.Sync() },
		syncDirFn: func(d *os.File) error { return d.Sync() },
	}
	if cfg.IdleFlushAfter > 0 {
		// 장전되지 않은 상태로 만든다. 첫 발화는 첫 Append 가 결정한다 —
		// 쓴 것이 없는데 fsync 하는 것은 재고 있는 것이 아니라 소음이다.
		w.idleTimer = time.AfterFunc(cfg.IdleFlushAfter, w.idleFlush)
		w.idleTimer.Stop()
	}

	var tail [32]byte
	var torn *tornTail
	var aborted []*tornTail
	for latestPath != "" {
		// fail-closed: real corruption (hash mismatch, bad magic, over-long
		// trailing garbage) must block issuance, not be papered over.
		res, serr := scanSegment(latestPath, nil, nil)
		if serr != nil {
			return nil, fmt.Errorf("blackbox: refusing to open (corrupt tail in %s): %w", latestPath, serr)
		}
		if res.abortedHeader {
			// [F-DUR-7] 헤더가 끝까지 착지하지 못한 세그먼트는 존재한 적 없는
			// 세그먼트다: 쓰기 순서가 create → 헤더 → 레코드이므로 담긴 레코드가
			// 없고 체인에 기여한 바도 없다. 지우고 그 앞을 본다.
			//
			// 지우지 않고 관용만 하면 다음 부팅의 리더에게는 **이력 중간**의 미완
			// 헤더가 되어(관용은 위치에 기댄다) 원인에서 한참 떨어진 자리에서
			// CHAIN_ERROR 로 도착한다 — `DUR-L2` 가 찢긴 꼬리에 대해 내린 것과
			// 같은 판단이다.
			if err := w.discardAbortedSegment(latestPath); err != nil {
				return nil, fmt.Errorf("blackbox: refusing to open (aborted segment %s undiscardable): %w", latestPath, err)
			}
			aborted = append(aborted, &tornTail{
				path:      latestPath,
				discarded: res.tornBytes,
				// seq 는 스캔이 아니라 **파일 이름**에서 온다. 미완 헤더는 seq
				// 필드까지 못 갔을 수 있고(0바이트면 확실히 못 갔다), 그때
				// res.segSeq 는 0 이다 — 그 0 을 선언에 적으면 "0번 세그먼트를
				// 버렸다"는 거짓이 서명된다.
				segSeq: latestSeq,
			})
			latestSeq, latestPath, err = latestSegment(dir)
			if err != nil {
				return nil, fmt.Errorf("blackbox: scan %s: %w", dir, err)
			}
			w.segSeq = latestSeq
			continue
		}
		tail = res.cleanTail
		if res.tornBytes > 0 {
			// [DUR-L2] A torn tail is NOT corruption: the record it belongs to
			// was never acknowledged to any caller, which is exactly the state
			// replay must not apply. Refusing here made a power loss — a normal
			// event — brick the robot permanently, and made "an attacker cut the
			// history" arrive as the same red line (H-B2).
			//
			// Tolerating it is not enough either: WalkDir's tolerance is
			// POSITIONAL (newest segment only), so the same bytes turn into
			// mid-history corruption on the NEXT boot, when the cause is much
			// further away. So we cut, durably — a tear is a transient state,
			// not history.
			torn = &tornTail{
				path:      latestPath,
				discarded: res.tornBytes,
				cleanSize: res.cleanSize,
				segSeq:    res.segSeq,
				tail:      res.cleanTail,
			}
			if err := w.cutTornTail(torn); err != nil {
				return nil, fmt.Errorf("blackbox: refusing to open (recovery failed for %s): %w", latestPath, err)
			}
		}
		break
	}

	if err := w.startSegment(tail); err != nil {
		// [F-DUR-8] 여기서 실패하면 **이미 일어난 폐기가 선언되지 못한다**.
		//
		// 순서(폐기 → 선언)는 뒤집을 수 없다: 선언을 먼저 내구화하면 2차 전원
		// 상실이 "일어나지 않은 절단"을 서명해 놓은 상태를 남긴다(cutTornTail
		// 주석 참조). 그래서 이 창은 좁히는 것이지 없앨 수 있는 것이 아니다.
		//
		// 없앨 수 없다면 **조용하지는 않게** 한다. 폐기량을 오류 문면에 실어
		// 거부와 같은 자리에서 읽히게 한다 — 적히지 않은 폐기가 침묵으로
		// 지나가면 그것은 "폐기가 없었다"와 같은 바이트다(H-B2).
		var undeclared int64
		for _, a := range aborted {
			undeclared += a.discarded
		}
		if torn != nil {
			undeclared += torn.discarded
		}
		if undeclared > 0 || len(aborted) > 0 {
			return nil, fmt.Errorf("blackbox: refusing to open — %d bytes were already discarded and could NOT be declared (aborted segments=%d, torn tail=%v): %w",
				undeclared, len(aborted), torn != nil, err)
		}
		return nil, err
	}
	// [DUR-L3] Record what was discarded, or refuse to run. A recovery we cannot
	// write down is a recovery we do not perform: we do not sign a placeholder
	// for something we cannot express.
	//
	// 폐기된 미완 헤더도 같은 규율을 받는다. 여기서 `discarded` 가 0 일 수 있다
	// (0바이트 시체) — 그래도 레코드는 쓴다. 세는 것은 바이트가 아니라 **선언의
	// 존재**이고, 선언이 없으면 "폐기가 일어났다"와 "폐기가 없었다"가 같은
	// 침묵이 된다(H-B2).
	for _, a := range aborted {
		a.tail = tail
		if err := w.appendRecoveryRecord(a); err != nil {
			w.f.Close()
			return nil, fmt.Errorf("blackbox: refusing to open (aborted-segment discard unrecordable): %w", err)
		}
	}
	if torn != nil {
		if err := w.appendRecoveryRecord(torn); err != nil {
			w.f.Close()
			return nil, fmt.Errorf("blackbox: refusing to open (recovery unrecordable): %w", err)
		}
	}
	return w, nil
}

// discardAbortedSegment removes a segment whose header never fully landed, and
// makes the removal durable. The directory fsync matters: without it a second
// power loss resurrects the corpse, and the next boot discards it again —
// forever, one recovery record per boot.
func (w *Writer) discardAbortedSegment(path string) error {
	if err := os.Remove(path); err != nil {
		return err
	}
	return w.syncDir()
}

// tornTail is what the startup path discarded, carried from the scan to the
// record that declares it.
type tornTail struct {
	path      string
	discarded int64
	cleanSize int64
	segSeq    uint64
	tail      [32]byte
}

// cutTornTail truncates the partial record away and makes that durable. The
// truncation must reach the disk before the recovery record claims it happened:
// otherwise a second power loss leaves a signed declaration of a cut that the
// media never saw.
func (w *Writer) cutTornTail(t *tornTail) error {
	f, err := os.OpenFile(t.path, os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Truncate(t.cleanSize); err != nil {
		return fmt.Errorf("truncate to %d: %w", t.cleanSize, err)
	}
	if err := w.syncFn(f); err != nil {
		return fmt.Errorf("fsync after truncate: %w", err)
	}
	return nil
}

func (w *Writer) appendRecoveryRecord(t *tornTail) error {
	unixMs := uint64(time.Now().UnixMilli())
	sig, err := w.cfg.Signer.Sign(RecoveryTruncateSignedInput(uint64(t.discarded), t.tail[:], t.segSeq, unixMs))
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("recovery sig size %d, want %d", len(sig), ed25519.SignatureSize)
	}
	payload := RecoveryTruncatePayload(uint64(t.discarded), t.tail[:], t.segSeq, unixMs, sig)
	if err := w.appendRecord(RecordRecoveryTruncate, unixMs, payload); err != nil {
		return err
	}
	return w.syncFn(w.f)
}

// latestSegment returns the highest segment_seq found in dir (0, "" if none).
func latestSegment(dir string) (uint64, string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, "", err
	}
	var names []string
	for _, e := range entries {
		var seq uint64
		if !e.IsDir() {
			if _, err := fmt.Sscanf(e.Name(), "pail_blackbox.%d.seg", &seq); err == nil {
				names = append(names, e.Name())
			}
		}
	}
	if len(names) == 0 {
		return 0, "", nil
	}
	sort.Strings(names) // zero-padded seq sorts lexicographically
	last := names[len(names)-1]
	var seq uint64
	fmt.Sscanf(last, "pail_blackbox.%d.seg", &seq)
	return seq, filepath.Join(dir, last), nil
}

func buildHeader(seq uint64, prevTail [32]byte, createdMs uint64) []byte {
	hdr := make([]byte, segHeaderSize)
	copy(hdr[0:4], segMagic)
	binary.LittleEndian.PutUint32(hdr[4:8], segVersion)
	binary.LittleEndian.PutUint64(hdr[8:16], seq)
	copy(hdr[16:48], prevTail[:])
	binary.LittleEndian.PutUint64(hdr[48:56], createdMs)
	return hdr
}

func (w *Writer) startSegment(prevTail [32]byte) error {
	seq := w.segSeq + 1
	path := filepath.Join(w.dir, segmentName(seq))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("blackbox: create segment %s: %w", path, err)
	}
	now := time.Now()
	hdr := buildHeader(seq, prevTail, uint64(now.UnixMilli()))
	if _, err := f.Write(hdr); err != nil {
		// [F-DUR-7] 실패한 생성이 남긴 파일을 지운다. O_EXCL 로 이미 만들어졌기
		// 때문에, 지우지 않으면 미완 헤더(흔히 0바이트)가 디렉터리에 남는다.
		// 실측(DUR-01): 매체가 가득 차 헤더 쓰기가 실패한 뒤 그 시체 하나가
		// **이미 기록된 이력 전체**를 리더에게 CHAIN_ERROR 로 만들었다. 기동이
		// 거부되는 것은 fail-closed 지만, 증거가 읽히지 않게 되는 것은 결함이다.
		f.Close()
		os.Remove(path)
		return fmt.Errorf("blackbox: write segment header: %w", err)
	}
	if w.cfg.Ship != nil {
		// Best-effort (see Config.Ship): catch-up re-covers a failed header.
		_ = w.cfg.Ship(seq, 0, hdr)
	}
	// [DUR-L5] The header is now in the file; the FILE is not yet in the
	// directory. A power loss here leaves records chained to a segment whose
	// name never existed. Sync the entry before anything chains to it.
	if err := w.syncDir(); err != nil {
		f.Close()
		os.Remove(path)
		return fmt.Errorf("blackbox: fsync dir after creating %s: %w", path, err)
	}
	if w.f != nil {
		w.f.Close()
	}
	w.f = f
	w.segSeq = seq
	w.segCreated = now
	w.segBytes = int64(segHeaderSize)
	w.segRecords = 0
	w.segStartTail = prevTail
	w.prevHash = sha256.Sum256(hdr) // header participates in the chain
	return nil
}

func (w *Writer) Append(recordType uint32, unixMs uint64, payload []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	// [F-PRF-1] 배경 fsync 가 실패했다면 그 실패를 여기서 갚는다. 앞에 세우는
	// 이유는 issuer-first 다 — 내구화가 깨진 것을 알면서 새 레코드를 받아들이면
	// 그 레코드도 같은 구멍으로 들어간다.
	if w.idleErr != nil {
		return w.idleErr
	}
	// [SEC-H07] An idle checkpoint that failed is owed before anything new is
	// accepted: records are not added on top of a tail we could not attest.
	// A signer that came back heals this by itself; one that is still down
	// keeps refusing, which is where issuance would fail anyway.
	if w.idleSealErr != nil {
		if err := w.writeCheckpoint(); err != nil {
			return fmt.Errorf("blackbox: pending idle checkpoint: %w", err)
		}
		w.idleSealErr = nil
	}
	if err := w.rotateIfNeeded(); err != nil {
		return err
	}
	if err := w.appendRecord(recordType, unixMs, payload); err != nil {
		return err
	}
	w.armIdle()
	w.sinceCkptRecords++
	if w.sinceCkptRecords >= w.cfg.CheckpointEveryRecords || time.Since(w.lastCkpt) >= w.cfg.CheckpointEvery {
		if err := w.writeCheckpoint(); err != nil {
			return err
		}
	}
	return nil
}

// armIdle re-arms the idle debounce. Called under mu, right after a record
// lands. Reset on an already-armed timer just pushes the deadline out, so a
// 10~20 Hz stream keeps the callback permanently in the future: 운전 중 비용은 0.
func (w *Writer) armIdle() {
	w.lastWrite = time.Now()
	if w.idleTimer != nil {
		w.idleTimer.Reset(w.cfg.IdleFlushAfter)
	}
}

// idleFlush is the debounce callback. When records are waiting outside every
// signature it writes a checkpoint over them (which also fsyncs); otherwise it
// only fsyncs.
//
// [SEC-H07] Until 0.2.0 this callback deliberately wrote no checkpoint, for two
// reasons, and both are answered rather than dropped:
//
//	(1) "a background goroutine has nowhere to report a signing failure" —
//	    the failure is kept in idleSealErr and the next Append repays it before
//	    accepting its record (issuer-first is kept: nothing new lands on top
//	    of a tail that could not be attested).
//	(2) "the on-disk format is frozen" — nothing is added to it. The record is
//	    the same CHECKPOINT v2 the Append path has always written.
//
// What the old behaviour cost is the reason for the change: the last records
// before a pause — and every record of a short run — stayed outside any
// signature, so a verifier could not insist on signed coverage without failing
// honest journals, and so it insisted on nothing.
func (w *Writer) idleFlush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.idleFires++
	if w.closed || w.f == nil {
		return
	}
	// 꼬리 쫓기 방지: 콜백이 mu 를 기다리는 사이에 새 Append 가 들어왔을 수
	// 있다. 그때 그냥 fsync 하면 「유휴여서 내려보냈다」가 아니라 운전 중
	// fsync 가 되고, 공표한 「운전 중 발화 0」이 조용히 거짓이 된다.
	if rest := w.cfg.IdleFlushAfter - time.Since(w.lastWrite); rest > 0 {
		w.idleTimer.Reset(rest)
		return
	}
	if w.sinceCkptRecords > 0 {
		err := w.writeCheckpoint()
		switch {
		case err == nil:
			w.idleSeals++
			w.idleFlushes++ // writeCheckpoint fsyncs
			return
		case errors.Is(err, errCheckpointFsync):
			w.idleErr = fmt.Errorf("blackbox: idle checkpoint: %w", err)
			return
		default:
			// Owed, not lost. Fall through to the plain fsync: the durability
			// of what is already in the file (F-PRF-1) must not depend on the
			// signer or the standby being reachable.
			w.idleSealErr = fmt.Errorf("blackbox: idle checkpoint: %w", err)
		}
	}
	if err := w.syncFn(w.f); err != nil {
		w.idleErr = fmt.Errorf("blackbox: idle fsync: %w", err)
		return
	}
	w.idleFlushes++
}

// IdleSealStats reports the idle checkpoints: how many landed, and the one
// still owed (nil when none is). A non-nil error here is not yet a failure of
// the journal — the next Append repays it or returns it.
func (w *Writer) IdleSealStats() (seals uint64, owed error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.idleSeals, w.idleSealErr
}

// IdleFlushStats reports the debounce's behaviour: how many times the callback
// woke, how many of those reached fsync, and whether a background fsync failed.
//
// 세 값인 이유는 H-B2 다. 하나로 줄이면 「유휴가 없었다」와 「타이머가 죽었다」가
// 구분되지 않고, 그 둘은 정반대의 뜻이다.
func (w *Writer) IdleFlushStats() (fires, flushes uint64, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.idleFires, w.idleFlushes, w.idleErr
}

// syncDir fsyncs the blackbox directory so a newly created segment's NAME is
// durable, not just its bytes (implementation contract; the same shape as
// internal/crypto/keyfile.go).
func (w *Writer) syncDir() error {
	d, err := os.Open(w.dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return w.syncDirFn(d)
}

func (w *Writer) rotateIfNeeded() error {
	if w.segBytes < w.cfg.MaxSegmentBytes && time.Since(w.segCreated) < w.cfg.MaxSegmentAge {
		return nil
	}
	// [DUR-L5] The outgoing segment is about to become unreachable for writing.
	// Whatever is still only in the page cache would be lost with no later
	// checkpoint to cover it, so durability happens HERE or nowhere. A failure
	// refuses the rotation, which fails the append — the caller must not be told
	// a record landed in a segment we could not close honestly.
	if w.f != nil {
		if err := w.syncFn(w.f); err != nil {
			return fmt.Errorf("blackbox: fsync before rotation (segment %d): %w", w.segSeq, err)
		}
	}
	// B-F3: rotating away from an EMPTY segment (e.g. writer idle past
	// MaxSegmentAge before its first append) must carry the tail the segment
	// inherited. w.prevHash would be sha256(the empty segment's header) here,
	// which the reader — for which empty segments are transparent — rejects as
	// a broken chain, and Rebuild then refuses to start.
	tail := w.prevHash
	if w.segRecords == 0 {
		tail = w.segStartTail
	}
	return w.startSegment(tail)
}

// shipError is a record that is in the local segment file but was not
// acknowledged by the standby. For a grant that is a refusal; for the closing
// checkpoint it is not a failure of the stop (SEC-H07): the tail is covered in
// the local journal and catch-up ships the record on reconnect.
type shipError struct{ err error }

func (e *shipError) Error() string { return "blackbox: ship (sync replication): " + e.err.Error() }
func (e *shipError) Unwrap() error { return e.err }

// errCheckpointFsync marks the one checkpoint failure that must not be retried:
// after a failed fsync a later "success" says nothing about the bytes that were
// pending, so the idle path treats it as terminal (idleErr) while a signing or
// shipping failure is merely owed (idleSealErr).
var errCheckpointFsync = errors.New("blackbox: checkpoint fsync")

// writeCheckpoint appends a CHECKPOINT v2 record (E-C3; LLD-v2 §5.3 as amended):
// payload(112) = head_hash(32) | record_count(u64 BE) | segment_seq(u64 BE) | sig(64).
// head_hash is the this_hash of the preceding record; record_count counts the
// records of the current segment covered by this checkpoint (the checkpoint
// record itself excluded).
//
// The writer emits ONLY v2. v1 (type 30) stays readable forever (F8) but is no
// longer produced — a format whose count is outside the signature must not keep
// being written while we call the hole closed.
func (w *Writer) writeCheckpoint() error {
	head := w.prevHash
	count := w.segRecords
	sig, err := w.cfg.Signer.Sign(CheckpointV2SignedInput(head[:], count, w.segSeq))
	if err != nil {
		return fmt.Errorf("blackbox: checkpoint sign: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("blackbox: checkpoint sig size %d, want %d", len(sig), ed25519.SignatureSize)
	}
	payload := CheckpointV2Payload(head[:], count, w.segSeq, sig)
	if err := w.appendRecord(RecordCheckpointV2, uint64(time.Now().UnixMilli()), payload); err != nil {
		return err
	}
	w.sinceCkptRecords = 0
	w.lastCkpt = time.Now()
	// [OR3/X30] The primary writer's durability point. Between checkpoints the
	// bytes are only in the page cache, so a checkpoint is also the loss
	// boundary a deployment can quote (§2.9 spec paragraph). A failing fsync
	// fails the append: returning success while the disk is gone is exactly the
	// untruth X30 names.
	//
	// [DUR-L4] The fsync lives HERE, ahead of the announce, and not in the
	// caller where it used to sit. An announcement is a report of a fact, not of
	// an intention (the mirror of C-B18): announcing first meant the anchor could
	// hold a head the blackbox does not contain. Keeping the order inside this
	// function is what stops the next caller from getting it wrong again.
	if err := w.syncFn(w.f); err != nil {
		return fmt.Errorf("%w: %v", errCheckpointFsync, err)
	}
	if w.cfg.OnCheckpoint != nil {
		w.cfg.OnCheckpoint(head, count)
	}
	return nil
}

func (w *Writer) appendRecord(recordType uint32, unixMs uint64, payload []byte) error {
	hdr := make([]byte, 4+4+8)
	binary.LittleEndian.PutUint32(hdr[0:4], recVersion)
	binary.LittleEndian.PutUint32(hdr[4:8], recordType)
	binary.LittleEndian.PutUint64(hdr[8:16], unixMs)

	h := sha256.New()
	h.Write(hdr)
	h.Write(payload)
	h.Write(w.prevHash[:])
	thisHash := h.Sum(nil)

	// write: hdr | payload_len | payload | prev_hash | this_hash
	rec := make([]byte, 0, 16+4+len(payload)+32+32)
	rec = append(rec, hdr...)
	rec = binary.LittleEndian.AppendUint32(rec, uint32(len(payload)))
	rec = append(rec, payload...)
	rec = append(rec, w.prevHash[:]...)
	rec = append(rec, thisHash...)

	if _, err := w.f.Write(rec); err != nil {
		return err
	}
	offset := uint64(w.segBytes)
	copy(w.prevHash[:], thisHash)
	w.segBytes += int64(len(rec))
	w.segRecords++
	if w.cfg.Ship != nil {
		// Sync commit (HA LLD §4.3): no standby ack => the append fails and
		// the caller refuses the grant. The bytes remain in the local segment
		// file and catch-up ships them on reconnect.
		// [OR3/X30] "In the file" is not "on the disk": this path performs no
		// fsync, and locally the bytes are only durable as of the next
		// checkpoint. HA is what makes the record survive a power loss here,
		// because the standby fsyncs before it acks.
		if err := w.cfg.Ship(w.segSeq, offset, rec); err != nil {
			return &shipError{err: err}
		}
	}
	return nil
}

// Snapshot returns the current chain position for anchoring (M9, LLD-v2 §7.1):
// head hash (this_hash of the last record, or the segment header hash if the
// segment is empty), segment_seq and the record count within that segment.
func (w *Writer) Snapshot() (headHash [32]byte, segmentSeq uint64, recordCount uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.prevHash, w.segSeq, w.segRecords
}

// Close durably closes the blackbox.
//
// [DUR-L5] The fsync is not optional politeness: without it a planned shutdown
// loses everything since the last checkpoint, and a clean stop would be no safer
// than a power cut. The sync error is returned even though the file is closed
// anyway — a Close that reports success while the last records are gone is the
// same untruth X30 named.
// Dir is the segment directory this writer appends to (read-only accessor;
// tests and the ledger index use it to replay what was written).
func (w *Writer) Dir() string { return w.dir }

func (w *Writer) Close() error { return w.closeFile(true) }

// Checkpoint writes a CHECKPOINT now, whether or not records are waiting.
//
// [SEC-H08] The Issuer calls it right after opening the journal when start-up
// replay adopted records that no signature covered (an unclean stop): on a new
// segment the checkpoint signs the header hash, the header carries the previous
// segment's tail, and so everything adopted is under a signature before the
// first new record is written.
func (w *Writer) Checkpoint() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.f == nil {
		return errors.New("blackbox: checkpoint on a closed writer")
	}
	if w.idleErr != nil {
		return w.idleErr
	}
	return w.writeCheckpoint()
}

// IsShipError reports whether err is a record that is in the local segment
// file but was not acknowledged by the standby.
func IsShipError(err error) bool {
	var se *shipError
	return errors.As(err, &se)
}

// Abandon closes the segment file WITHOUT the closing checkpoint, leaving the
// journal exactly as the appends left it — the shape a crash leaves. It exists
// for fixtures and crash probes that need that shape on purpose. A service
// stops with Close; nothing outside tests and probes calls this (pinned by
// TestH07AbandonHasNoProductionCaller).
func (w *Writer) Abandon() error { return w.closeFile(false) }

func (w *Writer) closeFile(seal bool) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	// [F-PRF-1] Stop() 은 이미 발화한 콜백을 되돌리지 못한다. 그 콜백은 지금
	// mu 를 기다리고 있을 수 있으므로, closed 를 세워 깨어난 뒤 닫힌 파일에
	// fsync 하지 않게 한다 — 순서(플래그 먼저, Close 나중)가 곧 방어다.
	w.closed = true
	if w.idleTimer != nil {
		w.idleTimer.Stop()
	}
	// [SEC-H07] A clean stop leaves nothing outside a signature: whatever was
	// appended since the last checkpoint is covered now. The file is closed
	// either way; a checkpoint that could not be written is returned, because
	// a stop that reports success while its last records are unattested is the
	// same untruth as one that reports success while they are unsynced.
	var sealErr error
	if seal && w.f != nil && w.sinceCkptRecords > 0 {
		sealErr = w.writeCheckpoint()
		var se *shipError
		if errors.As(sealErr, &se) {
			// The checkpoint IS in the local file; only the standby has not
			// acknowledged it. The local journal is covered, and a leader
			// must be able to stop while its standby is away.
			sealErr = nil
		}
	}
	serr := w.syncFn(w.f)
	cerr := w.f.Close()
	if sealErr != nil {
		return fmt.Errorf("blackbox: close checkpoint: %w", sealErr)
	}
	if serr != nil {
		return fmt.Errorf("blackbox: close fsync: %w", serr)
	}
	return cerr
}
