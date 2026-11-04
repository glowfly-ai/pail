// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// fms_denial_example — 거부 처분 계약을 지키는 FMS 측 참조 클라이언트 (DN4 산출물).
//
// 이 프로그램이 보여주는 것은 하나다: **거부를 문자열로 읽지 않는다.**
// PAIL 은 거부마다 네 필드를 준다.
//
//	reason_code     무엇이 막았는가        (기계 판독 가능한 이름)
//	disposition     어떻게 다뤄야 하는가   PERMANENT / CONDITIONAL / TRANSIENT
//	retry_after_ms  언제까지는 무의미한가  (하한이지 권고 간격이 아니다)
//	severity        얼마나 이상한가        NORMAL_DEFENSE / ANOMALY / SUSPECTED_TAMPER
//
// 세 가지 규율을 코드로 옮긴다.
//
//  1. 분기는 disposition 으로 한다. reason_code 문자열을 switch 하지 않는다 —
//     사유는 늘어나지만 처분은 셋뿐이다. 모르는 사유가 와도 처분은 안다.
//  2. retry_after_ms 는 하한이다. 백오프 알고리즘은 FMS 몫이고, PAIL 은
//     "이 전에는 다시 물어봐야 소용없다"는 바닥만 말한다. 그러므로
//     실제 대기 = max(내 백오프, 하한).
//  3. severity 는 처분과 직교한다. 재시도 판단에 쓰지 않고, 경보 라우팅에만
//     쓴다. 둘을 섞으면 O-20(경보 피로)이 되살아난다.
//
// 실행:
//
//	fms_denial_example -addr 127.0.0.1:50051 -robot robot-1 -tries 5
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"time"

	"google.golang.org/grpc"

	"github.com/glowfly/pail/services/internal/grpcauth"
	pb "github.com/glowfly/pail/services/proto/pailv1"
)

// backoff 는 FMS 자신의 정책이다. PAIL 은 여기에 관여하지 않는다.
// 지수 + 지터, 상한 30초 — 흔한 선택일 뿐 규정이 아니다.
type backoff struct {
	base time.Duration
	max  time.Duration
	n    int
}

func (b *backoff) next() time.Duration {
	d := b.base << b.n
	if d > b.max || d <= 0 {
		d = b.max
	} else {
		b.n++
	}
	// 지터: 함대가 통째로 같은 순간에 재제출하는 것을 피한다.
	return d/2 + time.Duration(rand.Int63n(int64(d/2)+1))
}

func (b *backoff) reset() { b.n = 0 }

// routeAlert 는 severity 로만 결정한다. 처분은 보지 않는다.
func routeAlert(d *pb.Denial) {
	switch d.GetSeverity() {
	case pb.Severity_SUSPECTED_TAMPER:
		// 운영자 호출 + 보안 채널. 재시도 여부와 무관하게 사람이 봐야 한다.
		log.Printf("[ALERT/SECURITY] %s — 조작 의심. 재시도 정책과 별개로 보안 대응 필요",
			d.GetReasonCode())
	case pb.Severity_ANOMALY:
		log.Printf("[ALERT/OPS] %s — 이상 징후. 대시보드 기록", d.GetReasonCode())
	case pb.Severity_NORMAL_DEFENSE:
		// 정상 방어다. 경보를 울리지 않는다 — 이것이 O-20 의 요점이다.
		log.Printf("[INFO] %s — 정상 방어(경보 아님)", d.GetReasonCode())
	default:
		log.Printf("[WARN] %s — severity 미지정. 구버전 이슈어이거나 결함",
			d.GetReasonCode())
	}
}

// handle 은 거부 하나를 처분에 따라 처리하고, (재시도할 것인가, 얼마나 기다릴 것인가)를 답한다.
func handle(d *pb.Denial, bo *backoff) (retry bool, wait time.Duration) {
	routeAlert(d)

	floor := time.Duration(d.GetRetryAfterMs()) * time.Millisecond

	switch d.GetDisposition() {
	case pb.Disposition_PERMANENT:
		// 계획 자체가 통과할 수 없다. 재제출은 무한 루프일 뿐이다.
		// 계획을 고치거나 사람에게 올린다.
		log.Printf("  -> PERMANENT: 재시도하지 않는다. 계획을 수정하거나 상신한다.")
		if origin := d.GetOriginReasonCode(); origin != "" {
			log.Printf("     (원 사유: %s)", origin)
		}
		return false, 0

	case pb.Disposition_CONDITIONAL:
		// 누군가/무언가가 바뀌어야 통과한다 — 운영자 해제, 점호 완료,
		// 사이트 모델 적재. 같은 계획을 그대로 다시 던지는 것은 그 변화를
		// 앞당기지 못한다. 하한까지는 확실히 기다리고, 그 뒤에도 조건이
		// 풀렸다는 근거가 있을 때 다시 던지는 것이 옳다.
		w := maxDur(bo.next(), floor)
		log.Printf("  -> CONDITIONAL: 조건 변화가 필요하다. %v 뒤 재확인(하한 %v)", w, floor)
		return true, w

	case pb.Disposition_TRANSIENT:
		// 아무도 아무것도 하지 않아도 해소될 수 있다. 백오프하며 재시도한다.
		w := maxDur(bo.next(), floor)
		log.Printf("  -> TRANSIENT: %v 뒤 재시도(하한 %v)", w, floor)
		return true, w

	default:
		// 처분을 모르는 응답. 구버전 이슈어이거나 계약 위반이다.
		// 안전한 쪽은 "영구"로 취급하고 사람에게 올리는 것이다 — 모르는 것을
		// 재시도 가능으로 낙관하면 그것이 곧 무한 재제출이다.
		log.Printf("  -> disposition 미지정: 보수적으로 중단하고 상신한다.")
		return false, 0
	}
}

func maxDur(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

func main() {
	addr := flag.String("addr", "127.0.0.1:50051", "PAIL northbound addr (이슈어 또는 robot_agent 관문)")
	robot := flag.String("robot", "robot-1", "robot_id")
	plan := flag.String("plan", "fms-example", "plan_id prefix")
	tries := flag.Int("tries", 5, "최대 제출 횟수")
	empty := flag.Bool("empty", false, "스텝 없는 계획을 보낸다(영구 거부 시연용)")
	speed := flag.Float64("speed", 0.2, "twist linear_x (정책 상한을 넘기면 영구 거부를 볼 수 있다)")
	useTLS := flag.Bool("tls", grpcauth.TLSEnabled(), "use mTLS")
	caPath := flag.String("ca", "", "CA cert path")
	certPath := flag.String("cert", "", "client cert path")
	keyPath := flag.String("key", "", "client key path")
	flag.Parse()

	dialOpts, err := grpcauth.ToolDialOptions(*addr, *useTLS, *caPath, *certPath, *keyPath)
	if err != nil {
		log.Fatalf("grpc credentials: %v", err)
	}
	conn, err := grpc.Dial(*addr, dialOpts...)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	c := pb.NewPailNorthboundClient(conn)

	bo := &backoff{base: 200 * time.Millisecond, max: 30 * time.Second}

	for i := 1; i <= *tries; i++ {
		// plan_id 는 매번 새로 만든다 — 실제 FMS 가 재계획할 때 그러하듯이.
		// PAIL 의 하한은 plan_id 가 아니라 계획 **내용**으로 판정하므로
		// ID 를 바꿔도 회피되지 않는다(설계 의도).
		var steps []*pb.PlanStep
		if !*empty {
			steps = []*pb.PlanStep{{
				StepId: "s1", Type: pb.StepType_STEP_TWIST,
				Twist: &pb.TwistCommand{LinearX: *speed, DurationSec: 1.0},
			}}
		}
		req := &pb.SubmitActionPlanRequest{
			SessionId: "fms-example",
			RobotId:   *robot,
			Plan: &pb.ActionPlan{
				PlanId: fmt.Sprintf("%s-%d", *plan, i),
				Steps:  steps,
			},
		}

		resp, err := c.SubmitActionPlan(context.Background(), req)
		if err != nil {
			// 전송 실패는 거부가 아니다 — 계약 밖의 사건이다.
			log.Printf("[%d/%d] 전송 실패: %v", i, *tries, err)
			time.Sleep(bo.next())
			continue
		}

		if resp.Status == pb.SubmitStatus_ACCEPTED {
			log.Printf("[%d/%d] ACCEPTED chain=%s tokens=%d",
				i, *tries, resp.ChainId, len(resp.Tokens))
			bo.reset()
			os.Exit(0)
		}

		d := resp.GetDenial()
		if d == nil {
			// 계약 위반: 거부인데 처분이 없다. 문자열로 후퇴하지 않는다 —
			// 그 후퇴가 바로 O-17 이 존재하는 이유다. 소리 내어 실패한다.
			log.Fatalf("[%d/%d] REJECTED 인데 denial 이 없다 — 계약 위반(구버전 이슈어?): %q",
				i, *tries, resp.RejectedReason)
		}

		log.Printf("[%d/%d] REJECTED code=%s disp=%v sev=%v retry_after=%dms origin=%q",
			i, *tries, d.GetReasonCode(), d.GetDisposition(), d.GetSeverity(),
			d.GetRetryAfterMs(), d.GetOriginReasonCode())

		retry, wait := handle(d, bo)
		if !retry {
			os.Exit(2)
		}
		if i == *tries {
			break // 마지막 시도 뒤에 기다리는 것은 아무 일도 하지 않는 대기다.
		}
		time.Sleep(wait)
	}

	log.Printf("제출 %d회 모두 거부됨 — 상신한다.", *tries)
	os.Exit(3)
}
