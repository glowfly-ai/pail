// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// uir_report aggregates blackbox GATE_DECISION records into an Unnecessary
// Interruption Rate report (implementation contract: in observe mode the whole pipeline
// runs and every decision is journaled, but nothing consumes the decision — so
// the journal already holds "what would have been blocked" and UIR is a read,
// not a new measurement path).
//
// Three things this tool refuses to do, each because doing it would publish a
// number that reads as fact:
//
//  1. It does not count decision RECORDS as interruptions. A gate deciding at
//     20 Hz and one deciding at 5 Hz report a 4x different denial ratio for
//     identical robot behaviour. What an operator experiences is an episode:
//     a maximal run of consecutive non-PERMIT decisions on one action chain.
//     Measured on deploy/.blackbox-m9: 27 denials of 55 records (49%) is ONE
//     episode. Both numbers are printed, and the record ratio is labelled as
//     the gate's decision frequency, not as UIR.
//
//  2. It does not mix effective_mode buckets. The field is three-valued —
//     "observe", "enforce", and ABSENT, which per generated_server.go means a
//     gate from before shadow mode and never means enforce. UIR is only
//     meaningful over observe records: in enforce the block actually happened,
//     so the same arithmetic answers a different question.
//
//  3. It does not silently drop chain_attributed=false denials. They cannot be
//     joined to any action, so they have no denominator; dropping them makes
//     UIR look better, which is the dangerous direction. They are counted into
//     their own bucket and printed next to the rate.
//
// Integrity is a precondition, not a footnote: records arrive through
// blackbox.WalkDir, which verifies the hash chain, and a chain error aborts
// before any count is emitted. That is NOT an independent audit — this tool
// shares the reader with the service that wrote the journal. The independent
// auditor is cmd/blackbox_verify --check-chain (LLD D3), and the report says so
// rather than letting "chain ok" be read as "audited".
//
// Exit codes are distinct so that "could not compute" never arrives as "zero":
//
//	0 = report emitted with a UIR value
//	1 = integrity failure or unreadable journal (no counts at all)
//	2 = usage error
//	3 = journal read cleanly but UIR is not computable; counts printed, rate withheld with a reason
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/glowfly/pail/services/internal/blackbox"
	"github.com/glowfly/pail/services/internal/completion"
)

const (
	exitOK           = 0
	exitIntegrity    = 1
	exitUsage        = 2
	exitIncomputable = 3
)

// modeUnknown is the bucket for a GATE_DECISION whose effective_mode key is
// absent. It is a separate word from "enforce" on purpose (implementation contract,
// D-S5): a pre-shadow gate did not declare a mode, and recording that silence
// as enforce would invent a declaration nobody made.
const modeUnknown = "unknown"

type gateDecision struct {
	completion.Record
	Fatal           bool    `json:"fatal"`
	Decision        *string `json:"decision"`
	ReasonCode      *string `json:"reason_code"`
	ChainID         *string `json:"chain_id"`
	StepComplete    *bool   `json:"step_complete"`
	EffectiveMode   *string `json:"effective_mode"`
	ChainAttributed *bool   `json:"chain_attributed"`
	UnixMs          uint64  `json:"unix_ms"`
}

type episode struct {
	chainID    string
	records    int
	reasonRuns int
	firstMs    uint64
	lastMs     uint64
	reasons    []string
}

type modeStats struct {
	Mode string `json:"mode"`

	Records int `json:"records"`
	Permits int `json:"permits"`
	Denials int `json:"denials"`

	// Attribution is three-valued for the same reason mode is: a missing
	// chain_attributed key is a gate that never answered the question.
	AttributedTrue    int `json:"attributed_true"`
	AttributedFalse   int `json:"attributed_false"`
	AttributedUnknown int `json:"attributed_unknown"`

	// UnattributedDenials have no action to divide by. They are the reason
	// the rate below is a floor rather than a total.
	UnattributedDenials int `json:"unattributed_denials"`

	AttemptedActions int `json:"attempted_actions"` // chains that received a decision
	CompletedActions int `json:"completed_actions"` // chains with issuer-accepted completion

	Episodes   []episode `json:"-"`
	EpisodeN   int       `json:"episodes"`
	ReasonRunN int       `json:"reason_runs"`

	ReasonBreakdown map[string]int `json:"reason_breakdown"`

	FirstMs uint64 `json:"first_unix_ms"`
	LastMs  uint64 `json:"last_unix_ms"`

	// order of first appearance, so the report is deterministic
	chainOrder []string
	byChain    map[string][]gateDecision
}

type report struct {
	Dir             string                `json:"dir"`
	TotalRecords    int                   `json:"total_records"`
	GateDecisions   int                   `json:"gate_decisions"`
	IssuedActions   int                   `json:"issued_actions"`
	AcceptedActions int                   `json:"accepted_actions"`
	TornTail        bool                  `json:"torn_tail"`
	Modes           map[string]*modeStats `json:"modes"`
	UIREpisodes     *float64              `json:"uir_episodes_per_action"`
	UIRReasonRuns   *float64              `json:"uir_reason_runs_per_action"`
	Incomputable    string                `json:"incomputable_reason,omitempty"`
	modeOrder       []string
}

func main() {
	dir := flag.String("dir", "", "blackbox segment directory (required)")
	asJSON := flag.Bool("json", false, "emit the report as JSON instead of text")
	flag.Parse()

	if err := validateArgs(flag.Args(), *dir); err != nil {
		fmt.Fprintf(os.Stderr, "uir_report: %v\n", err)
		flag.Usage()
		os.Exit(exitUsage)
	}

	rep, err := build(*dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "uir_report: %v\n", err)
		fmt.Fprintln(os.Stderr, "uir_report: no counts emitted — a journal whose chain does not verify has no rate")
		os.Exit(exitIntegrity)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintf(os.Stderr, "uir_report: %v\n", err)
			os.Exit(exitIntegrity)
		}
	} else {
		fmt.Print(rep.text())
	}
	if rep.Incomputable != "" {
		os.Exit(exitIncomputable)
	}
	os.Exit(exitOK)
}

// validateArgs refuses anything this tool does not understand, before it reads
// a byte. deform_ossb_b.py --help once started a four-hour tree deformation
// because an unrecognised argument fell through to the default action, and
// deform_shadow.py --list repeated it — the lesson has to live in the tool, not
// only in a note. It is a function rather than four lines inside main so that
// the refusal is reachable from a test; a check only main can run is a check
// nothing measures.
func validateArgs(rest []string, dir string) error {
	if len(rest) > 0 {
		return fmt.Errorf("unexpected argument %q", rest[0])
	}
	if dir == "" {
		return fmt.Errorf("-dir is required")
	}
	return nil
}

func build(dir string) (*report, error) {
	rep := &report{Dir: dir, Modes: map[string]*modeStats{}}
	issued := map[string]bool{}
	accepted := map[string]bool{}

	torn, err := blackbox.WalkDir(dir, func(r blackbox.Record) error {
		rep.TotalRecords++
		switch r.Type {
		case blackbox.RecordTokenIssued:
			if id, ok := chainIDOf(r.Payload); ok {
				issued[id] = true
			}
		case blackbox.RecordPlanAccepted:
			if id, ok := chainIDOf(r.Payload); ok {
				accepted[id] = true
			}
		case blackbox.RecordGateDecision:
			var gd gateDecision
			if err := json.Unmarshal(r.Payload, &gd); err != nil {
				// A GATE_DECISION we cannot parse is not a permit and not
				// a denial; counting it as either would be a guess. It is
				// surfaced as an error so the report is never built on a
				// journal this tool only partly understands.
				return fmt.Errorf("unparseable GATE_DECISION payload at unix_ms=%d: %w", r.UnixMs, err)
			}
			if gd.UnixMs == 0 {
				gd.UnixMs = r.UnixMs
			}
			rep.GateDecisions++
			rep.ingest(gd)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	rep.TornTail = torn
	rep.IssuedActions = len(issued)
	rep.AcceptedActions = len(accepted)

	for _, m := range rep.Modes {
		m.finish()
	}
	rep.computeRate()
	return rep, nil
}

func chainIDOf(payload []byte) (string, bool) {
	var v struct {
		ChainID *string `json:"chain_id"`
	}
	if err := json.Unmarshal(payload, &v); err != nil || v.ChainID == nil || *v.ChainID == "" {
		return "", false
	}
	return *v.ChainID, true
}

func (r *report) ingest(gd gateDecision) {
	mode := modeUnknown
	if gd.EffectiveMode != nil && *gd.EffectiveMode != "" {
		mode = *gd.EffectiveMode
	}
	m := r.Modes[mode]
	if m == nil {
		m = &modeStats{Mode: mode, ReasonBreakdown: map[string]int{}, byChain: map[string][]gateDecision{}}
		r.Modes[mode] = m
		r.modeOrder = append(r.modeOrder, mode)
	}
	m.add(gd)
}

func (m *modeStats) add(gd gateDecision) {
	m.Records++
	if m.FirstMs == 0 || gd.UnixMs < m.FirstMs {
		m.FirstMs = gd.UnixMs
	}
	if gd.UnixMs > m.LastMs {
		m.LastMs = gd.UnixMs
	}

	denied := !isPermit(gd)
	if denied {
		m.Denials++
		m.ReasonBreakdown[strOr(gd.ReasonCode, "<사유없음>")]++
	} else {
		m.Permits++
	}

	switch {
	case gd.ChainAttributed == nil:
		m.AttributedUnknown++
	case *gd.ChainAttributed:
		m.AttributedTrue++
	default:
		m.AttributedFalse++
	}

	// Episode arithmetic needs an action to attach to. A denial the gate
	// itself declared unattributable, or one with no chain_id, is counted
	// into its own bucket instead of being folded in or dropped.
	attributable := gd.ChainAttributed == nil || *gd.ChainAttributed
	id := strOr(gd.ChainID, "")
	if !attributable || id == "" {
		if denied {
			m.UnattributedDenials++
		}
		return
	}
	if _, seen := m.byChain[id]; !seen {
		m.chainOrder = append(m.chainOrder, id)
	}
	m.byChain[id] = append(m.byChain[id], gd)
}

func isPermit(gd gateDecision) bool {
	return gd.Decision != nil && *gd.Decision == "PERMIT"
}

func (m *modeStats) finish() {
	m.AttemptedActions = len(m.chainOrder)
	for _, id := range m.chainOrder {
		recs := m.byChain[id]
		completed := false
		cur := -1 // index into m.Episodes, not a pointer: appending reallocates
		var prevReason string
		for _, gd := range recs {
			if gd.Decision != nil && gd.StepComplete != nil {
				accepted, err := gd.Record.Validate(*gd.Decision, *gd.StepComplete, gd.Fatal, gd.ChainAttributed)
				if err == nil && accepted {
					completed = true
				}
			}
			if isPermit(gd) {
				cur = -1
				prevReason = ""
				continue
			}
			reason := strOr(gd.ReasonCode, "<사유없음>")
			if cur < 0 {
				m.Episodes = append(m.Episodes, episode{
					chainID: id, records: 1, reasonRuns: 1,
					firstMs: gd.UnixMs, lastMs: gd.UnixMs,
					reasons: []string{reason},
				})
				cur = len(m.Episodes) - 1
			} else {
				e := &m.Episodes[cur]
				e.records++
				e.lastMs = gd.UnixMs
				// A reason change inside one continuous stop is one
				// interruption to the operator and two causes to the
				// engineer. Both counts are kept; picking one silently
				// would hide which question the number answers.
				if reason != prevReason {
					e.reasonRuns++
					e.reasons = append(e.reasons, reason)
				}
			}
			prevReason = reason
		}
		if completed {
			m.CompletedActions++
		}
	}
	m.EpisodeN = len(m.Episodes)
	for _, e := range m.Episodes {
		m.ReasonRunN += e.reasonRuns
	}
}

func (r *report) computeRate() {
	obs := r.Modes["observe"]
	if obs == nil {
		other := strings.Join(r.modeOrder, ", ")
		if other == "" {
			other = "없음"
		}
		r.Incomputable = fmt.Sprintf("관측 모드(effective_mode=observe) 판정 레코드가 0건이다 (있는 버킷: %s). "+
			"enforce 레코드로 같은 산술을 하면 「막혔을 것」이 아니라 「막혔다」를 재게 된다.", other)
		return
	}
	if obs.AttemptedActions == 0 {
		r.Incomputable = "관측 모드에 판정을 받은 action(체인)이 0건이라 분모가 없다."
		return
	}
	ep := float64(obs.EpisodeN) / float64(obs.AttemptedActions)
	rr := float64(obs.ReasonRunN) / float64(obs.AttemptedActions)
	r.UIREpisodes = &ep
	r.UIRReasonRuns = &rr
}

func strOr(p *string, def string) string {
	if p == nil {
		return def
	}
	return *p
}

func (r *report) text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "UIR 리포트 — %s\n", r.Dir)
	fmt.Fprintf(&b, "무결성: 내부 리더(blackbox.WalkDir)로 해시체인 검증 통과. "+
		"독립 감사가 아니다 — 이 도구는 저널을 쓴 서비스와 리더를 공유한다. "+
		"독립 감사는 blackbox_verify --check-chain 으로 따로 수행한다.\n")
	if r.TornTail {
		fmt.Fprintf(&b, "⚠ 마지막 세그먼트의 꼬리가 잘려 있다 — 그 뒤 레코드는 이 집계에 없다. "+
			"아래 수는 하한이다.\n")
	}
	fmt.Fprintf(&b, "레코드 %d건 · GATE_DECISION %d건 · 발급된 action %d · 계획수락 action %d\n\n",
		r.TotalRecords, r.GateDecisions, r.IssuedActions, r.AcceptedActions)

	modes := append([]string(nil), r.modeOrder...)
	sort.Strings(modes)
	for _, name := range modes {
		m := r.Modes[name]
		label := name
		if name == modeUnknown {
			label = "unknown (effective_mode 키 부재 = 셰도우 이전 게이트. enforce 가 아니다)"
		}
		fmt.Fprintf(&b, "[%s]\n", label)
		fmt.Fprintf(&b, "  판정 레코드 %d (PERMIT %d · 거부 %d)\n", m.Records, m.Permits, m.Denials)
		fmt.Fprintf(&b, "  귀속: true %d · false %d · 키부재 %d\n",
			m.AttributedTrue, m.AttributedFalse, m.AttributedUnknown)
		fmt.Fprintf(&b, "  시도된 action %d · 완료된 action(issuer-accepted) %d\n",
			m.AttemptedActions, m.CompletedActions)
		fmt.Fprintf(&b, "  중단 에피소드 %d · 사유 런 %d\n", m.EpisodeN, m.ReasonRunN)
		if m.UnattributedDenials > 0 {
			fmt.Fprintf(&b, "  ⚠ 귀속 불가 거부 %d건 — 붙일 action 이 없어 분자·분모 어디에도 안 들어간다. "+
				"버리면 UIR 이 좋아지는 방향으로 틀린다.\n", m.UnattributedDenials)
		}
		if m.Records > 0 {
			fmt.Fprintf(&b, "  (참고) 판정 레코드 거부율 %.1f%% — 이것은 UIR 이 아니라 "+
				"게이트의 판정 주파수를 반영하는 값이다.\n",
				100*float64(m.Denials)/float64(m.Records))
		}
		if len(m.ReasonBreakdown) > 0 {
			keys := make([]string, 0, len(m.ReasonBreakdown))
			for k := range m.ReasonBreakdown {
				keys = append(keys, k)
			}
			sort.Slice(keys, func(i, j int) bool {
				if m.ReasonBreakdown[keys[i]] != m.ReasonBreakdown[keys[j]] {
					return m.ReasonBreakdown[keys[i]] > m.ReasonBreakdown[keys[j]]
				}
				return keys[i] < keys[j]
			})
			b.WriteString("  사유코드별 거부:")
			for _, k := range keys {
				fmt.Fprintf(&b, " %s=%d", k, m.ReasonBreakdown[k])
			}
			b.WriteString("\n")
		}
		if len(m.Episodes) > 0 {
			ds := make([]uint64, 0, len(m.Episodes))
			for _, e := range m.Episodes {
				ds = append(ds, e.lastMs-e.firstMs)
			}
			sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
			fmt.Fprintf(&b, "  에피소드 지속(ms): min=%d median=%d max=%d\n",
				ds[0], ds[len(ds)/2], ds[len(ds)-1])
		}
		b.WriteString("\n")
	}

	if r.Incomputable != "" {
		fmt.Fprintf(&b, "UIR: 산출 불가 — %s\n", r.Incomputable)
		return b.String()
	}
	obs := r.Modes["observe"]
	fmt.Fprintf(&b, "UIR(중단 에피소드 / 시도된 action) = %d / %d = %.3f\n",
		obs.EpisodeN, obs.AttemptedActions, *r.UIREpisodes)
	fmt.Fprintf(&b, "UIR(사유 런 / 시도된 action)      = %d / %d = %.3f\n",
		obs.ReasonRunN, obs.AttemptedActions, *r.UIRReasonRuns)
	if obs.CompletedActions == 0 {
		fmt.Fprintf(&b, "「완료된 action」을 분모로 한 값은 내지 않는다 — issuer-accepted completion = 0이라 0 으로 나눈다.\n")
	}
	return b.String()
}
