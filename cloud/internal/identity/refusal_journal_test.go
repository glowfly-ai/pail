// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package identity

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/glowfly/pail/services/internal/blackbox"
)

type memJournal struct {
	types    []uint32
	payloads [][]byte
	fail     bool
}

func (m *memJournal) Append(rtype uint32, _ uint64, payload []byte) error {
	if m.fail {
		return errors.New("journal down")
	}
	m.types = append(m.types, rtype)
	m.payloads = append(m.payloads, append([]byte(nil), payload...))
	return nil
}

// C2-C6: an unbound refusal writes record 90 with the identity keys; a pass
// writes nothing from the interceptor (the handler's 10/20 carry those).
func TestRefusalJournalsRecord90(t *testing.T) {
	strangerCtx, strangerFP := mtlsContext(t, []byte("stranger leaf DER"))
	robotCtx, robotFP := mtlsContext(t, []byte("robot-1 leaf DER"))
	_, orchFP := mtlsContext(t, []byte("orchestrator leaf DER"))
	ic := NewInterceptor(testRegistry(t, robotFP, orchFP))
	j := &memJournal{}
	ic.SetJournal(j)

	_, err := ic.Unary(strangerCtx, &scopedMsg{robotID: "robot-1"},
		&grpc.UnaryServerInfo{FullMethod: "/pail.TokenService/SubmitActionPlan"},
		func(ctx context.Context, req any) (any, error) { t.Fatal("handler must not run"); return nil, nil })
	if st, ok := status.FromError(err); !ok || st.Code() != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
	if len(j.types) != 1 || j.types[0] != blackbox.RecordIdentityRefused {
		t.Fatalf("want one record 90, got %v", j.types)
	}
	var ev map[string]any
	if err := json.Unmarshal(j.payloads[0], &ev); err != nil {
		t.Fatalf("payload json: %v", err)
	}
	for k, want := range map[string]string{
		"kind":           "IDENTITY_REFUSED",
		"method":         "/pail.TokenService/SubmitActionPlan",
		"robot_id":       "robot-1",
		"caller_kind":    "mtls",
		"caller_id":      strangerFP,
		"robot_id_bound": "unbound",
		"reason":         "fingerprint_unregistered",
	} {
		if got, _ := ev[k].(string); got != want {
			t.Errorf("payload %s = %q, want %q", k, got, want)
		}
	}
	if v, _ := ev["journal_v"].(float64); v != 4 {
		t.Errorf("journal_v = %v, want 4", ev["journal_v"])
	}

	// A bound pass must not add interceptor records.
	_, err = ic.Unary(robotCtx, &scopedMsg{robotID: "robot-1"},
		&grpc.UnaryServerInfo{FullMethod: "/x/Y"},
		func(ctx context.Context, req any) (any, error) { return nil, nil })
	if err != nil {
		t.Fatalf("bound must pass: %v", err)
	}
	if len(j.types) != 1 {
		t.Fatalf("pass verdicts must not journal record 90, got %v", j.types)
	}
}

// The window: repeats inside one window are suppressed and counted; the count
// rides the next written record.
func TestRefusalSuppressionWindow(t *testing.T) {
	strangerCtx, _ := mtlsContext(t, []byte("stranger leaf DER"))
	_, robotFP := mtlsContext(t, []byte("robot-1 leaf DER"))
	_, orchFP := mtlsContext(t, []byte("orchestrator leaf DER"))
	ic := NewInterceptor(testRegistry(t, robotFP, orchFP))
	j := &memJournal{}
	ic.SetJournal(j)

	call := func() {
		_, err := ic.Unary(strangerCtx, &scopedMsg{robotID: "robot-1"},
			&grpc.UnaryServerInfo{FullMethod: "/x/Y"},
			func(ctx context.Context, req any) (any, error) { return nil, nil })
		if st, ok := status.FromError(err); !ok || st.Code() != codes.PermissionDenied {
			t.Fatalf("want PermissionDenied, got %v", err)
		}
	}
	call()
	call()
	call()
	if len(j.types) != 1 {
		t.Fatalf("burst must journal once, got %d records", len(j.types))
	}

	// Age the entry past the window; the next refusal writes and carries the
	// suppressed count.
	ic.rmu.Lock()
	for _, s := range ic.refusals {
		s.lastMs -= refusalWindowMs
	}
	ic.rmu.Unlock()
	call()
	if len(j.types) != 2 {
		t.Fatalf("post-window refusal must journal, got %d records", len(j.types))
	}
	var ev map[string]any
	if err := json.Unmarshal(j.payloads[1], &ev); err != nil {
		t.Fatalf("payload json: %v", err)
	}
	if n, _ := ev["suppressed"].(float64); n != 2 {
		t.Errorf("suppressed = %v, want 2", ev["suppressed"])
	}
}

// The refusal must stand whether the journal is absent or failing —
// journaling a refusal is evidence, not authorization.
func TestRefusalStandsWithoutJournal(t *testing.T) {
	strangerCtx, _ := mtlsContext(t, []byte("stranger leaf DER"))
	_, robotFP := mtlsContext(t, []byte("robot-1 leaf DER"))
	_, orchFP := mtlsContext(t, []byte("orchestrator leaf DER"))

	for name, wire := range map[string]func(*Interceptor){
		"nil_journal":     func(_ *Interceptor) {},
		"failing_journal": func(ic *Interceptor) { ic.SetJournal(&memJournal{fail: true}) },
	} {
		ic := NewInterceptor(testRegistry(t, robotFP, orchFP))
		wire(ic)
		_, err := ic.Unary(strangerCtx, &scopedMsg{robotID: "robot-1"},
			&grpc.UnaryServerInfo{FullMethod: "/x/Y"},
			func(ctx context.Context, req any) (any, error) { return nil, nil })
		if st, ok := status.FromError(err); !ok || st.Code() != codes.PermissionDenied {
			t.Fatalf("%s: refusal must stand, got %v", name, err)
		}
	}
}
