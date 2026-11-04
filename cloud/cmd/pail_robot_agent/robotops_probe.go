// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/glowfly/pail/services/internal/buildinfo"
	"github.com/glowfly/pail/services/internal/grpcauth"
	ops "github.com/glowfly/pail/services/pkg/robotops"
	pb "github.com/glowfly/pail/services/proto/robotopsv1"
	tokenpb "github.com/glowfly/pail/services/proto/tokenv1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type selfProbe struct {
	reports *reportQueue
	pb.UnimplementedRobotAgentSelfProbeServer
	cloud                                                *failoverConn
	robot, deployment, fingerprint, instance, generation string
	mirror                                               *tokenMirror
	summarySeq                                           atomic.Uint64
}

// attachMirror lets ProbeSelf report the delegated-authority snapshot
// (LLD §11.6). Without it the summary is UNKNOWN, never EMPTY.
func (s *selfProbe) attachMirror(m *tokenMirror) { s.mirror = m }

// guardSummary is a read-only snapshot under the mirror lock: no drain,
// reconcile, lease query or upstream call happens because of it.
func (s *selfProbe) guardSummary() *pb.RuntimeGuardSummary {
	out := &pb.RuntimeGuardSummary{AuthorityState: "UNKNOWN", SnapshotBasis: "mirror not attached"}
	if s.mirror == nil {
		return out
	}
	mono, e := ops.LocalMonotonicNS()
	if e != nil {
		out.SnapshotBasis = "monotonic clock unavailable"
		return out
	}
	m := s.mirror
	m.mu.Lock()
	minIdx, maxIdx := int32(0), int32(0)
	first := true
	for idx := range m.lease {
		if first || idx < minIdx {
			minIdx = idx
		}
		if first || idx > maxIdx {
			maxIdx = idx
		}
		first = false
	}
	held := len(m.lease) > 0 || (m.resp != nil && m.resp.GetStatus() == tokenpb.ActiveTokenStatus_OK)
	out.CachedChainId, out.ServingIndex, out.LeaseMinIndex, out.LeaseMaxIndex = m.chainID, m.servingIdx, minIdx, maxIdx
	out.CachedAnswerPresent, out.MirrorRevision, out.IssuerEpochSeen = m.resp != nil, m.gen, m.epoch
	if len(m.lease) > 0 {
		out.LeaseMaxIndex = m.leaseMax
	}
	m.mu.Unlock()
	out.StreamUp = m.streamUp.Load()
	out.AuthorityState = "EMPTY"
	if held {
		out.AuthorityState = "HELD"
	}
	out.SummaryMonoNs = strconv.FormatInt(mono, 10)
	out.SnapshotBasis = "agent mirror/lease snapshot under lock; local process self-report, not attestation"
	_ = s.summarySeq.Add(1)
	return out
}

func newSelfProbe(f *failoverConn, robot, dep, fp string) (*selfProbe, error) {
	u, e := uuid.Parse(dep)
	if e != nil || u.String() != dep || f == nil || len(f.conns) == 0 || len(fp) != 64 || robot == "" {
		return nil, fmt.Errorf("robotops: missing loaded mTLS/deployment/upstream")
	}
	h := sha256.Sum256([]byte("pail.robotops.agent-loaded/v1\n" + robot + "\n" + dep + "\n" + fp + "\n" + strings.Join(f.addrs, "\n")))
	return &selfProbe{cloud: f, robot: robot, deployment: dep, fingerprint: fp, instance: uuid.NewString(), generation: hex.EncodeToString(h[:])}, nil
}
func (s *selfProbe) ProbeSelf(ctx context.Context, q *pb.ProbeSelfRequest) (*pb.ProbeSelfResponse, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "RO_LOCAL_PEER_REQUIRED")
	}
	cred, ok := p.AuthInfo.(grpcauth.UDSAuthInfo)
	if !ok || !cred.HaveCred || (cred.UID != uint32(os.Geteuid()) && cred.UID != 0) {
		return nil, status.Error(codes.PermissionDenied, "RO_LOCAL_OWNER_REQUIRED")
	}
	if q == nil || len(q.Nonce) != 32 {
		return nil, status.Error(codes.InvalidArgument, "RO_PROBE_INPUT")
	}
	response := &pb.ProbeSelfResponse{Nonce: append([]byte(nil), q.Nonce...), AgentRobotId: s.robot, AgentInstanceId: s.instance, AgentLoadedGeneration: s.generation, DeploymentId: s.deployment, LoadedClientFingerprintSha256: s.fingerprint, BuildId: buildinfo.String("robot_agent"), RuntimeGuardSummary: s.guardSummary()}
	// Agent relays signed bundles but does not load them as its action-token
	// trust store. Its TLS fingerprint is separately bound in this response.
	response.TrustSnapshotJson = `{"schema_version":1,"component":"robot_agent","loaded_mode":"NOT_APPLICABLE","load_verdict":"NOT_APPLICABLE","reason":"NO_ACTION_TOKEN_KEYRING_LOADER"}`
	response.ReportStorageState = "UNKNOWN"
	// protocol version of the report wire (one contract since 0.2.0-preview.40; not a mode)
	response.CoreCommContract = "v1"
	if s.reports != nil {
		response.ReportStorageState = reportStorageState(s.reports)
	}
	i := s.cloud.index()
	response.UpstreamRef = s.cloud.addrs[i]
	// Direct connection intentionally bypasses failover Invoke/observe, token
	// mirror and reconciliation. A diagnostic failure must not rotate the route.
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	up, err := pb.NewRobotBindingProbeClient(s.cloud.conns[i]).ProbeBinding(bounded, &pb.ProbeBindingRequest{RobotId: s.robot, Nonce: q.Nonce})
	if err != nil {
		response.UnavailableReason = "UPSTREAM_" + status.Code(err).String()
		return response, nil
	}
	if s.cloud.index() != i {
		response.UnavailableReason = "UPSTREAM_CHANGED_DURING_QUERY"
		return response, nil
	}
	if up == nil || !bytes.Equal(up.Nonce, q.Nonce) || up.DeploymentId != s.deployment || up.RobotId != s.robot || up.TlsClientFingerprintSha256 != s.fingerprint || up.Binding != pb.Binding_BOUND {
		response.UnavailableReason = "UPSTREAM_BINDING_MISMATCH"
		return response, nil
	}
	response.Upstream = up
	return response, nil
}

// reportStorageState is the probe's one-word state of the report path, by priority: the critical storage fault
// that stands until restart, then the C1 cohort hold that clears itself when the Issuer answers v1 again, then
// where a report pushed now lives (P37-M1: the two holds are distinct states, not one FAULT).
func reportStorageState(q *reportQueue) string {
	switch {
	case q == nil:
		return "UNKNOWN"
	case q.core != nil && !q.core.healthy():
		return "FAULT"
	case q.cohort.mismatched():
		return "COHORT_MISMATCH"
	case q.isDurable():
		return "LOCAL_DISK"
	default:
		return "MEMORY_ONLY"
	}
}
