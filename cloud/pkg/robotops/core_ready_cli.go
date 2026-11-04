// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package robotops

import (
	"bytes"
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	pb "github.com/glowfly/pail/services/proto/robotopsv1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"io"
	"time"
)

// RunCoreProbeCLI is a read-only subcommand of the existing checker. It never
// fetches a token or invokes management mutations. Caller supplies a fresh nonce.
func RunCoreProbeCLI(args []string, out, errs io.Writer) int {
	f := flag.NewFlagSet("probe-agent", flag.ContinueOnError)
	f.SetOutput(errs)
	socket := f.String("socket", "", "owner-checked agent Unix socket")
	robot := f.String("robot", "", "expected robot")
	deployment := f.String("deployment", "", "expected deployment")
	generation := f.String("generation", "", "expected loaded agent generation")
	nonceHex := f.String("nonce", "", "64 lowercase hexadecimal characters")
	if e := f.Parse(args); e != nil {
		return 2
	}
	nonce, e := hex.DecodeString(*nonceHex)
	if e != nil || len(nonce) != 32 || hex.EncodeToString(nonce) != *nonceHex || *socket == "" || *robot == "" || *deployment == "" || *generation == "" {
		fmt.Fprintln(errs, "CORE_PROBE_INPUT")
		return 2
	}
	c, e := grpc.NewClient("unix://"+*socket, grpc.WithTransportCredentials(LocalReadCredentials()))
	if e != nil {
		fmt.Fprintln(errs, "CORE_PROBE_CONNECT")
		return 3
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r, e := pb.NewRobotAgentSelfProbeClient(c).ProbeSelf(ctx, &pb.ProbeSelfRequest{Nonce: nonce})
	if e != nil || r == nil {
		fmt.Fprintln(errs, "CORE_PROBE_UNAVAILABLE")
		return 3
	}
	if !bytes.Equal(r.Nonce, nonce) || r.AgentRobotId != *robot || r.DeploymentId != *deployment || r.AgentLoadedGeneration != *generation || r.AgentInstanceId == "" || r.UnavailableReason != "" || r.Upstream == nil || r.Upstream.Binding != pb.Binding_BOUND || r.ReportStorageState != "LOCAL_DISK" || r.CoreCommContract != "v1" {
		fmt.Fprintln(errs, "CORE_PROBE_NOT_READY")
		return 3
	}
	b, e := protojson.MarshalOptions{UseProtoNames: true}.Marshal(r)
	if e != nil {
		return 2
	}
	fmt.Fprintln(out, string(b))
	return 0
}
