// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package grpclive

import (
	"context"
	tokenpb "github.com/glowfly/pail/services/proto/tokenv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const ExecutionHeader = "pail-execution-instance"

// ExecutionContext forwards protocol metadata, not a caller's transport identity.
func ExecutionContext(ctx context.Context) context.Context {
	in, _ := metadata.FromIncomingContext(ctx)
	out, _ := metadata.FromOutgoingContext(ctx)
	out = out.Copy()
	for _, key := range []string{ExecutionHeader, "pail-execution-reset", "pail-grant-request-id"} {
		if values := in.Get(key); len(values) > 0 {
			out.Set(key, values...)
		}
	}
	return metadata.NewOutgoingContext(ctx, out)
}

func SendExecutionHeaders(ctx context.Context, headers metadata.MD) error {
	values := headers.Get(ExecutionHeader)
	if len(values) == 0 {
		return nil
	}
	return grpc.SetHeader(ctx, metadata.MD{ExecutionHeader: append([]string(nil), values...)})
}

// TokenCall carries only the real upstream execution acknowledgement. Returned
// headers can be pinned with a replayed response; never mint a fresh ACK for it.
func TokenCall(ctx context.Context, client tokenpb.TokenServiceClient, req *tokenpb.GetActiveTokenRequest) (*tokenpb.GetActiveTokenResponse, metadata.MD, error) {
	var headers metadata.MD
	resp, err := client.GetActiveToken(ExecutionContext(ctx), req, grpc.Header(&headers))
	if err != nil {
		return nil, nil, err
	}
	if err = SendExecutionHeaders(ctx, headers); err != nil {
		return nil, nil, err
	}
	return resp, headers.Copy(), nil
}

// EchoFixtureExecution is for a deliberately synthetic test TokenService, not
// for a proxy: a proxy must carry its real peer's response via TokenCall.
func EchoFixtureExecution(ctx context.Context) error {
	in, _ := metadata.FromIncomingContext(ctx)
	return SendExecutionHeaders(ctx, in)
}
