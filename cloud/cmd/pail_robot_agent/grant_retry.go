// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"context"
	tokenpb "github.com/glowfly/pail/services/proto/tokenv1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"time"
)

// One nonce per single-flight call, never per robot or process. It is not
// retained after success/failure, Invalidate, or restart. Retrying a lost reply
// must not roll back the issuer's durable consumption/lease position.
func (m *tokenMirror) getWithRetry(ctx context.Context, req *tokenpb.GetActiveTokenRequest) (*tokenpb.GetActiveTokenResponse, error) {
	md, _ := metadata.FromOutgoingContext(ctx)
	md = md.Copy()
	md.Set("pail-grant-request-id", uuid.NewString())
	ctx = metadata.NewOutgoingContext(ctx, md)
	var resp *tokenpb.GetActiveTokenResponse
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		one, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		resp, err = m.c.GetActiveToken(one, req)
		cancel()
		if err == nil {
			return resp, nil
		}
		code := status.Code(err)
		if ctx.Err() != nil || (code != codes.Unavailable && code != codes.DeadlineExceeded) {
			return nil, err
		}
	}
	return resp, err
}
