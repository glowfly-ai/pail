// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"context"
	tokenpb "github.com/glowfly/pail/services/proto/tokenv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"testing"
)

type retryClient struct {
	tokenpb.TokenServiceClient
	ids  []string
	fail codes.Code
}

func (c *retryClient) GetActiveToken(ctx context.Context, r *tokenpb.GetActiveTokenRequest, o ...grpc.CallOption) (*tokenpb.GetActiveTokenResponse, error) {
	md, _ := metadata.FromOutgoingContext(ctx)
	v := md.Get("pail-grant-request-id")
	id := ""
	if len(v) == 1 {
		id = v[0]
	}
	c.ids = append(c.ids, id)
	if c.fail != codes.OK {
		return nil, status.Error(c.fail, "injected")
	}
	if len(c.ids) == 1 {
		return nil, status.Error(codes.Unavailable, "reply lost")
	}
	return &tokenpb.GetActiveTokenResponse{Status: tokenpb.ActiveTokenStatus_OK}, nil
}
func TestGrantRetryNonceScope(t *testing.T) {
	c := &retryClient{}
	m := &tokenMirror{c: c}
	r, e := m.getWithRetry(context.Background(), &tokenpb.GetActiveTokenRequest{RobotId: "robot-1"})
	if e != nil || r.Status != tokenpb.ActiveTokenStatus_OK || len(c.ids) != 2 || c.ids[0] == "" || c.ids[0] != c.ids[1] {
		t.Fatal("lost reply not retried as same RPC", c.ids, e)
	}
	m.getWithRetry(context.Background(), &tokenpb.GetActiveTokenRequest{RobotId: "robot-1"})
	if c.ids[2] == c.ids[0] {
		t.Fatal("new call reused nonce")
	}
	c = &retryClient{fail: codes.PermissionDenied}
	m.c = c
	m.getWithRetry(context.Background(), &tokenpb.GetActiveTokenRequest{})
	if len(c.ids) != 1 {
		t.Fatal("authorization failure retried")
	}
	c = &retryClient{fail: codes.Unavailable}
	m.c = c
	m.getWithRetry(context.Background(), &tokenpb.GetActiveTokenRequest{})
	if len(c.ids) != 3 {
		t.Fatal("unbounded or missing retries", len(c.ids))
	}
}
