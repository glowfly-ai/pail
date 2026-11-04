// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package robotops

import (
	"context"
	"fmt"
	"github.com/glowfly/pail/services/internal/grpcauth"
	"google.golang.org/grpc/credentials"
	"net"
	"os"
)

// LocalReadCredentials verifies the connected Unix server's kernel credentials,
// not merely the owner of a pathname observed before the connection.
func LocalReadCredentials() credentials.TransportCredentials { return localReadCreds{} }

type localReadCreds struct{}

func (localReadCreds) ClientHandshake(ctx context.Context, _ string, c net.Conn) (net.Conn, credentials.AuthInfo, error) {
	wrapped, ai, e := grpcauth.UDSCreds().ServerHandshake(c)
	if e != nil {
		return nil, nil, e
	}
	id, ok := ai.(grpcauth.UDSAuthInfo)
	if !ok || !id.HaveCred || (id.UID != 0 && id.UID != uint32(os.Geteuid())) {
		return nil, nil, fmt.Errorf("RO_LOCAL_SERVER_OWNER_REQUIRED")
	}
	return wrapped, ai, nil
}
func (localReadCreds) ServerHandshake(net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, fmt.Errorf("client-only credentials")
}
func (localReadCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "pail-local-read"}
}
func (localReadCreds) Clone() credentials.TransportCredentials { return localReadCreds{} }
func (localReadCreds) OverrideServerName(string) error         { return nil }
