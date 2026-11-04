// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package grpcauth

// Caller fingerprint for the context-provenance record (implementation contract, FB-1).
//
// Two fields, not one. A single "caller" string would make "we could not tell
// who this was" and "this arrived over a socket that has no certificate"
// collapse into the same bytes — and main.go registers the *same* service
// implementation on both the mTLS TCP listener and the plaintext UDS listener,
// so both shapes really do occur. caller_kind names the evidence available;
// caller_id names what that evidence said.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"syscall"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// Caller kinds — frozen vocabulary (implementation contract R-A / rule F6).
const (
	CallerMTLS    = "mtls"
	CallerUDS     = "uds"
	CallerUnknown = "unknown"
)

// UDSAuthInfo carries the peer credentials read at accept time. The read has to
// happen during the handshake because that is the only moment the raw socket is
// in our hands; afterwards gRPC owns the connection.
type UDSAuthInfo struct {
	UID, GID uint32
	HaveCred bool
}

func (UDSAuthInfo) AuthType() string { return "pail-uds" }

// udsCreds is a no-op transport (the socket's file mode is the access control,
// LLD-v2 §3) whose only job is to record who connected.
type udsCreds struct{}

// UDSCreds returns server credentials for the Unix domain socket listener.
func UDSCreds() credentials.TransportCredentials { return udsCreds{} }

func (udsCreds) ServerHandshake(c net.Conn) (net.Conn, credentials.AuthInfo, error) {
	var ai UDSAuthInfo
	if sc, ok := c.(syscall.Conn); ok {
		if raw, err := sc.SyscallConn(); err == nil {
			ai.UID, ai.GID, ai.HaveCred = peerCred(raw)
		}
	}
	return c, ai, nil
}

func (udsCreds) ClientHandshake(_ context.Context, _ string, c net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return c, UDSAuthInfo{}, nil
}

func (udsCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "pail-uds", SecurityVersion: "1.0"}
}

func (c udsCreds) Clone() credentials.TransportCredentials { return c }

func (udsCreds) OverrideServerName(string) error { return nil }

// CallerFromContext returns the (kind, id) pair to journal for this RPC.
//
// mtls: id = lowercase hex SHA-256 of the client leaf certificate DER. The DER
// is used rather than a subject string because the subject is chosen by whoever
// issued the certificate, while the DER is the exact bytes the CA signed.
//
// uds: id = "uid=<n>,gid=<n>". An empty id means the transport was a socket but
// the platform would not tell us the peer — which is a different fact from
// "unknown", and is recorded as such rather than upgraded or downgraded.
func CallerFromContext(ctx context.Context) (kind, id string) {
	p, ok := peer.FromContext(ctx)
	if !ok || p == nil {
		return CallerUnknown, ""
	}
	switch ai := p.AuthInfo.(type) {
	case credentials.TLSInfo:
		certs := ai.State.PeerCertificates
		if len(certs) == 0 {
			// TLS without a client certificate proves nothing about the caller.
			return CallerUnknown, ""
		}
		sum := sha256.Sum256(certs[0].Raw)
		return CallerMTLS, hex.EncodeToString(sum[:])
	case UDSAuthInfo:
		if !ai.HaveCred {
			return CallerUDS, ""
		}
		return CallerUDS, fmt.Sprintf("uid=%d,gid=%d", ai.UID, ai.GID)
	}
	if p.Addr != nil && p.Addr.Network() == "unix" {
		// Socket path without our credentials wrapper (an older wiring). Say so
		// instead of claiming a fingerprint we never took.
		return CallerUDS, ""
	}
	return CallerUnknown, ""
}
