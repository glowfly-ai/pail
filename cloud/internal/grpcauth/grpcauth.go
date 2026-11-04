// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// Package grpcauth centralizes gRPC control-plane authentication (LLD-v2 §3).
//
// SROS2 only protects ROS2 topics; without this, any process could forge
// ReportDecision(PERMIT, step_complete) or (ESTOP, fatal) against :50051.
// v2 requires mTLS on TCP (default on) or a Unix domain socket with file
// permissions for same-host deployments. Plaintext TCP is dev-only.
package grpcauth

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	DefaultCAPath   = "/etc/pail/grpc_certs/ca.crt"
	DefaultCertPath = "/etc/pail/grpc_certs/server.crt"
	DefaultKeyPath  = "/etc/pail/grpc_certs/server.key"

	DefaultClientCertPath = "/etc/pail/grpc_certs/client.crt"
	DefaultClientKeyPath  = "/etc/pail/grpc_certs/client.key"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// TLSEnabled reports whether PAIL_GRPC_TLS requests TLS. Default is on
// (fail-secure); only an explicit "off" disables it.
func TLSEnabled() bool {
	return envOr("PAIL_GRPC_TLS", "on") != "off"
}

// UDSPath returns PAIL_GRPC_UDS_PATH ("" = no UDS listener).
func UDSPath() string {
	return os.Getenv("PAIL_GRPC_UDS_PATH")
}

// ServerTLS builds mTLS server credentials: the server presents cert/key and
// requires a client certificate signed by the shared CA (mutual auth).
func ServerTLS(caPath, certPath, keyPath string) (credentials.TransportCredentials, error) {
	if caPath == "" {
		caPath = envOr("PAIL_GRPC_CA", DefaultCAPath)
	}
	if certPath == "" {
		certPath = envOr("PAIL_GRPC_CERT", DefaultCertPath)
	}
	if keyPath == "" {
		keyPath = envOr("PAIL_GRPC_KEY", DefaultKeyPath)
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("server cert/key: %w", err)
	}
	pool, err := loadCAPool(caPath)
	if err != nil {
		return nil, err
	}
	return credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}), nil
}

// ClientTLS builds mTLS client credentials (client cert + CA-pinned server).
//
// N-12 (crypto360): PAIL_GRPC_CERT/KEY 를 서버 역할과 나눠 쓰면 이중 역할
// 프로세스(robot-agent = northbound 서버 + cloud 상행 클라이언트)에서 한쪽
// 신원이 다른 쪽을 오염시킨다 — 서버가 로봇 클라이언트 인증서를 제시하는
// 것을 2026-08-12 라이브로 실측했다. 클라이언트 역할은 전용 이름을 먼저
// 읽고, 공유 이름은 순수 클라이언트(C++ 게이트·CLI 도구)의 폴백으로 남는다.
func ClientTLS(caPath, certPath, keyPath string) (credentials.TransportCredentials, error) {
	c, _, e := ClientTLSWithFingerprint(caPath, certPath, keyPath)
	return c, e
}

// ClientTLSWithFingerprint returns the fingerprint of the certificate actually loaded.
func ClientTLSWithFingerprint(caPath, certPath, keyPath string) (credentials.TransportCredentials, string, error) {
	if caPath == "" {
		caPath = envOr("PAIL_GRPC_CA", DefaultCAPath)
	}
	if certPath == "" {
		certPath = envOr("PAIL_GRPC_CLIENT_CERT", envOr("PAIL_GRPC_CERT", DefaultClientCertPath))
	}
	if keyPath == "" {
		keyPath = envOr("PAIL_GRPC_CLIENT_KEY", envOr("PAIL_GRPC_KEY", DefaultClientKeyPath))
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, "", fmt.Errorf("client cert/key: %w", err)
	}
	pool, err := loadCAPool(caPath)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(cert.Certificate[0])
	return credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
	}), hex.EncodeToString(sum[:]), nil
}

// ToolDialOptions builds dial options for CLI tools. UDS targets ("unix:...")
// rely on socket file permissions; TCP defaults to mTLS unless tlsOn is false.
func ToolDialOptions(addr string, tlsOn bool, ca, cert, key string) ([]grpc.DialOption, error) {
	if strings.HasPrefix(addr, "unix:") || !tlsOn {
		return []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}, nil
	}
	creds, err := ClientTLS(ca, cert, key)
	if err != nil {
		return nil, err
	}
	return []grpc.DialOption{grpc.WithTransportCredentials(creds)}, nil
}

func loadCAPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("ca: no certificate parsed from %s", path)
	}
	return pool, nil
}
