// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package grpcauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (ca *testCA) issue(t *testing.T, cn string, dir string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, cn+".crt")
	keyPath = filepath.Join(dir, cn+".key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func startTLSServer(t *testing.T, caPath, certPath, keyPath string) string {
	t.Helper()
	creds, err := ServerTLS(caPath, certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.Creds(creds))
	healthpb.RegisterHealthServer(srv, health.NewServer())
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	return lis.Addr().String()
}

func TestMutualTLSAcceptsAuthorizedClient(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t)
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, ca.pem, 0o600); err != nil {
		t.Fatal(err)
	}
	sCert, sKey := ca.issue(t, "server", dir)
	cCert, cKey := ca.issue(t, "client", dir)

	addr := startTLSServer(t, caPath, sCert, sKey)

	creds, err := ClientTLS(caPath, cCert, cKey)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{}); err != nil {
		t.Fatalf("authorized mTLS client must succeed: %v", err)
	}
}

func TestMutualTLSRejectsClientWithoutCert(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t)
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, ca.pem, 0o600); err != nil {
		t.Fatal(err)
	}
	sCert, sKey := ca.issue(t, "server", dir)
	addr := startTLSServer(t, caPath, sCert, sKey)

	// plaintext client (the as-built InsecureChannelCredentials attacker)
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{}); err == nil {
		t.Fatal("plaintext client must be rejected by mTLS server")
	}
}

func TestMutualTLSRejectsForeignCA(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t)
	rogue := newTestCA(t)
	caPath := filepath.Join(dir, "ca.crt")
	roguePath := filepath.Join(dir, "rogue_ca.crt")
	if err := os.WriteFile(caPath, ca.pem, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(roguePath, rogue.pem, 0o600); err != nil {
		t.Fatal(err)
	}
	sCert, sKey := ca.issue(t, "server", dir)
	rCert, rKey := rogue.issue(t, "attacker", dir)
	addr := startTLSServer(t, caPath, sCert, sKey)

	// client cert signed by a different (attacker) CA
	creds, err := ClientTLS(caPath, rCert, rKey)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{}); err == nil {
		t.Fatal("client signed by foreign CA must be rejected")
	}
}
