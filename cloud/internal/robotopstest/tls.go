// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package robotopstest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"google.golang.org/grpc/credentials"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// WireTLS creates ephemeral test credentials only in memory.
func WireTLS(t *testing.T) (credentials.TransportCredentials, credentials.TransportCredentials, string) {
	return wireTLS(t, "")
}

// WireTLSFiles writes short-lived test-only credentials to a private test directory.
func WireTLSFiles(t *testing.T, dir string) (credentials.TransportCredentials, credentials.TransportCredentials, string) {
	return wireTLS(t, dir)
}
func wireTLS(t *testing.T, dir string) (credentials.TransportCredentials, credentials.TransportCredentials, string) {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-only CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	ca, e = x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	leaf := func(serial int64, server bool) tls.Certificate {
		p, k, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		usage := x509.ExtKeyUsageClientAuth
		if server {
			usage = x509.ExtKeyUsageServerAuth
		}
		c := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "not-robot-id"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, ExtKeyUsage: []x509.ExtKeyUsage{usage}, KeyUsage: x509.KeyUsageDigitalSignature}
		b, e := x509.CreateCertificate(rand.Reader, c, ca, p, key)
		if e != nil {
			t.Fatal(e)
		}
		return tls.Certificate{Certificate: [][]byte{b}, PrivateKey: k}
	}
	server, client := leaf(2, true), leaf(3, false)
	if dir != "" {
		if e := os.MkdirAll(dir, 0700); e != nil {
			t.Fatal(e)
		}
		write := func(name string, b []byte) {
			if e := os.WriteFile(filepath.Join(dir, name), b, 0600); e != nil {
				t.Fatal(e)
			}
		}
		write("ca.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		for name, c := range map[string]tls.Certificate{"server": server, "client": client} {
			write(name+".crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate[0]}))
			key, e := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
			if e != nil {
				t.Fatal(e)
			}
			write(name+".key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
		}
	}

	h := sha256.Sum256(client.Certificate[0])
	return credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{server}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}), credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{client}, RootCAs: pool, ServerName: "localhost"}), hex.EncodeToString(h[:])
}
