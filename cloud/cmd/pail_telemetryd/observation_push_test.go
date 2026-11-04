// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/glowfly/pail/services/internal/identity"
	"github.com/glowfly/pail/services/internal/observability"
)

// OPSVIEW O7-01: the push listener binds the connection's certificate to a robot.

type pki struct {
	pool          *x509.CertPool
	server        tls.Certificate
	client, other tls.Certificate
	fingerprint   string
	caPEM         []byte
}

func leaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, name string, usage x509.ExtKeyUsage) (tls.Certificate, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, DNSNames: []string{"localhost"}}
	if usage == x509.ExtKeyUsageServerAuth {
		tpl.IPAddresses = nil
		tpl.DNSNames = []string{"localhost", "127.0.0.1"}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, hex.EncodeToString(sum[:])
}

func newPKI(t *testing.T) pki {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	server, _ := leaf(t, ca, caKey, "collector", x509.ExtKeyUsageServerAuth)
	client, fp := leaf(t, ca, caKey, "robot-1-observer", x509.ExtKeyUsageClientAuth)
	other, _ := leaf(t, ca, caKey, "stranger", x509.ExtKeyUsageClientAuth)
	return pki{pool: pool, server: server, client: client, other: other, fingerprint: fp, caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})}
}

// files writes the PKI as the fleet's prepare does: the CA, the collector's certificate and key.
func (k pki) files(t *testing.T) (ca, cert, key string) {
	t.Helper()
	dir := t.TempDir()
	der, _ := x509.MarshalECPrivateKey(k.server.PrivateKey.(*ecdsa.PrivateKey))
	for name, body := range map[string][]byte{"ca.crt": k.caPEM, "server.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: k.server.Certificate[0]}),
		"server.key": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "ca.crt"), filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
}

const pushDep = "5e8b24a0-2319-4a53-b5cf-a03afc977301"
const pushBoot = "2457dd0a-d7b1-42f6-b089-6ce0d5b2d8c3"

func pushCollector(t *testing.T) *observability.Collector {
	t.Helper()
	p := observability.Provider{ProviderID: "push-1", Kind: observability.PushKind, DeploymentID: pushDep, RobotID: "robot-1", Identity: "device-1", Allowed: []string{"motion", "liveness"},
		Owner: "actor", RunID: pushDep, StreamID: "ec054792-0db0-4162-83c1-ce2b7c401782", Trust: observability.PushTrust, Role: "primary"}
	c, err := observability.New(observability.SourceMap{SchemaVersion: 1, SourceID: "c68d3bdd-62b0-4721-9aec-9ea0d4ab0301", DeploymentID: pushDep, Providers: []observability.Provider{p}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func pushRecord(seq string, challenge string) map[string]any {
	return map[string]any{"schema_version": 2, "deployment_id": pushDep, "robot_id": "robot-1", "identity": "device-1", "owner": "actor", "run_id": pushDep, "kind": "liveness",
		"producer_instance_id": pushBoot, "stream_id": "ec054792-0db0-4162-83c1-ce2b7c401782", "producer_seq": seq, "observed_at_ms": time.Now().UnixMilli(), "clock_id": "robot-clock",
		"replayed": false, "challenge": challenge, "value": map[string]any{"state": "ALIVE", "component": "adapter", "physical_stop_proven": false}}
}

func TestOpsviewPushListener(t *testing.T) {
	k := newPKI(t)
	registry, err := identity.Parse([]byte("version: 1\nrobots:\n- robot_id: robot-1\n  role: robot\n  fingerprints:\n  - " + k.fingerprint + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	collector := pushCollector(t)
	srv := httptest.NewUnstartedServer(pushHandler(registry, collector))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{k.server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: k.pool}
	srv.StartTLS()
	defer srv.Close()
	client := func(cert *tls.Certificate) *http.Client {
		cfg := &tls.Config{RootCAs: k.pool, ServerName: "localhost", MinVersion: tls.VersionTLS13}
		if cert != nil {
			cfg.Certificates = []tls.Certificate{*cert}
		}
		return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 10 * time.Second}
	}
	post := func(c *http.Client, path string, body any) (int, string) {
		b, _ := json.Marshal(body)
		if s, ok := body.(string); ok {
			b = []byte(s)
		}
		resp, err := c.Post(srv.URL+path, "application/json", bytes.NewReader(b))
		if err != nil {
			return 0, err.Error()
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(out)
	}
	upload := func(robot string, records ...map[string]any) map[string]any {
		return map[string]any{"schema_version": 1, "robot_id": robot, "producer_instance_id": pushBoot, "records": records}
	}
	// the registered robot uploads: accepted, a challenge comes back, echoed next time
	status, body := post(client(&k.client), PushPath, upload("robot-1", pushRecord("1", "")))
	var result observability.PushResult
	if status != 200 || json.Unmarshal([]byte(body), &result) != nil || result.Accepted != 1 || len(result.Challenge) < 20 {
		t.Fatalf("first upload: %d %s", status, body)
	}
	status, body = post(client(&k.client), PushPath, upload("robot-1", pushRecord("2", result.Challenge)))
	if status != 200 || json.Unmarshal([]byte(body), &result) != nil || result.Accepted != 1 || len(result.Rejected) != 0 {
		t.Fatalf("second upload: %d %s", status, body)
	}
	if f := collector.Snapshot().Robots[0].Sources[0].Facets["liveness"]; f.FreshnessBasis != "challenge_bound" || f.Quality != "FRESH" {
		t.Fatalf("bound: %+v", f)
	}
	// the body names another robot than the certificate: refused, nothing taken
	status, body = post(client(&k.client), PushPath, upload("robot-2", pushRecord("3", "")))
	if status != 403 || !strings.Contains(body, "IDENTITY_UNBOUND:robot_id_mismatch") {
		t.Fatalf("other robot in body: %d %s", status, body)
	}
	// a record that names another robot inside an upload of robot-1
	rec := pushRecord("4", "")
	rec["robot_id"] = "robot-2"
	if status, body = post(client(&k.client), PushPath, upload("robot-1", rec)); status != 400 || !strings.Contains(body, "ROBOT_ID_MISMATCH") {
		t.Fatalf("record of another robot: %d %s", status, body)
	}
	// a certificate the registry does not know: refused before anything is read
	if status, body = post(client(&k.other), PushPath, upload("robot-1", pushRecord("5", ""))); status != 403 || !strings.Contains(body, "fingerprint_unregistered") {
		t.Fatalf("unregistered certificate: %d %s", status, body)
	}
	// no certificate: the handshake fails
	if status, body = post(client(nil), PushPath, upload("robot-1")); status != 0 || !strings.Contains(body, "tls") && !strings.Contains(body, "certificate") {
		t.Fatalf("no certificate: %d %s", status, body)
	}
	// form and bounds
	if status, _ = post(client(&k.client), PushPath, `{"schema_version":2,"robot_id":"robot-1","producer_instance_id":"`+pushBoot+`","records":[]}`); status != 400 {
		t.Fatalf("schema: %d", status)
	}
	if status, _ = post(client(&k.client), PushPath, `{"schema_version":1,"robot_id":"robot-1","robot_id":"robot-2","producer_instance_id":"`+pushBoot+`","records":[]}`); status != 400 {
		t.Fatalf("duplicate key: %d", status)
	}
	big := make([]map[string]any, 0, 300)
	for i := 0; i < 300; i++ {
		big = append(big, pushRecord("x", ""))
	}
	if status, body = post(client(&k.client), PushPath, upload("robot-1", big...)); status != 400 || !strings.Contains(body, "PUSH_TOO_MANY_RECORDS") {
		t.Fatalf("too many: %d %s", status, body)
	}
	if status, _ = post(client(&k.client), PushPath, strings.Repeat(" ", observability.PushMaxBytes+1)); status != 413 {
		t.Fatalf("oversize: %d", status)
	}
	if status, _ = post(client(&k.client), "/v1/observations/other", upload("robot-1")); status != 404 {
		t.Fatalf("path: %d", status)
	}
	resp, err := client(&k.client).Get(srv.URL + PushPath)
	if err != nil || resp.StatusCode != 405 {
		t.Fatalf("get: %v %v", err, resp)
	}
	// a robot the certificate names but the source map does not declare
	registry2, _ := identity.Parse([]byte("version: 1\nrobots:\n- robot_id: robot-9\n  role: robot\n  fingerprints:\n  - " + k.fingerprint + "\n"))
	srv2 := httptest.NewUnstartedServer(pushHandler(registry2, collector))
	srv2.TLS = srv.TLS
	srv2.StartTLS()
	defer srv2.Close()
	b, _ := json.Marshal(upload("robot-9", pushRecord("6", "")))
	resp, err = client(&k.client).Post(srv2.URL+PushPath, "application/json", bytes.NewReader(b))
	if err != nil || resp.StatusCode != 404 {
		t.Fatalf("undeclared robot: %v %v", err, resp)
	}
}

// The handler itself refuses a connection without a client certificate, whatever the
// listener in front of it verified: the second guard, reachable only if the first is gone.
func TestOpsviewPushHandlerWithoutCertificate(t *testing.T) {
	k := newPKI(t)
	registry, _ := identity.Parse([]byte("version: 1\nrobots:\n- robot_id: robot-1\n  role: robot\n  fingerprints:\n  - " + k.fingerprint + "\n"))
	h := pushHandler(registry, pushCollector(t))
	body, _ := json.Marshal(map[string]any{"schema_version": 1, "robot_id": "robot-1", "producer_instance_id": pushBoot, "records": []any{}})
	for name, state := range map[string]*tls.ConnectionState{"plain": nil, "tls without a peer": {}} {
		req := httptest.NewRequest("POST", PushPath, bytes.NewReader(body))
		req.TLS = state
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 403 || !strings.Contains(rec.Body.String(), "CLIENT_CERTIFICATE_REQUIRED") {
			t.Fatalf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
}

func TestOpsviewPushTLSFiles(t *testing.T) {
	if _, err := pushTLS("/nonexistent/ca.crt", "/nonexistent/s.crt", "/nonexistent/s.key"); err == nil || !strings.Contains(err.Error(), "push-ca") {
		t.Fatal(err)
	}
	// the listener as the collector starts it, from the files the fleet writes: only a client the
	// fleet CA signed gets in, and only over TLS 1.3
	k := newPKI(t)
	cfg, err := pushTLS(k.files(t))
	if err != nil {
		t.Fatal(err)
	}
	registry, _ := identity.Parse([]byte("version: 1\nrobots:\n- robot_id: robot-1\n  role: robot\n  fingerprints:\n  - " + k.fingerprint + "\n"))
	srv := httptest.NewUnstartedServer(pushHandler(registry, pushCollector(t)))
	srv.TLS = cfg
	srv.StartTLS()
	defer srv.Close()
	try := func(client *tls.Config) (int, string) {
		client.RootCAs, client.ServerName = k.pool, "localhost"
		b, _ := json.Marshal(map[string]any{"schema_version": 1, "robot_id": "robot-1", "producer_instance_id": pushBoot, "records": []any{}})
		resp, err := (&http.Client{Transport: &http.Transport{TLSClientConfig: client}, Timeout: 10 * time.Second}).Post(srv.URL+PushPath, "application/json", bytes.NewReader(b))
		if err != nil {
			return 0, err.Error()
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(out)
	}
	if status, body := try(&tls.Config{Certificates: []tls.Certificate{k.client}, MinVersion: tls.VersionTLS13}); status != 200 {
		t.Fatalf("the fleet's client: %d %s", status, body)
	}
	stranger := newPKI(t) // another CA
	if status, body := try(&tls.Config{Certificates: []tls.Certificate{stranger.client}, MinVersion: tls.VersionTLS13}); status != 0 || !strings.Contains(body, "tls") {
		t.Fatalf("a client of another CA: %d %s", status, body)
	}
	if status, body := try(&tls.Config{MinVersion: tls.VersionTLS13}); status != 0 || !strings.Contains(body, "tls") {
		t.Fatalf("no client certificate: %d %s", status, body)
	}
	if status, body := try(&tls.Config{Certificates: []tls.Certificate{k.client}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}); status != 0 || !strings.Contains(body, "tls") {
		t.Fatalf("TLS 1.2: %d %s", status, body)
	}
}
