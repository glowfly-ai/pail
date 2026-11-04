// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package grpcauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func ctxWith(ai credentials.AuthInfo, addr net.Addr) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{Addr: addr, AuthInfo: ai})
}

type unixAddr struct{}

func (unixAddr) Network() string { return "unix" }
func (unixAddr) String() string  { return "/tmp/x.sock" }

func selfSignedDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pail-test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	return der
}

// TestCallerFromContext_Shapes — FB-1 의 요구는 "네 상태가 서로 다른 바이트를
// 낸다"는 것이다. 지문이 한 필드였다면 UDS 와 unknown 이 같은 값이 됐고,
// 그것이 H7 위반이다 .
func TestCallerFromContext_Shapes(t *testing.T) {
	der := selfSignedDER(t)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	sum := sha256.Sum256(der)
	wantMTLS := hex.EncodeToString(sum[:])

	tlsWith := credentials.TLSInfo{State: tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert}}}
	tlsBare := credentials.TLSInfo{}

	cases := []struct {
		name     string
		ctx      context.Context
		wantKind string
		wantID   string
	}{
		{"no_peer", context.Background(), CallerUnknown, ""},
		{"mtls", ctxWith(tlsWith, nil), CallerMTLS, wantMTLS},
		{"tls_no_client_cert", ctxWith(tlsBare, nil), CallerUnknown, ""},
		// CX1-03 의 caller_id 와 같은 문자열이어야 한다.
		{"uds_cred", ctxWith(UDSAuthInfo{UID: 0, GID: 0, HaveCred: true}, unixAddr{}),
			CallerUDS, "uid=0,gid=0"},
		{"uds_no_cred", ctxWith(UDSAuthInfo{}, unixAddr{}), CallerUDS, ""},
		{"unix_addr_only", ctxWith(nil, unixAddr{}), CallerUDS, ""},
	}

	seen := map[string]string{}
	for _, c := range cases {
		kind, id := CallerFromContext(c.ctx)
		t.Logf("CALLER %s -> kind=%s id=%q", c.name, kind, id)
		if kind != c.wantKind || id != c.wantID {
			t.Errorf("%s: got (%s,%q) want (%s,%q)", c.name, kind, id, c.wantKind, c.wantID)
		}
		// mtls/uds/unknown 자체는 겹쳐도 되지만, (kind,id) 쌍은 서로 다른
		// 사실이면 서로 달라야 한다.
		key := kind + "\x00" + id
		if prev, dup := seen[key]; dup && prev != c.name {
			t.Logf("동일 지문 공유: %s ≡ %s (%s)", prev, c.name, key)
		}
		seen[key] = c.name
	}

	// UDS(자격 없음)와 unknown 이 구별되는지 — FB-1 의 정확한 요지.
	uk, ui := CallerFromContext(ctxWith(UDSAuthInfo{}, unixAddr{}))
	nk, ni := CallerFromContext(context.Background())
	if uk == nk && ui == ni {
		t.Fatal("UDS(자격 미상)와 unknown 이 같은 지문을 낸다 — H7 위반")
	}
}

// TestUDSCreds_RealPeerCred — 실제 유닉스 소켓 위에서 SO_PEERCRED 를 읽는다.
// 리눅스에서만 값이 나오는 것이 설계다. macOS 에서는 kind=uds/id="" 로
// 정직하게 비어야 하며, 그 정직함 자체를 여기서 확인한다.
func TestUDSCreds_RealPeerCred(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "p.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type res struct {
		kind, id string
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			ch <- res{"accept-error", err.Error()}
			return
		}
		defer c.Close()
		_, ai, err := udsCreds{}.ServerHandshake(c)
		if err != nil {
			ch <- res{"handshake-error", err.Error()}
			return
		}
		k, id := CallerFromContext(ctxWith(ai, c.RemoteAddr()))
		ch <- res{k, id}
	}()

	cc, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cc.Close()

	select {
	case r := <-ch:
		t.Logf("UDS-PEERCRED os=%s kind=%s id=%q", runtime.GOOS, r.kind, r.id)
		if r.kind != CallerUDS {
			t.Fatalf("kind=%s id=%q — uds 여야 한다", r.kind, r.id)
		}
		if runtime.GOOS == "linux" {
			want := "uid=" + itoa(os.Getuid()) + ",gid=" + itoa(os.Getgid())
			if r.id != want {
				t.Fatalf("id=%q — 리눅스에서는 %q 여야 한다", r.id, want)
			}
		} else if r.id != "" {
			t.Fatalf("id=%q — 비리눅스에서는 비어 있어야 한다(없는 사실을 지어내지 않는다)", r.id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handshake timeout")
	}
}

func itoa(n int) string { return big.NewInt(int64(n)).String() }
