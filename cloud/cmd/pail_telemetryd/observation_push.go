// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/glowfly/pail/services/internal/grpcauth"
	"github.com/glowfly/pail/services/internal/identity"
	"github.com/glowfly/pail/services/internal/observability"
)

// The push listener (design 15.1): a robot on another machine uploads its
// observation records over a connection it authenticates with its own
// certificate. The robot is the one the registry names for that certificate;
// a body that names another robot is refused. The listener is separate from
// the query API and answers one thing only.
const PushPath = "/v1/observations/push"

type pushUpload struct {
	SchemaVersion int                   `json:"schema_version"`
	RobotID       string                `json:"robot_id"`
	Producer      string                `json:"producer_instance_id"`
	Records       []observability.Event `json:"records"`
}

func pushTLS(caPath, certPath, keyPath string) (*tls.Config, error) {
	ca, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("push-ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("push-ca: no certificate in file")
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("push-cert/key: %w", err)
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}, nil
}

// pushHandler judges one upload. registry: fingerprint -> robot; collector: the
// push provider of that robot and the challenge of every record.
func pushHandler(registry *identity.Registry, collector *observability.Collector) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.Path != PushPath {
			http.Error(w, "NOT_FOUND", 404)
			return
		}
		if r.Method != "POST" {
			w.Header().Set("Allow", "POST")
			http.Error(w, "METHOD_NOT_ALLOWED", 405)
			return
		}
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "CLIENT_CERTIFICATE_REQUIRED", 403)
			return
		}
		sum := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
		fingerprint := hex.EncodeToString(sum[:])
		body, err := io.ReadAll(io.LimitReader(r.Body, observability.PushMaxBytes+1))
		if err != nil || len(body) > observability.PushMaxBytes {
			http.Error(w, "PUSH_OVERSIZE", 413)
			return
		}
		var up pushUpload
		if err := observability.StrictJSON(body, &up); err != nil || up.SchemaVersion != 1 {
			http.Error(w, "PUSH_SCHEMA", 400)
			return
		}
		// the robot is the one the certificate is registered for, and the body must agree
		binding := registry.Bind(grpcauth.CallerMTLS, fingerprint, up.RobotID)
		if binding.Verdict != identity.Bound {
			http.Error(w, "IDENTITY_UNBOUND:"+binding.Reason, 403)
			return
		}
		provider, ok := collector.PushProvider(up.RobotID)
		if !ok {
			http.Error(w, "PUSH_SOURCE_NOT_DECLARED", 404)
			return
		}
		for _, e := range up.Records {
			if e.RobotID != up.RobotID {
				http.Error(w, "ROBOT_ID_MISMATCH", 400)
				return
			}
		}
		result, err := collector.Push(provider, up.Producer, up.Records)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})
}

func servePush(addr, caPath, certPath, keyPath string, registry *identity.Registry, collector *observability.Collector) error {
	cfg, err := pushTLS(caPath, certPath, keyPath)
	if err != nil {
		return err
	}
	srv := &http.Server{Addr: addr, Handler: pushHandler(registry, collector), TLSConfig: cfg, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10}
	return srv.ListenAndServeTLS("", "")
}
