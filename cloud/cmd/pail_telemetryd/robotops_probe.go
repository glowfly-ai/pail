// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"encoding/hex"
	"github.com/glowfly/pail/services/internal/buildinfo"
	"github.com/glowfly/pail/services/internal/telemetry"
	ops "github.com/glowfly/pail/services/pkg/robotops"
	"github.com/google/uuid"
	"net/http"
	"net/url"
	"time"
)

// The surrounding auth wrapper is the existing dashboard access policy. No
// new token/management capability or configuration mutation is introduced.
func collectorProbeHandler(path string) http.HandlerFunc {
	instance := uuid.NewString()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", 405)
			return
		}
		q, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			http.Error(w, "invalid query", 400)
			return
		}
		nonce := q.Get("nonce")
		decoded, e := hex.DecodeString(nonce)
		if e != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != nonce || len(q) != 1 || len(q["nonce"]) != 1 {
			http.Error(w, "one lowercase 32-byte nonce required", 400)
			return
		}
		// registryView is also used by registry membership and ledger name resolution.
		// Digest and names come from the SAME successful identity.Parse invocation.
		view := registryView(path)
		result := ops.CollectorProbe{SchemaVersion: 1, Component: "telemetryd", InstanceID: instance, BuildID: buildinfo.String("telemetryd"), Nonce: nonce, GeneratedAtMS: time.Now().UnixMilli(), ResolutionStrategy: "per_request", RegistryState: view.Source, RegistryDigest: view.Digest, Robots: []ops.CollectorRobot{}, EvidenceKind: "query_time_process_self_report"}
		for _, robot := range view.Robots {
			result.Robots = append(result.Robots, ops.CollectorRobot{RobotID: robot.RobotID, RobotHash: robot.RobotHash})
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, result)
	}
}

func collectorSignalsHandler(path string, live *telemetry.LiveSignals) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", 405)
			return
		}
		q, e := url.ParseQuery(r.URL.RawQuery)
		nonce := q.Get("nonce")
		b, err := hex.DecodeString(nonce)
		if e != nil || err != nil || len(b) != 32 || hex.EncodeToString(b) != nonce || len(q) != 1 || len(q["nonce"]) != 1 {
			http.Error(w, "one lowercase 32-byte nonce required", 400)
			return
		}
		if live == nil {
			http.Error(w, "SIGNAL_SOURCE_UNAVAILABLE", 503)
			return
		}
		v := live.Current(nonce)
		registry := registryView(path)
		v.RegistryState = registry.Source
		v.RegistryDigest = registry.Digest
		for _, robot := range registry.Robots {
			v.RegistryRobots = append(v.RegistryRobots, ops.CollectorRobot{RobotID: robot.RobotID, RobotHash: robot.RobotHash})
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, v)
	}
}
