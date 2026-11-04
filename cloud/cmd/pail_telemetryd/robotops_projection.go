// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	ops "github.com/glowfly/pail/services/pkg/robotops"
)

// GET/HEAD /v1/telemetry/robotops (LLD §13.1): serves the sanitized projection
// snapshot the executor publishes. This process only reads the file; it never
// reads approvals, keys or private paths, and it never trusts a row because a
// file claims to be a projection. Pages are bound to one snapshot revision.
//
//	404  no projection configured (older deployments: feature unsupported)
//	503  SCHEMA_UNSUPPORTED / file unreadable
//	400  unknown parameter or malformed value
//	405  any method but GET/HEAD
//	304  If-None-Match equals the membership ETag
//	409  SNAPSHOT_CHANGED (cursor from another revision)
type projectionResponse struct {
	SchemaVersion    int                 `json:"schema_version"`
	SnapshotRevision uint64              `json:"snapshot_revision"`
	Source           string              `json:"source"`
	Producer         string              `json:"producer"`
	GeneratedAtMS    int64               `json:"generated_at_ms"`
	ServedAtMS       int64               `json:"served_at_ms"`
	Capabilities     []string            `json:"capabilities"`
	View             string              `json:"view"`
	Total            int                 `json:"total"`
	Rows             []ops.ProjectionRow `json:"rows"`
	NextCursor       string              `json:"next_cursor"`
	Stale            bool                `json:"stale"`
	StaleReason      string              `json:"stale_reason,omitempty"`
	Resolution       string              `json:"resolution"`
	Findings         []string            `json:"findings"`
}

type projectionSource struct {
	path     string
	maxAge   time.Duration
	now      func() time.Time
	readFile func(string) ([]byte, os.FileInfo, error)
}

func readProjectionFile(path string) ([]byte, os.FileInfo, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > ops.MaxDocument {
		return nil, nil, os.ErrInvalid
	}
	raw, err := os.ReadFile(path)
	return raw, fi, err
}

func newProjectionSource(path string, maxAge time.Duration) *projectionSource {
	return &projectionSource{path: path, maxAge: maxAge, now: time.Now, readFile: readProjectionFile}
}

func projectionHandler(src *projectionSource) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if src == nil || src.path == "" {
			http.Error(w, "robotops projection not configured", http.StatusNotFound)
			return
		}
		q := r.URL.Query()
		view, robot, limit, cursor := "inventory", "", 200, ""
		for k, vs := range q {
			if len(vs) != 1 {
				http.Error(w, "repeated parameter", http.StatusBadRequest)
				return
			}
			switch k {
			case "view":
				if vs[0] != "inventory" && vs[0] != "diagnostics" {
					http.Error(w, "view must be inventory or diagnostics", http.StatusBadRequest)
					return
				}
				view = vs[0]
			case "robot_id":
				if vs[0] == "" || len(vs[0]) > 128 {
					http.Error(w, "robot_id invalid", http.StatusBadRequest)
					return
				}
				robot = vs[0]
			case "limit":
				n, e := strconv.Atoi(vs[0])
				if e != nil || n < 1 || n > 1000 {
					http.Error(w, "limit must be 1..1000", http.StatusBadRequest)
					return
				}
				limit = n
			case "cursor":
				cursor = vs[0]
			default:
				http.Error(w, "unknown parameter "+k, http.StatusBadRequest)
				return
			}
		}
		raw, fi, err := src.readFile(src.path)
		if err != nil {
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "SCHEMA_UNSUPPORTED: projection unreadable", http.StatusServiceUnavailable)
			return
		}
		snap, err := ops.DecodeProjection(raw)
		if err != nil {
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "SCHEMA_UNSUPPORTED: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		// Quality must participate in conditional responses, before the 304 branch.
		now := src.now()
		stale, staleReason := projectionAge(snap.GeneratedAtMS, fi.ModTime(), now, src.maxAge)
		etag := ops.MembershipETag(snap)
		if stale {
			etag = strings.TrimSuffix(etag, "\"") + ":" + staleReason + "\""
		}
		w.Header().Set("ETag", etag)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Snapshot-Revision", strconv.FormatUint(snap.SnapshotRevision, 10))
		if match := r.Header.Get("If-None-Match"); match != "" && match == etag && cursor == "" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		offset := 0
		if cursor != "" {
			parts := strings.SplitN(cursor, ":", 2)
			rev, e1 := strconv.ParseUint(parts[0], 10, 64)
			off, e2 := 0, error(nil)
			if len(parts) == 2 {
				off, e2 = strconv.Atoi(parts[1])
			}
			if len(parts) != 2 || e1 != nil || e2 != nil || off < 0 {
				http.Error(w, "cursor malformed", http.StatusBadRequest)
				return
			}
			if rev != snap.SnapshotRevision {
				http.Error(w, "SNAPSHOT_CHANGED", http.StatusConflict)
				return
			}
			offset = off
		}
		resp := projectionResponse{SchemaVersion: 1, SnapshotRevision: snap.SnapshotRevision, Source: snap.Source, Producer: snap.Producer, GeneratedAtMS: snap.GeneratedAtMS, ServedAtMS: src.now().UnixMilli(), Capabilities: snap.Capabilities, View: view, Rows: []ops.ProjectionRow{}, Resolution: "resolved", Findings: append([]string{}, snap.Findings...)}
		resp.Stale, resp.StaleReason = stale, staleReason
		selected := []ops.ProjectionRow{}
		for _, row := range snap.Rows {
			if robot != "" && row.RobotID != robot {
				continue
			}
			selected = append(selected, row)
		}
		if robot != "" && len(selected) == 0 {
			resp.Resolution = "unresolved"
		}
		resp.Total = len(selected)
		if offset > len(selected) {
			offset = len(selected)
		}
		end := offset + limit
		if end > len(selected) {
			end = len(selected)
		}
		for _, row := range selected[offset:end] {
			if view == "inventory" {
				row.LoadedConfig, row.Diagnostics, row.Findings = nil, nil, nil
			}
			resp.Rows = append(resp.Rows, row)
		}
		if end < len(selected) {
			resp.NextCursor = strconv.FormatUint(snap.SnapshotRevision, 10) + ":" + strconv.Itoa(end)
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// A future clock is uncertain, not zero-age fresh. This is display quality,
// independent of management authorization or producer liveness.
func projectionAge(generated int64, modified, now time.Time, maxAge time.Duration) (bool, string) {
	if now.Before(modified) || generated > now.UnixMilli() {
		return true, "CLOCK_UNCERTAIN"
	}
	if now.Sub(modified) >= maxAge || now.UnixMilli()-generated >= maxAge.Milliseconds() {
		return true, "TTL_EXPIRED"
	}
	return false, ""
}
