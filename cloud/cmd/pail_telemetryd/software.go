// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"

	"github.com/glowfly/pail/services/internal/blackbox"
	"github.com/glowfly/pail/services/internal/buildinfo"
)

// GET /v1/telemetry/software (EC-2, EUC D2): which build of each component the
// chain says is running, and whether the SBOM on disk is the one that build
// claims. Every answer is a word, never a fold:
//
//	source           sealed (chain has ATTESTATION/CONFIG_SEALED for it) · unsealed
//	build_info_state valid · invalid (present but not the 7-token form) · absent
//	sbom.state       present (file there and sha256 == claim) · hash_mismatch ·
//	                 absent (no file) · unclaimed (file there, build_info claims no hash)
//
// The rows are the closed component vocabulary, so a component that never
// attested is a row that says so — not a missing row. Reads the chain
// directly (blackbox.WalkDir) rather than the ledger index: the index carries
// no build_info column and adding one is a schema bump for a value that is
// read once per query.

type sbomView struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Format string `json:"format"`
	State  string `json:"state"`
}

type softwareComponent struct {
	Component      string   `json:"component"`
	BuildInfo      string   `json:"build_info"`
	BuildInfoState string   `json:"build_info_state"`
	Source         string   `json:"source"`
	Kind           string   `json:"kind"`
	Seq            uint64   `json:"seq"`
	UnixMs         uint64   `json:"unix_ms"`
	Error          string   `json:"error,omitempty"`
	SBOM           sbomView `json:"sbom"`
}

type softwareResponse struct {
	Version    int                 `json:"version"`
	Source     string              `json:"source"`
	SBOMDir    string              `json:"sbom_dir"`
	Components []softwareComponent `json:"components"`
	Errors     []string            `json:"errors"`
}

// sbomFileFor maps a component to the SBOM file its image ships. The four Go
// components are one module and one image, so they share one part list; the
// mirror ships inside the gate image.
func sbomFileFor(component string) string {
	switch component {
	case "pep_gate", "permit_mirror":
		return "pep_gate.cdx.json"
	}
	return "pail_services_go.cdx.json"
}

type sealedBuild struct {
	buildInfo string
	kind      string
	seq       uint64
	unixMs    uint64
}

// latestBuilds walks the chain once and keeps, per component, the newest
// record that carries a build_info field. A record whose payload does not
// parse is counted, not skipped silently.
func latestBuilds(dir string) (map[string]sealedBuild, int, error) {
	out := map[string]sealedBuild{}
	skipped := 0
	_, err := blackbox.WalkDir(dir, func(r blackbox.Record) error {
		var kind string
		switch r.Type {
		case blackbox.RecordAttestation:
			kind = "ATTESTATION"
		case blackbox.RecordConfigSealed:
			kind = "CONFIG_SEALED"
		default:
			return nil
		}
		var p struct {
			Component string `json:"component"`
			BuildInfo string `json:"build_info"`
		}
		if json.Unmarshal(r.Payload, &p) != nil || p.Component == "" {
			skipped++
			return nil
		}
		out[p.Component] = sealedBuild{buildInfo: p.BuildInfo, kind: kind, seq: r.SegmentSeq, unixMs: r.UnixMs}
		return nil
	})
	return out, skipped, err
}

func sbomState(dir, file, claim string) sbomView {
	v := sbomView{File: file, Format: "cyclonedx-json"}
	b, err := os.ReadFile(filepath.Join(dir, file))
	if err != nil {
		v.State = "absent"
		return v
	}
	sum := sha256.Sum256(b)
	v.SHA256 = hex.EncodeToString(sum[:])
	switch {
	case claim == "":
		v.State = "unclaimed"
	case claim == v.SHA256:
		v.State = "present"
	default:
		v.State = "hash_mismatch"
	}
	return v
}

func softwareView(blackboxDir, sbomDir string) (softwareResponse, int) {
	out := softwareResponse{Version: 1, SBOMDir: sbomDir, Components: []softwareComponent{}, Errors: []string{}}
	builds, skipped, err := latestBuilds(blackboxDir)
	if err != nil {
		out.Source = "unreadable"
		out.Errors = append(out.Errors, err.Error())
		return out, http.StatusServiceUnavailable
	}
	out.Source = "chain"
	if skipped > 0 {
		out.Errors = append(out.Errors, "skipped records with unreadable payload: "+itoa(skipped))
	}
	for _, c := range buildinfo.Components {
		row := softwareComponent{Component: c, Source: "unsealed", BuildInfoState: "absent"}
		claim := ""
		if b, ok := builds[c]; ok {
			row.Source, row.Kind, row.Seq, row.UnixMs, row.BuildInfo = "sealed", b.kind, b.seq, b.unixMs, b.buildInfo
			if b.buildInfo != "" {
				if info, perr := buildinfo.Parse(b.buildInfo); perr != nil {
					row.BuildInfoState = "invalid"
					row.Error = perr.Error()
				} else {
					row.BuildInfoState = "valid"
					claim = info.SBOMSHA256
				}
			}
		}
		row.SBOM = sbomState(sbomDir, sbomFileFor(c), claim)
		out.Components = append(out.Components, row)
	}
	return out, http.StatusOK
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func softwareHandler(blackboxDir, sbomDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		view, code := softwareView(blackboxDir, sbomDir)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(view)
	}
}
