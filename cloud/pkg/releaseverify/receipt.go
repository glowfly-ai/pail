// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package releaseverify

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// ReceiptSchemaVersion is the receipt schema this verifier writes (design
// PAIL-p43 §2: v2 adds the tree digest fields; a v1 receipt is "ZIP only").
const ReceiptSchemaVersion = 2

// Receipt records one PASS of the verifier on this host; the launcher reads it
// back by release_id + lock_sha256[:16]. Field order is the JSON key order.
type Receipt struct {
	SchemaVersion            int        `json:"schema_version"`
	ReleaseID                string     `json:"release_id"`
	Artifact                 string     `json:"artifact"`
	ZipSHA256                string     `json:"zip_sha256"`
	ManifestSHA256           string     `json:"manifest_sha256"`
	LockSHA256               string     `json:"lock_sha256"`
	Signature                string     `json:"signature"`       // VERIFIED | CHECKSUMS_ONLY
	KeyFingerprint           *string    `json:"key_fingerprint"` // null when no signature was verified
	ExpectedFingerprintGiven bool       `json:"expected_fingerprint_given"`
	Backend                  *string    `json:"backend"` // null when no signature was verified
	VerifierNote             string     `json:"verifier_note"`
	Tool                     string     `json:"tool"`
	Files                    int        `json:"files"`      // ZIP entry count
	TreeScope                string     `json:"tree_scope"` // TreeScope
	TreeFiles                int        `json:"tree_files"` // keys compared (manifest files except images/)
	TreeSHA256               string     `json:"tree_sha256"`
	TreeMatched              *bool      `json:"tree_matched"` // null when the tree was not compared
	TreeMismatches           []Mismatch `json:"tree_mismatches"`
	At                       string     `json:"at"` // UTC, 2006-01-02T15:04:05Z
}

// String returns a pointer for the nullable receipt fields.
func String(s string) *string { return &s }

// Bool returns a pointer for the nullable receipt fields.
func Bool(b bool) *bool { return &b }

// ReceiptTimeLayout is the `at` format.
const ReceiptTimeLayout = "2006-01-02T15:04:05Z"

// ErrReceiptKept is returned by WriteReceipt when the existing receipt at the
// target path recorded a matching tree and this run's tree is modified: the
// evidence of the clean run is kept, nothing is written.
// ErrReceiptKeptNotCompared is the same rule for a run that did not compare
// the tree at all (tree_matched null).
var (
	ErrReceiptKept            = errors.New("existing receipt matched the tree; this run's tree is modified")
	ErrReceiptKeptNotCompared = errors.New("existing receipt matched the tree; this run did not compare the tree")
)

// IsReceiptKept reports whether err is one of the kept sentinels.
func IsReceiptKept(err error) bool {
	return errors.Is(err, ErrReceiptKept) || errors.Is(err, ErrReceiptKeptNotCompared)
}

// ReceiptName is <release_id>-<lock_sha256[:16]>.json.
func ReceiptName(releaseID, lockSHA256 string) string {
	short := lockSHA256
	if len(short) > 16 {
		short = short[:16]
	}
	return releaseID + "-" + short + ".json"
}

// existingTreeMatched reports whether a parseable receipt at path says
// tree_matched == true.
func existingTreeMatched(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var old struct {
		TreeMatched *bool `json:"tree_matched"`
	}
	if err := json.Unmarshal(data, &old); err != nil {
		return false
	}
	return old.TreeMatched != nil && *old.TreeMatched
}

// WriteReceipt creates dir (0700) and writes the receipt atomically
// (temp file + rename), JSON indented by two spaces with a trailing newline.
// When the receipt already at the target path has tree_matched true and r has
// tree_matched false or null, nothing is written: the existing path is
// returned with ErrReceiptKept / ErrReceiptKeptNotCompared.
func WriteReceipt(dir string, r Receipt) (string, error) {
	if r.ReleaseID == "" || r.LockSHA256 == "" {
		return "", errors.New("release_id and lock_sha256 are required")
	}
	if r.SchemaVersion == 0 {
		r.SchemaVersion = ReceiptSchemaVersion
	}
	if r.TreeMismatches == nil {
		r.TreeMismatches = []Mismatch{}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	target := filepath.Join(dir, ReceiptName(r.ReleaseID, r.LockSHA256))
	if (r.TreeMatched == nil || !*r.TreeMatched) && existingTreeMatched(target) {
		if r.TreeMatched == nil {
			return target, ErrReceiptKeptNotCompared
		}
		return target, ErrReceiptKept
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(dir, ".receipt-*.tmp")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return "", err
	}
	if err := os.Rename(tmpName, target); err != nil {
		os.Remove(tmpName)
		return "", err
	}
	return target, nil
}
