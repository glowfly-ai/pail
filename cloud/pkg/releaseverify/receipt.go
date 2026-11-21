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

// A receipt is kept when the run that would replace it is weaker (kept
// sentinels below; nothing is written and the existing path is returned).
//
// ErrReceiptKept / ErrReceiptKeptNotCompared: the existing receipt recorded a
// matching tree and this run's tree is modified / was not compared (P42-L1).
// ErrReceiptKeptSignature / ErrReceiptKeptPublisherKey (P024-L1): the existing
// receipt of the SAME manifest verified the signature / compared the publisher
// key and this run did not.
var (
	ErrReceiptKept             = errors.New("existing receipt matched the tree; this run's tree is modified")
	ErrReceiptKeptNotCompared  = errors.New("existing receipt matched the tree; this run did not compare the tree")
	ErrReceiptKeptSignature    = errors.New("existing receipt verified the signature; this run accepted checksums only")
	ErrReceiptKeptPublisherKey = errors.New("existing receipt compared the publisher key; this run did not")
)

// IsReceiptKept reports whether err is one of the kept sentinels.
func IsReceiptKept(err error) bool {
	return errors.Is(err, ErrReceiptKept) || errors.Is(err, ErrReceiptKeptNotCompared) ||
		errors.Is(err, ErrReceiptKeptSignature) || errors.Is(err, ErrReceiptKeptPublisherKey)
}

// ReceiptName is <release_id>-<lock_sha256[:16]>.json.
func ReceiptName(releaseID, lockSHA256 string) string {
	short := lockSHA256
	if len(short) > 16 {
		short = short[:16]
	}
	return releaseID + "-" + short + ".json"
}

// existingReceipt is what a receipt already at the target path recorded on
// the axes a later run may not weaken; ok is false when there is none, it
// does not parse, or it predates schema 2 (such a file is always replaced).
type existingReceipt struct {
	SchemaVersion            int    `json:"schema_version"`
	ManifestSHA256           string `json:"manifest_sha256"`
	Signature                string `json:"signature"`
	ExpectedFingerprintGiven bool   `json:"expected_fingerprint_given"`
	TreeMatched              *bool  `json:"tree_matched"`
}

func readExisting(path string) (existingReceipt, bool) {
	var old existingReceipt
	data, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(data, &old) != nil || old.SchemaVersion < 2 {
		return old, false
	}
	return old, true
}

// receiptKept is the precedence rule, the same as receipt_kept_reason of
// verification_receipt.py and tested against the same table
// (testdata/releaseverify/receipt_precedence.json).
//
// Same manifest bytes: the runs are about one signed object and are ordered
// by (signature verified, publisher key compared, tree matched),
// lexicographically; the first axis that differs decides. The signature and
// the key comparison exist only in a verifier run; the tree is last because
// the launcher re-hashes it on every start. Another manifest, or a receipt
// naming none: only the tree rule of P42-L1 applies, as before.
func receiptKept(old existingReceipt, r Receipt) error {
	treeOld := old.TreeMatched != nil && *old.TreeMatched
	treeNew := r.TreeMatched != nil && *r.TreeMatched
	treeErr := ErrReceiptKept
	if r.TreeMatched == nil {
		treeErr = ErrReceiptKeptNotCompared
	}
	if old.ManifestSHA256 != "" && old.ManifestSHA256 == r.ManifestSHA256 {
		axes := []struct {
			was, now bool
			kept     error
		}{
			{old.Signature == "VERIFIED", r.Signature == "VERIFIED", ErrReceiptKeptSignature},
			{old.ExpectedFingerprintGiven, r.ExpectedFingerprintGiven, ErrReceiptKeptPublisherKey},
			{treeOld, treeNew, treeErr},
		}
		for _, a := range axes {
			if a.was != a.now {
				if a.was {
					return a.kept
				}
				return nil
			}
		}
		return nil
	}
	if treeOld && !treeNew {
		return treeErr
	}
	return nil
}

// WriteReceipt creates dir (0700) and writes the receipt atomically
// (temp file + rename), JSON indented by two spaces with a trailing newline.
// When the receipt already at the target path is stronger than r (receiptKept),
// nothing is written: the existing path is returned with a kept sentinel.
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
	if old, ok := readExisting(target); ok {
		if kept := receiptKept(old, r); kept != nil {
			return target, kept
		}
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
