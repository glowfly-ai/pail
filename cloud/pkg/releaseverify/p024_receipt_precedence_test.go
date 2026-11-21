// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package releaseverify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// P024-L1 (0.2.4 recipient evaluation): which run a verification receipt keeps. The table is the one the Python
// writer is tested against (tests/contract/test_024_evaluation_findings.py), generated into the verifier fixture;
// a rule changed in one implementation only turns the other red.
type precedenceSide struct {
	Signature                string `json:"signature"`
	ExpectedFingerprintGiven bool   `json:"expected_fingerprint_given"`
	TreeMatched              *bool  `json:"tree_matched"`
}

type precedenceRow struct {
	Name         string          `json:"name"`
	Old          *precedenceSide `json:"old"`
	New          precedenceSide  `json:"new"`
	SameManifest bool            `json:"same_manifest"`
	Expect       string          `json:"expect"`
	Axis         *string         `json:"axis"`
}

func precedenceReceipt(s precedenceSide, manifest string) Receipt {
	r := Receipt{ReleaseID: "0.2.4-test", Artifact: "a.zip", ZipSHA256: "z", ManifestSHA256: manifest,
		LockSHA256: "0123456789abcdef0123456789abcdef", Signature: s.Signature, ExpectedFingerprintGiven: s.ExpectedFingerprintGiven,
		Tool: "pail_verify", TreeScope: TreeScope, TreeFiles: 1, TreeSHA256: "t", TreeMatched: s.TreeMatched, At: "2026-11-20T00:00:00Z"}
	if s.Signature == "VERIFIED" {
		r.KeyFingerprint, r.Backend = String("k"), String(Backend)
	}
	return r
}

func TestReceiptPrecedenceTable(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "cmd", "pail_verify", "testdata", "releaseverify", "receipt_precedence.json"))
	if err != nil {
		t.Fatalf("precedence table missing (run tests/tools/gen_releaseverify_fixture.py): %v", err)
	}
	var table struct {
		Rows []precedenceRow `json:"rows"`
	}
	if err := json.Unmarshal(data, &table); err != nil {
		t.Fatal(err)
	}
	if len(table.Rows) != 12 {
		t.Fatalf("%d rows, want 12", len(table.Rows))
	}
	for _, row := range table.Rows {
		t.Run(row.Name, func(t *testing.T) {
			dir := t.TempDir()
			var before []byte
			if row.Old != nil {
				p, err := WriteReceipt(dir, precedenceReceipt(*row.Old, "manifest-a"))
				if err != nil {
					t.Fatal(err)
				}
				before, _ = os.ReadFile(p)
			}
			manifest := "manifest-a"
			if !row.SameManifest {
				manifest = "manifest-b"
			}
			next := precedenceReceipt(row.New, manifest)
			next.At = "2026-11-20T01:00:00Z"
			p, err := WriteReceipt(dir, next)
			after, _ := os.ReadFile(p)
			switch row.Expect {
			case "kept":
				if !IsReceiptKept(err) || row.Axis == nil || !strings.Contains(err.Error(), *row.Axis) {
					t.Fatalf("want kept on %v, got %v", row.Axis, err)
				}
				if string(after) != string(before) {
					t.Errorf("the kept receipt was rewritten:\n%s", after)
				}
			case "replaced":
				if err != nil {
					t.Fatalf("want replaced, got %v", err)
				}
				if !strings.Contains(string(after), "\"at\": \"2026-11-20T01:00:00Z\"") {
					t.Errorf("the receipt on disk is not the new run's:\n%s", after)
				}
			default:
				t.Fatalf("unknown expectation %q", row.Expect)
			}
		})
	}
}
