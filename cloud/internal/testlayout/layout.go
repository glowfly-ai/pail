// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// Package testlayout locates shared test inputs in source and release layouts.
// Missing input is a test failure, never an empty fixture or an implicit skip.
package testlayout

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func Root(t testing.TB) string {
	t.Helper()
	if root := os.Getenv("PAIL_REPO_ROOT"); root != "" {
		return root
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for root := wd; ; root = filepath.Dir(root) {
		if _, err := os.Stat(filepath.Join(root, "libpail_gate", "CMakeLists.txt")); err == nil {
			return root
		}
		if filepath.Dir(root) == root {
			break
		}
	}
	t.Fatalf("source root not found from %s; run against the complete public snapshot or set PAIL_REPO_ROOT", wd)
	return ""
}

// Resolve maps an internal source-relative path to the public layout when needed.
// It does not require the file to exist, so callers can distinguish optional inputs.
func Resolve(t testing.TB, rel string) string {
	t.Helper()
	root := Root(t)
	if _, err := os.Stat(filepath.Join(root, "cloud", "go.mod")); err == nil {
		for _, pair := range [][2]string{{"tests/perf/", "examples/perf/"}, {"oss/spec/", "spec/"}, {"tests/golden/", "spec/vectors/"}, {"services/pail_services_go/", "cloud/"}, {"pail_ws/src/", "robot/"}, {"proto/", "sdk/proto/"}, {"services/permit_mirror/", "examples/permit_mirror/"}} {
			if strings.HasPrefix(rel, pair[0]) {
				rel = pair[1] + strings.TrimPrefix(rel, pair[0])
				break
			}
		}
	}
	return filepath.Join(root, filepath.FromSlash(rel))
}

func Path(t testing.TB, rel string) string {
	t.Helper()
	p := Resolve(t, rel)
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("required test input unavailable: %s: %v", p, err)
	}
	return p
}
