// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

// OBS-RET (T14): the collector rebuilds its index under its own storage
// configuration. A rebuild without it would insert every line of every raw
// file again and only then start removing them.

import (
	"os"
	"strings"
	"testing"
)

func TestORT14TheCollectorRebuildsUnderItsStorageConfig(t *testing.T) {
	b, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	if !strings.Contains(src, "ledgerq.RebuildWithStorage(") {
		t.Errorf("main.go does not call ledgerq.RebuildWithStorage")
	}
	if strings.Contains(src, "ledgerq.Rebuild(") {
		t.Errorf("main.go still calls ledgerq.Rebuild, which knows no retention")
	}
}
