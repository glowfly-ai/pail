// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

// 0.2.2 F4: this package's tests go through a fake disk measurement, not the host's free space (see the ledgerq
// package's disk_seam_f4_test.go). Design: the 0.2.2 fix F4 test design.

import (
	"os"
	"sync/atomic"
	"testing"

	"github.com/glowfly/pail/services/internal/ledgerq"
)

var fakeDiskCalls atomic.Int64

func TestMain(m *testing.M) {
	restore := ledgerq.SetDiskUsageForTesting(func(string) (int64, int64, bool) {
		fakeDiskCalls.Add(1)
		return int64(1) << 40, int64(2) << 40, true
	})
	code := m.Run()
	restore()
	os.Exit(code)
}

func TestF4T1TelemetrydTestsUseTheFakeDisk(t *testing.T) {
	before := fakeDiskCalls.Load()
	ledgerFixture(t)
	if fakeDiskCalls.Load() == before {
		t.Fatal("the ledger fixture never asked the injected disk measurement: the tests still read the host disk")
	}
}
