// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package ledgerq

// 0.2.2 F4: the result of this package's tests does not depend on the free disk space of the machine that runs
// them. 0.2.1: 56 tests failed with DB_DISK_PRESSURE on a host with 15 GiB free of 926 GiB (floor = 10 % of the
// disk, at most 20 GiB). Every test here sees a roomy fake measurement unless it installs its own. Design:
// the 0.2.2 fix F4 test design (T4-1..T4-4).

import (
	"os"
	"strings"
	"testing"

	"github.com/glowfly/pail/services/internal/telemetry"
)

const testFree, testTotal = int64(1) << 40, int64(2) << 40

func roomyDisk(string) (int64, int64, bool) { return testFree, testTotal, true }

func TestMain(m *testing.M) {
	restore := SetDiskUsageForTesting(roomyDisk)
	code := m.Run()
	restore()
	os.Exit(code)
}

func TestF4T1DiskMeasurementIsTheTestFake(t *testing.T) {
	free, total, ok := diskUsage(t.TempDir())
	if !ok || free != testFree || total != testTotal {
		t.Fatalf("diskUsage=%d/%d/%v during tests, want the fake %d/%d", free, total, ok, testFree, testTotal)
	}
}

func TestF4T2LowDiskIsDiskPressure(t *testing.T) {
	restore := SetDiskUsageForTesting(func(string) (int64, int64, bool) { return 15 << 30, 926 << 30, true })
	defer restore()
	d, dir := obsDB(t)
	obsWrite(t, dir, "decisions-01.jsonl", obsBurst+"\n")
	d.ConfigureStorage(telemetry.DefaultStorageConfig())
	if e := d.CheckStorage(); e == nil || !strings.Contains(e.Error(), "DB_DISK_PRESSURE") {
		t.Fatalf("CheckStorage=%v with 15 GiB free of 926 GiB, want DB_DISK_PRESSURE", e)
	}
}

func TestF4T4ProductionMeasurementReadsTheFilesystem(t *testing.T) {
	free, total, ok := statfsUsage(t.TempDir())
	if !ok || total <= 0 || free < 0 || free > total {
		t.Fatalf("statfsUsage=%d/%d/%v", free, total, ok)
	}
}
