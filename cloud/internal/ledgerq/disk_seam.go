// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package ledgerq

// diskUsage is how the index reads the free space of its filesystem. Production keeps statfsUsage; tests replace it
// so that their result does not depend on the free disk of the machine that runs them (0.2.2 F4: 56 tests failed
// with DB_DISK_PRESSURE on a host with 15 GiB free of 926 GiB).
var diskUsage = statfsUsage

// SetDiskUsageForTesting replaces the disk measurement and returns the function that restores the previous one.
// For tests only (this package's and cmd/pail_telemetryd's); production code never calls it. Not safe while
// another goroutine of the same test binary reads the measurement concurrently: the packages' tests are sequential.
func SetDiskUsageForTesting(f func(path string) (free, total int64, ok bool)) (restore func()) {
	prev := diskUsage
	diskUsage = f
	return func() { diskUsage = prev }
}
