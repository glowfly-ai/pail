// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"github.com/glowfly/pail/services/internal/robotopscheck"
	"github.com/glowfly/pail/services/pkg/robotops"
	"os"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "probe-agent" {
		os.Exit(robotops.RunCoreProbeCLI(os.Args[2:], os.Stdout, os.Stderr))
	}
	if len(os.Args) > 1 && os.Args[1] == "describe" {
		os.Exit(robotops.RunDescribeCLI(os.Args[2:], os.Stdout, os.Stderr, robotopscheck.Describe))
	}
	os.Exit(robotops.RunCLI(os.Args[1:], os.Stdout, os.Stderr, robotopscheck.Check))
}
