// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
// Package reportcontract exposes the core-comm report wire contract to adapters.
package reportcontract

import (
	"github.com/glowfly/pail/services/internal/corecomm"
	tp "github.com/glowfly/pail/services/proto/tokenv1"
)

func Digest(r *tp.ReportDecisionRequest) ([]byte, error) { return corecomm.ReportDigest(r) }
func CheckACK(r *tp.ReportDecisionRequest, a *tp.ReportDecisionResponse) error {
	return corecomm.CheckReportACK(r, a, false)
}

var ErrTerminalRejected = corecomm.ErrTerminalRejected
