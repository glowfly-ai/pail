// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package reportcontract

import (
	"github.com/glowfly/pail/services/internal/corecomm"
	pb "github.com/glowfly/pail/services/proto/pailv1"
)

// OperationAuthorized means fresh authority, not physical completion.
const OperationAuthorized = corecomm.OperationAuthorized

// CheckNoContractSetting: PAIL_CORE_COMM_CONTRACT has no meaning since 0.2.0-preview.40; a set value refuses by name.
func CheckNoContractSetting(value string) error { return corecomm.CheckNoContractSetting(value) }

// CheckNoContractSettingPresent refuses when the variable is present at all, an empty value included (P40-L2).
func CheckNoContractSettingPresent(value string, present bool) error {
	return corecomm.CheckNoContractSettingPresent(value, present)
}

// CheckNoContractSettingEnv reads the variable once (os.LookupEnv) and applies the presence rule.
func CheckNoContractSettingEnv() error { return corecomm.CheckNoContractSettingEnv() }

var ErrContractSettingRemoved = corecomm.ErrContractSettingRemoved

// SubmitOutcome uses the same identity, digest and durable-receipt checks as built-in clients.
func SubmitOutcome(req *pb.SubmitActionPlanRequest, response *pb.SubmitActionPlanResponse) (string, error) {
	return corecomm.SubmitOutcome(req, response)
}
