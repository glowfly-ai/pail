// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package observability

import "github.com/glowfly/pail/services/pkg/robotid"

func hash16ForTest(id string) string { return robotid.Hash16(id) }
