// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
// Package robotid holds the wire's identifier projection without collector/DB dependencies.
package robotid

import (
	"crypto/sha256"
	"encoding/hex"
)

// Hash16 is the burst v2 robot field: hex(sha256(robot_id)[:16]).
func Hash16(robotID string) string {
	h := sha256.Sum256([]byte(robotID))
	return hex.EncodeToString(h[:16])
}
