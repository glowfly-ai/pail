// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package robotops

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	jcs "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// InspectionDigest is NOT an approval/authorization signature and never uses
// the reserved apply-plan or approval domains. JCS is the RFC implementation,
// not an encoding/json approximation for Unicode or number serialization.
func InspectionDigest(kind string, value interface{}) (string, error) {
	switch kind {
	case "inventory", "resource-map", "inspection-plan", "check-report":
	default:
		return "", fmt.Errorf("RO_SCHEMA: unsupported read-only digest domain")
	}
	b, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("RO_SCHEMA: encoding failed")
	}
	var checked interface{}
	if err := StrictDecode(b, &checked, nil); err != nil {
		return "", err
	}
	canonical, err := jcs.Transform(b)
	if err != nil {
		return "", fmt.Errorf("RO_SCHEMA: canonical encoding refused")
	}
	digest := sha256.Sum256(append([]byte("pail.robotops."+kind+"/v1\n"), canonical...))
	return hex.EncodeToString(digest[:]), nil
}
