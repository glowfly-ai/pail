// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"os"
	"strings"
	"testing"
)

// 0.2.0-preview.40: one contract, no selecting setting. 0.2.0-preview.41 (P40-L2): the variable's presence refuses —
// an empty value is a present variable; only an absent one starts the agent.
func TestP39AgentContractDefaultsToV1(t *testing.T) {
	t.Setenv("PAIL_REPORT_QUEUE_DIR", t.TempDir())
	t.Setenv("PAIL_REPORT_QUEUE_BYTES", "1048576")
	t.Setenv("PAIL_CORE_COMM_CONTRACT", "placeholder") // registers the restore; the absent case below unsets it
	os.Unsetenv("PAIL_CORE_COMM_CONTRACT")
	o, e := reportQueueOptionsFromEnv("r")
	if e != nil || o.ReceiptVersion != 1 {
		t.Fatalf("absent must be the single contract (receipt version 1): %d %v", o.ReceiptVersion, e)
	}
	for _, v := range []string{"", "legacy", "v1"} {
		t.Setenv("PAIL_CORE_COMM_CONTRACT", v)
		if _, e = reportQueueOptionsFromEnv("r"); e == nil || !strings.HasPrefix(e.Error(), "CORE_COMM_CONTRACT_SETTING_REMOVED: ") {
			t.Fatalf("the setting was removed in 0.2.0-preview.40 and a present variable (%q) must refuse by name: %v", v, e)
		}
	}
	os.Unsetenv("PAIL_CORE_COMM_CONTRACT")
	t.Setenv("PAIL_REPORT_QUEUE_BYTES", "0")
	if _, e = reportQueueOptionsFromEnv("r"); e == nil {
		t.Fatal("default v1 silently became memory-only")
	}
}
