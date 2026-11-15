// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package telemetry

// OBS-RET (R7): the storage document gains the index window and the disk floor.
// Read through ParseStorageConfig and JSON so the file compiles before the
// fields exist.

import (
	"encoding/json"
	"testing"
)

func orDoc(t *testing.T, c StorageConfig) map[string]any {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestORT11aNewFieldsAreAccepted(t *testing.T) {
	c, err := ParseStorageConfig([]byte(`{"schema_version":1,"index_retain_days":3,"disk_free_min_bytes":1073741824,"db_max_bytes":0}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	m := orDoc(t, c)
	if m["index_retain_days"] != float64(3) || m["disk_free_min_bytes"] != float64(1073741824) || m["db_max_bytes"] != float64(0) {
		t.Fatalf("parsed %v", m)
	}
}

func TestORT11bcOutOfRangeValuesAreRefused(t *testing.T) {
	for _, doc := range []string{
		`{"schema_version":1,"index_retain_days":-1}`,
		`{"schema_version":1,"index_retain_days":36501}`,
		`{"schema_version":1,"disk_free_min_bytes":-1}`,
		`{"schema_version":1,"db_max_bytes":-1}`,
	} {
		if _, err := ParseStorageConfig([]byte(doc)); err == nil || err.Error() != "OBSERVABILITY_CONFIG: invalid limits" {
			t.Errorf("%s: err=%v, want invalid limits", doc, err)
		}
	}
}

func TestORT11dTheDefaultIsSevenDaysAndNoFixedBudget(t *testing.T) {
	m := orDoc(t, DefaultStorageConfig())
	if m["index_retain_days"] != float64(7) || m["db_max_bytes"] != float64(0) || m["disk_free_min_bytes"] != float64(0) {
		t.Fatalf("default %v, want index_retain_days 7, db_max_bytes 0 (no fixed budget), disk_free_min_bytes 0 (automatic)", m)
	}
}

func TestORT11efOlderDocumentsStillParse(t *testing.T) {
	c, err := ParseStorageConfig([]byte(`{"schema_version":1}`))
	if err != nil {
		t.Fatalf("minimal document: %v", err)
	}
	if got, want := orDoc(t, c), orDoc(t, DefaultStorageConfig()); got["index_retain_days"] != want["index_retain_days"] {
		t.Errorf("minimal document differs from the default: %v", got)
	}
	c, err = ParseStorageConfig([]byte(`{"schema_version":1,"db_max_bytes":2147483648}`))
	if err != nil || c.DBMaxBytes != 2147483648 {
		t.Fatalf("a document from 0.2.0: %v %d", err, c.DBMaxBytes)
	}
}
