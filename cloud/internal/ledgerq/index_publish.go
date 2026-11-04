// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package ledgerq

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// publishIndex is the sole filesystem mutation boundary for side-by-side
// rebuilds. Every destination is derived from the configured index path, never
// from an input segment, source directory or HTTP parameter.
func publishIndex(path, building string) error {
	if building != path+".building" {
		return fmt.Errorf("invalid index build path")
	}
	backup := fmt.Sprintf("%s.previous-%d", path, time.Now().UnixNano())
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		if _, err := os.Stat(path + suffix); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		var err error
		if suffix == "" {
			err = os.Link(path, backup)
		} else {
			err = os.Rename(path+suffix, backup+suffix)
		}
		if err != nil {
			return err
		}
	}
	if err := os.Rename(building, path); err != nil {
		return err
	}
	// Persist the publication directory entry. Raw telemetry and blackbox are
	// never renamed, removed or truncated by this function.
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
