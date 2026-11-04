// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
//go:build !linux && !darwin

package robotops

import "fmt"

func readContained(root, rel string) ([]byte, error) {
	return nil, fmt.Errorf("RO_CAPABILITY: public resource reader supports Linux and macOS only")
}

func readContainedInfo(root, rel string) ([]byte, fileMetadata, error) {
	return nil, fileMetadata{}, fmt.Errorf("RO_CAPABILITY: file capture unavailable")
}
func listContained(root, rel string) ([]string, error) {
	return nil, fmt.Errorf("RO_CAPABILITY: directory capture unavailable")
}
