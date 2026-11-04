// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package robotops

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"time"
)

type Checker func(Inventory, ResourceMap, string, time.Time) Report

// RunCLI is deliberately inspection-only. Unknown flags/modes refuse before
// any source reads. It cannot select an apply, prepare, network or recovery path.
func RunCLI(args []string, stdout, stderr io.Writer, check Checker) int {
	f := flag.NewFlagSet("robotops-check", flag.ContinueOnError)
	f.SetOutput(stderr)
	f.Usage = func() {
		fmt.Fprintln(stderr, "Usage: checker --inventory FILE --resources FILE --root DIR [--mode offline]")
		fmt.Fprintln(stderr, "Core helper additionally supports: pail_robotops_check describe --resources FILE --root DIR")
		fmt.Fprintln(stderr, "describe emits a planned inventory draft; it does not activate a robot.")
		f.PrintDefaults()
	}
	inventory := f.String("inventory", "", "management inventory YAML/JSON")
	resources := f.String("resources", "", "public inspection resource map YAML/JSON")
	root := f.String("root", "", "explicit configuration snapshot root (unprivileged)")
	mode := f.String("mode", "offline", "only offline is implemented")
	if err := f.Parse(args); err != nil {
		return 2
	}
	if len(f.Args()) != 0 || *mode != "offline" || *inventory == "" || *resources == "" || *root == "" {
		fmt.Fprintln(stderr, "RO_USAGE: require --inventory --resources --root; only --mode offline is implemented")
		return 2
	}
	raw, err := ReadDocument(*inventory)
	if err != nil {
		fmt.Fprintln(stderr, "RO_SCHEMA: inventory input unavailable")
		return 2
	}
	inv, err := DecodeInventory(raw)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	raw, err = ReadDocument(*resources)
	if err != nil {
		fmt.Fprintln(stderr, "RO_SCHEMA: resource map unavailable")
		return 2
	}
	m, err := DecodeResourceMap(raw)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	out := check(inv, m, *root, time.Now())
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err = enc.Encode(out); err != nil {
		return 2
	}
	return out.ExitCode()
}
func ReadDocument(path string) ([]byte, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	root, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return nil, err
	}
	return readContained(root, filepath.Base(abs))
}

func (r Report) ExitCode() int {
	switch r.Summary {
	case Pass:
		return 0
	case Fail:
		return 1
	default:
		return 2
	}
}
