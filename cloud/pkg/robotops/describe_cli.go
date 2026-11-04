// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package robotops

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
)

func RunDescribeCLI(args []string, out, errs io.Writer, describe func(ResourceMap, string) (Inventory, error)) int {
	f := flag.NewFlagSet("describe", flag.ContinueOnError)
	f.SetOutput(errs)
	mp := f.String("resources", "", "resource map")
	root := f.String("root", "", "public source")
	if f.Parse(args) != nil || len(f.Args()) != 0 || *mp == "" || *root == "" {
		return 2
	}
	raw, e := ReadDocument(*mp)
	if e != nil {
		fmt.Fprintln(errs, "RO_INPUT: resource map unavailable")
		return 2
	}
	m, e := DecodeResourceMap(raw)
	if e != nil {
		fmt.Fprintln(errs, e)
		return 2
	}
	v, e := describe(m, *root)
	if e != nil {
		fmt.Fprintln(errs, e)
		return 2
	}
	// Same serialization as the fixture writer (two-space indent, trailing
	// newline) so a draft and a generated inventory compare byte for byte.
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if enc.Encode(v) != nil {
		return 2
	}
	return 0
}
