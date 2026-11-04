// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package blackbox

import (
	_ "embed"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// EC-3 (EUC D3): which kind of intervention a record type is evidence of.
// The table is INTERVENTION_CLASSES.tsv beside this file — one source, read
// here by embed and by the contract test that checks it against records.go.

//go:embed INTERVENTION_CLASSES.tsv
var interventionClassesTSV string

// InterventionClass is one row of the table.
type InterventionClass struct {
	Type  uint32
	Kind  string
	Class string // legitimate | illegitimate | system | by_payload
	Note  string
}

// InterventionClassVocabulary is the closed set of `class` values.
var InterventionClassVocabulary = []string{"legitimate", "illegitimate", "system", "by_payload"}

var (
	classOnce  sync.Once
	classTable map[uint32]InterventionClass
	classErr   error
)

func loadClasses() {
	classTable = map[uint32]InterventionClass{}
	vocab := map[string]bool{}
	for _, v := range InterventionClassVocabulary {
		vocab[v] = true
	}
	for i, line := range strings.Split(interventionClassesTSV, "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) != 4 {
			classErr = fmt.Errorf("INTERVENTION_CLASSES.tsv line %d: %d columns, want 4", i+1, len(cols))
			return
		}
		n, err := strconv.ParseUint(cols[0], 10, 32)
		if err != nil {
			classErr = fmt.Errorf("INTERVENTION_CLASSES.tsv line %d: record_type %q: %w", i+1, cols[0], err)
			return
		}
		if !vocab[cols[2]] {
			classErr = fmt.Errorf("INTERVENTION_CLASSES.tsv line %d: class %q outside %v", i+1, cols[2], InterventionClassVocabulary)
			return
		}
		if _, dup := classTable[uint32(n)]; dup {
			classErr = fmt.Errorf("INTERVENTION_CLASSES.tsv line %d: record_type %d listed twice", i+1, n)
			return
		}
		classTable[uint32(n)] = InterventionClass{Type: uint32(n), Kind: cols[1], Class: cols[2], Note: cols[3]}
	}
	if len(classTable) == 0 {
		classErr = fmt.Errorf("INTERVENTION_CLASSES.tsv: no rows")
	}
}

// ClassOf returns the table row for a record type. ok=false is "not in the
// table" — a fourth answer, never folded into `system`: a record type nobody
// classified is exactly the record an auditor must be told about.
func ClassOf(t uint32) (InterventionClass, bool) {
	classOnce.Do(loadClasses)
	if classErr != nil {
		return InterventionClass{}, false
	}
	c, ok := classTable[t]
	return c, ok
}

// InterventionClasses returns every row (sorted by type) and the parse error,
// if any. Callers that print a summary use this so a broken table is a loud
// error rather than an empty summary.
func InterventionClasses() ([]InterventionClass, error) {
	classOnce.Do(loadClasses)
	if classErr != nil {
		return nil, classErr
	}
	out := make([]InterventionClass, 0, len(classTable))
	for _, c := range classTable {
		out = append(out, c)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1].Type > out[j].Type; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out, nil
}
