// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package telemetry

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// FileFor is the legacy daily filename, still accepted by every reader.
func FileFor(dir string, now time.Time) string {
	return filepath.Join(dir, "decisions-"+dayOf(now)+".jsonl")
}
func dayOf(now time.Time) string { return now.UTC().Format("20060102") }

// LoadDir reads every decisions-*.jsonl under dir, in name (= day) order.
// Bad line counts per file are returned beside the records, never dropped.
func LoadDir(dir string) (recs []Record, badByFile map[string]int, err error) {
	names, err := filepath.Glob(filepath.Join(dir, "decisions-*.jsonl"))
	if err != nil {
		return nil, nil, err
	}
	badByFile = map[string]int{}
	for _, name := range names {
		f, err := os.Open(name)
		if err != nil {
			return nil, nil, err
		}
		r, bad, rerr := ReadAll(f)
		f.Close()
		if rerr != nil {
			return nil, nil, fmt.Errorf("%s: %w", name, rerr)
		}
		if len(bad) > 0 {
			badByFile[filepath.Base(name)] = len(bad)
		}
		recs = append(recs, r...)
	}
	return recs, badByFile, nil
}

// ReadAll parses a JSONL stream. Unparseable lines are returned by number and
// excluded from the records — never silently dropped, because a dropped line
// is indistinguishable from a line that never existed (probe Report grammar,
// implementation contract D1).
func ReadAll(r io.Reader) (recs []Record, badLines []int, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		b := sc.Bytes()
		if len(b) == 0 {
			continue
		}
		rec, perr := ParseLine(b)
		if perr != nil {
			badLines = append(badLines, lineNo)
			continue
		}
		recs = append(recs, rec)
	}
	if serr := sc.Err(); serr != nil {
		return nil, nil, fmt.Errorf("scan: %w", serr)
	}
	return recs, badLines, nil
}
