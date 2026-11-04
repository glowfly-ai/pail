// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package blackbox

import (
	"errors"
	"os"
	"testing"
	"time"
)

func TestFirstReleaseDurableCompletionSync(t *testing.T) {
	for _, fail := range []bool{false, true} {
		name := "success"
		if fail {
			name = "sync_failure"
		}
		t.Run(name, func(t *testing.T) {
			w, e := OpenDir(t.TempDir(), Config{Signer: testSigner(testKey(t)), CheckpointEveryRecords: 100000, CheckpointEvery: 24 * time.Hour, IdleFlushAfter: -1})
			if e != nil {
				t.Fatal(e)
			}
			original := w.syncFn
			t.Cleanup(func() { w.syncFn = original; w.Close() })
			calls := 0
			injected := errors.New("injected completion sync failure")
			w.syncFn = func(f *os.File) error {
				calls++
				if fail {
					return injected
				}
				return f.Sync()
			}
			e = w.AppendDurable(RecordGateDecision, 1, []byte(`{"completion_result":"accepted"}`))
			if calls != 1 {
				t.Fatalf("sync calls %d", calls)
			}
			if fail {
				if !errors.Is(e, injected) {
					t.Fatal(e)
				}
				if e = w.Append(RecordGateDecision, 2, []byte(`{}`)); !errors.Is(e, injected) {
					t.Fatalf("writer did not retain failed durability: %v", e)
				}
			} else if e != nil {
				t.Fatal(e)
			}
		})
	}
}
