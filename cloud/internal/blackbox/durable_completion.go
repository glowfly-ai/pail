// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package blackbox

import "fmt"

// AppendDurable adds an explicit local fsync boundary to Append. Concurrent
// writes may join that sync; they cannot remove this record from its coverage.
// An error may follow a write (including replication/checkpoint failure), so
// callers must report an indeterminate RPC, not definitive rejection.
func (w *Writer) AppendDurable(kind uint32, ms uint64, payload []byte) error {
	if err := w.Append(kind, ms, payload); err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return fmt.Errorf("blackbox closed before durable append sync")
	}
	if w.idleErr != nil {
		return w.idleErr
	}
	if err := w.syncFn(w.f); err != nil {
		w.idleErr = fmt.Errorf("blackbox durable append sync: %w", err)
		return w.idleErr
	}
	w.durableAppends++
	return nil
}

// DurableAppendCount counts successful explicit local sync barriers. It does
// not claim power-loss testing or change the regular batched Append policy.
func (w *Writer) DurableAppendCount() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.durableAppends
}
