// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package corecomm

import (
	"errors"
	"github.com/glowfly/pail/services/internal/blackbox"
	devcrypto "github.com/glowfly/pail/services/internal/crypto"
	"github.com/glowfly/pail/services/internal/signer"
	"testing"
)

func TestHAC1BeginAckLossDoesNotReexecute(t *testing.T) {
	kp, err := devcrypto.NewDevKeypair("ha-c1-test")
	if err != nil {
		t.Fatal(err)
	}
	fail := false
	w, err := blackbox.OpenDir(t.TempDir(), blackbox.Config{Signer: signer.NewLocal(kp), Ship: func(uint64, uint64, []byte) error {
		if fail {
			return errors.New("injected ACK loss after local append")
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	j, err := OpenJournal(w)
	if err != nil {
		t.Fatal(err)
	}
	e := Entry{Scope: "caller", Robot: "robot", Plan: "plan", Kind: "SUBMIT", ID: "op", Digest: make([]byte, 32)}
	fail = true
	if _, _, err = j.Begin(e); err == nil {
		t.Fatal("injection did not fail")
	}
	fail = false
	if _, leader, err := j.Begin(e); err == nil && leader {
		t.Fatal("uncertain prepare retried as a NEW operation")
	}
	if !j.Blocked("robot") {
		t.Fatal("uncertain prepare did not hold authority")
	}
}

func TestHAC1FinishAckLossStopsFurtherJournalMutation(t *testing.T) {
	kp, err := devcrypto.NewDevKeypair("ha-c1-test")
	if err != nil {
		t.Fatal(err)
	}
	fail := false
	w, err := blackbox.OpenDir(t.TempDir(), blackbox.Config{Signer: signer.NewLocal(kp), Ship: func(uint64, uint64, []byte) error {
		if fail {
			return errors.New("injected ACK loss")
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	j, err := OpenJournal(w)
	if err != nil {
		t.Fatal(err)
	}
	e, _, err := j.Begin(Entry{Scope: "caller", Robot: "robot", Plan: "p", Kind: "SUBMIT", ID: "op", Digest: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	fail = true
	if _, err = j.Finish(e, "COMMITTED", []byte("response")); err == nil {
		t.Fatal("injection did not fail")
	}
	fail = false
	_, leader, err := j.Begin(Entry{Scope: "caller", Robot: "other", Plan: "q", Kind: "SUBMIT", ID: "other", Digest: make([]byte, 32)})
	if err == nil || leader {
		t.Fatal("journal mutated after uncertain commit; restart/recovery required")
	}
}
