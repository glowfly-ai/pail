// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

// SEC-H02 — the robot agent's half of revocation reach (test LLD §3.5, T18a–T18d).
//
// The gate takes up a placed bundle by itself, so the restart command stops being a
// condition for pulling. What `S20e` guarded — "a bundle was placed and nobody loaded
// it" — must not become silent because of that: after placing, the agent confirms that
// the gate judges with the placed version, and says so by name when it cannot.
//
// The two functions under DOOR are the only code here that differs before and after the
// fix.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	agentpb "github.com/glowfly/pail/services/proto/agentv1"
)

// ------------------------------------ DOOR ----------------------------------------------

// h02NewPuller builds the puller from the environment exactly as main does.
func h02NewPuller(client agentpb.AgentRelayClient, robotID string) (*keyringPuller, error) {
	return newKeyringPullerFromEnv(client, robotID)
}

// h02PullOnce runs one pull. applied reads the bundle version the gate judges with (the
// agent reads it from the gate's state file in production); bound is how long the agent
// waits for the gate to take up what it placed.
func h02PullOnce(k *keyringPuller, applied func() (uint64, error), bound time.Duration) {
	k.applied, k.confirmBound = applied, bound
	k.pullOnce()
}

// ---------------------------------- END DOOR --------------------------------------------

type h02Relay struct {
	agentpb.AgentRelayClient
	bundle []byte
}

func (r *h02Relay) GetKeyringBundle(ctx context.Context, in *agentpb.GetKeyringBundleRequest, opts ...grpc.CallOption) (*agentpb.GetKeyringBundleResponse, error) {
	return &agentpb.GetKeyringBundleResponse{Bundle: r.bundle}, nil
}

type h02Rig struct {
	dir, dest, marker string
	rootPriv          ed25519.PrivateKey
	relay             *h02Relay
}

// h02ReachRig places a version 1 bundle as "what the gate loaded" and serves version 2.
// restart: "" leaves PAIL_GATE_RESTART_CMD unset; "marker" sets a command that leaves a
// file behind when it runs.
func h02ReachRig(t *testing.T, restart string) h02Rig {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	r := h02Rig{dir: dir, dest: filepath.Join(dir, "keyring_bundle.json"), marker: filepath.Join(dir, "gate-restarted"), rootPriv: priv}
	rootPub := filepath.Join(dir, "root_pub.b64")
	if err := os.WriteFile(rootPub, []byte(base64.StdEncoding.EncodeToString(pub)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.dest, mustBundle(t, priv, 1, future()), 0644); err != nil {
		t.Fatal(err)
	}
	r.relay = &h02Relay{bundle: mustBundle(t, priv, 2, future())}
	t.Setenv("PAIL_ROOT_PUBKEY_FILE", rootPub)
	t.Setenv("PAIL_KEYRING_BUNDLE", r.dest)
	t.Setenv(EnvKeyringPollSec, "5")
	switch restart {
	case "":
		t.Setenv(EnvGateRestartCmd, "")
	case "marker":
		t.Setenv(EnvGateRestartCmd, "touch "+r.marker)
	default:
		t.Fatalf("h02ReachRig: unknown restart mode %q", restart)
	}
	return r
}

func (r h02Rig) restarted() bool {
	_, err := os.Stat(r.marker)
	return err == nil
}

func h02CaptureLog(t *testing.T, f func()) string {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)
	f()
	return buf.String()
}

// T18a: pulling no longer needs a restart command — the gate applies what is placed.
func TestH02PullerRunsWithoutRestartCmd(t *testing.T) {
	r := h02ReachRig(t, "")
	k, err := h02NewPuller(r.relay, "robot-1")
	if err != nil {
		t.Fatalf("puller refused without a restart command: %v", err)
	}
	if k == nil {
		t.Fatal("puller is off although the root key and the poll interval are set")
	}
}

// T18b: the agent confirms that the gate judges with the version it placed.
func TestH02PullerConfirmsTheGateApplied(t *testing.T) {
	r := h02ReachRig(t, "")
	k, err := h02NewPuller(r.relay, "robot-1")
	if err != nil || k == nil {
		t.Fatalf("puller: %v (nil=%v)", err, k == nil)
	}
	out := h02CaptureLog(t, func() {
		h02PullOnce(k, func() (uint64, error) { return 2, nil }, 2*time.Second)
	})
	if !strings.Contains(out, "placed bundle v2") {
		t.Fatalf("precondition: version 2 was not placed\n%s", out)
	}
	if !strings.Contains(out, "keyring pull: gate applied v2") {
		t.Errorf("no confirmation line for the applied version\n%s", out)
	}
	if strings.Contains(out, "KEYRING_APPLY_NOT_CONFIRMED") {
		t.Errorf("a not-confirmed warning although the gate applied\n%s", out)
	}
}

// T18c: a gate that keeps judging with the old version is named, and a configured
// restart command is the fallback.
func TestH02PullerNamesAnUnconfirmedApplication(t *testing.T) {
	for _, restart := range []string{"", "marker"} {
		t.Run("restart="+restart, func(t *testing.T) {
			r := h02ReachRig(t, restart)
			k, err := h02NewPuller(r.relay, "robot-1")
			if err != nil || k == nil {
				t.Fatalf("puller: %v (nil=%v)", err, k == nil)
			}
			out := h02CaptureLog(t, func() {
				h02PullOnce(k, func() (uint64, error) { return 1, nil }, 300*time.Millisecond)
			})
			if !strings.Contains(out, "placed bundle v2") {
				t.Fatalf("precondition: version 2 was not placed\n%s", out)
			}
			if !strings.Contains(out, "KEYRING_APPLY_NOT_CONFIRMED") {
				t.Errorf("the gate never took up v2 and nothing names it\n%s", out)
			}
			if restart == "marker" && !r.restarted() {
				t.Error("the configured restart command was not used as the fallback")
			}
		})
	}
}

// T18d: when the gate applies within the bound, a configured restart command is not run —
// a renewal no longer stops the robot.
func TestH02PullerDoesNotRestartAnApplyingGate(t *testing.T) {
	r := h02ReachRig(t, "marker")
	k, err := h02NewPuller(r.relay, "robot-1")
	if err != nil || k == nil {
		t.Fatalf("puller: %v (nil=%v)", err, k == nil)
	}
	out := h02CaptureLog(t, func() {
		h02PullOnce(k, func() (uint64, error) { return 2, nil }, 2*time.Second)
	})
	if !strings.Contains(out, "placed bundle v2") {
		t.Fatalf("precondition: version 2 was not placed\n%s", out)
	}
	if r.restarted() {
		t.Errorf("the gate applied v2 and the restart command ran anyway\n%s", out)
	}
}
