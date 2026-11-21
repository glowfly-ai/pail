// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// keyringPuller (KM2-2, KM LLD §7.1): periodically pulls the signed keyring
// bundle from the cloud and places it where the gate reads it.
//
// The transport is NOT a trust source: the cloud channel (mTLS or not) only
// carries opaque bytes. A bundle is accepted solely on the offline root
// ed25519 signature over the exact payload bytes — a compromised cloud can
// push whatever it wants and the robot still refuses anything the root did
// not sign. That is the point of KM2.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/glowfly/pail/services/internal/crypto"
	"github.com/glowfly/pail/services/internal/deploysec"
	agentpb "github.com/glowfly/pail/services/proto/agentv1"
)

// applyBundle decides whether fetched bundle bytes replace the currently
// placed bundle at destPath. Pure decision + atomic placement; no gRPC.
//
// Accept rules (mirror of the loader semantics, KM LLD §6.2):
//   - root signature over exact payload bytes must verify (F2/F4),
//   - not expired (F5),
//   - version strictly greater than the currently placed, verified bundle
//     (equal = already up to date, no-op; smaller = rollback attempt, refused
//     so a genuine old bundle can never clobber a newer local one — F3).
//
// A missing or non-verifying local file yields floor 0: anything valid may
// replace garbage. Rollback protection across gate restarts is enforced by
// the gate's own persisted state file; this check protects the placement.
func applyBundle(fetched []byte, rootPub ed25519.PublicKey, destPath string) (bool, error) {
	p, _, err := crypto.VerifyBundle(fetched, rootPub)
	if err != nil {
		return false, fmt.Errorf("pulled bundle rejected: %w", err)
	}
	if now := time.Now().Unix(); now >= p.ExpiresAtUnix {
		return false, fmt.Errorf("pulled bundle rejected: expired (now=%d >= expires_at=%d)", now, p.ExpiresAtUnix)
	}
	var cur uint64
	if existing, err := os.ReadFile(destPath); err == nil {
		if cp, _, err := crypto.VerifyBundle(existing, rootPub); err == nil {
			cur = cp.BundleVersion
		}
	}
	if p.BundleVersion < cur {
		return false, fmt.Errorf("pulled bundle rejected: version %d < placed %d (rollback)", p.BundleVersion, cur)
	}
	if p.BundleVersion == cur {
		return false, nil // already up to date
	}
	if dir := filepath.Dir(destPath); dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return false, fmt.Errorf("bundle place mkdir: %w", err)
		}
	}
	tmp := destPath + ".tmp"
	if err := os.WriteFile(tmp, fetched, 0644); err != nil {
		return false, fmt.Errorf("bundle place write tmp: %w", err)
	}
	if err := os.Rename(tmp, destPath); err != nil {
		return false, fmt.Errorf("bundle place rename: %w", err)
	}
	log.Printf("keyring pull: placed bundle v%d at %s (was v%d)", p.BundleVersion, destPath, cur)
	return true, nil
}

type keyringPuller struct {
	client     agentpb.AgentRelayClient
	robotID    string
	rootPub    ed25519.PublicKey
	destPath   string
	restartCmd string
	interval   time.Duration

	// SEC-H02: the gate takes up a placed bundle by itself. `applied` reads the bundle
	// version the gate judges with — the floor in the state file the gate writes the
	// moment it accepts a higher version — and confirmBound is how long the agent waits
	// for that floor to reach what it placed.
	applied      func() (uint64, error)
	confirmBound time.Duration
}

// applyConfirmBound: the gate looks at the bundle file four times a second (the ROS node)
// or on every tick (an adapter on the C ABI); five seconds is that, with a wide margin for
// a loaded robot computer.
const applyConfirmBound = 5 * time.Second

// gateFloorReader reads last_version from the gate's state file. The agent and the gate
// are two processes on one robot; the state file is the one thing the gate writes about
// its trust that needs no channel of its own.
func gateFloorReader(statePath string) func() (uint64, error) {
	return func() (uint64, error) {
		b, err := os.ReadFile(statePath)
		if err != nil {
			return 0, err
		}
		var st struct {
			LastVersion uint64 `json:"last_version"`
		}
		if err := json.Unmarshal(b, &st); err != nil {
			return 0, fmt.Errorf("gate state %s: %w", statePath, err)
		}
		return st.LastVersion, nil
	}
}

// EnvKeyringPollSec 는 폴링 주기(초). `0` 은 **명시적 비활성화**이고, 미설정은
// 비활성화가 아니라 `S20c` 기동 거부다.
//
// 예전에는 여기에 6h 기본값이 있었다(KM LLD §7.1). 기본값이 있으면 "6시간마다
// 받기로 정했다"와 "폴링을 생각해 본 적 없다"가 같은 배포가 된다 — 폐기 도달
// 상한이 `번들 만료 주기 + 폴링 주기`인데, 그 합의 한 항을 아무도 고르지 않은 채
// 상한을 주장하게 된다(`H-B2`).
const (
	EnvKeyringPollSec = "PAIL_KEYRING_POLL_SEC"
	EnvGateRestartCmd = "PAIL_GATE_RESTART_CMD"
)

// restartShell interprets PAIL_GATE_RESTART_CMD. The configurator's check and the exec below read this one value
// (SEC-H02B): a literal in two places is a literal that gets fixed in one of them. The tests point it elsewhere.
var restartShell = "/bin/sh"

// executableFile answers whether a path can be executed, without executing it: a start-up check must not run an
// arbitrary command to find out whether it could.
func executableFile(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.IsDir() {
		return fmt.Errorf("%s is a directory", path)
	}
	if st.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("%s is not executable (mode %v)", path, st.Mode().Perm())
	}
	return nil
}

// newKeyringPullerFromEnv returns nil (pulling disabled) unless a root public
// key is configured — without it no pulled bundle could ever be verified, and
// serving unverifiable bytes to the gate path would be worse than doing
// nothing. PAIL_KEYRING_POLL_SEC=0 also disables.
func newKeyringPullerFromEnv(client agentpb.AgentRelayClient, robotID string) (*keyringPuller, error) {
	rootPubFile := os.Getenv("PAIL_ROOT_PUBKEY_FILE")
	if rootPubFile == "" {
		return nil, nil
	}
	raw := strings.TrimSpace(os.Getenv(EnvKeyringPollSec))
	if raw == "" {
		return nil, deploysec.Cfg("S20c",
			"trust anchor: keyring poll interval not configured (%s) — revocation reach is bundle lifetime plus this, and one term of that sum is unchosen (set 0 to disable pulling on purpose)",
			EnvKeyringPollSec)
	}
	pollSec, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || pollSec < 0 {
		return nil, deploysec.Cfg("S20c",
			"trust anchor: %s=%q is not a non-negative integer number of seconds", EnvKeyringPollSec, raw)
	}
	if pollSec == 0 {
		return nil, nil
	}
	rootPub, err := crypto.ReadRootPubFile(rootPubFile)
	if err != nil {
		return nil, err
	}
	destPath := os.Getenv("PAIL_KEYRING_BUNDLE")
	if destPath == "" {
		destPath = "/etc/pail/keys/keyring_bundle.json"
	}
	// SEC-H02. The gate applies a placed bundle by itself, so a restart command is no
	// longer a condition for pulling (the start-up rule that refused a puller without
	// one is gone). What that rule guarded — "a bundle was placed and nobody loaded it"
	// — is now checked where it happens: after placing, pullOnce confirms from the
	// gate's state file that the gate judges with the placed version, names it when it
	// cannot (KEYRING_APPLY_NOT_CONFIRMED), and falls back to this command when one is
	// configured. A gate that cannot apply by itself (0.2.3 and older) still gets its
	// bundles that way.
	restartCmd := strings.TrimSpace(os.Getenv(EnvGateRestartCmd))
	// SEC-H02B: the fallback was asked for, so it must be able to run. The 0.2.3 defect behind this whole item was
	// a configured restart command on a host whose image has no shell: the rule of the day asked only whether the
	// variable was non-empty, so the deployment looked healthy and the revocation path was dead at the one moment
	// it mattered. Refused in every profile — the setting is untrue in a development deployment too.
	if restartCmd != "" {
		if err := executableFile(restartShell); err != nil {
			return nil, deploysec.Cfg("S20g",
				"trust anchor: %s is set but %s cannot run it (%v) — a fallback that cannot be executed is not a fallback; "+
					"unset %s (the gate applies a placed bundle by itself) or run the agent where that shell exists",
				EnvGateRestartCmd, restartShell, err, EnvGateRestartCmd)
		}
	}
	statePath := os.Getenv("PAIL_KEYRING_STATE")
	if statePath == "" {
		statePath = filepath.Join(filepath.Dir(destPath), "keyring_bundle.state.json")
	}
	return &keyringPuller{
		client:     client,
		robotID:    robotID,
		rootPub:    rootPub,
		destPath:   destPath,
		restartCmd: restartCmd,
		interval:   time.Duration(pollSec) * time.Second,

		applied:      gateFloorReader(statePath),
		confirmBound: applyConfirmBound,
	}, nil
}

// run polls at startup and then every interval (KM LLD §7.1). Pull or verify
// failures only log — the gate keeps its current keyring (fail-closed at
// token verification if it has none).
func (k *keyringPuller) run() {
	apply := "gate-self"
	if k.restartCmd != "" {
		apply += ", fallback=restart-cmd"
	}
	log.Printf("keyring pull: enabled (interval=%s dest=%s apply=%s)", k.interval, k.destPath, apply)
	for {
		k.pullOnce()
		time.Sleep(k.interval)
	}
}

func (k *keyringPuller) pullOnce() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	resp, err := k.client.GetKeyringBundle(ctx, &agentpb.GetKeyringBundleRequest{RobotId: k.robotID})
	cancel()
	if err != nil {
		log.Printf("keyring pull: fetch failed: %v", err)
		return
	}
	placed, err := applyBundle(resp.GetBundle(), k.rootPub, k.destPath)
	if err != nil {
		log.Printf("keyring pull: %v — keeping existing keyring", err)
		return
	}
	if !placed {
		return // up to date
	}
	// The gate takes the placed bundle up by itself. Confirm it: until the gate's floor
	// reaches the placed version, "placed" is not "in force".
	placedVersion := uint64(0)
	if p, _, err := crypto.VerifyBundle(resp.GetBundle(), k.rootPub); err == nil {
		placedVersion = p.BundleVersion
	}
	seen, seenErr := k.confirmApplied(placedVersion)
	if seenErr == nil && seen >= placedVersion {
		log.Printf("keyring pull: gate applied v%d", seen)
		return
	}
	gate := fmt.Sprintf("v%d", seen)
	if seenErr != nil {
		gate = "unreadable (" + seenErr.Error() + ")"
	}
	log.Printf("keyring pull: KEYRING_APPLY_NOT_CONFIRMED placed=v%d gate=%s after %s — the placed bundle is not known to be in force", placedVersion, gate, k.confirmBound)
	if k.restartCmd == "" {
		return
	}
	// The fallback of a gate that does not apply by itself: restart it. The trigger is a
	// deployment seam — compose/systemd decide what "restart the gate" means.
	out, err := exec.Command(restartShell, "-c", k.restartCmd).CombinedOutput()
	if err != nil {
		log.Printf("keyring pull: gate restart command failed: %v (output: %s)", err, out)
		return
	}
	log.Printf("keyring pull: gate restart triggered (%q)", k.restartCmd)
}

// confirmApplied polls the gate's floor until it reaches `want` or the bound passes.
// Returns the last floor read, or the last read error when no read succeeded.
func (k *keyringPuller) confirmApplied(want uint64) (uint64, error) {
	if k.applied == nil {
		return 0, fmt.Errorf("no reader for the gate's applied version")
	}
	deadline := time.Now().Add(k.confirmBound)
	var last uint64
	var lastErr error
	for {
		v, err := k.applied()
		if err == nil {
			last, lastErr = v, nil
			if v >= want {
				return v, nil
			}
		} else if last == 0 {
			lastErr = err
		}
		if !time.Now().Before(deadline) {
			return last, lastErr
		}
		time.Sleep(100 * time.Millisecond)
	}
}
