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
	// `B-R3`. 풀러가 켜졌는데 적용 수단이 없으면, 새 번들은 **놓이기만 하고 게이트는
	// 옛 키로 계속 돈다.** 예전에는 그것이 로그 한 줄이었다 — 그 줄은 폴링 주기마다
	// 다시 나오지도 않고(놓인 뒤에만 찍힌다), 아무도 안 읽으면 폐기가 영원히
	// 도달하지 않는다. 상한을 주장하려면 적용 수단이 배포 시점에 있어야 한다.
	restartCmd := strings.TrimSpace(os.Getenv(EnvGateRestartCmd))
	if restartCmd == "" {
		return nil, deploysec.Cfg("S20e",
			"trust anchor: keyring pulling is on (%s=%d) but no way to apply a new bundle (%s) — placing a bundle nobody loads is not a revocation path",
			EnvKeyringPollSec, pollSec, EnvGateRestartCmd)
	}
	return &keyringPuller{
		client:     client,
		robotID:    robotID,
		rootPub:    rootPub,
		destPath:   destPath,
		restartCmd: restartCmd,
		interval:   time.Duration(pollSec) * time.Second,
	}, nil
}

// run polls at startup and then every interval (KM LLD §7.1). Pull or verify
// failures only log — the gate keeps its current keyring (fail-closed at
// token verification if it has none).
func (k *keyringPuller) run() {
	log.Printf("keyring pull: enabled (interval=%s dest=%s)", k.interval, k.destPath)
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
	// §6.3: bundles are applied by restarting the gate. The trigger is a
	// deployment seam — compose/systemd decide what "restart the gate" means.
	// 빈 값 분기는 없다: 구성기가 이미 `S20e` 로 거부했으므로 여기 도달한 풀러는
	// 적용 수단을 갖고 있다.
	out, err := exec.Command("/bin/sh", "-c", k.restartCmd).CombinedOutput()
	if err != nil {
		log.Printf("keyring pull: gate restart command failed: %v (output: %s)", err, out)
		return
	}
	log.Printf("keyring pull: gate restart triggered (%q)", k.restartCmd)
}
