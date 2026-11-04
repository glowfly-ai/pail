// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package deploysec

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/glowfly/pail/services/internal/grpcauth"
)

// modeProbe answers StatMode from a table. A path absent from the table is
// absent from the filesystem; a path mapped to an error is there but could not
// be read, which is the case the three-valued status exists for.
func modeProbe(env map[string]string, modes map[string]os.FileMode, errs map[string]error) Probe {
	p := fakeProbe(env, nil)
	p.StatMode = func(path string) (os.FileMode, error) {
		if e, ok := errs[path]; ok {
			return 0, e
		}
		if m, ok := modes[path]; ok {
			return m, nil
		}
		return 0, fs.ErrNotExist
	}
	return p
}

func ruleIDs(errs []error) string {
	ids := make([]string, 0, len(errs))
	for _, e := range errs {
		ids = append(ids, RuleID(e))
	}
	return strings.Join(ids, ",")
}

func mustObserve(t *testing.T, component string, p Probe) []KeyModeObservation {
	t.Helper()
	obs, ok := ObserveKeyModes(component, p)
	if !ok {
		t.Fatalf("%s: the registry declares no private material", component)
	}
	return obs
}

// TestS19RefusesWideMode is §1.3 turned into a rule. The mode in the fixture is
// the one measured on config/keys/issuer_ed25519.json.
func TestS19RefusesWideMode(t *testing.T) {
	p := modeProbe(
		map[string]string{"PAIL_GRPC_TLS": "off"},
		map[string]os.FileMode{DefaultIssuerKeyfile: 0o644}, nil)
	errs := EvaluateKeyModes(mustObserve(t, "pail_cloud", p))
	if ruleIDs(errs) != "S19" {
		t.Fatalf("want one S19, got %q (%v)", ruleIDs(errs), errs)
	}
	msg := errs[0].Error()
	// The operator has to know which file and what it is now. A refusal that
	// says only "a key is too permissive" is a wall.
	if !strings.Contains(msg, DefaultIssuerKeyfile) || !strings.Contains(msg, "0644") {
		t.Errorf("the refusal must name the path and the mode: %s", msg)
	}
}

// TestS19RefusesUnreadableMode: a key whose mode nobody could read is not a key
// that passed. Its own id, because folding it onto S19 would mean deleting this
// branch leaves the other one emitting the same line (`H-B9`).
func TestS19RefusesUnreadableMode(t *testing.T) {
	p := modeProbe(
		map[string]string{"PAIL_GRPC_TLS": "off"},
		nil,
		map[string]error{DefaultIssuerKeyfile: os.ErrPermission})
	errs := EvaluateKeyModes(mustObserve(t, "pail_cloud", p))
	if ruleIDs(errs) != "S19b" {
		t.Fatalf("want one S19b, got %q (%v)", ruleIDs(errs), errs)
	}
	if !strings.Contains(errs[0].Error(), DefaultIssuerKeyfile) {
		t.Errorf("the refusal must name the path: %s", errs[0].Error())
	}
}

// TestS19IgnoresAbsentKey keeps S19 off S18's ground. Two rules reporting one
// missing file in different words send the operator looking for two faults.
func TestS19IgnoresAbsentKey(t *testing.T) {
	p := modeProbe(map[string]string{"PAIL_GRPC_TLS": "off"}, nil, nil)
	obs := mustObserve(t, "pail_cloud", p)
	if len(obs) != 1 || obs[0].Status != KeyModeAbsent {
		t.Fatalf("want one absent observation, got %+v", obs)
	}
	if errs := EvaluateKeyModes(obs); len(errs) != 0 {
		t.Fatalf("absence is S18's finding, not S19's: %v", errs)
	}
}

// TestS19AcceptsNarrowModes is the positive control. Without it this rule could
// refuse every deployment and every other unit here would still pass.
func TestS19AcceptsNarrowModes(t *testing.T) {
	for _, perm := range []os.FileMode{0o600, 0o400} {
		p := modeProbe(
			map[string]string{},
			map[string]os.FileMode{
				DefaultIssuerKeyfile: perm,
				DefaultGRPCServerKey: perm,
			}, nil)
		obs := mustObserve(t, "pail_cloud", p)
		if len(obs) != 2 {
			t.Fatalf("%04o: want issuer key and TLS key observed, got %+v", perm, obs)
		}
		if errs := EvaluateKeyModes(obs); len(errs) != 0 {
			t.Errorf("%04o must pass: %v", perm, errs)
		}
	}
}

// TestS19ChecksTLSKeyOnlyWhenTLSOn matches collectKeyMaterial's condition. With
// TLS off the process never opens the key, and refusing on a file it will not
// read turns the gate into a wall for every plaintext-UDS deployment.
func TestS19ChecksTLSKeyOnlyWhenTLSOn(t *testing.T) {
	modes := map[string]os.FileMode{DefaultIssuerKeyfile: 0o600, DefaultGRPCServerKey: 0o644}
	on := EvaluateKeyModes(mustObserve(t, "pail_services",
		modeProbe(map[string]string{}, modes, nil)))
	if ruleIDs(on) != "S19" {
		t.Fatalf("TLS on: the server key must be judged, got %q", ruleIDs(on))
	}
	off := EvaluateKeyModes(mustObserve(t, "pail_services",
		modeProbe(map[string]string{"PAIL_GRPC_TLS": "off"}, modes, nil)))
	if len(off) != 0 {
		t.Fatalf("TLS off: the server key is never opened: %v", off)
	}
}

// TestS19FollowsLoaderPaths: S19 must judge the file the loader will open, not
// the default it would have opened. A rule that reads only defaults reports
// every override as clean.
func TestS19FollowsLoaderPaths(t *testing.T) {
	p := modeProbe(
		map[string]string{
			"PAIL_ISSUER_KEYFILE": "/run/secrets/issuer.json",
			"PAIL_GRPC_KEY":       "/run/secrets/tls.key",
		},
		map[string]os.FileMode{
			"/run/secrets/issuer.json": 0o604,
			"/run/secrets/tls.key":     0o640,
			// The defaults are narrow. If the rule looked here it would pass.
			DefaultIssuerKeyfile: 0o600,
			DefaultGRPCServerKey: 0o600,
		}, nil)
	errs := EvaluateKeyModes(mustObserve(t, "pail_cloud", p))
	if ruleIDs(errs) != "S19,S19" {
		t.Fatalf("both overridden paths must be judged, got %q (%v)", ruleIDs(errs), errs)
	}
}

// TestS19RefusesUndeclaredComponent: registration alone is not a declaration.
// A component that says nothing about its private material must not be read as
// holding none — that is the S8 blind spot burst_recv lived in, one field over.
func TestS19RefusesUndeclaredComponent(t *testing.T) {
	const name = "pail_future_daemon"
	if _, ok := ObserveKeyModes(name, modeProbe(nil, nil, nil)); ok {
		t.Fatal("an unregistered component declares nothing")
	}
	componentKeyRegistry[name] = componentKeys{Files: nil}
	t.Cleanup(func() { delete(componentKeyRegistry, name) })
	if _, ok := ObserveKeyModes(name, modeProbe(nil, nil, nil)); ok {
		t.Fatal("registered with neither Private nor NoPrivate must not read as clean")
	}
}

// TestS19EveryRegisteredComponentDeclares is the rule that keeps the one above
// from being decoration: the next process added to the registry cannot inherit
// silence, because this fails the moment it does.
func TestS19EveryRegisteredComponentDeclares(t *testing.T) {
	for name, spec := range componentKeyRegistry {
		has, none := len(spec.Private) > 0, spec.NoPrivate
		if has == none {
			t.Errorf("%s: declare exactly one of Private (%d entries) or NoPrivate (%v)",
				name, len(spec.Private), none)
		}
		if has && spec.TLSCert != "" && spec.TLSKey == "" {
			t.Errorf("%s: holds a gRPC certificate but declares no private key for it", name)
		}
	}
	// burst_recv is the one that declares none, and it must stay observable as
	// a declaration rather than as an empty slot.
	if !componentKeyRegistry["burst_recv"].NoPrivate {
		t.Error("burst_recv verifies and never signs — say so out loud")
	}
}

// TestS19TLSKeyDefaultsMatchGrpcauth is the anti-drift unit. deploysec must not
// import the code it judges, so the TLS key defaults are a second copy; without
// this, moving grpcauth's default would leave S19 checking a path nobody opens
// and reporting the move as clean.
func TestS19TLSKeyDefaultsMatchGrpcauth(t *testing.T) {
	if DefaultGRPCServerKey != grpcauth.DefaultKeyPath {
		t.Errorf("server key default drifted: deploysec %q vs grpcauth %q",
			DefaultGRPCServerKey, grpcauth.DefaultKeyPath)
	}
	if DefaultGRPCClientKey != grpcauth.DefaultClientKeyPath {
		t.Errorf("client key default drifted: deploysec %q vs grpcauth %q",
			DefaultGRPCClientKey, grpcauth.DefaultClientKeyPath)
	}
}

// TestS19SystemProbeReadsRealModes: the pure rule above is tested through a
// table, so nothing there would notice if StatMode itself were wrong. This is
// the one unit that touches a real file.
func TestS19SystemProbeReadsRealModes(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/k.json"
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Explicitly create the wide-mode fixture even on a hardened umask 077 host.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	p := SystemProbe()
	perm, err := p.StatMode(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !ModeTooWide(perm) {
		t.Fatalf("0644 must read as too wide, got %04o", perm)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if perm, err = p.StatMode(path); err != nil || ModeTooWide(perm) {
		t.Fatalf("0600 must pass: %04o %v", perm, err)
	}
	if _, err = p.StatMode(dir + "/absent.json"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("absence must be distinguishable from any other error: %v", err)
	}
}
