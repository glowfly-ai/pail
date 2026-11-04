// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package deploysec

// S19 (implementation contract, §4.5, `F-KEY-07`): refuse to start when private key
// material this process opens is readable by anyone but its owner.
//
// The judgement is made at run time, on the path the loader will actually open.
// §1.3 measured three private keys at 0644 — the issuer seed, the SROS2 CA key,
// the pep_gate enclave key — and none of those modes came from the repository:
// git stores one executable bit and nothing else, so the modes are whatever the
// umask that created the files decided. `scripts/split_config.sh` chmods two
// Ed25519 JSONs and its guardrails read placement only, so the deployment
// script never looked either.
//
// That is why this is a second layer rather than a fix to the script. The
// script sees the moment a deployment is made; S19 sees the moment a process
// starts. The three 0644 files were made on a path that does not go through the
// script, so a script-only fix produces them again. `implementation contract` learned the
// same asymmetry from `COPY` in the other direction: the index said 100644
// while the working copy was 0600 and the container could not read its own key.
// The shared cause of both is that nobody read the mode.
//
// Not profile-exempt, like the rest of S15~S20 (§3.7). A world-readable signing
// key is not a protection somebody switched off; it is a key that has already
// been handed out to every account on the host, and `PAIL_PROFILE=dev` is where
// keys get made.

import (
	"errors"
	"io/fs"
	"os"
)

// KeyModeStatus is three-valued on purpose. Two values would make "could not
// tell" share a slot with one of the answers, and whichever slot it took, the
// unverified would arrive wearing that verdict's colour (`H-B2`).
type KeyModeStatus int

const (
	// KeyModeAbsent: the file is not there. S18 owns absence — it is the rule
	// that says a missing key is not an invitation to generate one. S19 judges
	// the mode of a file that exists and must stay silent about one that does
	// not, or the two rules report the same fault twice with different wording.
	KeyModeAbsent KeyModeStatus = iota
	// KeyModeUnknown: the path could not be resolved to a mode, and it was not
	// because it is absent. A permission error on the directory reads exactly
	// like this, and that is the case that matters most.
	KeyModeUnknown
	// KeyModeRead: Perm holds the permission bits.
	KeyModeRead
)

// KeyModeObservation is one private key file as the host presented it. Where
// names the role for the operator; Path is what to chmod.
type KeyModeObservation struct {
	Path   string
	Where  string
	Status KeyModeStatus
	Perm   os.FileMode
	Err    error
}

// ModeTooWide is the predicate: any group or other bit at all. 0600 and 0400
// pass, 0640 does not. Read access is the whole question — a key someone else
// can read is a key they have.
func ModeTooWide(perm os.FileMode) bool { return perm&0o077 != 0 }

// EvaluateKeyModes is pure.
//
// Three rule ids, not one. A key that is world-readable, a key whose mode
// nobody could read, and a component that never said what it holds are three
// different faults with three different remedies, and folding them onto one id
// means deleting any one branch leaves the others emitting the same line. `D29`
// measured that shape directly: folding reason ids still produced rc=78, so a
// harness that reads only the exit code saw nothing move.
func EvaluateKeyModes(obs []KeyModeObservation) []error {
	var out []error
	for _, o := range obs {
		switch o.Status {
		case KeyModeAbsent:
			continue
		case KeyModeUnknown:
			out = append(out, Cfg("S19b",
				"key: %s (%s) mode could not be read: %v — unexamined is not clean",
				o.Path, o.Where, o.Err))
		case KeyModeRead:
			if ModeTooWide(o.Perm) {
				out = append(out, Cfg("S19", "key: %s mode %04o (want 0600)",
					o.Path, uint32(o.Perm)))
			}
		}
	}
	return out
}

// ObserveKeyModes reads the modes of the private material a component declares,
// resolving each path the way its loader does: env override over default.
//
// ok=false means the component declared nothing — either it is not registered,
// or it is registered and set neither Private nor NoPrivate. The caller must
// not read that as "no private keys": nothing was looked for.
func ObserveKeyModes(component string, p Probe) (obs []KeyModeObservation, ok bool) {
	spec, registered := componentKeyRegistry[component]
	if !registered {
		return nil, false
	}
	if len(spec.Private) == 0 && !spec.NoPrivate {
		return nil, false
	}

	envOr := func(k, def string) string {
		if v := p.Get(k); v != "" {
			return v
		}
		return def
	}
	look := func(path, where string) {
		o := KeyModeObservation{Path: path, Where: where}
		perm, err := p.StatMode(path)
		switch {
		case err == nil:
			o.Status, o.Perm = KeyModeRead, perm
		case errors.Is(err, fs.ErrNotExist):
			o.Status = KeyModeAbsent
		default:
			o.Status, o.Err = KeyModeUnknown, err
		}
		obs = append(obs, o)
	}

	for _, s := range spec.Private {
		look(envOr(s.Env, s.Default), s.Where)
	}
	// Same condition collectKeyMaterial uses for the certificate. With TLS off
	// the process never opens the key, and refusing on a file it will not read
	// makes this a wall rather than a gate.
	if spec.TLSKey != "" && p.Get("PAIL_GRPC_TLS") != "off" {
		keyPath := envOr("PAIL_GRPC_KEY", spec.TLSKey)
		if spec.TLSClient {
			keyPath = envOr("PAIL_GRPC_CLIENT_KEY", keyPath)
		}
		look(keyPath, "gRPC private key")
	}
	return obs, true
}

// EnforceKeyModes is the wiring. It runs beside Preflight rather than inside
// it: Preflight downgrades its findings to a banner under PAIL_PROFILE=dev, and
// S19 must not be downgraded.
//
// It reports every violation before exiting. Exiting on the first would make an
// operator with three wide keys restart three times to learn that.
func EnforceKeyModes(component string) {
	obs, ok := ObserveKeyModes(component, SystemProbe())
	if !ok {
		RefuseConfigAll(component, []error{Cfg("S19c",
			"component %q declares no private key material — set Private or NoPrivate in componentKeyRegistry (deploysec/keymaterial.go); silence is not a declaration",
			component)})
		return
	}
	RefuseConfigAll(component, EvaluateKeyModes(obs))
}
