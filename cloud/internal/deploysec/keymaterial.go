// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package deploysec

// S8 (PAIL-SD2-LLD-v1 §2): refuse to start on key material that is committed to
// this repository.
//
// The judgement is on the fingerprint of the public key, not on the file path or
// the key_id. A committed key copied elsewhere, renamed, or re-labelled is the
// same key: whoever cloned the repository can sign with it.

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
)

// Default locations. The checks and the loaders must not drift apart, so main
// takes its defaults from here (PAIL-SD2-LLD-v1 §2.3).
const (
	DefaultIssuerKeyfile = "/etc/pail/keys/issuer_ed25519.json"
	DefaultKeyringPath   = "/etc/pail/keys/keyring.json"
	DefaultAgentKeyfile  = "/etc/pail/keys/agent_ed25519.json"

	// The TLS private keys. grpcauth holds the same defaults for loading, and
	// deploysec must not import the code it judges, so this is a second copy on
	// purpose. TestS19TLSKeyDefaultsMatchGrpcauth is what keeps the two from
	// drifting — without it, moving grpcauth's default would leave S19 checking
	// a path nobody opens and reporting the move as clean.
	DefaultGRPCServerKey = "/etc/pail/grpc_certs/server.key"
	DefaultGRPCClientKey = "/etc/pail/grpc_certs/client.key"
)

// KeyMaterial is one public key found somewhere a component trusts or signs
// with. Where is for the operator's error message.
type KeyMaterial struct {
	Where       string
	Kind        string // "ed25519" | "spki"
	Fingerprint string
}

// ReadFileFunc is os.ReadFile, injected so the scanners stay testable.
type ReadFileFunc func(string) ([]byte, error)

// Ed25519Fingerprint is sha256 of the raw 32-byte public key. Anything that is
// not 32 bytes is not an Ed25519 public key and returns "".
func Ed25519Fingerprint(pub []byte) string {
	if len(pub) != 32 {
		return ""
	}
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// SPKIFingerprintPEM is sha256 of the certificate's SubjectPublicKeyInfo DER.
// Pinning the key rather than the certificate means reissuing the certificate
// without changing the key is still caught.
func SPKIFingerprintPEM(pemBytes []byte) (string, error) {
	for rest := pemBytes; len(rest) > 0; {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return "", err
		}
		sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		return hex.EncodeToString(sum[:]), nil
	}
	return "", fmt.Errorf("no CERTIFICATE block")
}

// LookupDevKey reports whether a fingerprint is on the committed-key list.
func LookupDevKey(fpr string) (KnownDevKey, bool) {
	for _, k := range knownDevKeys {
		if k.Fingerprint == fpr {
			return k, true
		}
	}
	return KnownDevKey{}, false
}

// keyDoc covers both shapes: a single keypair file and a keyring array.
type keyDoc struct {
	KeyID        string `json:"key_id"`
	PublicKeyB64 string `json:"ed25519_public_key_base64"`
	Keys         []struct {
		KeyID        string `json:"key_id"`
		PublicKeyB64 string `json:"ed25519_public_key_base64"`
	} `json:"keys"`
}

// ScanEd25519File returns the public keys in a keyfile or keyring at path.
//
// A missing or malformed file yields nothing: S8 judges key material, and the
// loader that actually needs the file reports its own error. Reporting it twice
// with different wording would only confuse the operator.
func ScanEd25519File(rf ReadFileFunc, path, where string) []KeyMaterial {
	raw, err := rf(path)
	if err != nil {
		return nil
	}
	var doc keyDoc
	if json.Unmarshal(raw, &doc) != nil {
		return nil
	}
	var out []KeyMaterial
	add := func(b64, keyID string) {
		pub, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return
		}
		if f := Ed25519Fingerprint(pub); f != "" {
			out = append(out, KeyMaterial{
				Where:       fmt.Sprintf("%s [%s key_id=%s]", where, path, keyID),
				Kind:        "ed25519",
				Fingerprint: f,
			})
		}
	}
	if doc.PublicKeyB64 != "" {
		add(doc.PublicKeyB64, doc.KeyID)
	}
	for _, e := range doc.Keys {
		add(e.PublicKeyB64, e.KeyID)
	}
	return out
}

// ScanCertFile returns the SPKI fingerprint of the certificate at path.
func ScanCertFile(rf ReadFileFunc, path, where string) []KeyMaterial {
	raw, err := rf(path)
	if err != nil {
		return nil
	}
	f, err := SPKIFingerprintPEM(raw)
	if err != nil {
		return nil
	}
	return []KeyMaterial{{
		Where:       fmt.Sprintf("%s [%s]", where, path),
		Kind:        "spki",
		Fingerprint: f,
	}}
}

// EvaluateKeyMaterial is pure: one S8 finding per piece of material that is on
// the committed list.
func EvaluateKeyMaterial(items []KeyMaterial) []Finding {
	var out []Finding
	for _, it := range items {
		k, ok := LookupDevKey(it.Fingerprint)
		if !ok {
			continue
		}
		out = append(out, Finding{"S8", fmt.Sprintf(
			"%s is a key committed to this repository (sha256:%s = %s) — anyone with the source can sign with it",
			it.Where, it.Fingerprint[:16], k.Label)})
	}
	return out
}

// keyFileSource is one ed25519 keyfile or keyring a component reads, named the
// way its loader names it: an env override over a default path.
type keyFileSource struct{ Env, Default, Where string }

// componentKeys is everything S8 must look at for one PAIL process.
type componentKeys struct {
	Files []keyFileSource
	// TLSCert is the default gRPC certificate path, or "" when the process
	// holds no gRPC identity (burst_recv speaks UDP only).
	TLSCert string

	// Private is the private key material this process opens: the seed it signs
	// with. Public material (keyring, certificates) is deliberately not here —
	// S19 judges what must not be readable by anyone else, and a keyring that
	// is world-readable is not a finding (§1.3 lists keyring.json at 0644 as
	// normal).
	Private []keyFileSource
	// TLSKey is the private half of TLSCert, checked only when TLS is on — the
	// same condition under which collectKeyMaterial looks at the certificate.
	TLSKey string
	// NoPrivate is the declaration that a component holds no private key
	// material. A second field rather than an empty Private list, because in Go
	// a list nobody filled in and a list deliberately left empty are the same
	// literal — the shape `S16e` already paid for, where absence read as a
	// value. S19 refuses a registered component that declares neither.
	NoPrivate bool
	// TLSClient marks a component whose TLS identity loads through ClientTLS
	// (PAIL_GRPC_CLIENT_CERT/KEY first, shared names as fallback). The scanner
	// must resolve the same chain the loader resolves, or it scans a file the
	// process never opens and the loaded one goes unexamined (`H-B2`).
	TLSClient bool
}

// componentKeyRegistry is the literal list of PAIL processes and their key
// material (`B6-6`, implementation contract).
//
// The old form was a switch with no default, so a process the switch did not
// name got only its TLS material scanned and S8 reported OK — the signing key
// was never looked at, and "unexamined" arrived wearing the same green as
// "clean" (`H-B2`). burst_recv lived in that gap.
//
// One list, read by two places: collectKeyMaterial scans what is here, and
// EvaluateDeployment fails any component that is not. Two lists would drift,
// and the drift would show up as a pass.
var componentKeyRegistry = map[string]componentKeys{
	"pail_cloud": {
		Files: []keyFileSource{
			// (1) the issuer signing key: a committed one lets anyone mint tokens.
			{"PAIL_ISSUER_KEYFILE", DefaultIssuerKeyfile, "issuer signing key"},
			// (2) the legacy keyring: every entry is a trust anchor.
			{"PAIL_KEYRING", DefaultKeyringPath, "keyring entry"},
		},
		TLSCert: "/etc/pail/grpc_certs/server.crt",
		Private: []keyFileSource{
			{"PAIL_ISSUER_KEYFILE", DefaultIssuerKeyfile, "issuer signing key"},
		},
		TLSKey: DefaultGRPCServerKey,
	},
	"pail_services": {
		Files: []keyFileSource{
			{"PAIL_ISSUER_KEYFILE", DefaultIssuerKeyfile, "issuer signing key"},
			{"PAIL_KEYRING", DefaultKeyringPath, "keyring entry"},
		},
		TLSCert: "/etc/pail/grpc_certs/server.crt",
		Private: []keyFileSource{
			{"PAIL_ISSUER_KEYFILE", DefaultIssuerKeyfile, "issuer signing key"},
		},
		TLSKey: DefaultGRPCServerKey,
	},
	"pail_robot_agent": {
		// (5) the burst signing key.
		Files:   []keyFileSource{{"PAIL_AGENT_KEY", DefaultAgentKeyfile, "burst signing key"}},
		TLSCert: "/etc/pail/grpc_certs/client.crt",
		Private: []keyFileSource{
			{"PAIL_AGENT_KEY", DefaultAgentKeyfile, "burst signing key"},
		},
		TLSKey:    DefaultGRPCClientKey,
		TLSClient: true,
	},
	"burst_recv": {
		// The keyring is burst_recv's whole trust anchor set: every entry in it
		// can sign a burst packet this process will report as authentic.
		Files: []keyFileSource{{"PAIL_KEYRING", DefaultKeyringPath, "keyring entry"}},
		// It verifies and never signs, and it speaks UDP with no TLS identity.
		// Said out loud so that a future process that does hold a key cannot
		// inherit this silence.
		NoPrivate: true,
	},
	"pail_telemetryd": {
		// The dashboard collector (implementation contract D1): same trust shape as
		// burst_recv — the keyring decides which packets it records as sig=ok.
		Files: []keyFileSource{{"PAIL_KEYRING", DefaultKeyringPath, "keyring entry"}},
		// Verifies only; speaks UDP + loopback HTTP with no TLS identity.
		NoPrivate: true,
	},
}

// ComponentRegistered reports whether S8 knows what key material a component
// holds. Absence is not cleanliness — it is that nothing was looked for.
func ComponentRegistered(component string) bool {
	_, ok := componentKeyRegistry[component]
	return ok
}

// collectKeyMaterial gathers what a component signs with and trusts, from the
// same env vars and defaults the loaders use.
func collectKeyMaterial(component string, p Probe) []KeyMaterial {
	get, rf := p.Get, p.ReadFile
	envOr := func(k, def string) string {
		if v := get(k); v != "" {
			return v
		}
		return def
	}
	spec := componentKeyRegistry[component]
	var out []KeyMaterial
	for _, s := range spec.Files {
		out = append(out, ScanEd25519File(rf, envOr(s.Env, s.Default), s.Where)...)
	}
	// (3) TLS identity, when TLS is on. Default is on (grpcauth.TLSEnabled).
	if spec.TLSCert != "" && get("PAIL_GRPC_TLS") != "off" {
		out = append(out, ScanCertFile(rf,
			envOr("PAIL_GRPC_CA", "/etc/pail/grpc_certs/ca.crt"), "gRPC CA certificate")...)
		certPath := envOr("PAIL_GRPC_CERT", spec.TLSCert)
		if spec.TLSClient {
			certPath = envOr("PAIL_GRPC_CLIENT_CERT", certPath)
		}
		out = append(out, ScanCertFile(rf, certPath, "gRPC certificate")...)
	}
	return out
}

// EnforceTrustAnchors is check (4)/(6) of §2.3: the anchors the process actually
// loaded, after the keyring is resolved and before it serves.
//
// The file-path checks above run before the port is taken, but in bundle mode
// the real anchors are not knowable from a path. This is the authoritative one.
func EnforceTrustAnchors(component string, anchors []KeyMaterial) {
	fail := EvaluateKeyMaterial(anchors)
	if len(fail) == 0 {
		return
	}
	profile := os.Getenv("PAIL_PROFILE")
	if profile == "" {
		profile = "production"
	}
	if profile != "production" {
		fmt.Fprintf(os.Stderr, "PAIL PREFLIGHT: profile=%s INSECURE(S8) component=%s — NOT FOR PRODUCTION\n", profile, component)
		for _, f := range fail {
			fmt.Fprintf(os.Stderr, "PAIL PREFLIGHT:   %s %s\n", f.ID, f.Msg)
		}
		return
	}
	for _, f := range fail {
		fmt.Fprintf(os.Stderr, "PAIL PREFLIGHT FAIL: %s %s [profile=%s component=%s]\n", f.ID, f.Msg, profile, component)
	}
	fmt.Fprintf(os.Stderr, "PAIL PREFLIGHT FAIL: refusing to start. Set PAIL_PROFILE=dev to run without these protections (DEV ONLY).\n")
	os.Exit(ExitConfig)
}

// AnchorEntry is a loaded trust anchor, kept free of the crypto package's types
// so deploysec has no dependency on the code it is judging.
type AnchorEntry struct {
	KeyID        string
	PublicKeyB64 string
}

// TrustAnchorsFromKeyring turns loaded keyring entries into KeyMaterial.
func TrustAnchorsFromKeyring(where string, entries []AnchorEntry) []KeyMaterial {
	out := make([]KeyMaterial, 0, len(entries))
	for _, e := range entries {
		pub, err := base64.StdEncoding.DecodeString(e.PublicKeyB64)
		if err != nil {
			continue
		}
		if f := Ed25519Fingerprint(pub); f != "" {
			out = append(out, KeyMaterial{
				Where:       fmt.Sprintf("%s [loaded key_id=%s]", where, e.KeyID),
				Kind:        "ed25519",
				Fingerprint: f,
			})
		}
	}
	return out
}

// TrustAnchorFromPub covers the key the process actually signs with, which in a
// KMS or bundle deployment is not the file the path checks looked at.
func TrustAnchorFromPub(where, keyID string, pub []byte) []KeyMaterial {
	f := Ed25519Fingerprint(pub)
	if f == "" {
		return nil
	}
	return []KeyMaterial{{
		Where:       fmt.Sprintf("%s [loaded key_id=%s]", where, keyID),
		Kind:        "ed25519",
		Fingerprint: f,
	}}
}
