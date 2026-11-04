// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// Command pail-keyring-sign is the offline root-signing tool for KM2 keyring
// bundles (LLD §6.4). It has no network code and is meant to run on an
// air-gapped machine that holds the root private key.
//
//	pail-keyring-sign gen-root  --out root_ed25519.json [--key-id root-1]
//	pail-keyring-sign sign      --root root_ed25519.json --payload payload.json --out keyring_bundle.json
//	pail-keyring-sign verify    --root-pub root_pub.b64 --bundle keyring_bundle.json
//	pail-keyring-sign inspect   --bundle keyring_bundle.json
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/glowfly/pail/services/internal/crypto"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "gen-root":
		err = cmdGenRoot(os.Args[2:])
	case "sign":
		err = cmdSign(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "inspect":
		err = cmdInspect(os.Args[2:])
	case "inspect-json":
		err = cmdInspectJSON(os.Args[2:])
	case "prepare-renewal":
		err = cmdPrepareRenewal(os.Args[2:])
	case "validate-renewal":
		err = cmdValidateRenewal(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `pail-keyring-sign — offline KM2 keyring bundle signer

  gen-root  --out root_ed25519.json [--key-id root-1]
  sign      --root root_ed25519.json --payload payload.json --out keyring_bundle.json
  verify    --root-pub root_pub.b64 --bundle keyring_bundle.json
  inspect   --bundle keyring_bundle.json
  inspect-json --root-pub root_pub.b64 --bundle keyring_bundle.json
  prepare-renewal --root-pub root_pub.b64 --bundle base.json --consumers observations.json --issued-at UNIX --expires-at UNIX
  validate-renewal --root-pub root_pub.b64 --bundle base.json --consumers observations.json --candidate staged.json

Renewal commands are pure preparation/validation, NOT approval or application.
`)
}

func cmdGenRoot(args []string) error {
	fs := flag.NewFlagSet("gen-root", flag.ExitOnError)
	out := fs.String("out", "", "output root key file (JSON)")
	keyID := fs.String("key-id", "root-1", "root key id")
	_ = fs.Parse(args)
	if *out == "" {
		return fmt.Errorf("--out required")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	jf := crypto.KeyFileJSON{
		KeyID:        *keyID,
		PrivKeyB64:   base64.StdEncoding.EncodeToString(priv),
		PublicKeyB64: base64.StdEncoding.EncodeToString(pub),
	}
	b, err := json.MarshalIndent(jf, "", "  ")
	if err != nil {
		return err
	}
	if err := writeAtomic(*out, append(b, '\n'), 0600); err != nil {
		return err
	}
	// Print the public key so the operator can save root_pub.b64 for verifiers.
	fmt.Printf("root key generated: key_id=%s\n", *keyID)
	fmt.Printf("ROOT_PUBKEY_B64=%s\n", jf.PublicKeyB64)
	fmt.Fprintf(os.Stderr, "NOTE: keep %s offline; distribute only the public key above.\n", *out)
	return nil
}

func cmdSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	rootPath := fs.String("root", "", "root key file (JSON, holds private key)")
	payloadPath := fs.String("payload", "", "payload JSON to sign (signed byte-for-byte)")
	out := fs.String("out", "", "output bundle file")
	_ = fs.Parse(args)
	if *rootPath == "" || *payloadPath == "" || *out == "" {
		return fmt.Errorf("--root, --payload and --out are required")
	}
	jf, err := readKeyFile(*rootPath)
	if err != nil {
		return err
	}
	priv, err := base64.StdEncoding.DecodeString(jf.PrivKeyB64)
	if err != nil {
		return fmt.Errorf("root: decode private key: %w", err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("root: private key size %d (want %d)", len(priv), ed25519.PrivateKeySize)
	}
	payloadBytes, err := os.ReadFile(*payloadPath)
	if err != nil {
		return fmt.Errorf("read payload: %w", err)
	}
	warnDevKey(payloadBytes)
	bundle, err := crypto.BuildBundle(ed25519.PrivateKey(priv), jf.KeyID, payloadBytes)
	if err != nil {
		return err
	}
	if err := writeAtomic(*out, bundle, 0644); err != nil {
		return err
	}
	fmt.Printf("signed bundle written: %s (root key_id=%s)\n", *out, jf.KeyID)
	return nil
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	rootPubPath := fs.String("root-pub", "", "file with base64 root public key")
	bundlePath := fs.String("bundle", "", "bundle file to verify")
	_ = fs.Parse(args)
	if *rootPubPath == "" || *bundlePath == "" {
		return fmt.Errorf("--root-pub and --bundle are required")
	}
	rootPub, err := readRootPub(*rootPubPath)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*bundlePath)
	if err != nil {
		return fmt.Errorf("read bundle: %w", err)
	}
	p, _, err := crypto.VerifyBundle(raw, rootPub)
	if err != nil {
		return err
	}
	fmt.Printf("OK: signature valid — bundle_version=%d expires=%s keys=%d\n",
		p.BundleVersion, time.Unix(p.ExpiresAtUnix, 0).UTC().Format(time.RFC3339), len(p.Keys))
	return nil
}

func cmdInspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	bundlePath := fs.String("bundle", "", "bundle file to inspect")
	_ = fs.Parse(args)
	if *bundlePath == "" {
		return fmt.Errorf("--bundle required")
	}
	raw, err := os.ReadFile(*bundlePath)
	if err != nil {
		return fmt.Errorf("read bundle: %w", err)
	}
	var env crypto.BundleEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("parse envelope: %w", err)
	}
	pb, err := base64.StdEncoding.DecodeString(env.PayloadB64)
	if err != nil {
		return fmt.Errorf("decode payload_b64: %w", err)
	}
	var p crypto.BundlePayload
	if err := json.Unmarshal(pb, &p); err != nil {
		return fmt.Errorf("parse payload: %w", err)
	}
	fmt.Printf("schema_version : %d\n", env.SchemaVersion)
	fmt.Printf("root_key_id    : %s\n", env.RootKeyID)
	fmt.Printf("bundle_version : %d\n", p.BundleVersion)
	fmt.Printf("issued_at      : %s\n", time.Unix(p.IssuedAtUnix, 0).UTC().Format(time.RFC3339))
	fmt.Printf("expires_at     : %s\n", time.Unix(p.ExpiresAtUnix, 0).UTC().Format(time.RFC3339))
	fmt.Printf("keys (%d):\n", len(p.Keys))
	// role 이 비어 있으면 비어 있다고 적는다. 여기서 `issuer` 로 접으면 운영자가
	// inspect 로 본 것과 적재기가 판정하는 것이 달라진다 — 화면은 정상이라고
	// 말하고 배포는 `S15` 로 죽는다. inspect 는 서명을 검증하지 않는 **날것의
	// 표시**이므로 더더욱 접으면 안 된다.
	for _, e := range p.Keys {
		role := e.Role
		if role == "" {
			role = "(none) <<< refused by S15 at load"
		}
		fmt.Printf("  - %-16s role=%s\n", e.KeyID, role)
	}
	fmt.Fprintln(os.Stderr, "NOTE: inspect does NOT verify the signature — use `verify --root-pub`.")
	return nil
}

func warnDevKey(payloadBytes []byte) {
	var p crypto.BundlePayload
	if json.Unmarshal(payloadBytes, &p) != nil {
		return
	}
	for _, e := range p.Keys {
		if strings.HasPrefix(e.KeyID, "dev-key") {
			fmt.Fprintf(os.Stderr, "WARNING: payload includes dev key %q — dev keys must not ship in a production bundle (KM1-3).\n", e.KeyID)
		}
	}
}

func readKeyFile(path string) (*crypto.KeyFileJSON, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read root key: %w", err)
	}
	var jf crypto.KeyFileJSON
	if err := json.Unmarshal(b, &jf); err != nil {
		return nil, fmt.Errorf("parse root key: %w", err)
	}
	if jf.KeyID == "" {
		return nil, fmt.Errorf("root key: missing key_id")
	}
	return &jf, nil
}

func readRootPub(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read root-pub: %w", err)
	}
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("root-pub decode base64: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("root-pub size %d (want %d)", len(pub), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(pub), nil
}

func writeAtomic(path string, b []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, perm); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}
