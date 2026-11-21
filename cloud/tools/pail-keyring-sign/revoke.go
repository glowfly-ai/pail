// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

// SEC-H02 — two commands that need the root PUBLIC key only.
//
//	prepare-revoke  the payload of the bundle that revokes one key. During an incident the
//	                payload the root is about to sign used to be edited by hand; this does
//	                that one edit and nothing else. Signing stays with `sign`.
//	init-floor      the explicit first-install step of a production consumer: the version
//	                floor is written once, from a bundle the root signed.
//	                It reads only the bundle it is given and compares the floor with no
//	                other consumer: run on a rejected rollback candidate it writes that
//	                lower version (P024-L2), so it is run on the bundle meant to be current.

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/glowfly/pail/services/internal/crypto"
)

// prepareRevoke returns the payload of the bundle that revokes keyID: the given bundle,
// verified against rootPub, with that key moved from keys to revoked_keys and the
// version raised by one. Nothing else changes — the expiry in particular: a revocation
// must not quietly extend the life of the bundle it replaces. A result that leaves no
// active issuer key is refused unless allowNoIssuer says that is the intent (every gate
// that loads such a bundle refuses every token).
func prepareRevoke(bundle []byte, rootPub ed25519.PublicKey, keyID string, allowNoIssuer bool) ([]byte, error) {
	if keyID == "" {
		return nil, errors.New("prepare-revoke: --key-id is required")
	}
	p, _, err := crypto.VerifyBundle(bundle, rootPub)
	if err != nil {
		return nil, fmt.Errorf("prepare-revoke: the base bundle does not verify against the root: %w", err)
	}
	for _, e := range p.RevokedKeys {
		if e.KeyID == keyID {
			return nil, fmt.Errorf("prepare-revoke: key %q is already revoked in bundle version %d", keyID, p.BundleVersion)
		}
	}
	keep := make([]crypto.KeyringEntry, 0, len(p.Keys))
	var moved *crypto.KeyringEntry
	for i := range p.Keys {
		if p.Keys[i].KeyID == keyID {
			e := p.Keys[i]
			moved = &e
			continue
		}
		keep = append(keep, p.Keys[i])
	}
	if moved == nil {
		return nil, fmt.Errorf("prepare-revoke: key %q is not an active key of bundle version %d", keyID, p.BundleVersion)
	}
	issuers := 0
	for _, e := range keep {
		if e.Role == "issuer" {
			issuers++
		}
	}
	if issuers == 0 && !allowNoIssuer {
		return nil, fmt.Errorf("prepare-revoke: revoking %q leaves no active issuer key — every gate that loads the result refuses every token; pass --allow-no-issuer if that is the intent, or add the successor key to the base bundle first", keyID)
	}
	out := crypto.BundlePayload{
		BundleVersion: p.BundleVersion + 1,
		IssuedAtUnix:  time.Now().Unix(),
		ExpiresAtUnix: p.ExpiresAtUnix,
		Keys:          keep,
		RevokedKeys:   append(append([]crypto.KeyringEntry{}, p.RevokedKeys...), *moved),
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func cmdPrepareRevoke(args []string) error {
	fs := flag.NewFlagSet("prepare-revoke", flag.ExitOnError)
	bundlePath := fs.String("bundle", "", "the bundle in force (root-signed)")
	rootPubPath := fs.String("root-pub", "", "root public key file (base64)")
	keyID := fs.String("key-id", "", "key_id to revoke")
	out := fs.String("out", "", "output payload file (sign it with `sign`)")
	allow := fs.Bool("allow-no-issuer", false, "permit a result with no active issuer key (gates then refuse every token)")
	_ = fs.Parse(args)
	if *bundlePath == "" || *rootPubPath == "" || *keyID == "" || *out == "" {
		return fmt.Errorf("--bundle, --root-pub, --key-id and --out are required")
	}
	rootPub, err := readRootPub(*rootPubPath)
	if err != nil {
		return err
	}
	bundle, err := os.ReadFile(*bundlePath)
	if err != nil {
		return fmt.Errorf("read bundle: %w", err)
	}
	payload, err := prepareRevoke(bundle, rootPub, *keyID, *allow)
	if err != nil {
		return err
	}
	if err := writeAtomic(*out, payload, 0644); err != nil {
		return err
	}
	var p crypto.BundlePayload
	_ = json.Unmarshal(payload, &p)
	fmt.Printf("revocation payload written: %s (bundle_version=%d, revoked key_id=%s, expires_at_unix=%d unchanged)\n", *out, p.BundleVersion, *keyID, p.ExpiresAtUnix)
	fmt.Fprintln(os.Stderr, "NOTE: this is a payload, not a bundle. Sign it with `sign`, place the bundle where the Issuer serves it, and confirm on each gate that the version was applied.")
	return nil
}

func cmdInitFloor(args []string) error {
	fs := flag.NewFlagSet("init-floor", flag.ExitOnError)
	bundlePath := fs.String("bundle", "", "the placed bundle (root-signed)")
	rootPubPath := fs.String("root-pub", "", "root public key file (base64)")
	statePath := fs.String("state", "", "state file to create (PAIL_KEYRING_STATE of the consumer)")
	// P024T-N3: the sentence about what this command reads was in the top-level help only.
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, "init-floor writes a consumer's version floor once, from a root-signed bundle; it never overwrites a state file.\n"+
			"It reads only the bundle you give it and does not compare the floor with any other consumer; run it on the\n"+
			"bundle you intend to be current. It never reads the root private key.\n\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	if *bundlePath == "" || *rootPubPath == "" || *statePath == "" {
		return fmt.Errorf("--bundle, --root-pub and --state are required")
	}
	rootPub, err := readRootPub(*rootPubPath)
	if err != nil {
		return err
	}
	version, err := crypto.InitBundleFloor(*bundlePath, rootPub, *statePath)
	if err != nil {
		return err
	}
	fmt.Printf("version floor initialised: %s (last_version=%d)\n", *statePath, version)
	return nil
}
