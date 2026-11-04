// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package crypto

// Renewal preparation is deliberately pure: it never loads runtime trust,
// updates a rollback floor, signs, replaces a file, or restarts a consumer.
import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"reflect"
	"unicode/utf8"
)

const renewalMaxBytes = 32 * 1024
const renewalMaxUnix int64 = 253402300799

type RenewalConsumer struct {
	MaxBundleVersion    uint64 `json:"max_bundle_version"`
	RootFingerprint     string `json:"root_fingerprint_sha256"`
	MaterialDigest      string `json:"material_digest_sha256"`
	ID                  string `json:"id"`
	LoadedGeneration    string `json:"loaded_generation"`
	Observed            bool   `json:"observed"`
	RollbackFloor       uint64 `json:"rollback_floor"`
	NowMinUnix          int64  `json:"now_min_unix"`
	NowMaxUnix          int64  `json:"now_max_unix"`
	MaxRemainingSeconds int64  `json:"max_remaining_seconds"`
}

type RenewalProposal struct {
	SchemaVersion   int               `json:"schema_version"`
	BaseSHA256      string            `json:"base_sha256"`
	RootFingerprint string            `json:"root_fingerprint_sha256"`
	Payload         json.RawMessage   `json:"payload"`
	Consumers       []RenewalConsumer `json:"consumers"`
	MotionAction    string            `json:"motion_action"`
}

func trustHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// uniqueJSON rejects ambiguous duplicate names, including escaped equivalents.
// This stricter administrative boundary does not relax the runtime parser.
func uniqueJSON(b []byte) error {
	if !utf8.Valid(b) {
		return fmt.Errorf("TRUST_JSON_ENCODING")
	}
	if len(b) > renewalMaxBytes {
		return fmt.Errorf("TRUST_METADATA_TOO_LARGE")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 16 {
			return fmt.Errorf("TRUST_JSON_DEPTH")
		}
		t, e := d.Token()
		if e != nil {
			return e
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := k.(string)
				if !ok || seen[s] {
					return fmt.Errorf("TRUST_DUPLICATE_FIELD")
				}
				seen[s] = true
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
		case '[':
			for d.More() {
				if e := walk(depth + 1); e != nil {
					return e
				}
			}
		default:
			return fmt.Errorf("TRUST_JSON_DELIMITER")
		}
		_, e = d.Token()
		return e
	}
	if e := walk(0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return fmt.Errorf("TRUST_JSON_TRAILING")
	}
	return nil
}

// InspectTrustBundle checks bounded, unambiguous signed metadata, even if
// expired. It does not determine runtime validity or write any state.
func InspectTrustBundle(bundle []byte, root ed25519.PublicKey) (*BundlePayload, []byte, error) {
	if e := uniqueJSON(bundle); e != nil {
		return nil, nil, e
	}
	p, raw, e := VerifyBundle(bundle, root)
	if e != nil {
		return nil, nil, e
	}
	if e = uniqueJSON(raw); e != nil {
		return nil, nil, e
	}
	if len(p.Keys)+len(p.RevokedKeys) > 128 {
		return nil, nil, fmt.Errorf("TRUST_KEY_LIMIT")
	}
	return p, raw, nil
}

// PrepareTrustRenewal preserves every immutable payload field semantically.
// Signatures still cover the exact new payload bytes. Expired bases must
// authenticate under the approved root; unknown fields are never discarded.
func PrepareTrustRenewal(bundle []byte, root ed25519.PublicKey, consumers []RenewalConsumer, issued, expires int64) (*RenewalProposal, error) {
	p, raw, e := InspectTrustBundle(bundle, root)
	if e != nil {
		return nil, e
	}
	if issued <= 0 || expires <= issued || expires > renewalMaxUnix {
		return nil, fmt.Errorf("RENEWAL_TIME_INVALID")
	}
	if len(consumers) == 0 || len(consumers) > 128 {
		return nil, fmt.Errorf("CONSUMER_OBSERVATION_REQUIRED")
	}
	material, e := TrustMaterialDigest(p)
	if e != nil {
		return nil, e
	}
	rootFingerprint := trustHash(root)
	floor := p.BundleVersion
	seen := map[string]bool{}
	for _, c := range consumers {
		if c.MaxBundleVersion == 0 {
			return nil, fmt.Errorf("CONSUMER_VERSION_CAP_UNKNOWN")
		}
		if c.RootFingerprint != rootFingerprint || c.MaterialDigest != material {
			return nil, fmt.Errorf("CONSUMER_TRUST_MATERIAL_UNCONFIRMED")
		}
		if !c.Observed || c.ID == "" || len(c.ID) > 128 || c.LoadedGeneration == "" || len(c.LoadedGeneration) > 128 || seen[c.ID] {
			return nil, fmt.Errorf("CONSUMER_OBSERVATION_INVALID")
		}
		seen[c.ID] = true
		if c.NowMinUnix <= 0 || c.NowMaxUnix < c.NowMinUnix || c.NowMaxUnix > renewalMaxUnix || c.MaxRemainingSeconds <= 0 || c.MaxRemainingSeconds > renewalMaxUnix {
			return nil, fmt.Errorf("CONSUMER_CLOCK_OR_CAP_UNKNOWN")
		}
		if issued > c.NowMinUnix || expires <= c.NowMaxUnix || expires-c.NowMinUnix > c.MaxRemainingSeconds {
			return nil, fmt.Errorf("CONSUMER_LIFETIME_REJECTED")
		}
		if c.RollbackFloor > floor {
			floor = c.RollbackFloor
		}
	}
	if floor == math.MaxUint64 {
		return nil, fmt.Errorf("RENEWAL_VERSION_OVERFLOW")
	}
	for _, c := range consumers {
		if floor+1 > c.MaxBundleVersion {
			return nil, fmt.Errorf("CONSUMER_VERSION_CAP_EXCEEDED")
		}
	}
	var fields map[string]json.RawMessage
	if e = json.Unmarshal(raw, &fields); e != nil {
		return nil, e
	}
	fields["bundle_version"], _ = json.Marshal(floor + 1)
	fields["issued_at_unix"], _ = json.Marshal(issued)
	fields["expires_at_unix"], _ = json.Marshal(expires)
	candidate, e := json.Marshal(fields)
	if e != nil {
		return nil, e
	}
	if _, e = parsePayload(candidate); e != nil {
		return nil, e
	}
	return &RenewalProposal{1, trustHash(bundle), trustHash(root), candidate, append([]RenewalConsumer(nil), consumers...), "NONE"}, nil
}

// ValidateTrustRenewal repeats authentication and the pure policy evaluation
// after external signing. It is not an approval or an execution fence.
func ValidateTrustRenewal(base, candidate []byte, root ed25519.PublicKey, consumers []RenewalConsumer) error {
	next, nextRaw, e := InspectTrustBundle(candidate, root)
	if e != nil {
		return e
	}
	proposal, e := PrepareTrustRenewal(base, root, consumers, next.IssuedAtUnix, next.ExpiresAtUnix)
	if e != nil {
		return e
	}
	var expected, actual any
	a := json.NewDecoder(bytes.NewReader(proposal.Payload))
	a.UseNumber()
	b := json.NewDecoder(bytes.NewReader(nextRaw))
	b.UseNumber()
	if e = a.Decode(&expected); e != nil {
		return e
	}
	if e = b.Decode(&actual); e != nil {
		return e
	}
	if !reflect.DeepEqual(expected, actual) {
		return fmt.Errorf("RENEWAL_IMMUTABLE_OR_VERSION_CHANGED")
	}
	// Root labels are not trust anchors, but a renewal must not change them either.
	var oldEnv, newEnv BundleEnvelope
	if e = json.Unmarshal(base, &oldEnv); e != nil {
		return e
	}
	if e = json.Unmarshal(candidate, &newEnv); e != nil {
		return e
	}
	if oldEnv.RootKeyID != newEnv.RootKeyID {
		return fmt.Errorf("RENEWAL_ROOT_LABEL_CHANGED")
	}
	return nil
}

// DecodeRenewalConsumers refuses ambiguous or unrecognized observation fields.
func DecodeRenewalConsumers(raw []byte) ([]RenewalConsumer, error) {
	if e := uniqueJSON(raw); e != nil {
		return nil, e
	}
	var result []RenewalConsumer
	if e := strictDecode(raw, &result); e != nil {
		return nil, e
	}
	return result, nil
}

func loadedRoleFingerprints(keys []KeyringEntry) []map[string]string {
	out := make([]map[string]string, 0, len(keys))
	for _, key := range keys {
		pub, _ := base64.StdEncoding.DecodeString(key.PublicKeyB64)
		out = append(out, map[string]string{"role": key.Role, "fingerprint_sha256": trustHash(pub)})
	}
	return out
}

// TrustMaterialDigest binds active AND revoked keys, their roles, IDs and
// ordering. Versions and validity times are deliberately excluded. Lengths
// are uint64 big-endian; the domain ends with one NUL byte. Consumers report
// this from their actual accepted bundle, not by inspecting the renewal base.
func TrustMaterialDigest(p *BundlePayload) (string, error) {
	if p == nil {
		return "", fmt.Errorf("TRUST_MATERIAL_MISSING")
	}
	var b bytes.Buffer
	b.WriteString("pail.trust-material/v1\x00")
	put := func(raw []byte) { _ = binary.Write(&b, binary.BigEndian, uint64(len(raw))); b.Write(raw) }
	for _, list := range [][]KeyringEntry{p.Keys, p.RevokedKeys} {
		_ = binary.Write(&b, binary.BigEndian, uint64(len(list)))
		for _, key := range list {
			public, e := base64.StdEncoding.DecodeString(key.PublicKeyB64)
			if e != nil || len(public) != ed25519.PublicKeySize || key.KeyID == "" || key.Role == "" {
				return "", fmt.Errorf("TRUST_MATERIAL_INVALID")
			}
			put([]byte(key.KeyID))
			put([]byte(key.Role))
			put(public)
		}
	}
	return trustHash(b.Bytes()), nil
}
