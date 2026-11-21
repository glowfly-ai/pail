// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package crypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/glowfly/pail/services/internal/deploysec"
)

// Signed keyring bundle (KM2-1, LLD §6.1). The unsigned keyring.json is
// trusted only in unsigned-dev mode; the default trust path is this bundle,
// whose authenticity comes solely from an offline root signature — never from
// the transport that delivered it.
//
// The signature is computed over the exact payload bytes carried in
// payload_b64 (the SignedToken.action_token_bytes pattern), so verification
// re-decodes those bytes and never re-serializes JSON.
const BundleSchemaVersion = 1

// ErrBundleSignature identifies failed authentication without parsing diagnostic text.
var ErrBundleSignature = errors.New("bundle: root signature verification failed")

// BundleEnvelope is the outer, transport-facing object.
type BundleEnvelope struct {
	SchemaVersion int    `json:"schema_version"`
	PayloadB64    string `json:"payload_b64"`
	RootKeyID     string `json:"root_key_id"`
	RootSigB64    string `json:"root_sig_b64"`
}

// BundlePayload is the signed inner object (base64-wrapped in the envelope).
type BundlePayload struct {
	BundleVersion uint64         `json:"bundle_version"`
	IssuedAtUnix  int64          `json:"issued_at_unix"`
	ExpiresAtUnix int64          `json:"expires_at_unix"`
	Keys          []KeyringEntry `json:"keys"`

	// `C16-C2`: 폐기 목록은 **서명된 payload 안에서** 실린다. 봉투에 두면 폐기를
	// 떼어내는 것이 루트 서명을 깨지 않는다 — 그리고 떼어낸 뒤의 판정은 거부이긴
	// 하되 `ERR_UNKNOWN_KEY_ID` 이므로, fail-closed 는 유지되면서 「폐기가
	// 관측된다」는 성질만 조용히 죽는다. 그것이 정확히 이 조건이 닫는 형태다.
	//
	// `strictDecode`(`B9-4`)가 미지 필드를 거부하므로, 이 필드가 없으면 C++ 이
	// 받아들이는 번들을 Go 가 거부한다 — 형식이 갈라지는 것은 둘 중 하나가
	// 관대해서가 아니라 **한쪽에만 이름이 있어서**다.
	RevokedKeys []KeyringEntry `json:"revoked_keys,omitempty"`
}

type bundleState struct {
	LastVersion uint64 `json:"last_version"`
	// DC-10 / C3-C7 : the C++ gate's cross-restart wall-clock
	// rewind floor shares THIS file (a second state file would repeat the
	// F-KEY-07 permission work per file). The Go writer must carry the key
	// through a version bump — a clobbered floor is indistinguishable from a
	// first boot and silently reopens the rewind window. omitempty: pre-DC10
	// files stay byte-shaped as before until a gate writes a floor.
	WallMs0 int64 `json:"wall_ms0,omitempty"`
}

// EnvBundleMaxLifetime 는 번들 하나가 가질 수 있는 유효 창의 상한(초)이다.
//
// 이름을 상수로 두는 이유는 이 문자열을 읽는 자리와 **기동 거부 사유에 적는
// 자리**가 갈라지면, 사람이 오타 난 이름을 설정하고 로그가 맞는 이름을 말하는
// 상태가 되기 때문이다.
const EnvBundleMaxLifetime = "PAIL_KEYRING_MAX_LIFETIME_SEC"

// BundlePolicy 는 적재 시점에 번들의 **유효 창 길이**를 재는 상한이다(`B-R2`,
// implementation contract).
//
// 폐기 도달 상한이 `번들 만료 주기 + 폴링 주기`이므로, 만료 주기 자체에 천장이
// 없으면 그 합에도 천장이 없다 — 루트 서명자가 실수로 10년짜리 번들을 서명하면
// 폐기가 10년 뒤에 도달한다. 서명은 그 값이 **의도된 값인지**를 말하지 않는다.
//
// 영값이 "무제한"이 아니라 **"선언되지 않음"**인 것이 요점이다(`H-B2`). §1355
// `U-B5` 가 기각한 것이 바로 무제한 기본값이다 — 기본값을 두면 상한이 없는 배포와
// 상한을 정하지 않은 배포가 같은 로그를 낸다.
type BundlePolicy struct {
	MaxLifetime time.Duration
	// RequireState (SEC-H02): a missing state file is not a first load. Set by
	// BundlePolicyFromEnv in the production profile; a caller that builds its own
	// policy keeps the first-load behaviour unless it asks for this. Reading a
	// missing file as "no floor yet" lets a lost state directory bring back a
	// bundle from before a revocation — the floor of a production install is
	// written explicitly, once (InitBundleFloor / `pail-keyring-sign init-floor`).
	RequireState bool
}

// BundlePolicyFromEnv 는 상한을 환경에서 읽는다. 미설정은 기본값이 아니라 `S20b`
// 기동 거부다.
func BundlePolicyFromEnv() (BundlePolicy, error) {
	raw := strings.TrimSpace(os.Getenv(EnvBundleMaxLifetime))
	if raw == "" {
		return BundlePolicy{}, deploysec.Cfg("S20b",
			"trust anchor: bundle lifetime ceiling not configured (%s) — an unbounded validity window is a decision, and an unmade decision is not it",
			EnvBundleMaxLifetime)
	}
	sec, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || sec <= 0 {
		return BundlePolicy{}, deploysec.Cfg("S20b",
			"trust anchor: %s=%q is not a positive integer number of seconds",
			EnvBundleMaxLifetime, raw)
	}
	// Anything but an explicit "dev" is production (the reading of deploysec.Evaluate
	// and of the C++ gate's selector).
	return BundlePolicy{MaxLifetime: time.Duration(sec) * time.Second, RequireState: os.Getenv("PAIL_PROFILE") != "dev"}, nil
}

// checkLifetime 은 `S20`. 이미 만료된 번들을 재는 것이 아니라 **너무 긴 창**을
// 재는 것이다 — 만료 자체는 `TrustFreshness` 한 벌이 판정한다.
func (pol BundlePolicy) checkLifetime(expiresAtUnix int64, now time.Time) error {
	if pol.MaxLifetime <= 0 {
		return deploysec.Cfg("S20b",
			"trust anchor: bundle lifetime ceiling not declared at the load path (%s) — a load that never asked how long is too long did not check",
			EnvBundleMaxLifetime)
	}
	lifetime := time.Duration(expiresAtUnix-now.Unix()) * time.Second
	if lifetime > pol.MaxLifetime {
		return deploysec.Cfg("S20",
			"trust anchor: bundle validity window %s exceeds the configured ceiling %s (%s=%d) — revocation would take that long to land",
			lifetime, pol.MaxLifetime, EnvBundleMaxLifetime, int64(pol.MaxLifetime.Seconds()))
	}
	return nil
}

// BuildBundle wraps payloadBytes (the operator-authored payload JSON, byte for
// byte) in a root-signed envelope. Used by the offline signing CLI (§6.4);
// no network, no clock — only a signature over the given bytes.
func BuildBundle(rootPriv ed25519.PrivateKey, rootKeyID string, payloadBytes []byte) ([]byte, error) {
	if len(rootPriv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("bundle: root private key size %d (want %d)", len(rootPriv), ed25519.PrivateKeySize)
	}
	if rootKeyID == "" {
		return nil, errors.New("bundle: root_key_id required")
	}
	// Reject payloads that would never load, so bad bundles fail at sign time.
	if _, err := parsePayload(payloadBytes); err != nil {
		return nil, err
	}
	sig := ed25519.Sign(rootPriv, payloadBytes)
	env := BundleEnvelope{
		SchemaVersion: BundleSchemaVersion,
		PayloadB64:    base64.StdEncoding.EncodeToString(payloadBytes),
		RootKeyID:     rootKeyID,
		RootSigB64:    base64.StdEncoding.EncodeToString(sig),
	}
	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("bundle: marshal envelope: %w", err)
	}
	return append(out, '\n'), nil
}

// VerifyBundle checks the root signature over the exact payload bytes and
// returns the parsed payload plus those bytes. It has no side effects and does
// not enforce rollback or expiry — that is LoadKeyringBundle's job. Used by
// the CLI's verify/inspect and by LoadKeyringBundle.
func VerifyBundle(bundleBytes []byte, rootPub ed25519.PublicKey) (*BundlePayload, []byte, error) {
	if len(rootPub) != ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf("bundle: root public key size %d (want %d) — no trust anchor", len(rootPub), ed25519.PublicKeySize)
	}
	// 판 검사가 **엄격 파싱보다 먼저** 온다. §4.4 의 마이그레이션 지렛대는 판을
	// 올리면 구판 리더가 거부하는 것인데, 형식 변경은 대개 필드 추가를 함께
	// 데려온다 — 엄격 파싱이 먼저 서면 그 번들은 `unknown field` 로 죽고, 다음
	// 판으로 올라가라는 신호는 사라진다. 거부했다는 사실이 **어느 규칙이
	// 거부했는지**를 말하지 않는 그 형태(커밋16)이며, 진단이 가려진 fail-closed 는
	// 안전하되 고칠 수 없다. 그래서 관대한 탐침으로 판만 먼저 읽는다.
	var probe struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(bundleBytes, &probe); err != nil {
		return nil, nil, fmt.Errorf("bundle: parse envelope: %w", err)
	}
	if probe.SchemaVersion != BundleSchemaVersion {
		return nil, nil, fmt.Errorf("bundle: schema_version %d (want %d)", probe.SchemaVersion, BundleSchemaVersion)
	}
	// 봉투는 **전송이 만지는 바깥쪽**이다. payload 만 엄격하게 보면 서명이 덮지
	// 않는 자리에 필드를 실을 수 있고, 그것은 서명 검사를 통과한다.
	var env BundleEnvelope
	if err := strictDecode(bundleBytes, &env); err != nil {
		return nil, nil, fmt.Errorf("bundle: parse envelope: %w", err)
	}
	payloadBytes, err := base64.StdEncoding.DecodeString(env.PayloadB64)
	if err != nil {
		return nil, nil, fmt.Errorf("bundle: decode payload_b64: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(env.RootSigB64)
	if err != nil {
		return nil, nil, fmt.Errorf("bundle: decode root_sig_b64: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, nil, fmt.Errorf("bundle: root signature size %d (want %d)", len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(rootPub, payloadBytes, sig) {
		return nil, nil, fmt.Errorf("%w (forged, tampered, or wrong root key)", ErrBundleSignature)
	}
	p, err := parsePayload(payloadBytes)
	if err != nil {
		return nil, nil, err
	}
	return p, payloadBytes, nil
}

// LoadKeyringBundle verifies the bundle, enforces monotonic version (rollback
// defense) and expiry, persists the accepted version, and returns the keyring.
// Every failure means "ignore this bundle, keep the existing keyring" — a
// caller with no prior keyring must refuse to start (fail-closed).
func LoadKeyringBundle(bundlePath string, rootPub ed25519.PublicKey, statePath string, pol BundlePolicy) (*Keyring, error) {
	raw, err := os.ReadFile(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("bundle read: %w", err)
	}
	p, _, err := VerifyBundle(raw, rootPub)
	if err != nil {
		return nil, err
	}
	material, err := TrustMaterialDigest(p)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if err := pol.checkLifetime(p.ExpiresAtUnix, now); err != nil {
		return nil, err
	}
	// 만료 판정은 **한 벌**이다. 적재 시점의 검사와 사용 시점의 검사가 각자
	// 비교식을 들고 있으면 둘은 갈라질 수 있고, 갈라진 쪽이 느슨한 날 그 사실은
	// 아무 로그에도 안 나타난다. 같은 `CheckAt` 을 부른다.
	fresh, err := TrustFreshnessFromBundle(p.ExpiresAtUnix)
	if err != nil {
		return nil, err
	}
	if err := fresh.CheckAt(now); err != nil {
		return nil, err
	}
	if pol.RequireState {
		if _, statErr := os.Stat(statePath); errors.Is(statErr, os.ErrNotExist) {
			// Nothing is created here: a refusal that left a state file behind would
			// pass the next start.
			return nil, fmt.Errorf("bundle state: missing in the production profile (%s) — a missing floor is not a first load; initialise it once with `pail-keyring-sign init-floor`", statePath)
		}
	}
	last, err := readBundleState(statePath)
	if err != nil {
		return nil, err
	}
	// Strictly-smaller versions are rejected; the SAME version must load —
	// bundles are applied by restart, so a plain restart re-reads the
	// unchanged bundle (equal-version reload is not a rollback; the content
	// is fixed by the root signature).
	if p.BundleVersion < last {
		return nil, fmt.Errorf("bundle: version %d < last accepted %d (rollback rejected)", p.BundleVersion, last)
	}
	// Persist the accepted version only after all checks pass. Do it before
	// returning so a monotonic floor is recorded even if the caller crashes
	// while applying the keyring. Equal-version reloads leave the floor as is.
	if p.BundleVersion > last {
		if err := writeBundleState(statePath, p.BundleVersion); err != nil {
			return nil, err
		}
	}
	// 만료를 keyring 에 **동행시킨다**. 적재기가 검사하고 버리면 그 뒤의 수명
	// 전체가 무검사가 되고, `B-R1` 이 고치려는 것이 정확히 그 형태다.
	metadata, _ := json.Marshal(map[string]any{
		"schema_version": 1, "loaded_mode": "bundle", "load_verdict": "LOADED",
		"bundle_sha256": trustHash(raw), "root_fingerprint_sha256": trustHash(rootPub),
		"bundle_version": p.BundleVersion, "expires_at_unix": p.ExpiresAtUnix,
		"loaded_at_unix": now.Unix(), "max_remaining_seconds": int64(pol.MaxLifetime.Seconds()),
		"material_digest_sha256":     material,
		"max_bundle_version_decimal": strconv.FormatUint(^uint64(0), 10),
		"role_fingerprints":          loadedRoleFingerprints(p.Keys),
	})
	if len(metadata) > 32768 || len(p.Keys)+len(p.RevokedKeys) > 128 {
		metadata = []byte(`{"schema_version":1,"load_verdict":"NOT_OBSERVED","reason":"METADATA_LIMIT"}`)
	}
	return &Keyring{
		loadedTrustJSON: string(metadata),
		Keys:            p.Keys,
		RevokedKeys:     p.RevokedKeys,
		expiresAtUnix:   p.ExpiresAtUnix,
		expirySource:    expirySourceBundle,
	}, nil
}

// LoadTrustedKeyringFromEnv selects the keyring trust path (KM2-1, §6.2). The
// signed bundle is the default and only trusted source; the legacy unsigned
// keyring is permitted only when PAIL_KEYRING_MODE=unsigned-dev is set
// explicitly. It returns the mode string so the caller can log it.
//
//	PAIL_KEYRING_MODE       "" (default, bundle required) | "unsigned-dev"
//	PAIL_KEYRING_BUNDLE     bundle path (default legacyPath dir/keyring_bundle.json)
//	PAIL_ROOT_PUBKEY_FILE   base64 root public key (read-only mount)
//	PAIL_KEYRING_STATE      last-accepted-version state file
func LoadTrustedKeyringFromEnv(legacyPath string) (*Keyring, string, error) {
	switch mode := os.Getenv("PAIL_KEYRING_MODE"); mode {
	case "unsigned-dev":
		kr, err := LoadKeyring(legacyPath)
		if err != nil {
			return nil, mode, err
		}
		return kr, mode, nil
	case "", "bundle":
		bundlePath := os.Getenv("PAIL_KEYRING_BUNDLE")
		if bundlePath == "" {
			bundlePath = filepath.Join(filepath.Dir(legacyPath), "keyring_bundle.json")
		}
		rootPubFile := os.Getenv("PAIL_ROOT_PUBKEY_FILE")
		if rootPubFile == "" {
			return nil, "bundle", errors.New("keyring: bundle mode requires PAIL_ROOT_PUBKEY_FILE (set PAIL_KEYRING_MODE=unsigned-dev only for dev)")
		}
		rootPub, err := ReadRootPubFile(rootPubFile)
		if err != nil {
			return nil, "bundle", err
		}
		statePath := os.Getenv("PAIL_KEYRING_STATE")
		if statePath == "" {
			statePath = filepath.Join(filepath.Dir(bundlePath), "keyring_bundle.state.json")
		}
		pol, err := BundlePolicyFromEnv()
		if err != nil {
			return nil, "bundle", err
		}
		kr, err := LoadKeyringBundle(bundlePath, rootPub, statePath, pol)
		if err != nil {
			return nil, "bundle", err
		}
		return kr, "bundle", nil
	default:
		return nil, mode, fmt.Errorf("keyring: unknown PAIL_KEYRING_MODE=%q (want unsigned-dev|bundle)", mode)
	}
}

// ReadRootPubFile reads a bare-base64 root public key file (whitespace
// tolerated). Shared by the selector and the robot-agent bundle puller.
func ReadRootPubFile(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("root pubkey read: %w", err)
	}
	pub, err := decodeRootPub(b)
	if err != nil {
		return nil, fmt.Errorf("root pubkey %s: %w", path, err)
	}
	return pub, nil
}

// decodeRootPub accepts a bare base64 public key, tolerating surrounding
// whitespace/newline. Shared by the CLI verify command.
func decodeRootPub(b []byte) (ed25519.PublicKey, error) {
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("decode base64: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("size %d (want %d)", len(pub), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(pub), nil
}

// strictDecode 는 `B9-4`. 고치는 것: `json.Unmarshal` 이 미지
// 필드를 **조용히 버린다.** 그래서 `status: "revoked"` 같은 폐기 표시를 얹어도
// 구판 리더는 그것을 못 본 채 키를 계속 신뢰한다 — 폐기 표시를 더하는 일이 폐기를
// 무시하는 경로를 함께 만드는 셈이고, §4.2 가 그 필드를 기각하고 **부재 기반
// 폐기**를 유지한 근거가 이것이다. 그 결정은 파서가 모르는 것을 거부한다는 전제
// 위에 서므로, 전제를 여기서 세운다.
//
// 잉여 바이트 검사를 함께 옮기는 이유: `json.Unmarshal` 은 값 뒤의 바이트를
// 거부하지만 `json.Decoder` 는 한 값만 읽고 멈춘다. 엄격 파싱으로 바꾸면서 이
// 검사를 두고 오면 **구멍을 막으면서 다른 구멍을 낸다.** `More()` 가 아니라
// `Token()` 으로 재는 것은 `More()` 가 닫는 괄호를 끝으로 읽어 `]` 하나가 뒤에
// 붙은 경우를 통과시키기 때문이다.
func strictDecode(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing content after top-level value")
	}
	return nil
}

// parsePayload validates the inner payload independently of any signature so
// both signing and loading reject malformed content the same way.
func parsePayload(payloadBytes []byte) (*BundlePayload, error) {
	var p BundlePayload
	if err := strictDecode(payloadBytes, &p); err != nil {
		return nil, fmt.Errorf("bundle: parse payload: %w", err)
	}
	if p.BundleVersion == 0 {
		return nil, errors.New("bundle: bundle_version must be >= 1")
	}
	if p.ExpiresAtUnix <= 0 {
		return nil, errors.New("bundle: expires_at_unix required")
	}
	if len(p.Keys) == 0 {
		return nil, errors.New("bundle: keys[] is empty")
	}
	// 두 배열을 **같은 검사로** 훑는다. 폐기 목록에만 느슨한 검사를 두면 느슨해
	// 지는 쪽은 언제나 덜 쓰이는 쪽이고, 그쪽이 바로 유출 대응이 읽는 목록이다.
	for li, list := range [][]KeyringEntry{p.Keys, p.RevokedKeys} {
		// SEC-H02: one key_id, one entry per list. Two entries under one name make
		// "which key is dev-key-1" depend on which reader is asked — this loader
		// kept both, the C++ gate kept the last. Refused at signing time, since
		// BuildBundle calls this before it signs.
		seen := make(map[string]bool, len(list))
		for _, e := range list {
			if seen[e.KeyID] && e.KeyID != "" {
				return nil, fmt.Errorf("bundle: entry %q appears twice in %s", e.KeyID, [2]string{"keys", "revoked_keys"}[li])
			}
			seen[e.KeyID] = true
			if e.KeyID == "" {
				return nil, errors.New("bundle: entry with empty key_id")
			}
			// `S15` (§3.2). 서명된 경로도 같이 건다 — 여기를 비워두면 role 없는
			// 항목이 **루트 서명을 받은 채로** 들어오고, 그때 fail-open 은 서명의
			// 권위를 등에 업는다. `BuildBundle` 이 이 함수를 서명 전에 부르므로
			// 잘못된 번들은 서명 시점에 죽는다.
			if e.Role == "" {
				return nil, deploysec.Cfg("S15", "keyring: entry %q has no role", e.KeyID)
			}
			pub, err := base64.StdEncoding.DecodeString(e.PublicKeyB64)
			if err != nil {
				return nil, fmt.Errorf("bundle: key %s decode pubkey: %w", e.KeyID, err)
			}
			if len(pub) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("bundle: key %s pubkey size %d (want %d)", e.KeyID, len(pub), ed25519.PublicKeySize)
			}
		}
	}
	// `S15b` (`C16-C4`): 겹침은 서명 시점에 죽는다. 루트 서명자가 겹쳐 적으면
	// 그 번들은 배포되기 전에 거부된다 — 배치가 받은 뒤에야 거부하면 폐기
	// 선언은 이미 게재됐고 아무 곳에도 적용되지 않은 상태로 남는다.
	if err := (&Keyring{Keys: p.Keys, RevokedKeys: p.RevokedKeys}).ValidateRevocation(); err != nil {
		return nil, err
	}
	return &p, nil
}

// InitBundleFloor is the explicit first-install step of a production consumer
// (SEC-H02): it verifies the placed bundle against the root and writes the bundle's
// version as the version floor. It never touches an existing state file — an
// initialisation is not a way to lower a floor — and a bundle the root did not sign
// initialises nothing. Returns the floor it wrote.
func InitBundleFloor(bundlePath string, rootPub ed25519.PublicKey, statePath string) (uint64, error) {
	raw, err := os.ReadFile(bundlePath)
	if err != nil {
		return 0, fmt.Errorf("bundle read: %w", err)
	}
	p, _, err := VerifyBundle(raw, rootPub)
	if err != nil {
		return 0, err
	}
	b, err := json.Marshal(bundleState{LastVersion: p.BundleVersion})
	if err != nil {
		return 0, err
	}
	if dir := filepath.Dir(statePath); dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return 0, fmt.Errorf("bundle state dir: %w", err)
		}
	}
	// O_EXCL: the create and the "does not exist yet" check are one step.
	f, err := os.OpenFile(statePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return 0, fmt.Errorf("bundle state: %s already exists — the floor is initialised once and is not overwritten", statePath)
		}
		return 0, fmt.Errorf("bundle state create: %w", err)
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		os.Remove(statePath)
		return 0, fmt.Errorf("bundle state write: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(statePath)
		return 0, fmt.Errorf("bundle state sync: %w", err)
	}
	if err := f.Close(); err != nil {
		return 0, fmt.Errorf("bundle state close: %w", err)
	}
	return p.BundleVersion, nil
}

func readBundleState(statePath string) (uint64, error) {
	b, err := os.ReadFile(statePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil // first load: no floor yet
		}
		return 0, fmt.Errorf("bundle state read: %w", err)
	}
	var st bundleState
	if err := json.Unmarshal(b, &st); err != nil {
		return 0, fmt.Errorf("bundle state parse: %w", err)
	}
	return st.LastVersion, nil
}

func writeBundleState(statePath string, version uint64) error {
	// Merged, not literal (DC-10): read what is there, overlay the version,
	// keep the gate's wall floor. Refusing to clobber an unreadable file is
	// deliberate — overwriting it would turn "state we cannot read" into
	// "state that says whatever we wrote".
	st := bundleState{}
	if b, err := os.ReadFile(statePath); err == nil {
		if err := json.Unmarshal(b, &st); err != nil {
			return fmt.Errorf("bundle state parse before write: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("bundle state read before write: %w", err)
	}
	st.LastVersion = version
	out, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	if dir := filepath.Dir(statePath); dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("bundle state mkdir: %w", err)
		}
	}
	tmp := statePath + ".tmp"
	if err := os.WriteFile(tmp, out, 0600); err != nil {
		return fmt.Errorf("bundle state write tmp: %w", err)
	}
	if err := os.Rename(tmp, statePath); err != nil {
		return fmt.Errorf("bundle state rename: %w", err)
	}
	return nil
}
