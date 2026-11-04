// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package deploysec

import (
	"bufio"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glowfly/pail/services/internal/testlayout"
)

// tsvPath locates the shared fixture. It is the same file the C++ test reads:
// two languages must not each hold their own idea of which keys are committed.
func tsvPath(t *testing.T) string {
	t.Helper()
	return testlayout.Path(t, "pail_ws/src/pail_deploy_guard/known_dev_keys.tsv")
}

func readTSV(t *testing.T) []KnownDevKey {
	t.Helper()
	f, err := os.Open(tsvPath(t))
	if err != nil {
		t.Fatalf("open tsv: %v", err)
	}
	defer f.Close()
	var out []KnownDevKey
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		col := strings.Split(line, "\t")
		if len(col) != 3 {
			t.Fatalf("malformed row: %q", line)
		}
		out = append(out, KnownDevKey{col[0], col[1], col[2]})
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	return out
}

// TestDevKeysMatchTSV is the drift test (PAIL-SD2-LLD-v1 §2.2). Regenerate with
// scripts/gen_known_dev_keys.py when key material is added or removed.
func TestDevKeysMatchTSV(t *testing.T) {
	rows := readTSV(t)
	if len(rows) != len(knownDevKeys) {
		t.Fatalf("count: tsv=%d compiled=%d — run scripts/gen_known_dev_keys.py", len(rows), len(knownDevKeys))
	}
	for i, want := range rows {
		got := knownDevKeys[i]
		if got != want {
			t.Errorf("row %d:\n tsv=%+v\n go =%+v", i, want, got)
		}
	}
}

// removedMarker is how the generator records that a fingerprint stays on the
// list while its file has left the repository (AS-16 deleted config/keys and
// config/grpc_certs; the already-deployed copies keep the fingerprint live).
const removedMarker = "[저장소에서 제거됨"

// labelPaths splits one TSV label into the paths it names and whether the row
// is annotated as no longer committed.
func labelPaths(label string) (paths []string, removed bool) {
	if i := strings.Index(label, removedMarker); i >= 0 {
		removed = true
		label = label[:i]
	}
	for _, seg := range strings.Split(label, "|") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		if j := strings.Index(seg, " ("); j >= 0 { // strip the " (key_id)" suffix
			seg = seg[:j]
		}
		paths = append(paths, seg)
	}
	return paths, removed
}

// committedKeyPaths answers the question the anchors below actually need: which
// paths does this repository still commit key material at?
//
// It used to be answered with os.Stat, and that is the defect this replaces —
// os.Stat asks "is a file here", not "did we commit it". Since AS-16 the answer
// diverges: a rig that provisions its own trust material locally leaves a file
// at config/keys/issuer_ed25519.json that the repository never committed, and
// the anchor then failed with "committed issuer key is not on the list" when the
// truth was "that file is not the committed key" (`H-B2`, the precondition
// form: the check named one thing and measured another).
//
// git would answer directly, but the Go helper container mounts PAIL-v2 without
// .git, so a git-based precondition is "unknown" exactly where the tests run —
// and unknown must not be spelled the same as clean. The TSV records the fact
// itself, is committed, and needs no tooling. Measured 2026-08-22: its two
// populations match `git ls-files` on all 8 live paths.
func committedKeyPaths(t *testing.T) (live, removed []string) {
	t.Helper()
	seen := map[string]bool{}
	for _, row := range readTSV(t) {
		paths, isRemoved := labelPaths(row.Label)
		for _, p := range paths {
			if seen[p] {
				continue
			}
			seen[p] = true
			if isRemoved {
				removed = append(removed, p)
			} else {
				live = append(live, p)
			}
		}
	}
	return live, removed
}

// TestRemovedAnnotationIsStillRead is the positive control for the precondition
// above. If the generator ever reworded the annotation, labelPaths would stop
// recognising it, every removed path would silently rejoin `live`, and the
// anchor would go back to judging files it did not commit — the failure this
// change exists to remove. An empty `removed` set is that regression, not a
// clean repository.
func TestRemovedAnnotationIsStillRead(t *testing.T) {
	live, removed := committedKeyPaths(t)
	if len(removed) == 0 {
		t.Fatalf("no row carries %q — the annotation was reworded and the "+
			"committed/removed split has quietly collapsed", removedMarker)
	}
	if len(live) == 0 {
		t.Fatal("every recorded path is annotated as removed — the list is no " +
			"longer anchored to any file in the tree, so it can only check itself")
	}
	for _, p := range live {
		for _, r := range removed {
			if p == r {
				t.Errorf("%s is in both populations", p)
			}
		}
	}
}

// TestCommittedKeyMaterialIsListed anchors the list to real files rather than to
// itself: if any still-committed key material is rotated in place without
// regenerating, this fails. It replaces the per-file issuer/CA anchors, whose
// targets AS-16 removed from the repository.
func TestCommittedKeyMaterialIsListed(t *testing.T) {
	if _, err := os.Stat(filepath.Join(testlayout.Root(t), "cloud", "go.mod")); err == nil {
		t.Skip("historical source-key material is not distributed; public TSV/compiled fingerprint drift and fresh-key rejection tests run separately")
	}
	repo := filepath.Join("..", "..", "..", "..")
	live, _ := committedKeyPaths(t)
	for _, rel := range live {
		path := filepath.Join(repo, filepath.FromSlash(rel))
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s is recorded as committed but is not in the tree (%v) — "+
				"if it was deleted, rerun scripts/gen_known_dev_keys.py so the "+
				"row is annotated", rel, err)
			continue
		}
		var mats []KeyMaterial
		switch filepath.Ext(rel) {
		case ".json":
			mats = ScanEd25519File(os.ReadFile, path, "committed key material")
		case ".crt":
			mats = ScanCertFile(os.ReadFile, path, "committed certificate")
		default:
			t.Errorf("%s: no scanner for this extension — the row would be "+
				"counted as anchored while nothing read it", rel)
			continue
		}
		if len(mats) == 0 {
			t.Errorf("%s: nothing scanned out of a file the list claims to cover", rel)
			continue
		}
		for _, m := range mats {
			if _, ok := LookupDevKey(m.Fingerprint); !ok {
				t.Errorf("%s: %s (%s) is not on the list — rotated in place "+
					"without regenerating?", rel, m.Fingerprint, m.Kind)
			}
		}
		if f := EvaluateKeyMaterial(mats); len(f) != len(mats) {
			t.Errorf("%s: want one S8 finding per scanned key, got %d for %d",
				rel, len(f), len(mats))
		}
	}
}

// TestNoCommittedCertificateRemains records a gap rather than asserting one is
// absent. Every spki row is annotated removed, so the certificate half of the
// anchor has no target left in the tree: a certificate re-committed at one of
// those paths without regenerating would not be caught here. Requiring an spki
// anchor would be an unfixable RED, which hides real defects; leaving it
// unsaid would make the gap invisible. So it is stated, and this fails the day
// a certificate comes back — at which point the anchor above should cover it.
func TestNoCommittedCertificateRemains(t *testing.T) {
	live, _ := committedKeyPaths(t)
	for _, rel := range live {
		if filepath.Ext(rel) == ".crt" {
			t.Fatalf("%s is committed again — fold certificates back into the "+
				"anchor and delete this test", rel)
		}
	}
}

// TestFreshKeyPasses is the other half of the check: S8 must reject the
// committed keys and nothing else. A rule that refuses everything is
// indistinguishable from a broken deployment.
func TestFreshKeyPasses(t *testing.T) {
	fresh := make([]byte, 32)
	for i := range fresh {
		fresh[i] = byte(i * 7)
	}
	if _, ok := LookupDevKey(Ed25519Fingerprint(fresh)); ok {
		t.Fatal("a key that is not in the repository was reported as committed")
	}
	mats := TrustAnchorFromPub("issuer signing key", "prod-issuer-2026", fresh)
	if f := EvaluateKeyMaterial(mats); len(f) != 0 {
		t.Fatalf("want no finding, got %+v", f)
	}
}

// TestRenamedKeyStillRejected is the RED case from SD2-0: relabelling the
// committed key as "prod-issuer-2026" silenced the only existing defence
// (krsign's dev-key name prefix warning). The fingerprint does not care.
func TestRenamedKeyStillRejected(t *testing.T) {
	if _, err := os.Stat(filepath.Join(testlayout.Root(t), "cloud", "go.mod")); err == nil {
		t.Skip("historical source-key material is not distributed; public TSV/compiled fingerprint drift and fresh-key rejection tests run separately")
	}
	repo := filepath.Join("..", "..", "..", "..")
	live, _ := committedKeyPaths(t)
	var src string
	for _, rel := range live {
		if filepath.Ext(rel) == ".json" {
			src = filepath.Join(repo, filepath.FromSlash(rel))
			break
		}
	}
	if src == "" {
		t.Fatal("no committed ed25519 key material is left to rename — the RED " +
			"case can no longer be posed, so this test proves nothing")
	}
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("%s: %v", src, err)
	}
	renamed := strings.ReplaceAll(string(raw), "dev-key-", "prod-issuer-2026-")
	if renamed == string(raw) {
		t.Fatalf("%s names no dev-key-* to relabel — pick another anchor", src)
	}
	path := filepath.Join(t.TempDir(), "issuer_prod.json")
	if err := os.WriteFile(path, []byte(renamed), 0o600); err != nil {
		t.Fatal(err)
	}
	mats := ScanEd25519File(os.ReadFile, path, "issuer signing key")
	if len(mats) == 0 {
		t.Fatalf("%s scanned to nothing", src)
	}
	f := EvaluateKeyMaterial(mats)
	if len(f) != len(mats) {
		t.Fatalf("renamed committed keys were accepted: %d finding(s) for %d key(s): %+v",
			len(f), len(mats), mats)
	}
	if !strings.Contains(f[0].Msg, "prod-issuer-2026") {
		t.Errorf("the finding should name the key_id the operator used: %s", f[0].Msg)
	}
}

func TestScanMissingFileIsSilent(t *testing.T) {
	if m := ScanEd25519File(os.ReadFile, filepath.Join(t.TempDir(), "nope.json"), "x"); m != nil {
		t.Fatalf("want nothing for a missing file, got %+v", m)
	}
	if m := ScanCertFile(os.ReadFile, filepath.Join(t.TempDir(), "nope.crt"), "x"); m != nil {
		t.Fatalf("want nothing for a missing cert, got %+v", m)
	}
}

// TestEvaluateDeploymentS8 drives the whole verdict the way Preflight does.
func TestEvaluateDeploymentS8(t *testing.T) {
	dir := t.TempDir()
	committedPub := "B3LK7fgNQK/1von52kFaiDdDoExCjA3U8gskaWs8ksw=" // config/keys/issuer_ed25519.json
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	bad := write("bad.json", `{"key_id":"prod-issuer-2026","ed25519_public_key_base64":"`+committedPub+`"}`)

	freshPub := make([]byte, 32)
	for i := range freshPub {
		freshPub[i] = byte(200 - i)
	}
	good := write("good.json", `{"key_id":"prod-issuer-2026","ed25519_public_key_base64":"`+
		base64.StdEncoding.EncodeToString(freshPub)+`"}`)

	// Persistent evidence paths and an offered change authorization, so this
	// test judges S8 only (S9 and S40 have their own tests).
	probe := func(m map[string]string) Probe {
		m["PAIL_BLACKBOX_DIR"] = "/data/pail/blackbox"
		m["PAIL_ANCHOR_URL"] = "http://anchor.example:46100"
		m["PAIL_POLICY_AUTH"] = "/etc/pail/policy-auth.json"
		p := fakeProbe(m, nil)
		p.ReadFile = os.ReadFile
		return p
	}

	r := EvaluateDeployment("pail_cloud", probe(map[string]string{
		"PAIL_ISSUER_KEYFILE": bad,
		"PAIL_KEYRING":        filepath.Join(dir, "absent.json"),
		"PAIL_GRPC_TLS":       "off",
		"PAIL_GRPC_UDS_PATH":  "/run/pail/x.sock",
	}))
	if len(r.Fail) != 1 || r.Fail[0].ID != "S8" {
		t.Fatalf("want exactly one S8 failure, got %+v", r.Fail)
	}

	r = EvaluateDeployment("pail_cloud", probe(map[string]string{
		"PAIL_ISSUER_KEYFILE": good,
		"PAIL_KEYRING":        filepath.Join(dir, "absent.json"),
		"PAIL_GRPC_TLS":       "off",
		"PAIL_GRPC_UDS_PATH":  "/run/pail/x.sock",
	}))
	if len(r.Fail) != 0 {
		t.Fatalf("a fresh key must pass: %+v", r.Fail)
	}
	if strings.Join(r.Checked, ",") != "S4,S5,S8,S9,S40" {
		t.Errorf("Checked=%v", r.Checked)
	}

	// S0 stops everything: an untrustworthy profile makes the rest meaningless.
	r = EvaluateDeployment("pail_cloud", probe(map[string]string{
		"PAIL_PROFILE":        "staging",
		"PAIL_ISSUER_KEYFILE": bad,
	}))
	if len(r.Fail) != 1 || r.Fail[0].ID != "S0" {
		t.Fatalf("want only S0, got %+v", r.Fail)
	}
}

// TestS8RejectsUnregisteredComponent is `B6-6`: a PAIL process the registry does
// not name must FAIL S8, not pass it. Before this, collectKeyMaterial's switch
// had no default — an unnamed component's signing key was never read and the OK
// line still listed S8, so "unexamined" and "clean" printed the same green.
func TestS8RejectsUnregisteredComponent(t *testing.T) {
	env := map[string]string{
		"PAIL_GRPC_TLS":      "off",
		"PAIL_GRPC_UDS_PATH": "/run/pail/x.sock",
		"PAIL_BLACKBOX_DIR":  "/data/pail/blackbox",
		"PAIL_ANCHOR_URL":    "http://anchor.example:46100",
	}
	if ComponentRegistered("pail_future_daemon") {
		t.Fatal("fixture name must not be registered")
	}
	r := EvaluateDeployment("pail_future_daemon", fakeProbe(env, nil))
	if failIDs(r.Fail) != "S8" {
		t.Fatalf("an unregistered component must fail S8, got %+v", r.Fail)
	}
	if !strings.Contains(r.Fail[0].Msg, "pail_future_daemon") {
		t.Errorf("the finding must name the component: %s", r.Fail[0].Msg)
	}

	// The other half: registration alone is not a failure. A rule that refuses
	// every component is a wall, not a gate. (S40 is offered a bundle here; it
	// has its own test.)
	env["PAIL_POLICY_AUTH"] = "/etc/pail/policy-auth.json"
	for _, c := range []string{"pail_cloud", "pail_services", "pail_robot_agent", "burst_recv"} {
		if !ComponentRegistered(c) {
			t.Fatalf("%s must be registered", c)
		}
		if got := failIDs(EvaluateDeployment(c, fakeProbe(env, nil)).Fail); got != "" {
			t.Errorf("%s: want no failure, got %s", c, got)
		}
	}
}

// TestS8ScansBurstRecvKeyring is the other half of `B6-6`: being in the registry
// has to mean the keyring is actually read. burst_recv verifies every burst
// packet against that file, so a committed key in it makes the receiver call
// forged alerts authentic.
func TestS8ScansBurstRecvKeyring(t *testing.T) {
	committedPub := "B3LK7fgNQK/1von52kFaiDdDoExCjA3U8gskaWs8ksw=" // config/keys/issuer_ed25519.json
	path := filepath.Join(t.TempDir(), "keyring.json")
	if err := os.WriteFile(path, []byte(
		`{"keys":[{"key_id":"prod-issuer-2026","ed25519_public_key_base64":"`+
			committedPub+`","role":"issuer"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	p := fakeProbe(map[string]string{
		"PAIL_KEYRING":       path,
		"PAIL_GRPC_TLS":      "off",
		"PAIL_GRPC_UDS_PATH": "/run/pail/x.sock",
	}, nil)
	p.ReadFile = os.ReadFile

	mats := collectKeyMaterial("burst_recv", p)
	if len(mats) != 1 {
		t.Fatalf("burst_recv's keyring must be scanned, got %+v", mats)
	}
	if f := EvaluateKeyMaterial(mats); len(f) != 1 || f[0].ID != "S8" {
		t.Fatalf("want one S8 finding for the committed key, got %+v", f)
	}
	// burst_recv speaks UDP only: scanning a gRPC identity it does not hold
	// would report on key material that is not its own.
	p2 := fakeProbe(map[string]string{"PAIL_KEYRING": path}, nil)
	p2.ReadFile = os.ReadFile
	if got := collectKeyMaterial("burst_recv", p2); len(got) != 1 {
		t.Fatalf("TLS on must not add gRPC material for burst_recv, got %+v", got)
	}
}

// A caller label cannot bypass S8 for any registered public fingerprint.
func TestPublicKnownFingerprintsRejectRenamedLabels(t *testing.T) {
	for _, row := range readTSV(t) {
		findings := EvaluateKeyMaterial([]KeyMaterial{{Where: "prod-renamed-label", Kind: row.Kind, Fingerprint: row.Fingerprint}})
		if len(findings) != 1 || !strings.Contains(findings[0].Msg, "prod-renamed-label") {
			t.Fatalf("renaming a known fingerprint bypassed S8: %+v", findings)
		}
	}
}
