// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package releaseverify

import (
	"archive/zip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
)

func TestDecodeUniqueRejectsDuplicateKeysAtEveryLevel(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`{"a": 1, "a": 2}`, "Duplicate manifest key: a"},
		{`{"a": {"x": 1, "y": 2, "x": 3}}`, "Duplicate manifest key: x"},
		{`{"a": [{"k": 1}, {"k": 1, "k": 2}]}`, "Duplicate manifest key: k"},
	} {
		if _, err := DecodeUnique([]byte(tc.in)); err == nil || err.Error() != tc.want {
			t.Errorf("%s: got %v, want %q", tc.in, err, tc.want)
		}
	}
	v, err := DecodeUnique([]byte(`{"a": {"x": 1}, "b": {"x": 2}, "n": 12345678901234}`))
	if err != nil {
		t.Fatal(err)
	}
	obj := v.(map[string]any)
	if n, _ := obj["n"].(json.Number); n.String() != "12345678901234" {
		t.Errorf("number lost: %v", obj["n"])
	}
	if _, err := DecodeUnique([]byte(`{"a": 1} {"b": 2}`)); err == nil {
		t.Error("trailing document accepted")
	}
}

func TestPyJSONCompactMatchesPythonEnsureASCII(t *testing.T) {
	// Expected string computed with: json.dumps(m, sort_keys=True, separators=(',', ':'))  (python 3.11)
	m := map[string]string{
		"docs/ßœ.md":            "ab",
		"a\"b\\c\n\x7f\x01\t/é": "cd",
		"🤖":                     "ef",
		"z~":                    "00",
	}
	u := func(hex4 string) string { return `\u` + hex4 } // kept out of the literal so editors cannot decode the escapes
	want := `{"a\"b\\c\n` + u("007f") + u("0001") + `\t/` + u("00e9") + `":"cd","docs/` + u("00df") + u("0153") +
		`.md":"ab","z~":"00","` + u("d83e") + u("dd16") + `":"ef"}`
	if got := string(PyJSONCompact(m)); got != want {
		t.Errorf("\n got %s\nwant %s", got, want)
	}
	if got := string(PyJSONCompact(nil)); got != "{}" {
		t.Errorf("empty map: %s", got)
	}
	for r, esc := range map[rune]string{'\r': `\r`, '\b': `\b`, '\f': `\f`, 0x1f: `\u001f`, 0x7e: "~", 0x20: " "} {
		var b strings.Builder
		pyEscape(&b, string(r))
		if got := b.String(); got != `"`+esc+`"` {
			t.Errorf("%U: got %s want %q", r, got, esc)
		}
	}
}

func TestUnsafeName(t *testing.T) {
	for name, unsafe := range map[string]bool{
		"pail-evaluation/a.txt":   false,
		"a":                       false,
		".":                       false,
		"pail-evaluation/ßœ.md":   false,
		"pail-evaluation/.hidden": false,
		"/abs":                    true,
		"a/../b":                  true,
		"..":                      true,
		"a\\b":                    true,
		"a//b":                    true,
		"./a":                     true,
		"a/":                      true,
		"":                        true,
		"a/./b":                   true,
	} {
		if got := unsafeName(name); got != unsafe {
			t.Errorf("%q: unsafe=%v want %v", name, got, unsafe)
		}
	}
}

func TestRegularFileModeBits(t *testing.T) {
	// S_IFREG|0644 is regular; S_IFDIR, S_IFLNK and a bare 0644 (no type bits) are not.
	for mode, regular := range map[uint32]bool{0o100644: true, 0o100755: true, 0o104755: true, 0o040755: false, 0o120777: false, 0o644: false} {
		if got := mode&sIFMT == sIFREG; got != regular {
			t.Errorf("%07o: regular=%v want %v", mode, got, regular)
		}
	}
}

func writeTestPEM(t *testing.T, dir, name string, pub ed25519.PublicKey) string {
	t.Helper()
	der := append(append([]byte{}, spkiEd25519Prefix...), pub...)
	body := base64.StdEncoding.EncodeToString(der)
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("-----BEGIN PUBLIC KEY-----\n"+body[:44]+"\n"+body[44:]+"\n-----END PUBLIC KEY-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestKeyFingerprint(t *testing.T) {
	dir := t.TempDir()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := writeTestPEM(t, dir, "k.pub", pub)
	sum := sha256.Sum256(pub)
	if fp, err := KeyFingerprint(p); err != nil || fp != hex.EncodeToString(sum[:]) {
		t.Errorf("fingerprint %q err %v", fp, err)
	}
	// Wrong algorithm prefix (RSA-ish header) or wrong length is refused with the Python message.
	bad := filepath.Join(dir, "bad.pub")
	os.WriteFile(bad, []byte("-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n"), 0o644)
	if _, err := KeyFingerprint(bad); err == nil || err.Error() != "not an Ed25519 SubjectPublicKeyInfo: "+bad {
		t.Errorf("short key: %v", err)
	}
	der := append(append([]byte{}, spkiEd25519Prefix...), pub...)
	der[6] ^= 1 // break the OID
	os.WriteFile(bad, []byte("-----BEGIN PUBLIC KEY-----\n"+base64.StdEncoding.EncodeToString(der)+"\n-----END PUBLIC KEY-----\n"), 0o644)
	if _, err := KeyFingerprint(bad); err == nil {
		t.Error("wrong OID accepted")
	}
}

func TestVerifySignatureCodes(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	manifest := filepath.Join(dir, "m.manifest.json")
	os.WriteFile(manifest, []byte(`{"x":1}`), 0o644)
	pem := writeTestPEM(t, dir, "RELEASE-SIGNING-KEY.pub", pub)
	other := writeTestPEM(t, dir, "other.pub", otherPub)
	sum := sha256.Sum256(pub)
	fp := hex.EncodeToString(sum[:])

	rc, msg, err := VerifySignature(manifest, pem, "")
	if rc != 2 || msg != "no signature file beside the manifest (m.manifest.json.sig)" || err != nil {
		t.Errorf("no sig: %d %q %v", rc, msg, err)
	}
	os.WriteFile(manifest+".sig", ed25519.Sign(priv, []byte(`{"x":1}`)), 0o644)
	rc, msg, err = VerifySignature(manifest, filepath.Join(dir, "missing.pub"), "")
	if rc != 2 || msg != "public key not found; expected RELEASE-SIGNING-KEY.pub beside this tool or --public-key" || err != nil {
		t.Errorf("no key: %d %q %v", rc, msg, err)
	}
	if rc, msg, err = VerifySignature(manifest, "", ""); rc != 2 || err != nil {
		t.Errorf("empty key path: %d %q %v", rc, msg, err)
	}
	rc, msg, _ = VerifySignature(manifest, pem, "")
	if rc != 0 || msg != "VERIFIED key="+fp+" with pail_verify" {
		t.Errorf("good: %d %q", rc, msg)
	}
	rc, msg, _ = VerifySignature(manifest, pem, " "+strings.ToUpper(fp)+"\n")
	if rc != 0 {
		t.Errorf("fingerprint normalisation: %d %q", rc, msg)
	}
	rc, msg, _ = VerifySignature(manifest, pem, "00")
	if rc != 1 || msg != "KEY MISMATCH key="+fp+" expected=00" {
		t.Errorf("mismatch: %d %q", rc, msg)
	}
	rc, msg, _ = VerifySignature(manifest, other, "")
	if rc != 1 || !strings.HasPrefix(msg, "BAD SIGNATURE key=") {
		t.Errorf("wrong key: %d %q", rc, msg)
	}
	os.WriteFile(manifest+".sig", ed25519.Sign(priv, []byte(`{"x":1}`))[:63], 0o644)
	if rc, msg, _ = VerifySignature(manifest, pem, ""); rc != 1 || msg != "BAD SIGNATURE key="+fp {
		t.Errorf("short sig: %d %q", rc, msg)
	}
	os.WriteFile(pem, []byte("garbage"), 0o644)
	if _, _, err = VerifySignature(manifest, pem, ""); err == nil {
		t.Error("garbage key: no error")
	}
}

func TestWriteReceipt(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "verification")
	r := Receipt{ReleaseID: "0.2.0-x", Artifact: "a.zip", ZipSHA256: "z", ManifestSHA256: "m",
		LockSHA256: "0123456789abcdef0123456789abcdef", Signature: "VERIFIED", KeyFingerprint: String("k"),
		ExpectedFingerprintGiven: true, Backend: String(Backend), Tool: "pail_verify", Files: 3, At: "2026-10-29T00:00:00Z"}
	p, err := WriteReceipt(dir, r)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(p) != "0.2.0-x-0123456789abcdef.json" {
		t.Errorf("name %s", p)
	}
	if st, err := os.Stat(dir); err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %v %v", st.Mode(), err)
	}
	data, _ := os.ReadFile(p)
	// schema_version defaults to 2; a receipt without a tree result carries tree_matched null and an empty list.
	want := "{\n  \"schema_version\": 2,\n  \"release_id\": \"0.2.0-x\",\n  \"artifact\": \"a.zip\",\n  \"zip_sha256\": \"z\",\n" +
		"  \"manifest_sha256\": \"m\",\n  \"lock_sha256\": \"0123456789abcdef0123456789abcdef\",\n  \"signature\": \"VERIFIED\",\n" +
		"  \"key_fingerprint\": \"k\",\n  \"expected_fingerprint_given\": true,\n  \"backend\": \"pail_verify\",\n" +
		"  \"verifier_note\": \"\",\n  \"tool\": \"pail_verify\",\n  \"files\": 3,\n  \"tree_scope\": \"\",\n  \"tree_files\": 0,\n" +
		"  \"tree_sha256\": \"\",\n  \"tree_matched\": null,\n  \"tree_mismatches\": [],\n  \"at\": \"2026-10-29T00:00:00Z\"\n}\n"
	if string(data) != want {
		t.Errorf("receipt bytes:\n%s", data)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("temp file left behind: %v", entries)
	}
	// CHECKSUMS_ONLY: the nullable fields are JSON null, keys still present (as the Python tool writes them).
	// Written to a directory of its own: over the VERIFIED receipt above it would be kept out (P024-L1 — a run that
	// accepted checksums only never replaces a receipt of the same manifest that verified the signature).
	r.Signature, r.KeyFingerprint, r.Backend, r.ExpectedFingerprintGiven = "CHECKSUMS_ONLY", nil, nil, false
	if _, err := WriteReceipt(dir, r); !errors.Is(err, ErrReceiptKeptSignature) {
		t.Fatalf("checksums-only over verified: %v", err)
	}
	p, err = WriteReceipt(filepath.Join(t.TempDir(), "checksums-only"), r)
	if err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(p)
	if !strings.Contains(string(data), "  \"signature\": \"CHECKSUMS_ONLY\",\n  \"key_fingerprint\": null,\n  \"expected_fingerprint_given\": false,\n  \"backend\": null,\n") {
		t.Errorf("checksums-only receipt bytes:\n%s", data)
	}
	if _, err := WriteReceipt(dir, Receipt{}); err == nil {
		t.Error("empty receipt accepted")
	}
}

func TestVerifyVector(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	msg := []byte("pail signature vector")
	sig := ed25519.Sign(priv, msg)
	bad := append([]byte{}, sig...)
	bad[0] ^= 0x80
	sum := sha256.Sum256(pub)
	der := append(append([]byte{}, spkiEd25519Prefix...), pub...)
	v := Vector{Purpose: "test", Fingerprint: hex.EncodeToString(sum[:]),
		PublicKeyPEM:          "-----BEGIN PUBLIC KEY-----\n" + base64.StdEncoding.EncodeToString(der) + "\n-----END PUBLIC KEY-----\n",
		MessageB64:            base64.StdEncoding.EncodeToString(msg),
		SignatureB64:          base64.StdEncoding.EncodeToString(sig),
		CorruptedSignatureB64: base64.StdEncoding.EncodeToString(bad)}
	p := filepath.Join(dir, "vector.json")
	data, _ := json.Marshal(v)
	os.WriteFile(p, data, 0o644)
	pos, neg, err := VerifyVector(p)
	if err != nil || pos != 0 || neg != 1 {
		t.Errorf("vector: %d %d %v", pos, neg, err)
	}
	v.Fingerprint = "00"
	data, _ = json.Marshal(v)
	os.WriteFile(p, data, 0o644)
	if _, _, err := VerifyVector(p); err == nil {
		t.Error("fingerprint mismatch accepted")
	}
}

// TestVerifyArchiveEdgeCases covers branches the fixture cannot carry (unsafe
// names, directory and non-regular members, duplicate entries, root).
func TestVerifyArchiveEdgeCases(t *testing.T) {
	dir := t.TempDir()
	type member struct {
		name string
		mode uint32
		data string
	}
	build := func(name string, members []member) (string, Manifest) {
		p := filepath.Join(dir, name)
		f, err := os.Create(p)
		if err != nil {
			t.Fatal(err)
		}
		w := zip.NewWriter(f)
		for _, m := range members {
			h := &zip.FileHeader{Name: m.name, Method: zip.Store}
			h.ExternalAttrs = m.mode << 16
			h.CreatorVersion = 3 << 8
			fw, err := w.CreateHeader(h)
			if err != nil {
				t.Fatal(err)
			}
			if m.data != "" {
				fw.Write([]byte(m.data))
			}
		}
		w.Close()
		f.Close()
		st, _ := os.Stat(p)
		sum, _ := FileSHA256(p)
		man := Manifest{ReleaseID: "r", Artifact: name, RootDirectory: "pail-evaluation", Bytes: st.Size(), SHA256: sum,
			FilesSHA256: map[string]string{}, FileModes: map[string]string{}}
		for _, m := range members {
			key := strings.TrimPrefix(m.name, "pail-evaluation/")
			d := sha256.Sum256([]byte(m.data))
			man.FilesSHA256[key] = hex.EncodeToString(d[:])
			man.FileModes[key] = "0644"
		}
		man.FileCount = len(man.FilesSHA256)
		return p, man
	}
	cases := []struct {
		name    string
		members []member
		want    string
	}{
		{"ok.zip", []member{{"pail-evaluation/a", 0o100644, "A"}}, ""},
		{"dup.zip", []member{{"pail-evaluation/a", 0o100644, "A"}, {"pail-evaluation/a", 0o100644, "A"}}, "Duplicate archive entry: pail-evaluation/a"},
		{"unsafe.zip", []member{{"pail-evaluation/../a", 0o100644, "A"}}, "Unsafe member: pail-evaluation/../a"},
		{"slash.zip", []member{{"pail-evaluation//a", 0o100644, "A"}}, "Unsafe member: pail-evaluation//a"},
		{"dir.zip", []member{{"pail-evaluation/d/", 0o040755, ""}}, "Unsafe member: pail-evaluation/d/"},
		{"outside.zip", []member{{"other/a", 0o100644, "A"}}, "Unexpected archive member: other/a"},
		{"symlink.zip", []member{{"pail-evaluation/a", 0o120777, "A"}}, "Non-regular member: pail-evaluation/a"},
		{"setuid.zip", []member{{"pail-evaluation/a", 0o104644, "A"}}, "Unexpected path or mode: pail-evaluation/a"},
	}
	for _, tc := range cases {
		p, man := build(tc.name, tc.members)
		n, err := VerifyArchive(p, man, "r")
		got := ""
		if err != nil {
			got = err.Error()
		}
		if got != tc.want {
			t.Errorf("%s: got %q want %q", tc.name, got, tc.want)
		}
		if tc.want == "" && n != 1 {
			t.Errorf("%s: count %d", tc.name, n)
		}
	}
	// Manifest-level checks before the ZIP is opened.
	p, man := build("pre.zip", []member{{"pail-evaluation/a", 0o100644, "A"}})
	if _, err := VerifyArchive(p, man, "other"); err == nil || err.Error() != "Delivery identity mismatch" {
		t.Errorf("identity: %v", err)
	}
	m2 := man
	m2.Bytes++
	if _, err := VerifyArchive(p, m2, "r"); err == nil || err.Error() != "Archive size/digest mismatch" {
		t.Errorf("size: %v", err)
	}
	m3 := man
	m3.FileCount = 2
	if _, err := VerifyArchive(p, m3, "r"); err == nil || err.Error() != "Nonempty file map, modes and count must agree" {
		t.Errorf("count: %v", err)
	}
	m4 := man
	m4.RootDirectory = "x"
	if _, err := VerifyArchive(p, m4, "r"); err == nil || err.Error() != "Unexpected extraction root" {
		t.Errorf("root: %v", err)
	}
	m5 := man
	m5.FilesSHA256 = map[string]string{"a": man.FilesSHA256["a"], "b": "x"}
	m5.FileModes = map[string]string{"a": "0644", "b": "0644"}
	m5.FileCount = 2
	if _, err := VerifyArchive(p, m5, "r"); err == nil || err.Error() != "Missing archive members" {
		t.Errorf("missing: %v", err)
	}
	// native/BUILD.json listed in the manifest but absent from the ZIP: Python's KeyError text.
	m6 := man
	m6.FilesSHA256 = map[string]string{"a": man.FilesSHA256["a"], "native/BUILD.json": "x"}
	m6.FileModes = map[string]string{"a": "0644", "native/BUILD.json": "0644"}
	m6.FileCount = 2
	if _, err := VerifyArchive(p, m6, "r"); err == nil || err.Error() != `"There is no item named 'pail-evaluation/native/BUILD.json' in the archive"` {
		t.Errorf("build missing: %v", err)
	}
}

func TestVerifyArchiveBuildJSONDependencyMismatch(t *testing.T) {
	dir := t.TempDir()
	write := func(name, build string) (string, Manifest) {
		p := filepath.Join(dir, name)
		f, _ := os.Create(p)
		w := zip.NewWriter(f)
		members := map[string]string{"pail-evaluation/pail-core/x": "X", "pail-evaluation/native/BUILD.json": build}
		man := Manifest{ReleaseID: "r", Artifact: name, RootDirectory: "pail-evaluation", FilesSHA256: map[string]string{}, FileModes: map[string]string{}}
		for _, n := range []string{"pail-evaluation/native/BUILD.json", "pail-evaluation/pail-core/x"} {
			h := &zip.FileHeader{Name: n, Method: zip.Store}
			h.ExternalAttrs = 0o100644 << 16
			fw, _ := w.CreateHeader(h)
			fw.Write([]byte(members[n]))
			d := sha256.Sum256([]byte(members[n]))
			man.FilesSHA256[strings.TrimPrefix(n, "pail-evaluation/")] = hex.EncodeToString(d[:])
			man.FileModes[strings.TrimPrefix(n, "pail-evaluation/")] = "0644"
		}
		w.Close()
		f.Close()
		st, _ := os.Stat(p)
		man.Bytes, man.SHA256 = st.Size(), ""
		man.SHA256, _ = FileSHA256(p)
		man.FileCount = 2
		return p, man
	}
	xd := sha256.Sum256([]byte("X"))
	core := sha256.Sum256([]byte(`{"x":"` + hex.EncodeToString(xd[:]) + `"}`))
	ok := `{"core_source_sha256": "` + hex.EncodeToString(core[:]) + `"}`
	p, man := write("ok.zip", ok)
	if n, err := VerifyArchive(p, man, "r"); err != nil || n != 2 {
		t.Errorf("no go.sum on either side: %d %v", n, err)
	}
	p, man = write("dep.zip", `{"core_source_sha256": "`+hex.EncodeToString(core[:])+`", "cloud_go_sum_sha256": "abc"}`)
	if _, err := VerifyArchive(p, man, "r"); err == nil || err.Error() != "Native dependency source mismatch" {
		t.Errorf("dependency: %v", err)
	}
	p, man = write("dupkey.zip", `{"core_source_sha256": "a", "core_source_sha256": "b"}`)
	if _, err := VerifyArchive(p, man, "r"); err == nil || err.Error() != "Duplicate manifest key: core_source_sha256" {
		t.Errorf("dup: %v", err)
	}
	p, man = write("src.zip", `{"core_source_sha256": "nope"}`)
	if _, err := VerifyArchive(p, man, "r"); err == nil || err.Error() != "Native source snapshot mismatch" {
		t.Errorf("source: %v", err)
	}
}

func TestTreeDigestMatchesPython(t *testing.T) {
	// Expected hex computed once with:
	//   python3 -c "import hashlib,json;m={'a/b.txt':'0'*63+'1','z':'f'*64};print(hashlib.sha256(json.dumps(m,sort_keys=True,separators=(',',':')).encode()).hexdigest())"
	m := map[string]string{"a/b.txt": strings.Repeat("0", 63) + "1", "z": strings.Repeat("f", 64)}
	if got := TreeDigest(m); got != "89a1f29b956e3c7038819d462a45302690e3146de3c643026ce01918d5fb5c4a" {
		t.Errorf("digest %s", got)
	}
	// Empty map: sha256 of "{}" (the manifest of a bundle whose files are all under images/).
	if got := TreeDigest(map[string]string{}); got != "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a" {
		t.Errorf("empty digest %s", got)
	}
	keys := TreeKeys(map[string]string{"images/a.tar": "1", "images.lock.json": "2", "pail-core/x": "3", "native/images/y": "4"})
	if len(keys) != 3 || keys["images/a.tar"] != "" || keys["native/images/y"] != "4" {
		t.Errorf("TreeKeys: %v", keys)
	}
	if TreeScope != "manifest files except images/" {
		t.Errorf("TreeScope %q", TreeScope)
	}
}

func TestWalkTreeIgnoreListAndSymlinks(t *testing.T) {
	root := t.TempDir()
	write := func(rel, data string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("images.lock.json", "{}\n")
	write("pail-core/README.md", "# core\n")
	write("pail-core/docs/ßœ.md", "x\n") // non-ASCII path: compared as raw bytes, no normalisation
	write("run.sh", "#!/bin/sh\n")
	// ignored: names, directories at any depth, suffixes, and the top-level images/ directory
	write(".DS_Store", "junk")
	write("pail-core/.DS_Store", "junk")
	write("pail-core/__pycache__/x.pyc", "junk")
	write("pail-core/x.pyc", "junk")
	write(".git/HEAD", "ref")
	write("deep/.git/config", "x")
	write("images/pail-core.tar", "tar")
	// not ignored: a nested directory called images, a file named images inside a directory
	write("native/images/note.txt", "n")
	// symlinks are reported, never followed (even one pointing at a directory)
	if err := os.Symlink(filepath.Join(root, "run.sh"), filepath.Join(root, "pail-core", "link.sh")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	os.Symlink(filepath.Join(root, "pail-core"), filepath.Join(root, "core-link"))
	files, links, err := WalkTree(root)
	if err != nil {
		t.Fatal(err)
	}
	wantKeys := []string{"images.lock.json", "native/images/note.txt", "pail-core/README.md", "pail-core/docs/ßœ.md", "run.sh"}
	got := make([]string, 0, len(files))
	for k := range files {
		got = append(got, k)
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(wantKeys, ",") {
		t.Errorf("walked %v want %v", got, wantKeys)
	}
	d := sha256.Sum256([]byte("# core\n"))
	if files["pail-core/README.md"] != hex.EncodeToString(d[:]) {
		t.Errorf("hash %s", files["pail-core/README.md"])
	}
	if len(links) != 2 || links[0] != (Mismatch{"core-link", "symlink"}) || links[1] != (Mismatch{"pail-core/link.sh", "symlink"}) {
		t.Errorf("links %v", links)
	}
	// CompareTree: links count as mismatches of kind symlink, sorted with the rest by path.
	expected := map[string]string{}
	for k, v := range files {
		expected[k] = v
	}
	matched, expD, actD, mism, compared, err := CompareTree(root, expected)
	if err != nil || matched || expD != actD || compared != 5 || len(mism) != 2 || mism[0].Kind != "symlink" {
		t.Errorf("symlinks: matched=%v %s/%s compared=%d %v err=%v", matched, expD, actD, compared, mism, err)
	}
	os.Remove(filepath.Join(root, "pail-core", "link.sh"))
	os.Remove(filepath.Join(root, "core-link"))
	matched, expD, actD, mism, compared, err = CompareTree(root, expected)
	if err != nil || !matched || expD != actD || compared != 5 || len(mism) != 0 || mism == nil {
		t.Errorf("clean: matched=%v %s/%s compared=%d %v err=%v", matched, expD, actD, compared, mism, err)
	}
	// changed + missing + extra, sorted by path; the actual digest differs from the expected one.
	write("pail-core/README.md", "# changed\n")
	os.Remove(filepath.Join(root, "run.sh"))
	write("pail-core/extra.txt", "e")
	matched, expD, actD, mism, compared, err = CompareTree(root, expected)
	want := []Mismatch{{"pail-core/README.md", "changed"}, {"pail-core/extra.txt", "extra"}, {"run.sh", "missing"}}
	if err != nil || matched || expD == actD || compared != 5 || len(mism) != 3 || mism[0] != want[0] || mism[1] != want[1] || mism[2] != want[2] {
		t.Errorf("modified: matched=%v %s/%s compared=%d %v err=%v", matched, expD, actD, compared, mism, err)
	}
	if expD != TreeDigest(expected) {
		t.Errorf("expected digest %s", expD)
	}
	// CompareTree returns the FULL list (3 + 30 here); only the receipt caps it at 20 (CapMismatches), first 20 in path order.
	for i := 0; i < 30; i++ {
		write("zz/extra-"+string(rune('a'+i))+".txt", "e")
	}
	if _, _, _, mism, _, _ = CompareTree(root, expected); len(mism) != 33 || mism[32] != (Mismatch{"zz/extra-" + string(rune('a'+29)) + ".txt", "extra"}) {
		t.Errorf("full list: %d %v", len(mism), mism)
	}
	if capped := CapMismatches(mism); len(capped) != 20 || capped[19] != (Mismatch{"zz/extra-q.txt", "extra"}) {
		t.Errorf("cap: %d %v", len(capped), capped)
	}
	if capped := CapMismatches(nil); capped == nil || len(capped) != 0 {
		t.Errorf("cap nil: %v", capped)
	}
	// A missing root (or a file as root) is an error, not an empty tree; a root given through a symlink is walked.
	if _, _, err := WalkTree(filepath.Join(root, "nope")); err == nil {
		t.Error("missing root accepted")
	}
	if _, _, err := WalkTree(filepath.Join(root, "pail-core", "README.md")); err == nil {
		t.Error("file root accepted")
	}
	rootLink := filepath.Join(t.TempDir(), "root-link")
	os.Symlink(root, rootLink)
	if files, _, err := WalkTree(rootLink); err != nil || files["pail-core/extra.txt"] == "" {
		t.Errorf("symlinked root: %d files, %v", len(files), err)
	}
	if HasLock(root) != true || HasLock(filepath.Join(root, "pail-core")) {
		t.Error("HasLock")
	}
	os.Remove(filepath.Join(root, "images.lock.json"))
	os.Symlink(filepath.Join(root, "run.sh"), filepath.Join(root, "images.lock.json"))
	if HasLock(root) {
		t.Error("a symlink is not a lock file")
	}
}

// TestWalkTreeOddEntries: a FIFO is "irregular", an unreadable file or directory "unreadable", a top-level images
// entry is skipped whether directory or symlink, a symlink named like an ignored directory is hidden like one.
func TestWalkTreeOddEntries(t *testing.T) {
	root := t.TempDir()
	write := func(rel, data string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("images.lock.json", "{}\n")
	write("a.txt", "a")
	write("sub/b.txt", "b")
	write("elsewhere/pail-core.tar", "tar")
	if err := os.Symlink(filepath.Join(root, "elsewhere"), filepath.Join(root, "images")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	os.Mkdir(filepath.Join(root, "cache"), 0o755)
	os.Symlink(filepath.Join(root, "cache"), filepath.Join(root, "sub", "__pycache__")) // symlink to a directory: ignored like the directory
	os.Symlink(filepath.Join(root, "a.txt"), filepath.Join(root, "sub", ".git"))        // symlink to a file: not a directory, so reported
	if err := syscall.Mkfifo(filepath.Join(root, "sub", "pipe"), 0o644); err != nil {
		t.Fatal(err)
	}
	files, odd, err := WalkTree(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 4 || files["a.txt"] == "" || files["sub/b.txt"] == "" || files["images.lock.json"] == "" || files["elsewhere/pail-core.tar"] == "" {
		t.Errorf("files %v", files)
	}
	if len(odd) != 2 || odd[0] != (Mismatch{"sub/.git", "symlink"}) || odd[1] != (Mismatch{"sub/pipe", "irregular"}) {
		t.Errorf("odd %v", odd)
	}
	// A top-level regular file named images is skipped too (same as the Python walk).
	os.Remove(filepath.Join(root, "images"))
	write("images", "x")
	if files, _, _ := WalkTree(root); len(files) != 4 {
		t.Errorf("top-level images file hashed: %v", files)
	}
	if os.Geteuid() == 0 {
		t.Log("running as root: the unreadable cases cannot be exercised")
		return
	}
	write("sub/secret.txt", "s")
	os.Chmod(filepath.Join(root, "sub", "secret.txt"), 0)
	os.Mkdir(filepath.Join(root, "locked"), 0o755)
	write("locked/inner.txt", "i")
	os.Chmod(filepath.Join(root, "locked"), 0)
	t.Cleanup(func() {
		os.Chmod(filepath.Join(root, "locked"), 0o755)
		os.Chmod(filepath.Join(root, "sub", "secret.txt"), 0o644)
	})
	files, odd, err = WalkTree(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 4 || len(odd) != 4 || odd[0] != (Mismatch{"locked", "unreadable"}) || odd[3] != (Mismatch{"sub/secret.txt", "unreadable"}) {
		t.Errorf("unreadable: files %v odd %v", files, odd)
	}
	// CompareTree never fails for odd entries; they are all mismatches.
	expected := map[string]string{}
	for k, v := range files {
		expected[k] = v
	}
	if matched, _, _, mism, _, err := CompareTree(root, expected); err != nil || matched || len(mism) != 4 {
		t.Errorf("compare with odd entries: %v %v %v", matched, mism, err)
	}
	// Only an unreadable root fails the walk.
	os.Chmod(root, 0)
	t.Cleanup(func() { os.Chmod(root, 0o755) })
	if _, _, err := WalkTree(root); err == nil {
		t.Error("unreadable root accepted")
	}
}

func TestReceiptV2(t *testing.T) {
	dir := t.TempDir()
	r := Receipt{ReleaseID: "0.2.0-x", Artifact: "a.zip", ZipSHA256: "z", ManifestSHA256: "m", LockSHA256: "0123456789abcdef0123456789abcdef",
		Signature: "VERIFIED", KeyFingerprint: String("k"), ExpectedFingerprintGiven: true, Backend: String(Backend),
		VerifierNote: "this is the bundled verifier (pail_verify)", Tool: "pail_verify", Files: 7, TreeScope: TreeScope, TreeFiles: 6,
		TreeSHA256: "t", TreeMatched: Bool(false), TreeMismatches: []Mismatch{{"pail-core/README.md", "changed"}, {"run.sh", "missing"}},
		At: "2026-10-30T00:00:00Z"}
	p, err := WriteReceipt(dir, r)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p)
	// Key order byte-pinned (design PAIL-p43 §2).
	want := "{\n  \"schema_version\": 2,\n  \"release_id\": \"0.2.0-x\",\n  \"artifact\": \"a.zip\",\n  \"zip_sha256\": \"z\",\n" +
		"  \"manifest_sha256\": \"m\",\n  \"lock_sha256\": \"0123456789abcdef0123456789abcdef\",\n  \"signature\": \"VERIFIED\",\n" +
		"  \"key_fingerprint\": \"k\",\n  \"expected_fingerprint_given\": true,\n  \"backend\": \"pail_verify\",\n" +
		"  \"verifier_note\": \"this is the bundled verifier (pail_verify)\",\n  \"tool\": \"pail_verify\",\n  \"files\": 7,\n" +
		"  \"tree_scope\": \"manifest files except images/\",\n  \"tree_files\": 6,\n  \"tree_sha256\": \"t\",\n  \"tree_matched\": false,\n" +
		"  \"tree_mismatches\": [\n    {\n      \"path\": \"pail-core/README.md\",\n      \"kind\": \"changed\"\n    },\n" +
		"    {\n      \"path\": \"run.sh\",\n      \"kind\": \"missing\"\n    }\n  ],\n  \"at\": \"2026-10-30T00:00:00Z\"\n}\n"
	if string(data) != want {
		t.Errorf("receipt v2 bytes:\n%s\nwant:\n%s", data, want)
	}
	// Not compared: tree_matched null, tree_mismatches [] (nil slice becomes the empty list, never null).
	r.TreeMatched, r.TreeMismatches = nil, nil
	if _, err := WriteReceipt(dir, r); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(p)
	if !strings.Contains(string(data), "  \"tree_sha256\": \"t\",\n  \"tree_matched\": null,\n  \"tree_mismatches\": [],\n  \"at\"") {
		t.Errorf("not-compared receipt bytes:\n%s", data)
	}
	var back Receipt
	if err := json.Unmarshal(data, &back); err != nil || back.SchemaVersion != 2 || back.TreeMatched != nil || back.TreeMismatches == nil || len(back.TreeMismatches) != 0 {
		t.Errorf("round trip: %+v %v", back, err)
	}
}

func TestReceiptKept(t *testing.T) {
	dir := t.TempDir()
	base := Receipt{ReleaseID: "0.2.0-x", Artifact: "a.zip", LockSHA256: "0123456789abcdef0123456789abcdef", Signature: "VERIFIED",
		Tool: "pail_verify", TreeScope: TreeScope, TreeFiles: 1, TreeSHA256: "t", At: "2026-10-30T00:00:00Z"}
	matched := base
	matched.TreeMatched = Bool(true)
	p, err := WriteReceipt(dir, matched)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(p)
	// A modified tree never overwrites the evidence of a matched one.
	modified := base
	modified.TreeMatched, modified.TreeMismatches, modified.At = Bool(false), []Mismatch{{"run.sh", "changed"}}, "2026-10-30T01:00:00Z"
	kept, err := WriteReceipt(dir, modified)
	if !errors.Is(err, ErrReceiptKept) || kept != p {
		t.Fatalf("kept: %q %v", kept, err)
	}
	if after, _ := os.ReadFile(p); string(after) != string(before) {
		t.Errorf("matched receipt overwritten:\n%s", after)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("temp file left behind: %v", entries)
	}
	// A run that did not compare the tree (tree_matched null) is kept out the same way, with its own message.
	nullDir := filepath.Join(dir, "null-over-matched")
	if _, err := WriteReceipt(nullDir, matched); err != nil {
		t.Fatal(err)
	}
	if kept, err := WriteReceipt(nullDir, base); !errors.Is(err, ErrReceiptKeptNotCompared) || !IsReceiptKept(err) ||
		kept != filepath.Join(nullDir, ReceiptName(base.ReleaseID, base.LockSHA256)) ||
		err.Error() != "existing receipt matched the tree; this run did not compare the tree" {
		t.Errorf("null over matched: %q %v", kept, err)
	}
	if IsReceiptKept(nil) || IsReceiptKept(errors.New("x")) {
		t.Error("IsReceiptKept")
	}
	// Replaced otherwise: matched over matched, matched over modified, modified over modified, anything over
	// not-compared, and anything over a v1 receipt (no tree_matched) or an unparseable file.
	for name, pair := range map[string][2]Receipt{
		"matched-over-matched":   {matched, matched},
		"matched-over-modified":  {modified, matched},
		"modified-over-modified": {modified, modified},
		"null-over-modified":     {modified, base},
		"modified-over-null":     {base, modified},
	} {
		d := filepath.Join(dir, name)
		if _, err := WriteReceipt(d, pair[0]); err != nil {
			t.Fatal(err)
		}
		second := pair[1]
		second.At = "2026-10-30T02:00:00Z"
		p, err := WriteReceipt(d, second)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		data, _ := os.ReadFile(p)
		if !strings.Contains(string(data), "02:00:00Z") {
			t.Errorf("%s: not replaced:\n%s", name, data)
		}
	}
	v1 := filepath.Join(dir, "v1")
	os.MkdirAll(v1, 0o700)
	target := filepath.Join(v1, ReceiptName(base.ReleaseID, base.LockSHA256))
	os.WriteFile(target, []byte("{\n  \"schema_version\": 1,\n  \"release_id\": \"0.2.0-x\"\n}\n"), 0o600)
	if _, err := WriteReceipt(v1, modified); err != nil {
		t.Errorf("v1 receipt not replaced: %v", err)
	}
	os.WriteFile(target, []byte("not json"), 0o600)
	if _, err := WriteReceipt(v1, modified); err != nil {
		t.Errorf("garbage receipt not replaced: %v", err)
	}
	if data, _ := os.ReadFile(target); !strings.Contains(string(data), "\"tree_matched\": false") {
		t.Errorf("replacement bytes:\n%s", data)
	}
}
