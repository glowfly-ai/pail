// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package releaseverify

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf16"
)

const (
	expectedRoot = "pail-evaluation"
	corePrefix   = "pail-core/"
	sIFMT        = 0o170000
	sIFREG       = 0o100000
)

func digestReader(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// FileSHA256 returns the hex sha256 of a file.
func FileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return digestReader(f)
}

// unsafeName mirrors the Python check: absolute, a '..' part, a backslash, or a
// name PurePosixPath would normalise ("a//b", "./a", "a/", the empty name).
func unsafeName(name string) bool {
	if strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
		return true
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return true
		}
	}
	return path.Clean(name) != name
}

// PyJSONCompact serialises a string map like Python's
// json.dumps(m, sort_keys=True, separators=(',', ':')) with the default
// ensure_ascii=True: keys sorted by code point, no whitespace, non-ASCII and
// control characters as \uXXXX (UTF-16 surrogate pairs above the BMP).
func PyJSONCompact(m map[string]string) []byte {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys) // byte order == code point order for valid UTF-8
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		pyEscape(&b, k)
		b.WriteByte(':')
		pyEscape(&b, m[k])
	}
	b.WriteByte('}')
	return []byte(b.String())
}

func pyEscape(b *strings.Builder, s string) {
	const hexdigits = "0123456789abcdef"
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r >= 0x20 && r <= 0x7e {
				b.WriteRune(r)
				continue
			}
			units := []uint16{uint16(r)}
			if r > 0xffff {
				hi, lo := utf16.EncodeRune(r)
				units = []uint16{uint16(hi), uint16(lo)}
			}
			for _, u := range units {
				b.WriteString(`\u`)
				b.WriteByte(hexdigits[(u>>12)&0xf])
				b.WriteByte(hexdigits[(u>>8)&0xf])
				b.WriteByte(hexdigits[(u>>4)&0xf])
				b.WriteByte(hexdigits[u&0xf])
			}
		}
	}
	b.WriteByte('"')
}

func openZip(zipPath string) (*zip.ReadCloser, error) {
	z, err := zip.OpenReader(zipPath)
	if err != nil && (z == nil || !errors.Is(err, zip.ErrInsecurePath)) {
		if errors.Is(err, zip.ErrFormat) {
			return nil, errors.New("File is not a zip file")
		}
		return nil, err
	}
	// ErrInsecurePath: the reader is usable; the member loop refuses such names itself.
	return z, nil
}

// VerifyArchive is a 1:1 port of verify_evaluation.verify(); it returns the
// verified file count or an error whose text equals the Python ValueError.
func VerifyArchive(zipPath string, m Manifest, expectedRelease string) (int, error) {
	if m.ReleaseID != expectedRelease || m.Artifact != filepath.Base(zipPath) {
		return 0, errors.New("Delivery identity mismatch")
	}
	st, err := os.Stat(zipPath)
	if err != nil {
		return 0, err
	}
	sum, err := FileSHA256(zipPath)
	if err != nil {
		return 0, err
	}
	if st.Size() != m.Bytes || sum != m.SHA256 {
		return 0, errors.New("Archive size/digest mismatch")
	}
	files := m.FilesSHA256
	if len(files) == 0 || len(files) != m.FileCount || !sameKeys(m.FileModes, files) {
		return 0, errors.New("Nonempty file map, modes and count must agree")
	}
	root := m.RootDirectory
	if root != expectedRoot {
		return 0, errors.New("Unexpected extraction root")
	}
	z, err := openZip(zipPath)
	if err != nil {
		return 0, err
	}
	defer z.Close()
	seen := map[string]bool{}
	var buildEntry *zip.File
	for _, entry := range z.File {
		name := entry.Name
		if seen[name] {
			return 0, errors.New("Duplicate archive entry: " + name)
		}
		seen[name] = true
		if unsafeName(name) {
			return 0, errors.New("Unsafe member: " + name)
		}
		if !strings.HasPrefix(name, root+"/") || strings.HasSuffix(name, "/") {
			return 0, errors.New("Unexpected archive member: " + name)
		}
		mode := entry.ExternalAttrs >> 16
		if mode&sIFMT != sIFREG {
			return 0, errors.New("Non-regular member: " + name)
		}
		key := name[len(root)+1:]
		want, ok := files[key]
		if !ok || fmt.Sprintf("%04o", mode&0o7777) != m.FileModes[key] {
			return 0, errors.New("Unexpected path or mode: " + name)
		}
		got, err := memberDigest(entry)
		if err != nil {
			return 0, err
		}
		if got != want {
			return 0, errors.New("Member digest mismatch: " + name)
		}
		if key == "native/BUILD.json" {
			buildEntry = entry
		}
	}
	// Source provenance is independently recomputable from verified ZIP members.
	if _, ok := files["native/BUILD.json"]; ok {
		if buildEntry == nil {
			// Python: str(KeyError(msg)) wraps the message in quotes (repr).
			return 0, errors.New("\"There is no item named '" + root + "/native/BUILD.json' in the archive\"")
		}
		raw, err := readMember(buildEntry)
		if err != nil {
			return 0, err
		}
		bv, err := DecodeUnique(raw)
		if err != nil {
			return 0, err
		}
		build, _ := bv.(map[string]any)
		core := map[string]string{}
		for n, h := range files {
			if strings.HasPrefix(n, corePrefix) {
				core[n[len(corePrefix):]] = h
			}
		}
		sourceHash := sha256.Sum256(PyJSONCompact(core))
		if !pyEqualString(build["core_source_sha256"], hex.EncodeToString(sourceHash[:]), true) {
			return 0, errors.New("Native source snapshot mismatch")
		}
		goSum, present := core["cloud/go.sum"]
		if !pyEqualString(build["cloud_go_sum_sha256"], goSum, present) {
			return 0, errors.New("Native dependency source mismatch")
		}
	}
	if len(seen) != len(files) {
		return 0, errors.New("Missing archive members")
	}
	for n := range files {
		if !seen[root+"/"+n] {
			return 0, errors.New("Missing archive members")
		}
	}
	return len(files), nil
}

// pyEqualString mirrors `build.get(k) == value` where the right side is a
// string when present and None otherwise; JSON null equals absent.
func pyEqualString(got any, want string, wantPresent bool) bool {
	if got == nil {
		return !wantPresent
	}
	s, ok := got.(string)
	return ok && wantPresent && s == want
}

func sameKeys(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

func memberDigest(entry *zip.File) (string, error) {
	rc, err := entry.Open()
	if err != nil {
		return "", err
	}
	defer rc.Close()
	sum, err := digestReader(rc)
	if errors.Is(err, zip.ErrChecksum) {
		return "", errors.New("Bad CRC-32 for file '" + entry.Name + "'")
	}
	return sum, err
}

func readMember(entry *zip.File) ([]byte, error) {
	rc, err := entry.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if errors.Is(err, zip.ErrChecksum) {
		return nil, errors.New("Bad CRC-32 for file '" + entry.Name + "'")
	}
	return data, err
}
