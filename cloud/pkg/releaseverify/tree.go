// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package releaseverify

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// TreeScope names what the tree digest covers (receipt field tree_scope,
// design PAIL-p43 §1): every manifest file except the images/ archives, which
// the launcher verifies when it loads them.
const TreeScope = "manifest files except images/"

// The ignore lists are shared with verification_receipt.py byte for byte.
var (
	IgnoredNames    = []string{".DS_Store"}           // file names
	IgnoredDirs     = []string{"__pycache__", ".git"} // directory names, at any depth
	IgnoredSuffixes = []string{".pyc"}
)

// Mismatch is one difference between the manifest and the extracted tree.
// Kind is changed | missing | extra | symlink.
type Mismatch struct {
	Path string `json:"path"`
	Kind string `json:"kind"`
}

// MaxReceiptMismatches bounds the list the receipt carries (the TREE: line's
// totals are counted over the full list).
const MaxReceiptMismatches = 20

// TreeKeys copies the manifest's files_sha256 without the images/ keys.
func TreeKeys(filesSHA256 map[string]string) map[string]string {
	out := make(map[string]string, len(filesSHA256))
	for k, v := range filesSHA256 {
		if !strings.HasPrefix(k, "images/") {
			out[k] = v
		}
	}
	return out
}

// TreeDigest is the hex sha256 of PyJSONCompact(m): the same bytes Python
// hashes with json.dumps(m, sort_keys=True, separators=(',', ':')).
func TreeDigest(m map[string]string) string {
	sum := sha256.Sum256(PyJSONCompact(m))
	return hex.EncodeToString(sum[:])
}

func inList(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func ignoredFile(name string) bool {
	if inList(IgnoredNames, name) {
		return true
	}
	for _, suffix := range IgnoredSuffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

// WalkTree hashes every regular file under root (posix relative path →
// hex sha256), skipping the top-level images entry (directory or symlink:
// out of scope, load verifies the archives), the ignored names, directories
// and suffixes. Every entry is Lstat'ed; nothing is followed. Odd entries
// come back as mismatches instead of errors: a symbolic link is kind
// "symlink", a socket/FIFO/device "irregular", an entry that cannot be
// stat'ed or read "unreadable". The walk fails only when root itself cannot
// be read. Paths are the raw names on disk, without Unicode normalisation.
func WalkTree(root string) (map[string]string, []Mismatch, error) {
	// A root given through a symlink is walked at its target (os.walk does the same).
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	files := map[string]string{}
	var odd []Mismatch
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if p == root {
			if err == nil && !d.IsDir() {
				return errors.New("not a directory: " + root)
			}
			return err // nil, or the root cannot be read: the only failure
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if err != nil {
			// WalkDir reports a directory it could not read with a second call; its entries are unknown.
			odd = append(odd, Mismatch{Path: rel, Kind: "unreadable"})
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if rel == "images" || inList(IgnoredDirs, name) {
				return filepath.SkipDir
			}
			return nil
		}
		if rel == "images" || ignoredFile(name) {
			return nil
		}
		if inList(IgnoredDirs, name) && d.Type()&fs.ModeSymlink != 0 {
			// os.walk lists a symlink to a directory among the directories, where the ignore list hides it.
			if st, err := os.Stat(p); err == nil && st.IsDir() {
				return nil
			}
		}
		st, err := os.Lstat(p)
		switch {
		case err != nil:
			odd = append(odd, Mismatch{Path: rel, Kind: "unreadable"})
		case st.Mode()&fs.ModeSymlink != 0:
			odd = append(odd, Mismatch{Path: rel, Kind: "symlink"})
		case !st.Mode().IsRegular():
			odd = append(odd, Mismatch{Path: rel, Kind: "irregular"})
		default:
			if sum, err := FileSHA256(p); err != nil {
				odd = append(odd, Mismatch{Path: rel, Kind: "unreadable"})
			} else {
				files[rel] = sum
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return files, odd, nil
}

// CompareTree walks root and compares it with expected (already without
// images/). mismatches: missing/changed for expected keys, extra for walked
// files not expected, symlink/irregular/unreadable for the odd entries (all
// three count as extra in the verifier's totals); the FULL list sorted by path (byte
// order) — the verifier's totals are counted over it and only the receipt caps
// it (CapMismatches). compared = len(expected). The digests are TreeDigest of
// expected and of the walked files.
func CompareTree(root string, expected map[string]string) (matched bool, expectedDigest, actualDigest string, mismatches []Mismatch, compared int, err error) {
	actual, links, err := WalkTree(root)
	if err != nil {
		return false, "", "", nil, 0, err
	}
	mismatches = []Mismatch{}
	for k, h := range expected {
		got, ok := actual[k]
		switch {
		case !ok:
			mismatches = append(mismatches, Mismatch{Path: k, Kind: "missing"})
		case got != h:
			mismatches = append(mismatches, Mismatch{Path: k, Kind: "changed"})
		}
	}
	for k := range actual {
		if _, ok := expected[k]; !ok {
			mismatches = append(mismatches, Mismatch{Path: k, Kind: "extra"})
		}
	}
	mismatches = append(mismatches, links...)
	sort.Slice(mismatches, func(i, j int) bool { return mismatches[i].Path < mismatches[j].Path })
	return len(mismatches) == 0, TreeDigest(expected), TreeDigest(actual), mismatches, len(expected), nil
}

// CapMismatches returns the first MaxReceiptMismatches entries (the list the
// receipt carries); never nil.
func CapMismatches(mismatches []Mismatch) []Mismatch {
	if len(mismatches) > MaxReceiptMismatches {
		mismatches = mismatches[:MaxReceiptMismatches]
	}
	if mismatches == nil {
		return []Mismatch{}
	}
	return mismatches
}

// HasLock reports whether <root>/images.lock.json is a regular file: the
// condition under which the verifier compares the tree at all.
func HasLock(root string) bool {
	st, err := os.Lstat(filepath.Join(root, "images.lock.json"))
	return err == nil && st.Mode().IsRegular()
}
