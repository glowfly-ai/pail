// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// Package releaseverify is a standard-library-only port of
// oss/distribution/verify_evaluation.py: the delivery manifest, the archive
// walk, the Ed25519 manifest signature, the verification receipt and the
// doctor vector. Error and message strings are the Python tool's, byte for
// byte, so the two implementations can be run over the same fixtures.
package releaseverify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
)

// Manifest is the subset of the delivery manifest the verifier reads.
type Manifest struct {
	ReleaseID     string
	Artifact      string
	RootDirectory string
	Bytes         int64
	SHA256        string
	FileCount     int
	FilesSHA256   map[string]string
	FileModes     map[string]string
}

// DecodeUnique parses JSON like Python's json.loads(..., object_pairs_hook=unique):
// objects become map[string]any, arrays []any, numbers json.Number, and a key
// repeated inside one object is an error "Duplicate manifest key: <k>".
func DecodeUnique(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := decodeValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return nil, errors.New("Extra data after JSON document")
		}
		return nil, err
	}
	return v, nil
}

func decodeValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := map[string]any{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := kt.(string)
				if !ok {
					return nil, fmt.Errorf("object key is not a string: %v", kt)
				}
				if _, dup := obj[key]; dup {
					return nil, errors.New("Duplicate manifest key: " + key)
				}
				val, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				obj[key] = val
			}
			if _, err := dec.Token(); err != nil { // '}'
				return nil, err
			}
			return obj, nil
		case '[':
			arr := []any{}
			for dec.More() {
				val, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, val)
			}
			if _, err := dec.Token(); err != nil { // ']'
				return nil, err
			}
			return arr, nil
		}
		return nil, fmt.Errorf("unexpected delimiter %v", t)
	default:
		return tok, nil
	}
}

func manifestString(obj map[string]any, key string) (string, error) {
	v, ok := obj[key]
	if !ok {
		return "", errors.New("missing manifest key: " + key)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("manifest key %s is not a string", key)
	}
	return s, nil
}

func manifestInt(obj map[string]any, key string) (int64, error) {
	v, ok := obj[key]
	if !ok {
		return 0, errors.New("missing manifest key: " + key)
	}
	n, ok := v.(json.Number)
	if !ok {
		return 0, fmt.Errorf("manifest key %s is not a number", key)
	}
	i, err := strconv.ParseInt(n.String(), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("manifest key %s is not an integer", key)
	}
	return i, nil
}

func manifestStringMap(obj map[string]any, key string) (map[string]string, error) {
	v, ok := obj[key]
	if !ok {
		return nil, errors.New("missing manifest key: " + key)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("manifest key %s is not an object", key)
	}
	out := make(map[string]string, len(m))
	for k, val := range m {
		s, ok := val.(string)
		if !ok {
			return nil, fmt.Errorf("manifest key %s[%s] is not a string", key, k)
		}
		out[k] = s
	}
	return out, nil
}

// ParseManifest decodes manifest bytes with duplicate-key detection.
func ParseManifest(data []byte) (Manifest, error) {
	var m Manifest
	v, err := DecodeUnique(data)
	if err != nil {
		return m, err
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return m, errors.New("manifest is not a JSON object")
	}
	if m.ReleaseID, err = manifestString(obj, "release_id"); err != nil {
		return m, err
	}
	if m.Artifact, err = manifestString(obj, "artifact"); err != nil {
		return m, err
	}
	if m.Bytes, err = manifestInt(obj, "bytes"); err != nil {
		return m, err
	}
	if m.SHA256, err = manifestString(obj, "sha256"); err != nil {
		return m, err
	}
	if m.FilesSHA256, err = manifestStringMap(obj, "files_sha256"); err != nil {
		return m, err
	}
	count, err := manifestInt(obj, "file_count")
	if err != nil {
		return m, err
	}
	m.FileCount = int(count)
	if m.FileModes, err = manifestStringMap(obj, "file_modes"); err != nil {
		return m, err
	}
	if m.RootDirectory, err = manifestString(obj, "root_directory"); err != nil {
		return m, err
	}
	return m, nil
}

// LoadManifest reads and parses the manifest file.
func LoadManifest(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, err
	}
	return ParseManifest(data)
}
