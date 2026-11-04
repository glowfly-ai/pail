// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package robotops

import (
	"bytes"
	"encoding/json"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"strconv"
	"unicode/utf8"
)

// StrictDecode accepts the restricted management YAML/JSON data model, not
// arbitrary YAML objects. YAML's scalar coercions never populate typed strings.
func StrictDecode(raw []byte, out interface{}, required []string) error {
	if len(raw) == 0 || len(raw) > MaxDocument || !utf8.Valid(raw) {
		return fmt.Errorf("RO_SCHEMA: empty, oversized or non-UTF8 document")
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		return fmt.Errorf("RO_SCHEMA: malformed document")
	}
	var tail yaml.Node
	if err := dec.Decode(&tail); err != io.EOF {
		return fmt.Errorf("RO_SCHEMA: trailing document")
	}
	if len(doc.Content) != 1 {
		return fmt.Errorf("RO_SCHEMA: missing root")
	}
	v, err := nodeValue(doc.Content[0])
	if err != nil {
		return err
	}
	obj, ok := v.(map[string]interface{})
	if !ok {
		return fmt.Errorf("RO_SCHEMA: root must be an object")
	}
	for _, key := range required {
		if _, ok := obj[key]; !ok {
			return fmt.Errorf("RO_SCHEMA: required field %s absent", key)
		}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("RO_SCHEMA: encoding failed")
	}
	jd := json.NewDecoder(bytes.NewReader(b))
	jd.DisallowUnknownFields()
	if err = jd.Decode(out); err != nil {
		return fmt.Errorf("RO_SCHEMA: unknown field or wrong type")
	}
	return nil
}
func nodeValue(n *yaml.Node) (interface{}, error) {
	bad := func() (interface{}, error) { return nil, fmt.Errorf("RO_SCHEMA: unsupported YAML value") }
	if n.Anchor != "" || n.Kind == yaml.AliasNode || n.Style&yaml.TaggedStyle != 0 {
		return bad()
	}
	switch n.Kind {
	case yaml.MappingNode:
		if n.Tag != "!!map" {
			return bad()
		}
		out := map[string]interface{}{}
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode || k.Tag != "!!str" || k.Anchor != "" || k.Style&yaml.TaggedStyle != 0 {
				return bad()
			}
			if _, ok := out[k.Value]; ok {
				return nil, fmt.Errorf("RO_SCHEMA: duplicate key")
			}
			v, err := nodeValue(n.Content[i+1])
			if err != nil {
				return nil, err
			}
			out[k.Value] = v
		}
		return out, nil
	case yaml.SequenceNode:
		if n.Tag != "!!seq" {
			return bad()
		}
		out := make([]interface{}, 0, len(n.Content))
		for _, c := range n.Content {
			v, err := nodeValue(c)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!str":
			return n.Value, nil
		case "!!null":
			return nil, nil
		case "!!bool":
			if n.Value == "true" {
				return true, nil
			}
			if n.Value == "false" {
				return false, nil
			}
			return bad()
		case "!!int":
			v, err := strconv.ParseInt(n.Value, 10, 64)
			if err != nil || v > MaxSafeInteger || v < -MaxSafeInteger || n.Value != strconv.FormatInt(v, 10) {
				return bad()
			}
			return v, nil
		}
	}
	return bad()
}
