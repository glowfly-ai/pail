// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
// Package corecomm implements core-comm-v1 receipt contracts, not motion authority.
package corecomm

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	pb "github.com/glowfly/pail/services/proto/pailv1"
	tp "github.com/glowfly/pail/services/proto/tokenv1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"math"
	"sort"
	"unicode/utf8"
)

const MaxCanonicalBytes = 1 << 20

func ValidID(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, c := range []byte(s) {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}
func valid(m protoreflect.Message) error {
	if len(m.GetUnknown()) != 0 {
		return errors.New("unknown canonical fields")
	}
	return nil
}
func kind(k protoreflect.Kind) byte {
	switch k {
	case protoreflect.BoolKind:
		return 1
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return 2
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return 3
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return 4
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return 5
	case protoreflect.FloatKind:
		return 6
	case protoreflect.DoubleKind:
		return 7
	case protoreflect.StringKind:
		return 8
	case protoreflect.BytesKind:
		return 9
	case protoreflect.MessageKind:
		return 10
	case protoreflect.EnumKind:
		return 13
	}
	return 0
}
func scalar(f protoreflect.FieldDescriptor, v protoreflect.Value, depth int) ([]byte, error) {
	switch f.Kind() {
	case protoreflect.BoolKind:
		if v.Bool() {
			return []byte{1}, nil
		}
		return []byte{0}, nil
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return binary.BigEndian.AppendUint32(nil, uint32(v.Int())), nil
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return binary.BigEndian.AppendUint32(nil, uint32(v.Uint())), nil
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return binary.BigEndian.AppendUint64(nil, uint64(v.Int())), nil
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return binary.BigEndian.AppendUint64(nil, v.Uint()), nil
	case protoreflect.EnumKind:
		if f.Enum().Values().ByNumber(v.Enum()) == nil {
			return nil, errors.New("unknown enum")
		}
		return binary.BigEndian.AppendUint32(nil, uint32(v.Enum())), nil
	case protoreflect.FloatKind, protoreflect.DoubleKind:
		x := v.Float()
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return nil, errors.New("nonfinite number")
		}
		if x == 0 {
			x = 0
		}
		if f.Kind() == protoreflect.FloatKind {
			return binary.BigEndian.AppendUint32(nil, math.Float32bits(float32(x))), nil
		}
		return binary.BigEndian.AppendUint64(nil, math.Float64bits(x)), nil
	case protoreflect.StringKind:
		if !utf8.ValidString(v.String()) {
			return nil, errors.New("invalid UTF8")
		}
		return []byte(v.String()), nil
	case protoreflect.BytesKind:
		return v.Bytes(), nil
	case protoreflect.MessageKind:
		if !v.Message().IsValid() {
			return nil, nil
		}
		return canonical(v.Message(), nil, nil, depth+1)
	}
	return nil, errors.New("unsupported canonical type")
}
func piece(k byte, b []byte) []byte {
	r := []byte{k}
	r = binary.BigEndian.AppendUint64(r, uint64(len(b)))
	return append(r, b...)
}
func canonical(m protoreflect.Message, include, exclude map[protoreflect.FieldNumber]bool, depth int) ([]byte, error) {
	if depth > 16 {
		return nil, errors.New("canonical depth exceeded")
	}
	if e := valid(m); e != nil {
		return nil, e
	}
	fs := m.Descriptor().Fields()
	fields := make([]protoreflect.FieldDescriptor, fs.Len())
	for i := range fields {
		fields[i] = fs.Get(i)
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i].Number() < fields[j].Number() })
	var out []byte
	for _, f := range fields {
		if include != nil && !include[f.Number()] {
			if !exclude[f.Number()] {
				return nil, errors.New("unclassified canonical field")
			}
			continue
		}
		var b []byte
		var err error
		k := kind(f.Kind())
		v := m.Get(f)
		if f.IsMap() {
			k = 12
			var entries [][]byte
			var mapErr error
			v.Map().Range(func(key protoreflect.MapKey, value protoreflect.Value) bool {
				a, e := scalar(f.MapKey(), key.Value(), depth)
				if e != nil {
					mapErr = e
					return false
				}
				c, e := scalar(f.MapValue(), value, depth)
				if e != nil {
					mapErr = e
					return false
				}
				entries = append(entries, append(piece(kind(f.MapKey().Kind()), a), piece(kind(f.MapValue().Kind()), c)...))
				return true
			})
			if mapErr != nil {
				return nil, mapErr
			}
			sort.Slice(entries, func(i, j int) bool { return bytes.Compare(entries[i], entries[j]) < 0 })
			b = binary.BigEndian.AppendUint64(b, uint64(len(entries)))
			for _, entry := range entries {
				b = append(b, entry...)
			}
		} else if f.IsList() {
			k = 11
			ls := v.List()
			b = binary.BigEndian.AppendUint64(b, uint64(ls.Len()))
			for i := 0; i < ls.Len(); i++ {
				item, e := scalar(f, ls.Get(i), depth)
				if e != nil {
					return nil, e
				}
				b = append(b, piece(kind(f.Kind()), item)...)
				if len(b) > MaxCanonicalBytes {
					return nil, errors.New("canonical size exceeded")
				}
			}
		} else {
			b, err = scalar(f, v, depth)
		}
		if err != nil {
			return nil, err
		}
		out = binary.BigEndian.AppendUint32(out, uint32(f.Number()))
		out = append(out, piece(k, b)...)
		if len(out) > MaxCanonicalBytes {
			return nil, errors.New("canonical size exceeded")
		}
	}
	return out, nil
}
func digest(domain string, m proto.Message, include, exclude map[protoreflect.FieldNumber]bool) ([]byte, error) {
	if m == nil || !m.ProtoReflect().IsValid() {
		return nil, errors.New("nil canonical message")
	}
	if proto.Size(m) > MaxCanonicalBytes {
		return nil, errors.New("message too large")
	}
	b, e := canonical(m.ProtoReflect(), include, exclude, 0)
	if e != nil {
		return nil, e
	}
	h := sha256.Sum256(append([]byte(domain+"\x00"), b...))
	return h[:], nil
}
func ReportDigest(r *tp.ReportDecisionRequest) ([]byte, error) {
	in := map[protoreflect.FieldNumber]bool{16: true}
	ex := map[protoreflect.FieldNumber]bool{}
	for i := 1; i <= 11; i++ {
		in[protoreflect.FieldNumber(i)] = true
	}
	for _, i := range []int{12, 13, 14, 15, 17, 18, 19} {
		ex[protoreflect.FieldNumber(i)] = true
	}
	return digest("pail-core-report:v1", r, in, ex)
}
func SubmitDigest(r *pb.SubmitActionPlanRequest) ([]byte, error) {
	return digest("pail-core-operation:v1", r, map[protoreflect.FieldNumber]bool{1: true, 2: true, 3: true}, map[protoreflect.FieldNumber]bool{4: true})
}
func CancelDigest(r *pb.CancelPlanRequest) ([]byte, error) {
	return digest("pail-core-operation:v1", r, map[protoreflect.FieldNumber]bool{1: true}, map[protoreflect.FieldNumber]bool{2: true})
}
