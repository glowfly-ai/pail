// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package graph

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"

	"golang.org/x/text/unicode/norm"
)

// Canonical encoder format constants. FORMAT_VERSION is the encoder's own
// version, independent of the token schema_version.
const (
	magicGraph    = "PAILCG"
	magicSubgraph = "PAILSG"
	formatVersion = 0x01
)

var (
	errUnspecifiedKind = errors.New("graph: node kind KindUnspecified is not encodable")
	errDuplicateNodeID = errors.New("graph: duplicate node_id in encoding")
	errNonFiniteDouble = errors.New("graph: double attribute is NaN or Inf (not encodable)")
	errUnknownTag      = errors.New("graph: unknown attribute tag")
)

// CanonicalGraph returns the deterministic byte encoding of a graph. The output
// is independent of the insertion order of nodes, edges, and attrs.
func CanonicalGraph(g *Graph) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(magicGraph)
	b.WriteByte(formatVersion)
	writeU64(&b, g.Epoch)

	nodes := make([]*Node, 0, len(g.Nodes))
	for _, n := range g.Nodes {
		nodes = append(nodes, n)
	}
	if err := writeNodes(&b, nodes); err != nil {
		return nil, err
	}
	writeEdges(&b, g.Edges)
	return b.Bytes(), nil
}

// CanonicalSubgraph returns the deterministic byte encoding of a subgraph. This
// is the input to SnapshotHash. Node encoding is identical to CanonicalGraph, so
// a verifier can rebuild a subgraph from the graph and recompute the same hash.
func CanonicalSubgraph(sg *Subgraph) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(magicSubgraph)
	b.WriteByte(formatVersion)
	writeU64(&b, sg.GraphEpoch)
	if err := writeNodes(&b, sg.Nodes); err != nil {
		return nil, err
	}
	writeEdges(&b, sg.Edges)
	return b.Bytes(), nil
}

// writeNodes encodes nodes sorted by their canonical bytes, rejecting duplicates.
func writeNodes(b *bytes.Buffer, nodes []*Node) error {
	encoded := make([][]byte, 0, len(nodes))
	ids := make([][]byte, 0, len(nodes))
	for _, n := range nodes {
		e, err := encodeNode(n)
		if err != nil {
			return err
		}
		encoded = append(encoded, e)
		ids = append(ids, nfcBytes(n.ID))
	}
	// Sort node encodings; a node's encoding begins with lp(ID), so byte order
	// is ID-major and stable.
	order := byteSortOrder(encoded)
	writeU32(b, uint32(len(encoded)))
	var prevID []byte
	for i, idx := range order {
		if i > 0 && bytes.Equal(ids[idx], prevID) {
			return fmt.Errorf("%w: %q", errDuplicateNodeID, nodes[idx].ID)
		}
		prevID = ids[idx]
		b.Write(encoded[idx])
	}
	return nil
}

// writeEdges encodes edges sorted by their canonical bytes. Duplicate edges are
// allowed to collapse naturally only if identical; we keep them as-is (the graph
// builder is responsible for not producing spurious duplicates).
func writeEdges(b *bytes.Buffer, edges []Edge) {
	encoded := make([][]byte, 0, len(edges))
	for _, e := range edges {
		encoded = append(encoded, encodeEdge(e))
	}
	order := byteSortOrder(encoded)
	writeU32(b, uint32(len(encoded)))
	for _, idx := range order {
		b.Write(encoded[idx])
	}
}

func encodeNode(n *Node) ([]byte, error) {
	if n.Kind == KindUnspecified {
		return nil, fmt.Errorf("%w: %q", errUnspecifiedKind, n.ID)
	}
	var b bytes.Buffer
	writeLP(&b, n.ID)
	b.WriteByte(byte(n.Kind))
	b.WriteByte(byte(n.State))
	writeU64(&b, n.Version)
	if err := encodeAttrs(&b, n.Attrs); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func encodeAttrs(b *bytes.Buffer, m map[string]AttrVal) error {
	writeU32(b, uint32(len(m)))
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return bytes.Compare(nfcBytes(keys[i]), nfcBytes(keys[j])) < 0
	})
	for _, k := range keys {
		writeLP(b, k)
		v := m[k]
		b.WriteByte(byte(v.Tag))
		switch v.Tag {
		case TagString:
			writeLP(b, v.S)
		case TagInt64:
			writeI64(b, v.I)
		case TagDouble:
			if math.IsNaN(v.F) || math.IsInf(v.F, 0) {
				return fmt.Errorf("%w: key=%q", errNonFiniteDouble, k)
			}
			f := v.F
			if f == 0 { // normalize -0.0 to +0.0
				f = 0
			}
			var buf [8]byte
			binary.BigEndian.PutUint64(buf[:], math.Float64bits(f))
			b.Write(buf[:])
		case TagBool:
			if v.B {
				b.WriteByte(1)
			} else {
				b.WriteByte(0)
			}
		default:
			return fmt.Errorf("%w: key=%q tag=0x%02x", errUnknownTag, k, v.Tag)
		}
	}
	return nil
}

func encodeEdge(e Edge) []byte {
	var b bytes.Buffer
	writeLP(&b, e.From)
	b.WriteByte(byte(e.Rel))
	writeLP(&b, e.To)
	return b.Bytes()
}

// --- primitives ---

// nfcBytes returns the NFC-normalized UTF-8 bytes of s. Identifiers are expected
// to be ASCII in practice (YAML ids like "zone:z7"), for which NFC is a no-op;
// normalization guards against representational variants of any non-ASCII text.
func nfcBytes(s string) []byte { return norm.NFC.Bytes([]byte(s)) }

func writeLP(b *bytes.Buffer, s string) {
	nb := nfcBytes(s)
	writeU32(b, uint32(len(nb)))
	b.Write(nb)
}

func writeU32(b *bytes.Buffer, v uint32) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	b.Write(buf[:])
}

func writeU64(b *bytes.Buffer, v uint64) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	b.Write(buf[:])
}

func writeI64(b *bytes.Buffer, v int64) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(v))
	b.Write(buf[:])
}

// byteSortOrder returns indices that sort the encoded byte slices in ascending
// byte-lexicographic order (stable on ties).
func byteSortOrder(encoded [][]byte) []int {
	order := make([]int, len(encoded))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(i, j int) bool {
		return bytes.Compare(encoded[order[i]], encoded[order[j]]) < 0
	})
	return order
}
