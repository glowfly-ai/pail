// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package graph

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math"
	"sort"
	"testing"

	"golang.org/x/text/unicode/norm"
)

// goldenSubgraph builds a small, hand-checkable subgraph used as the frozen
// golden vector: 3 nodes (agent, zone, constraint), 2 edges, 2 attrs each on the
// zone and constraint.
func goldenSubgraph() *Subgraph {
	return &Subgraph{
		ID:         "sg-golden",
		GraphEpoch: 7,
		Nodes: []*Node{
			{ID: "robot:tb1", Kind: KindAgent, State: StateActive, Version: 3},
			{ID: "zone:z7", Kind: KindZone, State: StateActive, Version: 1,
				Attrs: map[string]AttrVal{"type": AString("work_area"), "adjacent_count": AInt(2)}},
			{ID: "constraint:speed@z7", Kind: KindConstraint, State: StateActive, Version: 1,
				Attrs: map[string]AttrVal{"max_linear_speed_mps": ADouble(0.5), "hard": ABool(true)}},
		},
		Edges: []Edge{
			{From: "robot:tb1", To: "zone:z7", Rel: RelLocatedIn},
			{From: "constraint:speed@z7", To: "zone:z7", Rel: RelConstrains},
		},
	}
}

// GOLDEN VECTOR — frozen after first docker run. See GOLDEN_VECTORS.md.
// If empty, TestGoldenVector prints the computed values and fails so they can be
// frozen. Any future change to the encoder that alters these is an intentional,
// reviewed evidence-format change.
const (
	goldenCanonicalHex = "5041494c534701000000000000000700000003000000077a6f6e653a7a3704000000000000000001000000020000000e61646a6163656e745f636f756e7402000000000000000200000004747970650100000009776f726b5f6172656100000009726f626f743a746231010000000000000000030000000000000013636f6e73747261696e743a7370656564407a37060000000000000000010000000200000004686172640401000000146d61785f6c696e6561725f73706565645f6d7073033fe00000000000000000000200000009726f626f743a74623101000000077a6f6e653a7a3700000013636f6e73747261696e743a7370656564407a3703000000077a6f6e653a7a37"
	goldenHashHex      = "58b631c03edf4600000aec54715c022b0c5505d29b1639af021abf79d1474aa1"
)

func TestGoldenVector(t *testing.T) {
	sg := goldenSubgraph()
	b, err := CanonicalSubgraph(sg)
	if err != nil {
		t.Fatalf("CanonicalSubgraph: %v", err)
	}
	sum := sha256.Sum256(b)
	gotCanon := hex.EncodeToString(b)
	gotHash := hex.EncodeToString(sum[:])

	if goldenHashHex == "" {
		t.Logf("FREEZE THESE into GOLDEN_VECTORS.md and the test constants:")
		t.Logf("goldenCanonicalHex = %q", gotCanon)
		t.Logf("goldenHashHex      = %q", gotHash)
		t.Fatalf("golden vector not frozen yet")
	}
	if gotHash != goldenHashHex {
		t.Fatalf("hash drift:\n got  %s\n want %s\n canon=%s", gotHash, goldenHashHex, gotCanon)
	}
	if want, _ := hex.DecodeString(goldenCanonicalHex); !bytes.Equal(b, want) {
		t.Fatalf("canonical bytes drift:\n got  %s\n want %s", gotCanon, goldenCanonicalHex)
	}
}

// TestDeterminismOrderIndependent builds the same logical subgraph with three
// different node/edge/attr insertion orders and asserts identical bytes + hash.
func TestDeterminismOrderIndependent(t *testing.T) {
	base := goldenSubgraph()
	want, err := SnapshotHash(base)
	if err != nil {
		t.Fatal(err)
	}
	for trial := 0; trial < 3; trial++ {
		sg := goldenSubgraph()
		// reverse nodes and edges; attrs are maps (Go randomizes range order).
		for i, j := 0, len(sg.Nodes)-1; i < j; i, j = i+1, j-1 {
			sg.Nodes[i], sg.Nodes[j] = sg.Nodes[j], sg.Nodes[i]
		}
		for i, j := 0, len(sg.Edges)-1; i < j; i, j = i+1, j-1 {
			sg.Edges[i], sg.Edges[j] = sg.Edges[j], sg.Edges[i]
		}
		got, err := SnapshotHash(sg)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("trial %d: hash changed with reordering", trial)
		}
	}
}

// TestCrossCheck verifies the primary encoder against an independent
// re-implementation (different code path) — guards against endianness, tag, and
// ordering transcription bugs that would silently corrupt all evidence.
func TestCrossCheck(t *testing.T) {
	sg := goldenSubgraph()
	got, err := CanonicalSubgraph(sg)
	if err != nil {
		t.Fatal(err)
	}
	ref := refEncodeSubgraph(t, sg)
	if !bytes.Equal(got, ref) {
		t.Fatalf("cross-check mismatch:\n primary %s\n ref     %s",
			hex.EncodeToString(got), hex.EncodeToString(ref))
	}
}

func TestRejectPaths(t *testing.T) {
	t.Run("unspecified kind", func(t *testing.T) {
		sg := &Subgraph{Nodes: []*Node{{ID: "x", Kind: KindUnspecified}}}
		if _, err := SnapshotHash(sg); err == nil {
			t.Fatal("expected error for KindUnspecified")
		}
	})
	t.Run("NaN double", func(t *testing.T) {
		sg := &Subgraph{Nodes: []*Node{{ID: "z", Kind: KindZone,
			Attrs: map[string]AttrVal{"v": ADouble(math.NaN())}}}}
		if _, err := SnapshotHash(sg); err == nil {
			t.Fatal("expected error for NaN double")
		}
	})
	t.Run("Inf double", func(t *testing.T) {
		sg := &Subgraph{Nodes: []*Node{{ID: "z", Kind: KindZone,
			Attrs: map[string]AttrVal{"v": ADouble(math.Inf(1))}}}}
		if _, err := SnapshotHash(sg); err == nil {
			t.Fatal("expected error for +Inf double")
		}
	})
	t.Run("duplicate node id", func(t *testing.T) {
		sg := &Subgraph{Nodes: []*Node{
			{ID: "dup", Kind: KindZone}, {ID: "dup", Kind: KindZone}}}
		if _, err := SnapshotHash(sg); err == nil {
			t.Fatal("expected error for duplicate node_id")
		}
	})
}

func TestNegZeroNormalized(t *testing.T) {
	pos := &Subgraph{Nodes: []*Node{{ID: "z", Kind: KindZone,
		Attrs: map[string]AttrVal{"v": ADouble(0.0)}}}}
	neg := &Subgraph{Nodes: []*Node{{ID: "z", Kind: KindZone,
		Attrs: map[string]AttrVal{"v": ADouble(math.Copysign(0, -1))}}}}
	hp, err := SnapshotHash(pos)
	if err != nil {
		t.Fatal(err)
	}
	hn, err := SnapshotHash(neg)
	if err != nil {
		t.Fatal(err)
	}
	if hp != hn {
		t.Fatal("-0.0 and +0.0 must hash identically")
	}
}

func TestReverseIndex(t *testing.T) {
	ri := NewReverseIndex()
	sgA := &Subgraph{ID: "A", Nodes: []*Node{{ID: "zone:z7"}, {ID: "robot:r1"}}}
	sgB := &Subgraph{ID: "B", Nodes: []*Node{{ID: "zone:z8"}, {ID: "robot:r2"}}}
	ri.Add(sgA)
	ri.Add(sgB)

	if got := ri.Affected("zone:z7"); len(got) != 1 || got[0] != "A" {
		t.Fatalf("Affected(z7) = %v, want [A]", got)
	}
	// shared node visible to both
	sgC := &Subgraph{ID: "C", Nodes: []*Node{{ID: "zone:z7"}}}
	ri.Add(sgC)
	if got := ri.Affected("zone:z7"); len(got) != 2 || got[0] != "A" || got[1] != "C" {
		t.Fatalf("Affected(z7) = %v, want [A C]", got)
	}
	ri.Remove("A")
	if got := ri.Affected("zone:z7"); len(got) != 1 || got[0] != "C" {
		t.Fatalf("after Remove(A): Affected(z7) = %v, want [C]", got)
	}
	if got := ri.Affected("zone:z8", "robot:r2"); len(got) != 1 || got[0] != "B" {
		t.Fatalf("Affected(z8,r2) = %v, want [B]", got)
	}
}

// --- independent reference encoder (test-only, different construction) ---

func refEncodeSubgraph(t *testing.T, sg *Subgraph) []byte {
	t.Helper()
	var out []byte
	out = append(out, []byte("PAILSG")...)
	out = append(out, 0x01)
	out = refU64(out, sg.GraphEpoch)

	type kv struct {
		enc []byte
	}
	nenc := make([]kv, 0, len(sg.Nodes))
	for _, n := range sg.Nodes {
		nenc = append(nenc, kv{refEncodeNode(t, n)})
	}
	sort.Slice(nenc, func(i, j int) bool { return bytes.Compare(nenc[i].enc, nenc[j].enc) < 0 })
	out = refU32(out, uint32(len(nenc)))
	for _, e := range nenc {
		out = append(out, e.enc...)
	}

	eenc := make([][]byte, 0, len(sg.Edges))
	for _, e := range sg.Edges {
		var b []byte
		b = refLP(b, e.From)
		b = append(b, byte(e.Rel))
		b = refLP(b, e.To)
		eenc = append(eenc, b)
	}
	sort.Slice(eenc, func(i, j int) bool { return bytes.Compare(eenc[i], eenc[j]) < 0 })
	out = refU32(out, uint32(len(eenc)))
	for _, e := range eenc {
		out = append(out, e...)
	}
	return out
}

func refEncodeNode(t *testing.T, n *Node) []byte {
	t.Helper()
	var b []byte
	b = refLP(b, n.ID)
	b = append(b, byte(n.Kind), byte(n.State))
	b = refU64(b, n.Version)
	// attrs
	keys := make([]string, 0, len(n.Attrs))
	for k := range n.Attrs {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return bytes.Compare(norm.NFC.Bytes([]byte(keys[i])), norm.NFC.Bytes([]byte(keys[j]))) < 0
	})
	b = refU32(b, uint32(len(keys)))
	for _, k := range keys {
		b = refLP(b, k)
		v := n.Attrs[k]
		b = append(b, byte(v.Tag))
		switch v.Tag {
		case TagString:
			b = refLP(b, v.S)
		case TagInt64:
			b = refU64(b, uint64(v.I))
		case TagDouble:
			f := v.F
			if f == 0 {
				f = 0
			}
			var buf [8]byte
			binary.BigEndian.PutUint64(buf[:], math.Float64bits(f))
			b = append(b, buf[:]...)
		case TagBool:
			if v.B {
				b = append(b, 1)
			} else {
				b = append(b, 0)
			}
		}
	}
	return b
}

func refLP(b []byte, s string) []byte {
	nb := norm.NFC.Bytes([]byte(s))
	b = refU32(b, uint32(len(nb)))
	return append(b, nb...)
}

func refU32(b []byte, v uint32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	return append(b, buf[:]...)
}

func refU64(b []byte, v uint64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	return append(b, buf[:]...)
}
