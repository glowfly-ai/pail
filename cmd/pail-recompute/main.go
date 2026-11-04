// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// Command pail-recompute recomputes, from files and offline, the world-slice
// hash that every PAIL action token carries in its signed bytes
// (ActionToken.subgraph_snapshot_hash, field 61), and reports whether the
// value the issuer signed is the value the specification yields.
//
// It is a separate Go module that shares no code with the issuer. Everything it
// does — reading the ledger segments, decoding the signed token, compiling the
// site declaration, replaying context events, selecting the slice, encoding
// and hashing it — is implemented here from spec/SUBGRAPH_HASH.md. Agreement
// between this tool and the issuer is evidence; a verifier built from the
// issuer's own packages would agree by identity.
//
// Three exit states, deliberately not two:
//
//	0  verified — every token that could be recomputed carries the hash the
//	   specification yields (and at least one could be)
//	1  finding  — a token's signed hash, or the ledger's own bytes, contradict
//	   the recomputation
//	2  cannot   — unreadable input, a site file that is not the one the issuer
//	   loaded, a world state the ledger does not let this tool rebuild
//
// The third state exists because "we never checked" must not reach a caller
// wearing the same face as "we checked and it was fine".
//
//	pail-recompute vectors -dir spec/subgraph-vectors
//	pail-recompute ledger  -site site.yaml -journal DIR [-chain ID] [-v]
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/text/unicode/norm"
	"gopkg.in/yaml.v3"
)

const (
	exitVerified = 0
	exitFinding  = 1
	exitCannot   = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func usage(w *os.File) int {
	fmt.Fprint(w, `pail-recompute — recompute the world-slice hash signed into PAIL tokens

  pail-recompute vectors -dir DIR
      re-derive every case of the frozen set (spec/subgraph-vectors) and check
      the manifest; the self-test of this tool against the specification
  pail-recompute ledger -site F -journal DIR [-chain ID] [-v]
      walk a blackbox journal, rebuild the world at each token's issuance epoch
      from the site declaration and the GRAPH_MUTATION records, and compare the
      recomputed hash with the token's signed field 61

exit 0 verified · 1 finding · 2 cannot verify
`)
	return exitCannot
}

func run(args []string, out, errw *os.File) int {
	if len(args) == 0 {
		return usage(errw)
	}
	switch args[0] {
	case "vectors":
		fs := flag.NewFlagSet("vectors", flag.ContinueOnError)
		fs.SetOutput(errw)
		dir := fs.String("dir", "", "vector set directory")
		if err := fs.Parse(args[1:]); err != nil || *dir == "" || fs.NArg() != 0 {
			return usage(errw)
		}
		return runVectors(*dir, out)
	case "ledger":
		fs := flag.NewFlagSet("ledger", flag.ContinueOnError)
		fs.SetOutput(errw)
		site := fs.String("site", "", "site declaration (YAML) the issuer loaded")
		journal := fs.String("journal", "", "blackbox journal directory (pail_blackbox.NNNNNNNN.seg)")
		chain := fs.String("chain", "", "only tokens of this chain id")
		verbose := fs.Bool("v", false, "print every token line")
		if err := fs.Parse(args[1:]); err != nil || *site == "" || *journal == "" || fs.NArg() != 0 {
			return usage(errw)
		}
		return runLedger(*site, *journal, *chain, *verbose, out)
	}
	return usage(errw)
}

// ───────────────────────────────────────────── data model (spec section 2)

const (
	kindAgent      = 1
	kindExecutor   = 2
	kindObject     = 3
	kindZone       = 4
	kindHuman      = 5
	kindConstraint = 6

	stateActive      = 0
	stateMaintenance = 1
	stateCordoned    = 2

	relLocatedIn  = 1
	relTargets    = 2
	relConstrains = 3
	relOperates   = 4
	relOccupies   = 5

	tagString = 0x01
	tagInt64  = 0x02
	tagDouble = 0x03
	tagBool   = 0x04
)

type attr struct {
	tag int
	s   string
	i   int64
	f   float64
	b   bool
}

type node struct {
	id      string
	kind    int
	state   int
	version uint64
	attrs   map[string]attr
}

type edge struct {
	from string
	rel  int
	to   string
}

type graph struct {
	epoch uint64
	nodes map[string]*node
	edges []edge
}

func newGraph() *graph { return &graph{nodes: map[string]*node{}} }

func (g *graph) clone() *graph {
	c := &graph{epoch: g.epoch, nodes: make(map[string]*node, len(g.nodes)), edges: append([]edge(nil), g.edges...)}
	for id, n := range g.nodes {
		c.nodes[id] = n.clone()
	}
	return c
}

func (n *node) clone() *node {
	c := &node{id: n.id, kind: n.kind, state: n.state, version: n.version, attrs: map[string]attr{}}
	for k, v := range n.attrs {
		c.attrs[k] = v
	}
	return c
}

type subgraph struct {
	epoch uint64
	nodes []*node
	edges []edge
}

// ───────────────────────────────────────────── canonical encoding (section 3)

var (
	errKindUnspecified = errors.New("kind_unspecified")
	errNonFiniteDouble = errors.New("non_finite_double")
	errDuplicateNodeID = errors.New("duplicate_node_id")
	errUnknownAttrTag  = errors.New("unknown_attr_tag")
)

func nfc(s string) []byte { return norm.NFC.Bytes([]byte(s)) }

func lp(b *bytes.Buffer, s string) {
	nb := nfc(s)
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(nb)))
	b.Write(l[:])
	b.Write(nb)
}

func u32(b *bytes.Buffer, v uint32) {
	var x [4]byte
	binary.BigEndian.PutUint32(x[:], v)
	b.Write(x[:])
}

func u64(b *bytes.Buffer, v uint64) {
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], v)
	b.Write(x[:])
}

func encodeNode(n *node) ([]byte, error) {
	if n.kind == 0 {
		return nil, errKindUnspecified
	}
	var b bytes.Buffer
	lp(&b, n.id)
	b.WriteByte(byte(n.kind))
	b.WriteByte(byte(n.state))
	u64(&b, n.version)
	keys := make([]string, 0, len(n.attrs))
	for k := range n.attrs {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return bytes.Compare(nfc(keys[i]), nfc(keys[j])) < 0 })
	u32(&b, uint32(len(keys)))
	for _, k := range keys {
		v := n.attrs[k]
		lp(&b, k)
		b.WriteByte(byte(v.tag))
		switch v.tag {
		case tagString:
			lp(&b, v.s)
		case tagInt64:
			u64(&b, uint64(v.i))
		case tagDouble:
			if math.IsNaN(v.f) || math.IsInf(v.f, 0) {
				return nil, errNonFiniteDouble
			}
			f := v.f
			if f == 0 {
				f = 0
			}
			u64(&b, math.Float64bits(f))
		case tagBool:
			if v.b {
				b.WriteByte(1)
			} else {
				b.WriteByte(0)
			}
		default:
			return nil, errUnknownAttrTag
		}
	}
	return b.Bytes(), nil
}

func encodeEdge(e edge) []byte {
	var b bytes.Buffer
	lp(&b, e.from)
	b.WriteByte(byte(e.rel))
	lp(&b, e.to)
	return b.Bytes()
}

func canonical(sg *subgraph, magic string) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(magic)
	b.WriteByte(0x01)
	u64(&b, sg.epoch)
	encs := make([][]byte, 0, len(sg.nodes))
	ids := map[string]bool{}
	for _, n := range sg.nodes {
		e, err := encodeNode(n)
		if err != nil {
			return nil, err
		}
		encs = append(encs, e)
		k := string(nfc(n.id))
		if ids[k] {
			return nil, errDuplicateNodeID
		}
		ids[k] = true
	}
	sort.Slice(encs, func(i, j int) bool { return bytes.Compare(encs[i], encs[j]) < 0 })
	u32(&b, uint32(len(encs)))
	for _, e := range encs {
		b.Write(e)
	}
	eencs := make([][]byte, 0, len(sg.edges))
	for _, e := range sg.edges {
		eencs = append(eencs, encodeEdge(e))
	}
	sort.Slice(eencs, func(i, j int) bool { return bytes.Compare(eencs[i], eencs[j]) < 0 })
	u32(&b, uint32(len(eencs)))
	for _, e := range eencs {
		b.Write(e)
	}
	return b.Bytes(), nil
}

func snapshotHash(sg *subgraph) ([32]byte, error) {
	b, err := canonical(sg, "PAILSG")
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// ───────────────────────────────────────────── selection (section 5)

func selectSlice(g *graph, robotID, targetObjectID string) *subgraph {
	agent := "robot:" + robotID
	picked := map[string]*node{}
	order := []string{}
	var edges []edge
	add := func(id string) {
		if n, ok := g.nodes[id]; ok {
			if _, done := picked[id]; !done {
				picked[id] = n.clone()
				order = append(order, id)
			}
		}
	}
	add(agent)
	for _, e := range g.edges {
		if e.from == agent && (e.rel == relLocatedIn || e.rel == relOperates) {
			add(e.to)
			edges = append(edges, e)
		}
	}
	zones := map[string]bool{}
	for id, n := range picked {
		if n.kind == kindZone {
			zones[id] = true
		}
	}
	for _, e := range g.edges {
		if e.rel == relConstrains && (e.to == agent || zones[e.to]) {
			add(e.from)
			edges = append(edges, e)
		}
	}
	for _, e := range g.edges {
		if e.rel == relLocatedIn && zones[e.to] {
			if n, ok := g.nodes[e.from]; ok && n.kind == kindHuman {
				add(e.from)
				edges = append(edges, e)
			}
		}
	}
	if targetObjectID != "" {
		obj := "object:" + targetObjectID
		add(obj)
		edges = append(edges, edge{from: agent, rel: relTargets, to: obj})
		for _, e := range g.edges {
			if e.from == obj && e.rel == relLocatedIn {
				add(e.to)
				edges = append(edges, e)
			}
		}
	}
	sg := &subgraph{epoch: g.epoch, edges: edges}
	for _, id := range order {
		sg.nodes = append(sg.nodes, picked[id])
	}
	return sg
}

func evaluate(sg *subgraph) (bool, string) {
	for _, n := range sg.nodes {
		if n.kind == kindAgent {
			if n.state == stateMaintenance {
				return true, "NODE_MAINTENANCE"
			}
			if n.state == stateCordoned {
				return true, "NODE_CORDONED"
			}
		}
	}
	zones := map[string]bool{}
	byID := map[string]*node{}
	for _, n := range sg.nodes {
		byID[n.id] = n
		if n.kind == kindZone {
			zones[n.id] = true
		}
	}
	for _, e := range sg.edges {
		if e.rel == relLocatedIn && zones[e.to] {
			if n, ok := byID[e.from]; ok && n.kind == kindHuman {
				return true, "HUMAN_IN_ZONE"
			}
		}
	}
	return false, ""
}

// ───────────────────────────────────────────── ephemeral world (section 6.3)

func ephemeralWorld(robotID, targetObjectID string, lin, ang, dur float64) *graph {
	g := newGraph()
	agent := "robot:" + robotID
	g.nodes[agent] = &node{id: agent, kind: kindAgent, version: 1, attrs: map[string]attr{}}
	if lin > 0 || ang > 0 || dur > 0 {
		cid := "constraint:speed@" + robotID
		attrs := map[string]attr{}
		if lin > 0 {
			attrs["max_linear_speed_mps"] = attr{tag: tagDouble, f: lin}
		}
		if ang > 0 {
			attrs["max_angular_speed_rps"] = attr{tag: tagDouble, f: ang}
		}
		if dur > 0 {
			attrs["max_duration_sec"] = attr{tag: tagDouble, f: dur}
		}
		g.nodes[cid] = &node{id: cid, kind: kindConstraint, version: 1, attrs: attrs}
		g.edges = append(g.edges, edge{from: cid, rel: relConstrains, to: agent})
	}
	if targetObjectID != "" {
		oid := "object:" + targetObjectID
		g.nodes[oid] = &node{id: oid, kind: kindObject, version: 1, attrs: map[string]attr{}}
	}
	return g
}

// ───────────────────────────────────────────── site compiler (section 6.1)

type compileError struct{ reason, detail string }

func (e *compileError) Error() string { return e.reason + ": " + e.detail }

func cerr(reason, format string, a ...any) error {
	return &compileError{reason: reason, detail: fmt.Sprintf(format, a...)}
}

func asMap(v any, what string) (map[string]any, error) {
	switch t := v.(type) {
	case map[string]any:
		return t, nil
	case map[any]any:
		out := map[string]any{}
		for k, val := range t {
			out[fmt.Sprint(k)] = val
		}
		return out, nil
	case nil:
		return map[string]any{}, nil
	}
	return nil, cerr("unknown_key", "%s is not a mapping", what)
}

func asList(v any, what string) ([]any, error) {
	if v == nil {
		return nil, nil
	}
	l, ok := v.([]any)
	if !ok {
		return nil, cerr("unknown_key", "%s is not a list", what)
	}
	return l, nil
}

func strField(m map[string]any, key string) string {
	if v, ok := m[key]; ok && v != nil {
		return fmt.Sprint(v)
	}
	return ""
}

func strList(m map[string]any, key string) ([]string, error) {
	l, err := asList(m[key], key)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(l))
	for _, x := range l {
		out = append(out, fmt.Sprint(x))
	}
	return out, nil
}

func onlyKeys(m map[string]any, what string, allowed ...string) error {
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	var extra []string
	for k := range m {
		if !ok[k] {
			extra = append(extra, k)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return cerr("unknown_key", "%s: unexpected %v", what, extra)
	}
	return nil
}

// compileSite builds the epoch-0 world from a site declaration (the generic
// YAML/JSON value), following spec/SUBGRAPH_HASH.md section 6.1.
func compileSite(doc any) (*graph, error) {
	site, err := asMap(doc, "document")
	if err != nil {
		return nil, err
	}
	if err := onlyKeys(site, "document", "site", "schema", "zones", "objects", "robots", "constraints", "actions", "policy"); err != nil {
		return nil, err
	}
	if strField(site, "site") == "" {
		return nil, cerr("missing_site", "`site` is required")
	}
	g := newGraph()
	zoneIDs := map[string]bool{}
	objectIDs := map[string]bool{}
	var zoneOrder, objectOrder []string

	zones, err := asList(site["zones"], "zones")
	if err != nil {
		return nil, err
	}
	var zoneMaps []map[string]any
	for _, z := range zones {
		zm, err := asMap(z, "zone")
		if err != nil {
			return nil, err
		}
		if err := onlyKeys(zm, "zone", "id", "type", "adjacent"); err != nil {
			return nil, err
		}
		id := strField(zm, "id")
		if id == "" {
			return nil, cerr("unknown_key", "zone with empty id")
		}
		if zoneIDs[id] {
			return nil, cerr("duplicate_id", "zone %q", id)
		}
		zoneIDs[id] = true
		zoneOrder = append(zoneOrder, id)
		attrs := map[string]attr{}
		if t := strField(zm, "type"); t != "" {
			attrs["type"] = attr{tag: tagString, s: t}
		}
		adj, err := strList(zm, "adjacent")
		if err != nil {
			return nil, err
		}
		if len(adj) > 0 {
			sort.Strings(adj)
			attrs["adjacent"] = attr{tag: tagString, s: strings.Join(adj, ",")}
		}
		g.nodes["zone:"+id] = &node{id: "zone:" + id, kind: kindZone, attrs: attrs}
		zoneMaps = append(zoneMaps, zm)
	}
	for _, zm := range zoneMaps {
		adj, _ := strList(zm, "adjacent")
		for _, a := range adj {
			if !zoneIDs[a] {
				return nil, cerr("dangling_reference", "zone %q adjacent to undeclared zone %q", strField(zm, "id"), a)
			}
		}
	}
	objects, err := asList(site["objects"], "objects")
	if err != nil {
		return nil, err
	}
	for _, o := range objects {
		om, err := asMap(o, "object")
		if err != nil {
			return nil, err
		}
		if err := onlyKeys(om, "object", "id", "at"); err != nil {
			return nil, err
		}
		id := strField(om, "id")
		if id == "" {
			return nil, cerr("unknown_key", "object with empty id")
		}
		if objectIDs[id] {
			return nil, cerr("duplicate_id", "object %q", id)
		}
		objectIDs[id] = true
		objectOrder = append(objectOrder, id)
		g.nodes["object:"+id] = &node{id: "object:" + id, kind: kindObject, attrs: map[string]attr{}}
		if at := strField(om, "at"); at != "" {
			if !zoneIDs[at] {
				return nil, cerr("dangling_reference", "object %q at undeclared zone %q", id, at)
			}
			g.edges = append(g.edges, edge{from: "object:" + id, rel: relLocatedIn, to: "zone:" + at})
		}
	}
	robots, err := asList(site["robots"], "robots")
	if err != nil {
		return nil, err
	}
	seenRobot := map[string]bool{}
	for _, r := range robots {
		rm, err := asMap(r, "robot")
		if err != nil {
			return nil, err
		}
		if err := onlyKeys(rm, "robot", "id", "capabilities", "schema", "home", "robot_class"); err != nil {
			return nil, err
		}
		id := strField(rm, "id")
		if id == "" {
			return nil, cerr("unknown_key", "robot with empty id")
		}
		if seenRobot[id] {
			return nil, cerr("duplicate_id", "robot %q", id)
		}
		seenRobot[id] = true
		attrs := map[string]attr{}
		caps, err := strList(rm, "capabilities")
		if err != nil {
			return nil, err
		}
		if len(caps) > 0 {
			sort.Strings(caps)
			attrs["capabilities"] = attr{tag: tagString, s: strings.Join(caps, ",")}
		}
		if s := strField(rm, "schema"); s != "" {
			attrs["schema"] = attr{tag: tagString, s: s}
		}
		if rc := strField(rm, "robot_class"); rc != "" {
			attrs["robot_class"] = attr{tag: tagString, s: rc}
		}
		rid, xid := "robot:"+id, "executor:"+id
		g.nodes[rid] = &node{id: rid, kind: kindAgent, attrs: attrs}
		g.nodes[xid] = &node{id: xid, kind: kindExecutor, attrs: map[string]attr{}}
		g.edges = append(g.edges, edge{from: rid, rel: relOperates, to: xid})
		if home := strField(rm, "home"); home != "" {
			if !zoneIDs[home] {
				return nil, cerr("dangling_reference", "robot %q home is undeclared zone %q", id, home)
			}
			g.edges = append(g.edges, edge{from: rid, rel: relLocatedIn, to: "zone:" + home})
		}
	}
	sortedZones := append([]string(nil), zoneOrder...)
	sort.Strings(sortedZones)
	sortedObjects := append([]string(nil), objectOrder...)
	sort.Strings(sortedObjects)
	constraints, err := asList(site["constraints"], "constraints")
	if err != nil {
		return nil, err
	}
	for i, c := range constraints {
		cm, err := asMap(c, "constraint")
		if err != nil {
			return nil, err
		}
		t := strField(cm, "type")
		switch t {
		case "human_exclusion":
			if err := onlyKeys(cm, "human_exclusion", "type", "zone"); err != nil {
				return nil, &compileError{"unexpected_field", err.Error()}
			}
			z := strField(cm, "zone")
			if z == "" {
				return nil, cerr("unexpected_field", "human_exclusion without zone")
			}
			targets := []string{z}
			if z == "*" {
				targets = sortedZones
			}
			for _, zz := range targets {
				if !zoneIDs[zz] {
					return nil, cerr("dangling_reference", "human_exclusion references undeclared zone %q", zz)
				}
				cid := "constraint:human_excl@" + zz
				g.nodes[cid] = &node{id: cid, kind: kindConstraint, attrs: map[string]attr{"ctype": {tag: tagString, s: "human_exclusion"}}}
				g.edges = append(g.edges, edge{from: cid, rel: relConstrains, to: "zone:" + zz})
			}
		case "exclusive":
			if err := onlyKeys(cm, "exclusive", "type", "object"); err != nil {
				return nil, &compileError{"unexpected_field", err.Error()}
			}
			o := strField(cm, "object")
			if o == "" {
				return nil, cerr("unexpected_field", "exclusive without object")
			}
			targets := []string{o}
			if o == "*" {
				targets = sortedObjects
			}
			for _, oo := range targets {
				if !objectIDs[oo] {
					return nil, cerr("dangling_reference", "exclusive references undeclared object %q", oo)
				}
				g.nodes["object:"+oo].attrs["exclusive"] = attr{tag: tagBool, b: true}
			}
		case "speed_limit":
			return nil, cerr("speed_limit", "constraint #%d: speed_limit is not accepted in the site model", i)
		case "":
			return nil, cerr("unknown_constraint_type", "constraint #%d has no type", i)
		default:
			return nil, cerr("unknown_constraint_type", "constraint #%d: %q", i, t)
		}
	}
	return g, nil
}

// ───────────────────────────────────────────── event replay (section 6.2)

type mutation struct {
	kind, eventNodeID, arg string
}

var errUnknownNode = errors.New("unknown node")

// applyEvent mutates g in place and returns the journal triple.
func applyEvent(g *graph, m mutation) (oldV, newV, epoch uint64, err error) {
	switch m.kind {
	case "MAINTENANCE_ON", "MAINTENANCE_OFF", "CORDON_ON", "CORDON_OFF":
		n, ok := g.nodes[m.eventNodeID]
		if !ok {
			return 0, 0, g.epoch, errUnknownNode
		}
		oldV = n.version
		n.state = map[string]int{"MAINTENANCE_ON": stateMaintenance, "MAINTENANCE_OFF": stateActive, "CORDON_ON": stateCordoned, "CORDON_OFF": stateActive}[m.kind]
		n.version++
		g.epoch++
		return oldV, n.version, g.epoch, nil
	case "HUMAN_ENTER":
		if !strings.HasPrefix(m.eventNodeID, "zone:") {
			return 0, 0, g.epoch, errUnknownNode
		}
		if _, ok := g.nodes[m.eventNodeID]; !ok {
			return 0, 0, g.epoch, errUnknownNode
		}
		hid := "human:" + m.arg
		n, ok := g.nodes[hid]
		if !ok {
			n = &node{id: hid, kind: kindHuman, attrs: map[string]attr{}}
			g.nodes[hid] = n
		} else {
			oldV = n.version
			n.version++
		}
		e := edge{from: hid, rel: relLocatedIn, to: m.eventNodeID}
		present := false
		for _, x := range g.edges {
			if x == e {
				present = true
				break
			}
		}
		if !present {
			g.edges = append(g.edges, e)
		}
		g.epoch++
		return oldV, n.version, g.epoch, nil
	case "HUMAN_LEAVE":
		hid := "human:" + m.arg
		n, ok := g.nodes[hid]
		if !ok || !strings.HasPrefix(m.eventNodeID, "zone:") {
			return 0, 0, g.epoch, errUnknownNode
		}
		oldV = n.version
		kept := g.edges[:0:0]
		still := false
		for _, x := range g.edges {
			if x.from == hid && x.rel == relLocatedIn && x.to == m.eventNodeID {
				continue
			}
			if x.from == hid && x.rel == relLocatedIn {
				still = true
			}
			kept = append(kept, x)
		}
		g.edges = kept
		if still {
			n.version++
			newV = n.version
		} else {
			delete(g.nodes, hid)
			newV = oldV + 1
		}
		g.epoch++
		return oldV, newV, g.epoch, nil
	case "OBJECT_MOVE":
		n, ok := g.nodes[m.eventNodeID]
		zid := "zone:" + m.arg
		if !ok || !strings.HasPrefix(m.eventNodeID, "object:") {
			return 0, 0, g.epoch, errUnknownNode
		}
		if _, ok := g.nodes[zid]; !ok {
			return 0, 0, g.epoch, errUnknownNode
		}
		oldV = n.version
		kept := g.edges[:0:0]
		for _, x := range g.edges {
			if x.from == m.eventNodeID && x.rel == relLocatedIn {
				continue
			}
			kept = append(kept, x)
		}
		g.edges = append(kept, edge{from: m.eventNodeID, rel: relLocatedIn, to: zid})
		n.version++
		g.epoch++
		return oldV, n.version, g.epoch, nil
	}
	return 0, 0, g.epoch, fmt.Errorf("unknown event kind %q", m.kind)
}

func graphAsSubgraph(g *graph) *subgraph {
	sg := &subgraph{epoch: g.epoch, edges: append([]edge(nil), g.edges...)}
	for _, n := range g.nodes {
		sg.nodes = append(sg.nodes, n)
	}
	return sg
}

// ───────────────────────────────────────────── JSON vector shapes (section 7)

type jAttr struct {
	T   string `json:"t"`
	V   any    `json:"v"`
	Tag int    `json:"tag"`
}

type jNode struct {
	ID      string           `json:"id"`
	Kind    int              `json:"kind"`
	State   int              `json:"state"`
	Version uint64           `json:"version"`
	Attrs   map[string]jAttr `json:"attrs"`
}

type jEdge struct {
	From string `json:"from"`
	Rel  int    `json:"rel"`
	To   string `json:"to"`
}

type jSubgraph struct {
	Epoch uint64  `json:"epoch"`
	Nodes []jNode `json:"nodes"`
	Edges []jEdge `json:"edges"`
}

func fromJSONSubgraph(j *jSubgraph) (*subgraph, error) {
	sg := &subgraph{epoch: j.Epoch}
	for _, n := range j.Nodes {
		nn := &node{id: n.ID, kind: n.Kind, state: n.State, version: n.Version, attrs: map[string]attr{}}
		for k, a := range n.Attrs {
			switch a.T {
			case "string":
				nn.attrs[k] = attr{tag: tagString, s: fmt.Sprint(a.V)}
			case "int64":
				var i int64
				switch v := a.V.(type) {
				case float64:
					i = int64(v)
				case json.Number:
					i, _ = v.Int64()
				default:
					i, _ = strconv.ParseInt(fmt.Sprint(v), 10, 64)
				}
				nn.attrs[k] = attr{tag: tagInt64, i: i}
			case "double":
				f, err := strconv.ParseFloat(fmt.Sprint(a.V), 64)
				if err != nil {
					return nil, fmt.Errorf("double attribute %q: %v", k, err)
				}
				nn.attrs[k] = attr{tag: tagDouble, f: f}
			case "bool":
				b, _ := a.V.(bool)
				nn.attrs[k] = attr{tag: tagBool, b: b}
			default:
				nn.attrs[k] = attr{tag: a.Tag}
			}
		}
		sg.nodes = append(sg.nodes, nn)
	}
	for _, e := range j.Edges {
		sg.edges = append(sg.edges, edge{from: e.From, rel: e.Rel, to: e.To})
	}
	return sg, nil
}

func graphFromSubgraph(sg *subgraph) *graph {
	g := newGraph()
	g.epoch = sg.epoch
	for _, n := range sg.nodes {
		g.nodes[n.id] = n.clone()
	}
	g.edges = append([]edge(nil), sg.edges...)
	return g
}

func decodeJSONNumbers(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	return dec.Decode(v)
}

// ───────────────────────────────────────────── vectors self-test

func runVectors(dir string, out *os.File) int {
	man, err := os.ReadFile(filepath.Join(dir, "MANIFEST.sha256"))
	if err != nil {
		fmt.Fprintf(out, "cannot: read manifest: %v\n", err)
		return exitCannot
	}
	listed := map[string]string{}
	var setLine string
	for _, ln := range strings.Split(string(man), "\n") {
		if strings.HasPrefix(ln, "#") || strings.TrimSpace(ln) == "" {
			continue
		}
		if strings.HasPrefix(ln, "set_sha256") {
			f := strings.Fields(ln)
			if len(f) > 1 {
				setLine = f[1]
			}
			continue
		}
		parts := strings.SplitN(ln, "  ", 2)
		if len(parts) == 2 {
			listed[parts[1]] = parts[0]
		}
	}
	findings := 0
	files := map[string][]byte{}
	for _, name := range []string{"cases.json", "selection.json", "world.json"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			fmt.Fprintf(out, "cannot: read %s: %v\n", name, err)
			return exitCannot
		}
		files[name] = b
		h := sha256.Sum256(b)
		if listed[name] != hex.EncodeToString(h[:]) {
			fmt.Fprintf(out, "finding: %s hash differs from the manifest\n", name)
			findings++
		}
	}
	names := make([]string, 0, len(listed))
	for n := range listed {
		names = append(names, n)
	}
	sort.Strings(names)
	var body strings.Builder
	for _, n := range names {
		fmt.Fprintf(&body, "%s  %s\n", listed[n], n)
	}
	sh := sha256.Sum256([]byte(body.String()))
	if setLine != hex.EncodeToString(sh[:]) {
		fmt.Fprintf(out, "finding: set_sha256 differs from the manifest rows\n")
		findings++
	}

	// cases.json
	var cases struct {
		Format        string `json:"format"`
		FormatVersion int    `json:"format_version"`
		Cases         []struct {
			ID           string     `json:"id"`
			Expect       string     `json:"expect"`
			Reason       string     `json:"reason"`
			Subgraph     *jSubgraph `json:"subgraph"`
			CanonicalHex string     `json:"canonical_hex"`
			SHA256       string     `json:"sha256"`
		} `json:"cases"`
	}
	if err := decodeJSONNumbers(files["cases.json"], &cases); err != nil {
		fmt.Fprintf(out, "cannot: cases.json: %v\n", err)
		return exitCannot
	}
	if cases.Format != "PAILSG" || cases.FormatVersion != 1 {
		fmt.Fprintf(out, "cannot: cases.json declares format %s v%d; this tool implements PAILSG v1\n", cases.Format, cases.FormatVersion)
		return exitCannot
	}
	encOK, rejOK := 0, 0
	for _, c := range cases.Cases {
		sg, err := fromJSONSubgraph(c.Subgraph)
		if err != nil {
			fmt.Fprintf(out, "finding: %s: %v\n", c.ID, err)
			findings++
			continue
		}
		b, err := canonical(sg, "PAILSG")
		switch c.Expect {
		case "accept":
			if err != nil {
				fmt.Fprintf(out, "finding: %s refused (%v) but the set accepts it\n", c.ID, err)
				findings++
				continue
			}
			h := sha256.Sum256(b)
			if hex.EncodeToString(b) != c.CanonicalHex {
				fmt.Fprintf(out, "finding: %s canonical bytes differ\n", c.ID)
				findings++
				continue
			}
			if hex.EncodeToString(h[:]) != c.SHA256 {
				fmt.Fprintf(out, "finding: %s hash differs\n", c.ID)
				findings++
				continue
			}
			encOK++
		case "reject":
			if err == nil {
				fmt.Fprintf(out, "finding: %s accepted but the set rejects it (%s)\n", c.ID, c.Reason)
				findings++
				continue
			}
			if err.Error() != c.Reason {
				fmt.Fprintf(out, "finding: %s refused for %s, the set says %s\n", c.ID, err.Error(), c.Reason)
				findings++
				continue
			}
			rejOK++
		}
	}

	// selection.json
	var sel struct {
		Cases []struct {
			ID        string `json:"id"`
			Mode      string `json:"mode"`
			Ephemeral *struct {
				RobotID        string  `json:"robot_id"`
				TargetObjectID string  `json:"target_object_id"`
				Lin            float64 `json:"max_linear_speed_mps"`
				Ang            float64 `json:"max_angular_speed_rps"`
				Dur            float64 `json:"max_duration_sec"`
			} `json:"ephemeral"`
			World   *jSubgraph `json:"world"`
			Request struct {
				RobotID        string `json:"robot_id"`
				TargetObjectID string `json:"target_object_id"`
			} `json:"request"`
			Selected struct {
				NodeIDs []string `json:"node_ids"`
				Edges   []jEdge  `json:"edges"`
			} `json:"selected"`
			Evaluate struct {
				Violated bool   `json:"violated"`
				Reason   string `json:"reason"`
			} `json:"evaluate"`
			SHA256 string `json:"sha256"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(files["selection.json"], &sel); err != nil {
		fmt.Fprintf(out, "cannot: selection.json: %v\n", err)
		return exitCannot
	}
	selOK := 0
	for _, c := range sel.Cases {
		var g *graph
		if c.Mode == "ephemeral" && c.Ephemeral != nil {
			g = ephemeralWorld(c.Ephemeral.RobotID, c.Ephemeral.TargetObjectID, c.Ephemeral.Lin, c.Ephemeral.Ang, c.Ephemeral.Dur)
		} else {
			w, err := fromJSONSubgraph(c.World)
			if err != nil {
				fmt.Fprintf(out, "finding: %s: %v\n", c.ID, err)
				findings++
				continue
			}
			g = graphFromSubgraph(w)
		}
		sg := selectSlice(g, c.Request.RobotID, c.Request.TargetObjectID)
		ids := make([]string, 0, len(sg.nodes))
		for _, n := range sg.nodes {
			ids = append(ids, n.id)
		}
		sort.Strings(ids)
		if strings.Join(ids, "\x00") != strings.Join(c.Selected.NodeIDs, "\x00") {
			fmt.Fprintf(out, "finding: %s selected nodes differ: %v vs %v\n", c.ID, ids, c.Selected.NodeIDs)
			findings++
			continue
		}
		v, r := evaluate(sg)
		if v != c.Evaluate.Violated || r != c.Evaluate.Reason {
			fmt.Fprintf(out, "finding: %s evaluation differs\n", c.ID)
			findings++
			continue
		}
		h, err := snapshotHash(sg)
		if err != nil || hex.EncodeToString(h[:]) != c.SHA256 {
			fmt.Fprintf(out, "finding: %s hash differs\n", c.ID)
			findings++
			continue
		}
		selOK++
	}

	// world.json
	var world struct {
		Cases []struct {
			ID     string `json:"id"`
			Expect string `json:"expect"`
			Reason string `json:"reason"`
			Site   any    `json:"site"`
			Events []struct {
				Kind       string `json:"kind"`
				NodeID     string `json:"node_id"`
				Arg        string `json:"arg"`
				Epoch      uint64 `json:"epoch"`
				OldVersion uint64 `json:"old_version"`
				NewVersion uint64 `json:"new_version"`
			} `json:"events"`
			GraphSHA256 string `json:"graph_sha256"`
			Requests    []struct {
				RobotID        string   `json:"robot_id"`
				TargetObjectID string   `json:"target_object_id"`
				NodeIDs        []string `json:"node_ids"`
				SHA256         string   `json:"sha256"`
			} `json:"requests"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(files["world.json"], &world); err != nil {
		fmt.Fprintf(out, "cannot: world.json: %v\n", err)
		return exitCannot
	}
	worldOK := 0
	for _, c := range world.Cases {
		g, err := compileSite(c.Site)
		if c.Expect == "reject" {
			var ce *compileError
			if err == nil {
				fmt.Fprintf(out, "finding: %s compiled but the set rejects it (%s)\n", c.ID, c.Reason)
				findings++
			} else if !errors.As(err, &ce) || ce.reason != c.Reason {
				fmt.Fprintf(out, "finding: %s refused for %v, the set says %s\n", c.ID, err, c.Reason)
				findings++
			} else {
				worldOK++
			}
			continue
		}
		if err != nil {
			fmt.Fprintf(out, "finding: %s compile refused: %v\n", c.ID, err)
			findings++
			continue
		}
		bad := false
		for i, ev := range c.Events {
			o, n, e, err := applyEvent(g, mutation{kind: ev.Kind, eventNodeID: ev.NodeID, arg: ev.Arg})
			if err != nil || o != ev.OldVersion || n != ev.NewVersion || e != ev.Epoch {
				fmt.Fprintf(out, "finding: %s event %d (%s) replay differs\n", c.ID, i, ev.Kind)
				findings++
				bad = true
				break
			}
		}
		if bad {
			continue
		}
		gb, err := canonical(graphAsSubgraph(g), "PAILCG")
		if err != nil {
			fmt.Fprintf(out, "finding: %s world not encodable: %v\n", c.ID, err)
			findings++
			continue
		}
		gh := sha256.Sum256(gb)
		if hex.EncodeToString(gh[:]) != c.GraphSHA256 {
			fmt.Fprintf(out, "finding: %s graph hash differs\n", c.ID)
			findings++
			continue
		}
		for _, rq := range c.Requests {
			sg := selectSlice(g, rq.RobotID, rq.TargetObjectID)
			h, err := snapshotHash(sg)
			if err != nil || hex.EncodeToString(h[:]) != rq.SHA256 {
				fmt.Fprintf(out, "finding: %s request (%s,%s) hash differs\n", c.ID, rq.RobotID, rq.TargetObjectID)
				findings++
				bad = true
			}
		}
		if !bad {
			worldOK++
		}
	}
	fmt.Fprintf(out, "vectors: encoding %d accept %d reject · selection %d · world %d · findings %d\n", encOK, rejOK, selOK, worldOK, findings)
	if findings > 0 {
		return exitFinding
	}
	if encOK == 0 || selOK == 0 || worldOK == 0 {
		fmt.Fprintf(out, "cannot: an empty plane cannot establish agreement\n")
		return exitCannot
	}
	return exitVerified
}

// ───────────────────────────────────────────── ledger segments

type record struct {
	segment uint64
	typ     uint32
	unixMs  uint64
	payload []byte
}

var errChain = errors.New("hash chain broken")

// readJournal walks pail_blackbox.NNNNNNNN.seg files in order, verifying the
// per-record hash chain and the cross-segment tail inheritance as written in
// the format description of the reference reader: header 56 bytes
// (magic PBSG | version u32 | seq u64 | prev tail 32 | created ms u64, little
// endian), then records hdr(version u32 | type u32 | unix_ms u64) |
// payload_len u32 | payload | prev_hash 32 | this_hash 32 with
// this_hash = sha256(hdr | payload | prev_hash) and the first prev_hash of a
// segment = sha256(header). A truncated tail in the newest segment is
// tolerated; anything else is an error.
func readJournal(dir string) ([]record, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		var seq uint64
		if !e.IsDir() {
			if _, err := fmt.Sscanf(e.Name(), "pail_blackbox.%d.seg", &seq); err == nil {
				names = append(names, e.Name())
			}
		}
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no pail_blackbox.*.seg files in %s", dir)
	}
	sort.Strings(names)
	var out []record
	var expectTail [32]byte
	for i, name := range names {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		last := i == len(names)-1
		if len(data) < 56 {
			if last {
				break
			}
			return nil, fmt.Errorf("%s: aborted header mid-history", name)
		}
		hdr := data[:56]
		if string(hdr[:4]) != "PBSG" || binary.LittleEndian.Uint32(hdr[4:8]) != 2 {
			return nil, fmt.Errorf("%s: not a v2 segment", name)
		}
		seq := binary.LittleEndian.Uint64(hdr[8:16])
		if !bytes.Equal(hdr[16:48], expectTail[:]) {
			return nil, fmt.Errorf("%s: %w (segment tail inheritance)", name, errChain)
		}
		prev := sha256.Sum256(hdr)
		off := 56
		for off < len(data) {
			if off+20 > len(data) {
				if last {
					break
				}
				return nil, fmt.Errorf("%s: truncated record header mid-history", name)
			}
			rh := data[off : off+16]
			plen := int(binary.LittleEndian.Uint32(data[off+16 : off+20]))
			end := off + 20 + plen + 64
			if end > len(data) {
				if last {
					break
				}
				return nil, fmt.Errorf("%s: truncated record mid-history", name)
			}
			payload := data[off+20 : off+20+plen]
			prevHash := data[off+20+plen : off+20+plen+32]
			thisHash := data[off+20+plen+32 : end]
			if !bytes.Equal(prevHash, prev[:]) {
				return nil, fmt.Errorf("%s offset %d: %w (prev_hash)", name, off, errChain)
			}
			h := sha256.New()
			h.Write(rh)
			h.Write(payload)
			h.Write(prevHash)
			if !bytes.Equal(h.Sum(nil), thisHash) {
				return nil, fmt.Errorf("%s offset %d: %w (this_hash)", name, off, errChain)
			}
			copy(prev[:], thisHash)
			out = append(out, record{segment: seq, typ: binary.LittleEndian.Uint32(rh[4:8]), unixMs: binary.LittleEndian.Uint64(rh[8:16]), payload: append([]byte(nil), payload...)})
			off = end
		}
		expectTail = prev
	}
	return out, nil
}

// ───────────────────────────────────────────── protobuf wire reader

type pbField struct {
	wire uint8
	num  int
	v    uint64
	b    []byte
}

func pbParse(data []byte) ([]pbField, error) {
	var out []pbField
	for len(data) > 0 {
		key, n := binary.Uvarint(data)
		if n <= 0 {
			return nil, errors.New("bad field key")
		}
		data = data[n:]
		f := pbField{wire: uint8(key & 7), num: int(key >> 3)}
		switch f.wire {
		case 0:
			v, n := binary.Uvarint(data)
			if n <= 0 {
				return nil, errors.New("bad varint")
			}
			f.v = v
			data = data[n:]
		case 1:
			if len(data) < 8 {
				return nil, errors.New("short fixed64")
			}
			f.v = binary.LittleEndian.Uint64(data[:8])
			data = data[8:]
		case 2:
			l, n := binary.Uvarint(data)
			if n <= 0 || uint64(len(data)-n) < l {
				return nil, errors.New("bad length-delimited field")
			}
			f.b = data[n : n+int(l)]
			data = data[n+int(l):]
		case 5:
			if len(data) < 4 {
				return nil, errors.New("short fixed32")
			}
			f.v = uint64(binary.LittleEndian.Uint32(data[:4]))
			data = data[4:]
		default:
			return nil, fmt.Errorf("unsupported wire type %d", f.wire)
		}
		out = append(out, f)
	}
	return out, nil
}

func pbBytes(fs []pbField, num int) []byte {
	for _, f := range fs {
		if f.num == num && f.wire == 2 {
			return f.b
		}
	}
	return nil
}

func pbVarint(fs []pbField, num int) uint64 {
	for _, f := range fs {
		if f.num == num && f.wire == 0 {
			return f.v
		}
	}
	return 0
}

func pbDouble(fs []pbField, num int) float64 {
	for _, f := range fs {
		if f.num == num && f.wire == 1 {
			return math.Float64frombits(f.v)
		}
	}
	return 0
}

// signedTokenView is what this tool reads out of SignedToken.action_token_bytes
// (sdk/proto/pail.proto): the exact bytes the issuer signed, never a
// re-serialization.
type signedTokenView struct {
	tokenID, chainID, robotID, targetObjectID string
	seq                                       uint64
	schema                                    uint64
	snapshot                                  []byte
	lin, ang, dur                             float64
}

func decodeSignedToken(b64 string) (*signedTokenView, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	st, err := pbParse(raw)
	if err != nil {
		return nil, fmt.Errorf("SignedToken: %v", err)
	}
	atb := pbBytes(st, 4)
	if atb == nil {
		return nil, errors.New("SignedToken.action_token_bytes (field 4) absent")
	}
	at, err := pbParse(atb)
	if err != nil {
		return nil, fmt.Errorf("ActionToken: %v", err)
	}
	v := &signedTokenView{
		tokenID:        string(pbBytes(at, 1)),
		chainID:        string(pbBytes(at, 2)),
		seq:            pbVarint(at, 3),
		robotID:        string(pbBytes(at, 10)),
		targetObjectID: string(pbBytes(at, 20)),
		schema:         pbVarint(at, 60),
		snapshot:       pbBytes(at, 61),
	}
	if c := pbBytes(at, 51); c != nil {
		cf, err := pbParse(c)
		if err == nil {
			v.lin, v.ang, v.dur = pbDouble(cf, 1), pbDouble(cf, 2), pbDouble(cf, 3)
		}
	}
	return v, nil
}

// ───────────────────────────────────────────── ledger mode

type tokenIssued struct {
	RobotID        string   `json:"robot_id"`
	ChainID        string   `json:"chain_id"`
	SequenceIndex  int64    `json:"sequence_index"`
	TokenID        string   `json:"token_id"`
	SchemaVersion  uint64   `json:"schema_version"`
	GraphEpoch     uint64   `json:"graph_epoch"`
	NodeRefs       []string `json:"node_refs"`
	SnapshotHex    string   `json:"subgraph_snapshot_hash_hex"`
	SiteModelHash  string   `json:"site_model_hash_hex"`
	SignedTokenB64 string   `json:"signed_token_b64"`
}

type graphMutation struct {
	MutationKind string `json:"mutation_kind"`
	NodeID       string `json:"node_id"`
	EventNodeID  string `json:"event_node_id"`
	Arg          string `json:"arg"`
	Epoch        uint64 `json:"epoch"`
	OldVersion   uint64 `json:"old_version"`
	NewVersion   uint64 `json:"new_version"`
}

type tally struct{ verified, mismatch, cannot int }

func runLedger(sitePath, journalDir, onlyChain string, verbose bool, out *os.File) int {
	siteBytes, err := os.ReadFile(sitePath)
	if err != nil {
		fmt.Fprintf(out, "cannot: read site file: %v\n", err)
		return exitCannot
	}
	sh := sha256.Sum256(siteBytes)
	siteHash := hex.EncodeToString(sh[:])
	var doc any
	if err := yaml.Unmarshal(siteBytes, &doc); err != nil {
		fmt.Fprintf(out, "cannot: site file is not YAML: %v\n", err)
		return exitCannot
	}
	compiled, err := compileSite(doc)
	if err != nil {
		fmt.Fprintf(out, "cannot: site declaration does not compile: %v\n", err)
		return exitCannot
	}
	records, err := readJournal(journalDir)
	if err != nil {
		if errors.Is(err, errChain) {
			fmt.Fprintf(out, "finding: %v\n", err)
			return exitFinding
		}
		fmt.Fprintf(out, "cannot: %v\n", err)
		return exitCannot
	}

	world := compiled.clone()
	worldKnown := true // false once the ledger stopped letting us follow the world
	var t tally
	report := func(status, detail string, ti *tokenIssued) {
		switch status {
		case "VERIFIED":
			t.verified++
		case "MISMATCH":
			t.mismatch++
		default:
			t.cannot++
		}
		if verbose || status != "VERIFIED" {
			fmt.Fprintf(out, "%-8s chain=%s seq=%d token=%s epoch=%d %s\n", status, ti.ChainID, ti.SequenceIndex, ti.TokenID, ti.GraphEpoch, detail)
		}
	}
	for _, r := range records {
		switch r.typ {
		case 50: // GRAPH_MUTATION
			var m graphMutation
			if err := json.Unmarshal(r.payload, &m); err != nil {
				fmt.Fprintf(out, "finding: GRAPH_MUTATION payload is not JSON: %v\n", err)
				return exitFinding
			}
			if m.Epoch == 1 && world.epoch != 0 {
				// The issuer reloaded the site model (epoch restarted at 0).
				world = compiled.clone()
				worldKnown = true
			}
			if !worldKnown {
				continue
			}
			if m.Epoch != world.epoch+1 {
				worldKnown = false // a gap: mutations this ledger does not carry
				continue
			}
			if m.EventNodeID == "" && (m.MutationKind == "HUMAN_ENTER" || m.MutationKind == "HUMAN_LEAVE" || m.MutationKind == "OBJECT_MOVE") {
				worldKnown = false // pre-2026-09-18 record: zone/destination not journaled
				continue
			}
			ev := mutation{kind: m.MutationKind, eventNodeID: m.EventNodeID, arg: m.Arg}
			if ev.eventNodeID == "" {
				ev.eventNodeID = m.NodeID
			}
			o, n, e, err := applyEvent(world, ev)
			if err != nil {
				worldKnown = false
				continue
			}
			if o != m.OldVersion || n != m.NewVersion || e != m.Epoch {
				fmt.Fprintf(out, "finding: GRAPH_MUTATION %s %s replays as (%d,%d,%d) but the ledger says (%d,%d,%d)\n",
					m.MutationKind, m.NodeID, o, n, e, m.OldVersion, m.NewVersion, m.Epoch)
				return exitFinding
			}
		case 10: // TOKEN_ISSUED
			var ti tokenIssued
			if err := json.Unmarshal(r.payload, &ti); err != nil {
				fmt.Fprintf(out, "finding: TOKEN_ISSUED payload is not JSON: %v\n", err)
				return exitFinding
			}
			if onlyChain != "" && ti.ChainID != onlyChain {
				continue
			}
			if ti.SchemaVersion < 3 {
				report("CANNOT", "token schema < 3 carries no world hash", &ti)
				continue
			}
			tok, err := decodeSignedToken(ti.SignedTokenB64)
			if err != nil {
				report("CANNOT", "signed token undecodable: "+err.Error(), &ti)
				continue
			}
			if hex.EncodeToString(tok.snapshot) != ti.SnapshotHex {
				report("MISMATCH", "ledger subgraph_snapshot_hash_hex differs from the signed field 61", &ti)
				continue
			}
			if tok.robotID != ti.RobotID {
				report("MISMATCH", "ledger robot_id differs from the signed token", &ti)
				continue
			}
			var sg *subgraph
			if ti.SiteModelHash == "" {
				// Ephemeral issuance: the world is a function of the token itself.
				sg = selectSlice(ephemeralWorld(tok.robotID, tok.targetObjectID, tok.lin, tok.ang, tok.dur), tok.robotID, tok.targetObjectID)
			} else {
				if ti.SiteModelHash != siteHash {
					report("CANNOT", "issued against site model "+ti.SiteModelHash[:16]+"…, the given file is "+siteHash[:16]+"…", &ti)
					continue
				}
				if !worldKnown {
					report("CANNOT", "world at this epoch cannot be rebuilt from this ledger (gap or pre-2026-09-18 event record)", &ti)
					continue
				}
				if ti.GraphEpoch != world.epoch {
					report("CANNOT", fmt.Sprintf("token epoch %d but replay stands at %d", ti.GraphEpoch, world.epoch), &ti)
					continue
				}
				sg = selectSlice(world, tok.robotID, tok.targetObjectID)
			}
			h, err := snapshotHash(sg)
			if err != nil {
				report("CANNOT", "selected slice not encodable: "+err.Error(), &ti)
				continue
			}
			if !bytes.Equal(h[:], tok.snapshot) {
				report("MISMATCH", "recomputed "+hex.EncodeToString(h[:])+" signed "+hex.EncodeToString(tok.snapshot), &ti)
				continue
			}
			if len(ti.NodeRefs) > 0 {
				refs := make([]string, 0, len(sg.nodes))
				for _, n := range sg.nodes {
					refs = append(refs, n.id+"@"+strconv.FormatUint(n.version, 10))
				}
				sort.Strings(refs)
				want := append([]string(nil), ti.NodeRefs...)
				sort.Strings(want)
				if strings.Join(refs, "\x00") != strings.Join(want, "\x00") {
					report("MISMATCH", "hash agrees but node_refs differ: "+strings.Join(refs, ",")+" vs "+strings.Join(want, ","), &ti)
					continue
				}
			}
			report("VERIFIED", "", &ti)
		}
	}
	fmt.Fprintf(out, "ledger: records %d · verified %d · mismatch %d · cannot %d\n", len(records), t.verified, t.mismatch, t.cannot)
	if t.mismatch > 0 {
		return exitFinding
	}
	if t.verified == 0 {
		fmt.Fprintf(out, "cannot: no token could be recomputed\n")
		return exitCannot
	}
	return exitVerified
}
