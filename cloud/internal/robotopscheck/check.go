// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
// Package robotopscheck validates an offline declared configuration snapshot.
// No live server is instantiated and no token/lease/management API is called.
package robotopscheck

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	cfg "github.com/glowfly/pail/services/internal/config"
	"github.com/glowfly/pail/services/internal/graph"
	"github.com/glowfly/pail/services/internal/grpcauth"
	"github.com/glowfly/pail/services/internal/identity"
	"github.com/glowfly/pail/services/internal/skills"
	ops "github.com/glowfly/pail/services/pkg/robotops"
	"os"
	"path/filepath"
	"time"
)

var Required = []string{"RO-C01", "RO-C02", "RO-C03.static", "RO-C04", "RO-C05", "RO-C07.declared", "RO-C08.declared", "RO-C11.declared"}

type certInfo struct {
	fingerprint string
	valid       bool
}

func certificate(raw []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for len(bytes.TrimSpace(raw)) > 0 {
		b, rest := pem.Decode(raw)
		if b == nil || b.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("public certificate PEM expected")
		}
		c, e := x509.ParseCertificate(b.Bytes)
		if e != nil {
			return nil, fmt.Errorf("invalid public certificate")
		}
		out = append(out, c)
		raw = rest
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty certificate file")
	}
	return out, nil
}
func Check(inv ops.Inventory, m ops.ResourceMap, root string, now time.Time) ops.Report {
	out := ops.NewReport("a_offline_declared/v1", inv.DeploymentID, append([]string(nil), Required...))
	if err := inv.Validate(); err != nil || m.DeploymentID != inv.DeploymentID || m.ValidateMap() != nil {
		out.Add("RO-C01", ops.CannotCheck, "inventory", "schema", "invalid inventory or deployment mismatch", "", "")
		out.Finish()
		return out
	}
	out.Add("RO-C01", ops.Pass, "inventory", "schema", "inventory and resource-map deployment agree", "", "")
	f, err := ops.NewFiles(root, m)
	if err != nil {
		out.Add("RO-C01", ops.CannotCheck, "resources", "root", "config root unavailable", "", "")
		out.Finish()
		return out
	}
	out.RequiredSubjects = map[string][]string{}
	for _, id := range []string{"RO-C03.static", "RO-C04", "RO-C05", "RO-C07.declared", "RO-C08.declared", "RO-C11.declared"} {
		for _, robot := range inv.Robots {
			out.RequiredSubjects[id] = append(out.RequiredSubjects[id], robot.RobotID)
		}
	}
	idx := m.Index()
	add := func(id string, status ops.Status, subject, field, reason string) {
		out.Add(id, status, subject, field, reason, "", "")
	}
	regBytes, e := f.Read(inv.ResourceBindings.Registry, "registry")
	var reg *identity.Registry
	if e != nil {
		add("RO-C02", ops.CannotCheck, "registry", "file", "public registry unavailable")
	} else if reg, e = identity.Parse(regBytes); e != nil {
		add("RO-C02", ops.Fail, "registry", "schema", "official registry parser refused input")
	} else {
		add("RO-C02", ops.Pass, "registry", "schema", "official RG parser accepted")
	}
	siteBytes, e := f.Read(inv.ResourceBindings.SiteModel, "site_model")
	var g *graph.Graph
	var site *graph.SiteModel
	if e != nil {
		add("RO-C04", ops.CannotCheck, "site", "file", "site model unavailable")
	} else if g, site, e = graph.Compile(siteBytes); e != nil {
		add("RO-C04", ops.Fail, "site", "schema", "official site compiler refused input")
	}
	// LoadPolicy owns policy semantics. Feed it a private immutable copy so the
	// inspected input hash and the bytes the official loader sees cannot differ.
	policyBytes, e := f.Read(inv.ResourceBindings.Policy, "policy")
	var pol *cfg.Policy
	if e != nil {
		add("RO-C05", ops.CannotCheck, "policy", "file", "policy unavailable")
	} else {
		temp, er := os.MkdirTemp("", "pail-robotops-policy-")
		if er != nil {
			add("RO-C05", ops.CannotCheck, "policy", "snapshot", "cannot create own temporary snapshot")
		} else {
			defer os.RemoveAll(temp)
			file := filepath.Join(temp, "policy.yaml")
			if er = os.WriteFile(file, policyBytes, 0600); er != nil {
				add("RO-C05", ops.CannotCheck, "policy", "snapshot", "cannot snapshot policy")
			} else if pol, _, er = cfg.LoadPolicy(file); er != nil {
				add("RO-C05", ops.Fail, "policy", "schema", "official policy parser refused input")
			}
		}
	}
	certs := map[string]certInfo{}
	inspectCert := func(ref, rid string) certInfo { return certInfo{} }
	inspectCert = func(ref, rid string) certInfo {
		if c, ok := certs[ref+"|"+rid]; ok {
			return c
		}
		ci := certInfo{}
		defer func() { certs[ref+"|"+rid] = ci }()
		res, er := f.Resource(ref, "certificate")
		if er != nil {
			add("RO-C03.static", ops.CannotCheck, rid, "client_credential_ref", "certificate ref unavailable")
			return ci
		}
		raw, er := f.Read(ref, "certificate")
		if er != nil {
			add("RO-C03.static", ops.CannotCheck, rid, "certificate", "public certificate unavailable")
			return ci
		}
		cs, er := certificate(raw)
		if er != nil || cs[0].IsCA {
			add("RO-C03.static", ops.Fail, rid, "certificate", "client leaf required; no key material accepted")
			return ci
		}
		hash := sha256.Sum256(cs[0].Raw)
		ci.fingerprint = hex.EncodeToString(hash[:])
		caRaw, er := f.Read(res.CARef, "ca_certificate")
		if er != nil {
			add("RO-C03.static", ops.CannotCheck, rid, "ca_ref", "CA ref unavailable")
			return ci
		}
		cas, er := certificate(caRaw)
		if er != nil {
			add("RO-C03.static", ops.Fail, rid, "ca_ref", "invalid public CA bundle")
			return ci
		}
		roots := x509.NewCertPool()
		for _, ca := range cas {
			roots.AddCert(ca)
		}
		inter := x509.NewCertPool()
		for _, c := range cs[1:] {
			inter.AddCert(c)
		}
		if _, er = cs[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); er != nil {
			add("RO-C03.static", ops.Fail, rid, "certificate", "client chain, purpose or validity refused")
			return ci
		}
		if reg == nil {
			add("RO-C03.static", ops.CannotCheck, rid, "registry", "cannot bind without valid registry")
			return ci
		}
		binding := reg.Bind(grpcauth.CallerMTLS, ci.fingerprint, rid)
		if binding.Verdict != identity.Bound {
			out.Add("RO-C03.static", ops.Fail, rid, "registry", "leaf not bound to this robot", rid, binding.Verdict.String()+":"+binding.Reason)
			return ci
		}
		ci.valid = true
		out.Add("RO-C03.static", ops.Pass, rid, "certificate", "public chain and registry binding; private-key possession NOT observed", "", ci.fingerprint)
		return ci
	}
	classes, dirErr := f.SkillClasses(inv.ResourceBindings.Skills)
	if dirErr != nil {
		add("RO-C05", ops.CannotCheck, "skills_directory", "skills", "all registry files could not be enumerated")
	} else {
		for _, class := range classes {
			raw, err := f.ReadSkill(inv.ResourceBindings.Skills, class)
			if err != nil {
				add("RO-C05", ops.CannotCheck, "skills_directory", "skills", "class registry unavailable")
				continue
			}
			if _, err = skills.Parse(raw, class); err != nil {
				add("RO-C05", ops.Fail, "skills_directory", "skills", "unused or selected class registry invalid")
			}
		}
	}
	groups := map[string]string{}
	for _, r := range inv.Robots {
		inspectCert(r.ClientCredentialRef, r.RobotID)
		class, cok := idx[r.ClassRef]
		home, hok := idx[r.HomeRef]
		if site == nil || g == nil {
			add("RO-C04", ops.CannotCheck, r.RobotID, "site", "site semantics unavailable")
		} else if !cok || class.Kind != "class" || !hok || home.Kind != "zone" {
			add("RO-C04", ops.CannotCheck, r.RobotID, "class_ref/home_ref", "class or home declaration unavailable")
		} else {
			located := false
			for _, edge := range g.Edges {
				if edge.From == "robot:"+r.RobotID && edge.To == "zone:"+home.Value && edge.Rel == graph.RelLocatedIn {
					located = true
				}
			}
			if site.RobotClass[r.RobotID] != class.Value || !located {
				add("RO-C04", ops.Fail, r.RobotID, "site", "robot class or home differs from declared site")
			} else {
				add("RO-C04", ops.Pass, r.RobotID, "site", "official graph matches class and home")
			}
		}
		if !cok || class.Kind != "class" || !hok || home.Kind != "zone" || pol == nil {
			add("RO-C05", ops.CannotCheck, r.RobotID, "skills", "class/home/policy unavailable")
		} else {
			raw, er := f.ReadSkill(inv.ResourceBindings.Skills, class.Value)
			if er != nil {
				add("RO-C05", ops.CannotCheck, r.RobotID, "skills", "declared class registry unavailable")
			} else if sr, er := skills.Parse(raw, class.Value); er != nil {
				add("RO-C05", ops.Fail, r.RobotID, "skills", "official skill parser refused input")
			} else {
				req, ok := idx[r.RequesterRef]
				if !ok || req.Kind != "requester" || len(req.Skills) == 0 {
					add("RO-C05", ops.CannotCheck, r.RobotID, "requester_ref", "explicit requested skill list unavailable")
				} else {
					valid := true
					for _, name := range req.Skills {
						skill, ok := sr.Lookup(name)
						if !ok {
							valid = false
							continue
						}
						_, missing := pol.Guardrails.Envelope(skill.Envelope, home.Value)
						if len(missing) > 0 {
							valid = false
						}
					}
					if valid {
						add("RO-C05", ops.Pass, r.RobotID, "skills", "requested skills and configured envelope exist; no issuance claimed")
					} else {
						add("RO-C05", ops.Fail, r.RobotID, "skills", "requested skill or guardrail is not declared")
					}
				}
			}
		}
		agent, aok := idx[r.AgentRef]
		gate, gok := idx[r.GateRef]
		bridge, bok := idx[r.BridgeRef]
		issuer, iok := idx[agent.UpstreamRef]
		if !aok || agent.Kind != "agent" || !gok || gate.Kind != "gate" || !bok || bridge.Kind != "bridge" || !iok || issuer.Kind != "issuer" {
			add("RO-C07.declared", ops.CannotCheck, r.RobotID, "route", "required route component declaration missing")
		} else {
			ci := inspectCert(agent.CredentialRef, r.RobotID)
			if agent.RobotID != r.RobotID || gate.RobotID != r.RobotID || bridge.RobotID != r.RobotID || gate.UpstreamRef != agent.ID || bridge.UpstreamRef != gate.ID || !ci.valid {
				add("RO-C07.declared", ops.Fail, r.RobotID, "route", "declared robot/agent/credential route mismatch")
			} else {
				add("RO-C07.declared", ops.Pass, r.RobotID, "route", "declared route agrees; runtime binding NOT observed")
			}
		}
		transport, ok := idx[r.TransportRef]
		if !ok || transport.Kind != "transport" || transport.Group == "" {
			add("RO-C08.declared", ops.CannotCheck, r.RobotID, "transport", "isolation declaration unavailable")
		} else if agent.Group != transport.Group || gate.Group != transport.Group || bridge.Group != transport.Group {
			add("RO-C08.declared", ops.Fail, r.RobotID, "transport", "component group differs from robot transport declaration")
		} else if owner, dup := groups[transport.Group]; dup && owner != r.RobotID {
			add("RO-C08.declared", ops.Fail, r.RobotID, "transport", "two robots share a declared isolation group")
		} else {
			groups[transport.Group] = r.RobotID
			add("RO-C08.declared", ops.Pass, r.RobotID, "transport", "distinct declared group; actual DDS isolation NOT observed")
		}
		collector, ok := idx[r.CollectorRef]
		if !ok || collector.Kind != "collector" {
			add("RO-C11.declared", ops.CannotCheck, r.RobotID, "collector", "collector declaration unavailable")
		} else if cr, er := f.Read(collector.RegistryRef, "registry"); er != nil {
			add("RO-C11.declared", ops.CannotCheck, r.RobotID, "collector.registry", "collector registry unavailable")
		} else if reg == nil {
			add("RO-C11.declared", ops.CannotCheck, r.RobotID, "registry", "issuer registry unavailable")
		} else if !bytes.Equal(cr, regBytes) {
			add("RO-C11.declared", ops.Fail, r.RobotID, "collector.registry", "declared collector and issuer registry bytes differ")
		} else {
			add("RO-C11.declared", ops.Pass, r.RobotID, "collector.registry", "same snapshot bytes; running collector NOT observed")
		}
	}
	out.InputHashes = f.Hashes
	out.Finish()
	return out
}
