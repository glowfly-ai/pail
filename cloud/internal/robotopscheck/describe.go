// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package robotopscheck

import (
	"fmt"
	"github.com/glowfly/pail/services/internal/graph"
	"github.com/glowfly/pail/services/internal/identity"
	ops "github.com/glowfly/pail/services/pkg/robotops"
	"sort"
)

// Describe imports identity/site semantics and explicit component declarations.
// Ambiguous/missing topology is refused, not guessed from container/file names.
// Imported robots stay planned: observing a robot is not authority to activate it.
func Describe(m ops.ResourceMap, root string) (ops.Inventory, error) {
	inv := ops.Inventory{SchemaVersion: 1, DeploymentID: m.DeploymentID, Revision: 1, ProfileID: "local-compose-ros2/v1", Robots: []ops.Robot{}}
	if m.ValidateMap() != nil {
		return inv, fmt.Errorf("RO_SCHEMA: resource map")
	}
	unique := func(kind string, predicate func(ops.Resource) bool) (ops.Resource, error) {
		var chosen ops.Resource
		count := 0
		for _, r := range m.Resources {
			if r.Kind == kind && (predicate == nil || predicate(r)) {
				chosen = r
				count++
			}
		}
		if count != 1 {
			return chosen, fmt.Errorf("RO_IMPORT_AMBIGUOUS: %s needs exactly one explicit binding", kind)
		}
		return chosen, nil
	}
	bind := []*string{&inv.ResourceBindings.Registry, &inv.ResourceBindings.SiteModel, &inv.ResourceBindings.Policy, &inv.ResourceBindings.Skills}
	for i, k := range []string{"registry", "site_model", "policy", "skills_dir"} {
		r, e := unique(k, nil)
		if e != nil {
			return inv, e
		}
		*bind[i] = r.ID
	}
	f, e := ops.NewFiles(root, m)
	if e != nil {
		return inv, e
	}
	b, e := f.Read(inv.ResourceBindings.Registry, "registry")
	if e != nil {
		return inv, e
	}
	reg, e := identity.Parse(b)
	if e != nil {
		return inv, fmt.Errorf("RO_IMPORT: registry semantics invalid")
	}
	b, e = f.Read(inv.ResourceBindings.SiteModel, "site_model")
	if e != nil {
		return inv, e
	}
	g, site, e := graph.Compile(b)
	if e != nil {
		return inv, fmt.Errorf("RO_IMPORT: site semantics invalid")
	}
	ids := reg.RobotIDs()
	sort.Strings(ids)
	for _, id := range ids {
		bot := ops.Robot{RobotID: id, DisplayName: id, Lifecycle: "planned"}
		class, e := unique("class", func(r ops.Resource) bool { return r.Value == site.RobotClass[id] })
		if e != nil {
			return inv, e
		}
		bot.ClassRef = class.ID
		homes := map[string]bool{}
		for _, edge := range g.Edges {
			if edge.From == "robot:"+id && edge.Rel == graph.RelLocatedIn {
				homes[edge.To] = true
			}
		}
		home, e := unique("zone", func(r ops.Resource) bool { return homes["zone:"+r.Value] })
		if e != nil {
			return inv, e
		}
		bot.HomeRef = home.ID
		agent, e := unique("agent", func(r ops.Resource) bool { return r.RobotID == id })
		if e != nil {
			return inv, e
		}
		bot.AgentRef = agent.ID
		bot.ClientCredentialRef = agent.CredentialRef
		gate, e := unique("gate", func(r ops.Resource) bool { return r.RobotID == id && r.UpstreamRef == agent.ID })
		if e != nil {
			return inv, e
		}
		bot.GateRef = gate.ID
		bridge, e := unique("bridge", func(r ops.Resource) bool { return r.RobotID == id && r.UpstreamRef == gate.ID })
		if e != nil {
			return inv, e
		}
		bot.BridgeRef = bridge.ID
		req, e := unique("requester", func(r ops.Resource) bool { return r.CredentialRef == agent.CredentialRef })
		if e != nil {
			return inv, e
		}
		bot.RequesterRef = req.ID
		transport, e := unique("transport", func(r ops.Resource) bool { return r.Group == agent.Group })
		if e != nil {
			return inv, e
		}
		bot.TransportRef = transport.ID
		collector, e := unique("collector", func(r ops.Resource) bool { return r.RegistryRef == inv.ResourceBindings.Registry })
		if e != nil {
			return inv, e
		}
		bot.CollectorRef = collector.ID
		inv.Robots = append(inv.Robots, bot)
	}
	return inv, inv.Validate()
}
