// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
// pail_robotops_fixture writes a complete, throwaway declaration set for the
// offline robot-operations checkers (examples/robotops/README.md): a fresh CA,
// one or two robot client certificates, registry, requesters, site model, the
// public reference policy and skill registry, and the inventory/resource map
// that reference them. Certificate private keys exist only in memory while the
// certificates are created and are never written; nothing here can enrol or
// operate a robot.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	ops "github.com/glowfly/pail/services/pkg/robotops"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

type Fixture struct {
	Root         string
	Inventory    ops.Inventory
	Map          ops.ResourceMap
	Fingerprints []string
	Now          time.Time
}

func build(root, config string, count int) *Fixture {
	f := &Fixture{Root: root, Now: time.Now().UTC()}
	dep := "5e8b24a0-2319-4a53-b5cf-a03afc977301"
	write := func(name string, b []byte) {
		if err := os.WriteFile(filepath.Join(f.Root, name), b, 0600); err != nil {
			panic(err)
		}
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: f.Now.Add(-time.Hour), NotAfter: f.Now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		panic(err)
	}
	write("ca.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	reg := "version: 1\nrobots:\n"
	req := "version: 1\nrequesters:\n"
	f.Map = ops.ResourceMap{SchemaVersion: 1, DeploymentID: dep, Resources: []ops.Resource{{ID: "res:registry", Kind: "registry", Path: "robot_registry.yaml"}, {ID: "res:site", Kind: "site_model", Path: "site_model.yaml"}, {ID: "res:policy", Kind: "policy", Path: "policy.yaml"}, {ID: "res:skills", Kind: "skills_dir", Path: "."}, {ID: "res:ca", Kind: "ca_certificate", Path: "ca.crt"}, {ID: "res:requesters", Kind: "requesters", Path: "requesters.yaml"}, {ID: "res:class", Kind: "class", Value: "diff_drive_amr"}, {ID: "res:home", Kind: "zone", Value: "z1"}, {ID: "cmp:issuer", Kind: "issuer", Group: "cloud", Port: 50061}, {ID: "cmp:collector", Kind: "collector", RegistryRef: "res:registry", Group: "host", Port: 8090}}}
	f.Inventory = ops.Inventory{SchemaVersion: 1, DeploymentID: dep, Revision: 1, ProfileID: "local-compose-ros2/v1", ResourceBindings: ops.Bindings{Registry: "res:registry", SiteModel: "res:site", Policy: "res:policy", Skills: "res:skills"}}
	for i, rid := range []string{"robot-01", "robot-added-02"}[:count] {
		client, _, er := ed25519.GenerateKey(rand.Reader)
		if er != nil {
			panic(er)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 2)), Subject: pkix.Name{CommonName: "not-an-authority-for-robot-name"}, NotBefore: f.Now.Add(-time.Hour), NotAfter: f.Now.Add(12 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		b, er := x509.CreateCertificate(rand.Reader, leaf, ca, client, key)
		if er != nil {
			panic(er)
		}
		name := fmt.Sprintf("client%d.crt", i)
		write(name, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b}))
		h := sha256.Sum256(b)
		fp := hex.EncodeToString(h[:])
		f.Fingerprints = append(f.Fingerprints, fp)
		reg += fmt.Sprintf("  - robot_id: %s\n    role: robot\n    fingerprints: [\"%s\"]\n", rid, fp)
		req += fmt.Sprintf("  - match: {caller: mtls, cert_sha256: \"%s\"}\n    kind: agentic_ai\n    id: requester-%d\n    skills: [twist]\n", fp, i)
		suffix := fmt.Sprint(i)
		cert := "cred:c" + suffix
		agent := "cmp:a" + suffix
		gate := "cmp:g" + suffix
		bridge := "cmp:b" + suffix
		requester := "res:q" + suffix
		transport := "res:n" + suffix
		f.Inventory.Robots = append(f.Inventory.Robots, ops.Robot{RobotID: rid, DisplayName: rid, Lifecycle: "planned", ClassRef: "res:class", HomeRef: "res:home", AgentRef: agent, GateRef: gate, BridgeRef: bridge, ClientCredentialRef: cert, RequesterRef: requester, TransportRef: transport, CollectorRef: "cmp:collector"})
		f.Map.Resources = append(f.Map.Resources, ops.Resource{ID: cert, Kind: "certificate", Path: name, CARef: "res:ca"}, ops.Resource{ID: agent, Kind: "agent", RobotID: rid, CredentialRef: cert, UpstreamRef: "cmp:issuer", Group: "net" + suffix, Port: 50051}, ops.Resource{ID: gate, Kind: "gate", RobotID: rid, UpstreamRef: agent, Group: "net" + suffix}, ops.Resource{ID: bridge, Kind: "bridge", RobotID: rid, UpstreamRef: gate, Group: "net" + suffix}, ops.Resource{ID: requester, Kind: "requester", Value: "requester-" + suffix, RequesterKind: "agentic_ai", RegistryRef: "res:requesters", CredentialRef: cert, Skills: []string{"twist"}}, ops.Resource{ID: transport, Kind: "transport", Group: "net" + suffix})
	}
	write("robot_registry.yaml", []byte(reg))
	write("requesters.yaml", []byte(req))
	site := "site: test\nschema: v3\nzones:\n  - {id: z1, type: work_area, adjacent: []}\nobjects:\n  - {id: sample-box, at: z1}\nrobots:\n"
	for _, bot := range f.Inventory.Robots {
		site += fmt.Sprintf("  - {id: %s, capabilities: [move], schema: v3, home: z1, robot_class: diff_drive_amr}\n", bot.RobotID)
	}
	write("site_model.yaml", []byte(site))
	for _, name := range []string{"policy.yaml", "skills.diff_drive_amr.yaml"} {
		b, e := os.ReadFile(filepath.Join(config, name))
		if e != nil {
			panic(e)
		}
		write(name, b)
	}
	for name, value := range map[string]interface{}{"inventory.json": f.Inventory, "resources.json": f.Map} {
		b, e := json.MarshalIndent(value, "", "  ")
		if e != nil {
			panic(e)
		}
		write(name, append(b, '\n'))
	}

	return f
}

// This program prepares throwaway public inspection data only. It cannot deploy
// or operate a robot: certificate private keys are discarded without being saved.
func main() {
	out := flag.String("out", "", "new directory outside the source checkout")
	config := flag.String("config", "../config", "public reference config directory")
	count := flag.Int("robots", 2, "one or two offline robot declarations")
	flag.Parse()
	if *out == "" || (*count != 1 && *count != 2) || len(flag.Args()) != 0 {
		fmt.Fprintln(os.Stderr, "require --out NEW_DIR and --robots 1|2")
		os.Exit(2)
	}
	defer func() {
		if e := recover(); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(2)
		}
	}()
	if e := os.Mkdir(*out, 0700); e != nil {
		panic(e)
	}
	f := build(*out, *config, *count)
	fmt.Printf("Created %d planned robots; public certificates only; valid for 12 hours; no runtime or apply authority.\n", len(f.Inventory.Robots))
}
