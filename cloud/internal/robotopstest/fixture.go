// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
// Package robotopstest builds isolated PUBLIC inspection fixtures. Private keys
// exist only in memory during certificate creation; no deployment key is used.
package robotopstest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	ops "github.com/glowfly/pail/services/pkg/robotops"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type Fixture struct {
	Root         string
	Inventory    ops.Inventory
	Map          ops.ResourceMap
	Fingerprints []string
	Now          time.Time
}

func New(t *testing.T) *Fixture {
	t.Helper()
	f := &Fixture{Root: t.TempDir(), Now: time.Now().UTC()}
	dep := "5e8b24a0-2319-4a53-b5cf-a03afc977301"
	write := func(name string, b []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(f.Root, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: f.Now.Add(-time.Hour), NotAfter: f.Now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	write("ca.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	reg := "version: 1\nrobots:\n"
	req := "version: 1\nrequesters:\n"
	f.Map = ops.ResourceMap{SchemaVersion: 1, DeploymentID: dep, Resources: []ops.Resource{{ID: "res:registry", Kind: "registry", Path: "robot_registry.yaml"}, {ID: "res:site", Kind: "site_model", Path: "site_model.yaml"}, {ID: "res:policy", Kind: "policy", Path: "policy.yaml"}, {ID: "res:skills", Kind: "skills_dir", Path: "."}, {ID: "res:ca", Kind: "ca_certificate", Path: "ca.crt"}, {ID: "res:requesters", Kind: "requesters", Path: "requesters.yaml"}, {ID: "res:class", Kind: "class", Value: "diff_drive_amr"}, {ID: "res:home", Kind: "zone", Value: "z1"}, {ID: "cmp:issuer", Kind: "issuer", Group: "cloud", Port: 50061}, {ID: "cmp:collector", Kind: "collector", RegistryRef: "res:registry", Group: "host", Port: 8090}, {ID: "cred:private", Kind: "private_key", Path: "private.key"}}}
	f.Inventory = ops.Inventory{SchemaVersion: 1, DeploymentID: dep, Revision: 1, ProfileID: "local-compose-ros2/v1", ResourceBindings: ops.Bindings{Registry: "res:registry", SiteModel: "res:site", Policy: "res:policy", Skills: "res:skills"}}
	for i, rid := range []string{"robot-01", "robot-added-02"} {
		client, _, er := ed25519.GenerateKey(rand.Reader)
		if er != nil {
			t.Fatal(er)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 2)), Subject: pkix.Name{CommonName: "not-an-authority-for-robot-name"}, NotBefore: f.Now.Add(-time.Hour), NotAfter: f.Now.Add(12 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		b, er := x509.CreateCertificate(rand.Reader, leaf, ca, client, key)
		if er != nil {
			t.Fatal(er)
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
		f.Inventory.Robots = append(f.Inventory.Robots, ops.Robot{RobotID: rid, DisplayName: rid, Lifecycle: "active", ClassRef: "res:class", HomeRef: "res:home", AgentRef: agent, GateRef: gate, BridgeRef: bridge, ClientCredentialRef: cert, RequesterRef: requester, TransportRef: transport, CollectorRef: "cmp:collector"})
		f.Map.Resources = append(f.Map.Resources, ops.Resource{ID: cert, Kind: "certificate", Path: name, CARef: "res:ca"}, ops.Resource{ID: agent, Kind: "agent", RobotID: rid, CredentialRef: cert, UpstreamRef: "cmp:issuer", Group: "net" + suffix, Port: 50051}, ops.Resource{ID: gate, Kind: "gate", RobotID: rid, UpstreamRef: agent, Group: "net" + suffix}, ops.Resource{ID: bridge, Kind: "bridge", RobotID: rid, UpstreamRef: gate, Group: "net" + suffix}, ops.Resource{ID: requester, Kind: "requester", Value: "requester-" + suffix, RequesterKind: "agentic_ai", RegistryRef: "res:requesters", CredentialRef: cert, Skills: []string{"twist"}}, ops.Resource{ID: transport, Kind: "transport", Group: "net" + suffix})
	}
	write("robot_registry.yaml", []byte(reg))
	write("requesters.yaml", []byte(req))
	write("private.key", []byte("PRIVATE_RESOURCE_CANARY_NOT_A_KEY"))
	write("site_model.yaml", []byte("site: test\nschema: v3\nzones:\n  - {id: z1, type: work_area, adjacent: []}\nobjects:\n  - {id: sample-box, at: z1}\nrobots:\n  - {id: robot-01, capabilities: [move], schema: v3, home: z1, robot_class: diff_drive_amr}\n  - {id: robot-added-02, capabilities: [move], schema: v3, home: z1, robot_class: diff_drive_amr}\n"))
	cwd, _ := os.Getwd()
	found := false
	for dir := cwd; dir != filepath.Dir(dir); dir = filepath.Dir(dir) {
		if _, er := os.Stat(filepath.Join(dir, "config/policy.yaml")); er != nil {
			continue
		}
		for _, name := range []string{"policy.yaml", "skills.diff_drive_amr.yaml"} {
			b, er := os.ReadFile(filepath.Join(dir, "config", name))
			if er != nil {
				t.Fatal(er)
			}
			write(name, b)
		}
		found = true
		break
	}
	if !found {
		t.Fatal("public reference policy fixture missing")
	}
	return f
}
func (f *Fixture) Change(id string, fn func(*ops.Resource)) {
	for i := range f.Map.Resources {
		if f.Map.Resources[i].ID == id {
			fn(&f.Map.Resources[i])
			return
		}
	}
	panic("fixture id not found")
}
