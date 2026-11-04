// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package robotops

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Change authorization (AS-4 / O-4): replacing one of the issuer's standing
// inputs — the policy file or the site model — is a privileged act. A
// PolicyChange document names the subject, the exact bytes (sha256) it
// installs and the bytes it replaces; a PolicyAuthorization bundles that
// document with approvals from distinct trusted principals. The issuer
// verifies the bundle against the bytes it is about to load and refuses to
// start when the approvals do not cover them. Nothing here interprets the
// content; it only decides whether these bytes, for this subject, were
// authorized.

const DomainPolicy = "policy"

// Subjects a PolicyChange may name. Each subject has its own resource id, so
// a key whose target_scope covers only res:policy cannot approve a site
// model change, and a bundle for one subject never authorizes the other.
const (
	SubjectPolicy    = "policy"
	SubjectSiteModel = "site_model"

	PolicyResource    = "res:policy"
	SiteModelResource = "res:site_model"
)

// ResourceForSubject maps a change subject to the resource id an approval's
// target_scope must cover. Unknown subjects are refused, never defaulted.
func ResourceForSubject(subject string) (string, error) {
	switch subject {
	case SubjectPolicy:
		return PolicyResource, nil
	case SubjectSiteModel:
		return SiteModelResource, nil
	}
	return "", fmt.Errorf("RO_POLICY: unknown change subject")
}

type PolicyChange struct {
	SchemaVersion         int    `json:"schema_version"`
	DocumentKind          string `json:"document_kind"`
	DocumentID            string `json:"document_id"`
	DeploymentID          string `json:"deployment_id"`
	CreatedAtMS           int64  `json:"created_at_ms"`
	ToolBuild             string `json:"tool_build"`
	Subject               string `json:"subject"`
	ContentSHA256         string `json:"content_sha256"`
	PreviousContentSHA256 string `json:"previous_content_sha256"` // "" when no predecessor is claimed
	Note                  string `json:"note"`
	Digest                string `json:"digest"`
}

type PolicyAuthorization struct {
	SchemaVersion int          `json:"schema_version"`
	DocumentKind  string       `json:"document_kind"`
	Change        PolicyChange `json:"change"`
	Approvals     []Approval   `json:"approvals"`
}

// PolicyChangeDigest recomputes the management digest of the change body.
func PolicyChangeDigest(c PolicyChange) (string, error) {
	return ManagementDigest(DomainPolicy, c)
}

func (c PolicyChange) validate() error {
	if _, err := ResourceForSubject(c.Subject); err != nil {
		return err
	}
	if c.SchemaVersion != 1 || c.DocumentKind != "PolicyChange" || !uuidName.MatchString(c.DocumentID) || !deploymentName.MatchString(c.DeploymentID) || !hexDigest.MatchString(c.ContentSHA256) || (c.PreviousContentSHA256 != "" && !hexDigest.MatchString(c.PreviousContentSHA256)) || c.CreatedAtMS <= 0 || len(c.Note) > 512 {
		return fmt.Errorf("RO_POLICY: change document invalid")
	}
	if c.PreviousContentSHA256 == c.ContentSHA256 {
		return fmt.Errorf("RO_POLICY: change names identical previous and new content")
	}
	d, err := PolicyChangeDigest(c)
	if err != nil || d != c.Digest {
		return fmt.Errorf("RO_POLICY: change digest invalid")
	}
	return nil
}

// DecodePolicyAuthorization strictly decodes and shape-checks a bundle.
func DecodePolicyAuthorization(raw []byte) (PolicyAuthorization, error) {
	var a PolicyAuthorization
	if err := StrictDecode(raw, &a, []string{"schema_version", "document_kind", "change", "approvals"}); err != nil {
		return a, err
	}
	if a.SchemaVersion != 1 || a.DocumentKind != "PolicyAuthorization" || len(a.Approvals) == 0 || len(a.Approvals) > 16 {
		return a, fmt.Errorf("RO_POLICY: authorization document invalid")
	}
	if err := a.Change.validate(); err != nil {
		return a, err
	}
	return a, nil
}

// PolicyBytesSHA256 is the digest the change names: the exact file bytes.
func PolicyBytesSHA256(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// VerifyPolicyAuthorization decides whether contentRaw may be loaded as
// subject: the change must name this subject and exactly these bytes, and at
// least minApprovals valid policy_change approvals from distinct keys AND
// distinct principals must bind to the change document with the subject's
// resource in scope. It returns the approving keys. Any error means the
// content is not authorized.
func VerifyPolicyAuthorization(store TrustStore, a PolicyAuthorization, contentRaw []byte, subject string, minApprovals int, nowMS int64) ([]TrustKey, error) {
	if minApprovals < 1 {
		return nil, fmt.Errorf("RO_POLICY: minimum approvals must be at least 1")
	}
	if err := a.Change.validate(); err != nil {
		return nil, err
	}
	resource, err := ResourceForSubject(subject)
	if err != nil {
		return nil, err
	}
	if a.Change.Subject != subject {
		return nil, fmt.Errorf("RO_POLICY: change is for subject %q, not %q", a.Change.Subject, subject)
	}
	if a.Change.DeploymentID != store.DeploymentID {
		return nil, fmt.Errorf("RO_POLICY: change is for another deployment")
	}
	if PolicyBytesSHA256(contentRaw) != a.Change.ContentSHA256 {
		return nil, fmt.Errorf("RO_POLICY: %s bytes differ from the authorized change", subject)
	}
	binding := ApprovalBinding{Action: "policy_change", DeploymentID: a.Change.DeploymentID, TargetID: a.Change.DocumentID, PlanDigest: a.Change.Digest, Resources: []string{resource}}
	keys, principals := map[string]bool{}, map[string]bool{}
	var out []TrustKey
	for i, ap := range a.Approvals {
		k, err := VerifyApproval(store, ap, binding, nowMS)
		if err != nil {
			return nil, fmt.Errorf("RO_POLICY: approval %d: %v", i, err)
		}
		if keys[k.KeyID] || keys[k.PublicKey] || principals[k.PrincipalID] {
			return nil, fmt.Errorf("RO_POLICY: approval %d repeats a key or principal already counted", i)
		}
		keys[k.KeyID], keys[k.PublicKey], principals[k.PrincipalID] = true, true, true
		out = append(out, k)
	}
	if len(out) < minApprovals {
		return nil, fmt.Errorf("RO_POLICY: %d distinct approval(s), %d required", len(out), minApprovals)
	}
	return out, nil
}
