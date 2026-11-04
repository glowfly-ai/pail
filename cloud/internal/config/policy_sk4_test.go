// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package config

import "testing"

// PAIL-CASE: policy_token_schema
// SK-4 : `token_schema` absent = 4 (an upgraded issuer must not
// start minting what an un-upgraded gate refuses), 5 = the named envelope,
// anything else is refused at load — an edition nobody implemented must not
// read as "the newest".
func TestPolicyTokenSchema(t *testing.T) {
	p, err := loadContent(t, validPolicy)
	if err != nil || p.TokenSchema != TokenSchemaClassMask {
		t.Fatalf("default: err=%v token_schema=%d", err, p.TokenSchema)
	}
	p, err = loadContent(t, validPolicy+"token_schema: 5\n")
	if err != nil || p.TokenSchema != TokenSchemaNamedEnvelope {
		t.Fatalf("5: err=%v token_schema=%d", err, p.TokenSchema)
	}
	wantRule(t, "S16b", validPolicy+"token_schema: 7\n")
}
