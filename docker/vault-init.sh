#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

# KM1-2① dev-vault init (DEV ONLY, LLD §2.5).
# Creates the issuer signing key INSIDE the vault (Transit ed25519 — private
# key never leaves), a least-privilege policy, a scoped token, and the
# self-check keyring for pail-cloud.
set -eu

i=0
until vault status >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -gt 30 ]; then
    echo "vault-init: vault not reachable at $VAULT_ADDR" >&2
    exit 1
  fi
  sleep 1
done

vault secrets enable -path=transit transit 2>/dev/null || true
if ! vault read transit/keys/pail-issuer >/dev/null 2>&1; then
  vault write -f transit/keys/pail-issuer type=ed25519
fi

cat > /tmp/pail-issuer-policy.hcl <<'EOF'
path "transit/sign/pail-issuer" {
  capabilities = ["update"]
}
path "transit/keys/pail-issuer" {
  capabilities = ["read"]
}
EOF
vault policy write pail-issuer /tmp/pail-issuer-policy.hcl

token=$(vault token create -policy=pail-issuer -ttl=24h -field=token)
printf '%s' "$token" > /pail-vault/token

pub=$(vault read -format=json transit/keys/pail-issuer \
  | grep -o '"public_key": *"[^"]*"' | head -1 \
  | sed 's/.*"public_key": *"//; s/"$//')
if [ -z "$pub" ]; then
  echo "vault-init: could not extract transit public key" >&2
  exit 1
fi

cat > /pail-vault/keyring.json <<EOF
{"keys":[{"key_id":"vault-issuer-1","ed25519_public_key_base64":"$pub","role":"issuer"}]}
EOF

echo "vault-init: transit key=pail-issuer key_id=vault-issuer-1 pub=$pub"
