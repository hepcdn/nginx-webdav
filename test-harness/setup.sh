#!/usr/bin/env bash
# One-shot setup for the HEPCDN test cluster (this file lives in
# test-harness/; nodes are built from the repo's nginx/ by compose):
#   1. generate the test CA + self-signed certs (idp, node1..node4)
#   2. write per-node config.json (seed peers, issuer, IdP pubkey, client creds)
#   3. start the stack: docker compose up -d --build
#
# Usage: ./setup.sh [--force]   (--force regenerates certs)
set -euo pipefail
cd "$(dirname "$0")"

FORCE="${1:-}"

# --- 1. certificates ----------------------------------------------------------
regen_certs=false
if [[ -f certs/ca.pem && "$FORCE" != "--force" ]]; then
  echo "==> certs/ already present (pass --force to regenerate)"
else
  echo "==> Generating test CA and self-signed certs"
  regen_certs=true
  rm -rf certs
  mkdir -p certs/idp certs/node1 certs/node2 certs/node3 certs/node4 certs/ca-bundle-dir

  # CA extensions: modern OpenSSL (e.g. Python 3.13's ssl) rejects CAs without
  # keyUsage keyCertSign, so make this a properly-formed X.509v3 CA.
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 3650 \
    -subj "/CN=HEPCDN Test CA" \
    -addext "basicConstraints=critical,CA:true" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" \
    -keyout certs/ca.key -out certs/ca.pem 2>/dev/null

  for n in idp node1 node2 node3 node4; do
    openssl req -newkey rsa:2048 -nodes -keyout "certs/$n/key.pem" \
      -subj "/CN=$n" -out "certs/$n/csr.pem" 2>/dev/null
    printf "subjectAltName=DNS:%s,DNS:localhost\n" "$n" > "certs/$n/san.cnf"
    openssl x509 -req -in "certs/$n/csr.pem" -CA certs/ca.pem -CAkey certs/ca.key \
      -CAcreateserial -days 825 -sha256 \
      -extfile "certs/$n/san.cnf" -out "certs/$n/cert.pem" 2>/dev/null
    rm -f "certs/$n/csr.pem" "certs/$n/san.cnf"
  done

  cp certs/ca.pem certs/ca-bundle.pem
  cp certs/ca.pem certs/ca-bundle-dir/
  openssl rehash certs/ca-bundle-dir >/dev/null
fi

# --- 2. per-node config ---------------------------------------------------------
PUBKEY_FILE=$(mktemp)
openssl pkey -in certs/idp/key.pem -pubout -out "$PUBKEY_FILE"

mkdir -p config
for i in 1 2 3 4; do
  seeds=""
  for j in 1 2 3 4; do
    if [[ $i -ne $j ]]; then seeds+="https://node$j:8080/,"; fi
  done
  seeds="${seeds%,}"
  HCID=$(( (RANDOM << 15) ^ RANDOM ))
  python3 - "$i" "$seeds" "$HCID" "$PUBKEY_FILE" <<'EOF'
import json, sys

i, seeds, hcid, pubfile = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
config = {
    "seed_peers": seeds,
    "openidc_iss": "https://idp:8443/",
    "openidc_pubkey": open(pubfile).read(),
    "openidc_client_id": "hepcdn",
    "openidc_client_secret": "hepcdn-secret",
    "public_client_id": "hepcdn-public",
    "gossip_delay": 5,
    "gossip_fraction": 0.5,
    "health_check_id": hcid,
}
with open(f"config/node{i}.json", "w") as f:
    json.dump(config, f, indent=2)
print(f"    config/node{i}.json (health_check_id={hcid})")
EOF
done
rm -f "$PUBKEY_FILE"

# --- 3. bring the stack up -------------------------------------------------------
if $regen_certs; then
  # new CA means every container must reload certs/trust: full restart
  # (without -v, so storage volumes survive)
  docker compose down
fi
echo "==> docker compose up -d --build"
docker compose up -d --build
echo
docker compose ps
