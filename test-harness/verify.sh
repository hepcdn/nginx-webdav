#!/usr/bin/env bash
# End-to-end verification of the HEPCDN test cluster:
#   1. all four nodes healthy
#   2. mock IdP mints WLCG tokens
#   3. gossip forms a 4-node cluster (every node sees 4/4 alive peers)
#   4. WebDAV PUT/GET on node1 + TPC third-party copy node1 -> node2 + GET
#
# All HTTP runs INSIDE the compose network via the IdP container
# (`docker exec hepcdn-idp`): the host's docker port publishing
# intermittently refuses connections (multi-minute ECONNREFUSED windows),
# while container-to-container traffic is stable. The docker-published
# ports (IdP 20443, nodes 20081-20084, all >20000 to avoid host service
# conflicts) remain available for ad-hoc use.
#
# Authenticated HTTP goes through hepcdn_http.py (urllib). Tokens live in
# ./run/tok (== /tok inside the IdP container), never in process argv:
# `curl -H 'Authorization: Bearer ***'` gets the bearer value rewritten to
# '***' by this environment's credential redaction layer, which made every
# such request fail with 401 "invalid jwt: invalid jwt string".
set -uo pipefail
cd "$(dirname "$0")"

mkdir -p run/tok
fail() { echo "FAIL: $*" >&2; exit 1; }

# Run the helper inside the IdP container (in-cluster mode). Retries
# transient failures; keeps stdout (results) and stderr (diagnostics)
# separate so callers see clean output.
runpy() {
  local errf out rc=1
  errf=$(mktemp)
  for _ in 1 2 3; do
    out=$(docker exec hepcdn-idp env IN_CLUSTER=1 python3 /hepcdn_http.py "$@" 2>"$errf")
    rc=$?
    [[ $rc -eq 0 ]] && break
    sleep 1
  done
  cat "$errf" >&2
  rm -f "$errf"
  printf '%s\n' "$out"
  return $rc
}

SRC1="https://node1:8080"   # in-cluster name, resolvable from node2 (TPC source)

echo "==> 1/4 node health"
for i in 1 2 3 4; do
  body=$(runpy health $i) || fail "node$i not healthy (see: docker compose logs node$i) - $body"
  [[ "$body" == OK\ * ]] || fail "node$i unexpected health body: $body"
  echo "  node$i: $body"
done

echo "==> 2/4 minting tokens from the mock IdP"
runpy mint hepcdn "storage.read:/ hepcdn.access" > /dev/null || fail "IdP /mint unreachable"
runpy mint rw "openid offline_access storage.read:/ storage.create:/" > /dev/null || fail "IdP /mint unreachable (rw token)"
echo "  minted hepcdn.access + read/create tokens (issuer https://idp:8443/)"

echo "==> 3/4 cluster formation (every node must see 4/4 alive peers)"
ok=0
for attempt in $(seq 1 30); do
  ok=0
  for i in 1 2 3 4; do
    n=$(runpy gossip-count $i hepcdn 2>/dev/null | tail -1 || echo 0)
    [[ "$n" == "4" ]] && ok=$((ok+1))
  done
  echo "  attempt $attempt: $ok/4 nodes have the full peer view"
  [[ $ok -eq 4 ]] && break
  sleep 2
done
[[ $ok -eq 4 ]] || { docker compose logs --tail=50; fail "cluster did not form within 60s"; }

echo "  peer view reported by node1:"
runpy gossip-view 1 hepcdn | sed 's/^/    /'

echo "==> 4/4 WebDAV + TPC"
FNAME="hello-$$-$RANDOM.txt"   # fresh name per run: PUT is always 201-created
put=$(runpy put 1 /webdav/$FNAME rw "Hello, HEPCDN test cluster!" | head -1)
[[ "$put" == "201" ]] || fail "PUT to node1 returned $put"
echo "  PUT  node1 /webdav/$FNAME -> 201 created"

got=$(runpy get 1 /webdav/$FNAME rw)
[[ "$got" == "Hello, HEPCDN test cluster!" ]] || fail "GET from node1 returned: $got"
echo "  GET  node1 /webdav/$FNAME -> OK"

copy=$(runpy copy 2 /webdav/$FNAME rw "$SRC1/webdav/$FNAME" rw | head -1)
[[ "$copy" == "202" ]] || fail "TPC COPY returned $copy"
echo "  COPY node1 -> node2 (TPC) -> 202 accepted"

got2=$(runpy get 2 /webdav/$FNAME rw)
[[ "$got2" == "Hello, HEPCDN test cluster!" ]] || fail "GET from node2 returned: $got2"
echo "  GET  node2 /webdav/$FNAME -> OK"

echo
echo "ALL CHECKS PASSED"
