#!/usr/bin/env bash
# TPC copy test for the HEPCDN test cluster (developer machine or CI):
#   1. bring the cluster up        (./setup.sh: certs + per-node config + compose up --build)
#   2. wait for ready              (IdP mints tokens, 4/4 nodes healthy,
#                                   4/4 gossip peer view on every node)
#   3. copy data between instances (PUT node1 -> TPC COPY node1->node2 ->
#                                   TPC COPY node2->node3, verifying the
#                                   copied bytes on every destination)
#
# Usage:
#   ./tpc-copy-test.sh                  # full run: build + up + wait + copy
#   SKIP_BUILD=1 ./tpc-copy-test.sh     # skip --build (reuse the existing image)
#   PAYLOAD_KB=32 ./tpc-copy-test.sh    # payload size in KiB (default 16, max 96)
#   READY_TIMEOUT=300 ./tpc-copy-test.sh
#
# Exit 0 = all copies verified, 1 = any failure.
#
# All HTTP goes through hepcdn_http.py inside the IdP container: tokens are
# written to files (never process argv), and container-to-container traffic
# avoids the host's intermittently flaky docker port publishing.
set -uo pipefail
cd "$(dirname "$0")"

SKIP_BUILD="${SKIP_BUILD:-0}"
PAYLOAD_KB="${PAYLOAD_KB:-16}"
READY_TIMEOUT="${READY_TIMEOUT:-180}"
MAX_PAYLOAD_KB=96   # payload travels as one process argument (128 KiB limit)

fail() { echo "FAIL: $*" >&2; exit 1; }
now() { date +%s; }

# --- 0. prerequisites ----------------------------------------------------------
for c in docker openssl python3; do
  command -v "$c" >/dev/null || fail "required command not found: $c"
done
docker compose version >/dev/null 2>&1 || fail "docker compose plugin not found"
[[ "$PAYLOAD_KB" =~ ^[0-9]+$ ]] && (( PAYLOAD_KB >= 1 )) || fail "PAYLOAD_KB must be a positive integer"
(( PAYLOAD_KB <= MAX_PAYLOAD_KB )) || fail "PAYLOAD_KB too large (max $MAX_PAYLOAD_KB)"

# --- 1. bring the cluster up ------------------------------------------------------
if [[ "$SKIP_BUILD" == "1" ]]; then
  echo "==> SKIP_BUILD=1: docker compose up -d (reusing existing image)"
  docker compose up -d
else
  echo "==> bringing the cluster up (./setup.sh)"
  ./setup.sh
fi

# --- 2. in-cluster HTTP helpers ----------------------------------------------------
mkdir -p run/tok
# Up to 3 attempts (transient startup failures). Returns the helper's exit code.
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
# Single attempt, for polling loops (the outer loop does the retrying).
runpy1() {
  local errf rc
  errf=$(mktemp)
  docker exec hepcdn-idp env IN_CLUSTER=1 python3 /hepcdn_http.py "$@" 2>"$errf"
  rc=$?
  cat "$errf" >&2
  rm -f "$errf"
  return $rc
}

# --- 3. wait for ready --------------------------------------------------------------
echo "==> waiting for the IdP (token minting, timeout ${READY_TIMEOUT}s)"
deadline=$(( $(now) + READY_TIMEOUT ))
while :; do
  if runpy1 mint hepcdn "storage.read:/ hepcdn.access" >/dev/null 2>&1; then break; fi
  if (( $(now) >= deadline )); then
    docker compose logs idp --tail=50 || true
    fail "IdP not ready within ${READY_TIMEOUT}s"
  fi
  sleep 2
done
runpy1 mint rw "openid offline_access storage.read:/ storage.create:/" >/dev/null \
  || fail "could not mint rw token (storage.read:/ storage.create:/)"
echo "  IdP ready (minted hepcdn.access + rw tokens)"

echo "==> waiting for 4/4 nodes healthy (timeout ${READY_TIMEOUT}s)"
deadline=$(( $(now) + READY_TIMEOUT ))
while :; do
  ok=0
  for i in 1 2 3 4; do
    runpy1 health "$i" >/dev/null 2>&1 && ok=$((ok+1))
  done
  [[ $ok -eq 4 ]] && break
  if (( $(now) >= deadline )); then
    docker compose logs --tail=40 || true
    fail "only $ok/4 nodes healthy after ${READY_TIMEOUT}s"
  fi
  sleep 2
done
echo "  4/4 nodes healthy"

echo "==> waiting for 4/4 gossip on every node (timeout ${READY_TIMEOUT}s)"
deadline=$(( $(now) + READY_TIMEOUT ))
while :; do
  ok=0
  for i in 1 2 3 4; do
    n=$(runpy1 gossip-count "$i" hepcdn 2>/dev/null | tail -1 || echo 0)
    [[ "$n" == "4" ]] && ok=$((ok+1))
  done
  echo "  $ok/4 nodes with the full peer view"
  [[ $ok -eq 4 ]] && break
  if (( $(now) >= deadline )); then
    docker compose logs --tail=40 || true
    fail "cluster did not reach 4/4 within ${READY_TIMEOUT}s"
  fi
  sleep 2
done
echo "  cluster formed (4/4 on every node)"

# --- 4. copy data between instances ---------------------------------------------------
echo "==> generating ${PAYLOAD_KB}KiB payload (deterministic, alphanumeric)"
PAYLOAD=$(python3 -c '
import random, string, sys
random.seed(0x5eed)
alphabet = string.ascii_letters + string.digits
sys.stdout.write("".join(random.choice(alphabet) for _ in range(int(sys.argv[1]) * 1024)))
' "$PAYLOAD_KB")
[[ -n "$PAYLOAD" ]] || fail "payload generation failed"
FNAME="tpc-test-$$.txt"

echo "==> PUT node1 /webdav/$FNAME"
put=$(runpy put 1 "/webdav/$FNAME" rw "$PAYLOAD" | head -1)
[[ "$put" == "201" ]] || fail "PUT to node1 returned $put"

got1=$(runpy get 1 "/webdav/$FNAME" rw) || fail "GET node1 failed"
[[ "$got1" == "$PAYLOAD" ]] || fail "GET node1: payload does not match (source round-trip)"
echo "  node1 round-trip OK (${#PAYLOAD} bytes)"

echo "==> TPC COPY node1 -> node2"
copy=$(runpy copy 2 "/webdav/$FNAME" rw "https://node1:8080/webdav/$FNAME" rw | head -1)
[[ "$copy" == "202" ]] || fail "TPC COPY node1->node2 returned $copy"
got2=$(runpy get 2 "/webdav/$FNAME" rw) || fail "GET node2 failed"
[[ "$got2" == "$PAYLOAD" ]] || fail "GET node2: copied data does not match (got ${#got2} bytes, want ${#PAYLOAD})"
echo "  node2 copy verified (${#got2} bytes)"

echo "==> TPC COPY node2 -> node3"
copy=$(runpy copy 3 "/webdav/$FNAME" rw "https://node2:8080/webdav/$FNAME" rw | head -1)
[[ "$copy" == "202" ]] || fail "TPC COPY node2->node3 returned $copy"
got3=$(runpy get 3 "/webdav/$FNAME" rw) || fail "GET node3 failed"
[[ "$got3" == "$PAYLOAD" ]] || fail "GET node3: copied data does not match (got ${#got3} bytes, want ${#PAYLOAD})"
echo "  node3 copy verified (${#got3} bytes)"

echo
echo "TPC COPY TEST PASSED: ${#PAYLOAD} bytes PUT to node1, TPC-copied node1 -> node2 -> node3, bytes verified on each node"
