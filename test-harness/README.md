# HEPCDN test cluster (self-contained, docker compose)

Four `hepcdn/nginx-webdav` storage gateways (`node1`..`node4`) federated as one
gossip cluster, all trusting a single mock OIDC IdP and one self-signed test CA.
No external services are required — the IdP, the CA and all certificates live
here; the node images are built from the `nginx/` directory of **this
repository** (whatever commit is checked out).

```
        +-----------+        +----------------+  https://localhost:20081
        |   idp     |        |   node1        |
        | :20443    |<:=====>| node2  :20082  |
        +-----------+  (TLS, | node3  :20083  |    gossip + TPC over
              shared CA      | node4  :20084  |    https, CA-verified
                             +----------------+
```

Host ports are all >20000 on purpose: this host runs other services
(k8s, etc.) on the low ports. Container-internal ports stay 8443 (IdP)
and 8080 (nodes); all cluster-internal names/URLs (`idp:8443`,
`nodeN:8080`) are unchanged.

## Quickstart

From this directory (`test-harness/`):

```sh
./setup.sh                   # generate CA + certs + per-node config, compose up --build (from ../nginx)
python3 tests/test_idp.py    # mock IdP unit test: 53 checks (token endpoint, WLCG claims, RS256 sig, negatives)
./verify.sh                  # health, token minting, 4/4 cluster formation, PUT/GET/TPC-COPY
```

Tear down (also deletes the storage volumes):

```sh
docker compose down -v
```

## Layout

| Path | Purpose |
|---|---|
| `docker-compose.yml` | idp + node1..node4 (shared image, per-node cert/config/volume) |
| `setup.sh` | generates everything below, then `docker compose up -d --build` |
| `verify.sh` | end-to-end check (exit 0 = cluster fully functional); runs in-cluster via the IdP container |
| `hepcdn_http.py` | urllib HTTP helper (mint/health/gossip/put/get/copy); host or `IN_CLUSTER=1` mode |
| `tests/test_idp.py` | standalone mock-IdP test (stdlib + optional `cryptography`), hits the live IdP on :20443 |
| `mock-idp/` | mock OIDC IdP: `POST /token` (client_credentials, what the nodes call), `POST /mint` (test backdoor for client tokens), `GET /.well-known/openid-configuration` |
| `certs/` | `HEPCDN Test CA` + per-service self-signed certs (SAN: service name + localhost), `ca-bundle.pem` and `ca-bundle-dir/` (hashed) — generated, not committed |
| `config/node{1..4}.json` | per-node `config.json`: seed peers, `openidc_iss=https://idp:8443/`, IdP public key, client credentials, health id — generated, not committed |

## Trust model

- One test CA signs: the IdP cert, and one cert per node (SAN `DNS:<name>,DNS:localhost`).
- Each node mounts the CA bundle over the image's
  `lua_ssl_trusted_certificate` path (`/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`)
  **and** into `SSL_CERT_DIR` (hashed) — so cosocket TLS to the IdP, peer gossip
  and TPC pulls verify chain *and* hostname against the test CA.
- Client JWTs (WLCG profile, RS256) are verified against the IdP public key
  embedded in each node's `config.json`; the node's gossip timer refreshes its
  own `storage.read:/ hepcdn.access` token from the IdP every ~10 min via the
  `client_credentials` grant (client `hepcdn` / `hepcdn-secret`).

## Endpoints (from the host)

Use `--cacert certs/ca-bundle.pem` with curl, e.g.:

```sh
curl --cacert certs/ca-bundle.pem https://localhost:20081/webdav_health
curl --cacert certs/ca-bundle.pem -d "scope=openid offline_access storage.read:/ storage.create:/" \
     https://localhost:20443/mint                                   # -> raw JWT
```

Per node (port 2008N): `/webdav/...` (WebDAV, COPY = TPC), `/webdav_health`,
`/gossip` (needs `hepcdn.access` scope), `/redirect/<path>` (federation redirect).

## Environment pitfalls (observed)

- **Bearer tokens via `curl -H` get redacted in some environments.** A
  credential-redaction layer can rewrite the value after
  `Authorization: Bearer ` in a process's argv to `***` (3 chars) before
  exec, so the cluster answers `401 invalid jwt: invalid jwt string`. That
  is a *client-side* artifact — the token, the IdP and the nodes are all
  fine. Always send tokens through `hepcdn_http.py` (urllib; tokens travel
  in files/memory, never argv).
- **Host docker port publishing can be intermittently flaky** (multi-minute
  ECONNREFUSED windows on published ports; container-to-container traffic is
  unaffected). `verify.sh` therefore performs all HTTP inside the compose
  network via `docker exec hepcdn-idp python3 /hepcdn_http.py`
  (`IN_CLUSTER=1`), which is the same path real clients on the cluster use.
  The published ports (all >20000) remain available for ad-hoc use when the
  host proxy is healthy.

## Notes

- The stack builds `nginx/` from the current checkout, so re-run `./setup.sh`
  (existing certs are kept) after updating the branch. `./setup.sh --force`
  regenerates the CA — nodes and IdP must all come back up together
  (`docker compose down && docker compose up -d`).
- First image build compiles OpenResty (~2 min); later builds are fast.
- Image tags are `hepcdn-test-nginx-webdav` / `hepcdn-test-idp` so this stack
  never collides with other nginx-webdav images on the host.
