# nebula-oidc-signer

Short-lived [Nebula](https://github.com/slackhq/nebula) host certificates in
exchange for an identity token:

- **people** log in to an OIDC provider (with a passkey) and get a
  certificate for one of their devices;
- **Kubernetes workloads** present a projected service account token and get
  a certificate for their pod.

The Nebula CA private keys never leave OpenBao/Vault: they are
non-exportable `ed25519` [transit](https://openbao.org/docs/secrets/transit/)
keys, and certificates are signed through
[`transitsign`](https://github.com/awapf/terraform-provider-nebula/tree/main/transitsign)
(the same code as
[terraform-provider-nebula](https://github.com/awapf/terraform-provider-nebula),
which you can use to create the CAs).

```
 laptop / pod                        nebula-oidc-signer                 OpenBao
 ────────────                        ──────────────────                 ───────
 X25519 key pair (stays local)
 token (OIDC login / SA token)
 POST /v1/sign {public_key, token} ─▶ verify token (JWKS, alg, iss,
                                      aud, exp/nbf/iat, age, passkey)
                                      first matching rule → CA, groups,
                                      IP pool, duration
                                      stable IP from SQLite lease
                                      build cert, sign TBS bytes ──────▶ transit/sign/<ca>
                                      verify signature + CA constraints ◀─
 host.crt, host.key, ca.crt ◀──────── {certificate, ca_bundle, not_after}
 SIGHUP nebula
```

## Why

Nebula has no online CA. Handing every host a long-lived certificate signed
offline doesn't scale to people's laptops or to pods that come and go, and
giving workloads `transit/sign` directly would let any of them mint any
certificate. This signer sits in between. It turns identities you already have
(IdP groups, Kubernetes namespaces and service accounts) into short-lived
certificates, and policy decides the groups and addresses.

## Threat model

- **Signer compromise.** A compromised signer can mint certificates, but only
  inside its CAs' constraints: Nebula refuses certificates whose groups or
  networks fall outside the signing CA's. Give each population its own CA with
  tight `groups` and `networks` (e.g. `nebula-people`,
  `nebula-k8s-<cluster>`). Do not let the signer's CAs carry the groups your
  infrastructure hosts use. The signer cannot read or export CA keys.
- **Group names are global in Nebula firewalls.** A rule like
  `groups: [admin]` matches a certificate from *any* CA the host trusts. So
  each issuer has a `grant`: the only groups and networks its logins can ever
  receive. Grants may not overlap between issuers, so a certificate's groups
  and address tell which kind of login produced it. `reserved_groups` lists
  your infrastructure's groups, and no grant may contain one, even if a CA or
  a rule would allow it. On the hosts, pin sensitive firewall rules to a CA
  (`ca_name`/`ca_sha`) and don't trust the signer's CAs where you don't need
  them.
- **Never give workloads `transit/sign` directly.** Then any workload could
  sign any certificate the CA allows, with any group and IP. The signer is
  the policy enforcement point.
- **Stolen tokens.** Tokens are accepted only for the configured audience,
  must be fresh (`max_token_age`), and Kubernetes tokens must be short-lived
  and bound to a pod. A token alone is not enough either: the certificate is
  bound to the caller's public key. Certificates are short-lived. Revocation
  isn't implemented; the design relies on expiry.
- **Token forgery.** Only asymmetric JWS algorithms are accepted (no `none`,
  no `HS*`, so no "public key as HMAC secret"). Keys come from the issuer's
  JWKS: OIDC discovery, or a pinned file for Kubernetes.
- **Weak logins.** People issuers must require an `acr` (or `amr`) value, so
  you can insist on passkeys.
- **Defence in depth.** Rules are checked against their issuer's grant and
  their CA's constraints at config load and again at issue time. Every transit signature is verified
  against the key's public half, and every certificate against its CA, before
  it is returned. The client checks that the certificate is for its key and
  chains to the returned CA bundle.
- **Abuse.** Request bodies are capped at 64 KiB, JSON decoding is strict,
  and requests are rate limited per client IP and per subject. Behind a
  reverse proxy all requests share the proxy's IP, so size `per_ip_per_minute`
  accordingly.
- **Audit.** One JSON log line per issuance (issuer, sub, rule, name, groups,
  ip, fingerprint, not_after) and per denial (status, reason). Tokens are never
  logged.

## OpenBao/Vault setup

```sh
bao secrets enable transit
bao write -f transit/keys/nebula-people type=ed25519 exportable=false
# Create the CA certificate, e.g. with terraform-provider-nebula's nebula_ca.
```

The signer's token needs exactly this, per CA key:

```hcl
# nebula-oidc-signer.hcl
path "transit/keys/nebula-people" { capabilities = ["read"] }    # public key
path "transit/sign/nebula-people" { capabilities = ["update"] }  # sign
```

```sh
bao policy write nebula-oidc-signer nebula-oidc-signer.hcl
```

Use a periodic token or an agent sink (`transit.token_file`, re-read on every
issuance). The acceptance test runs the signer with a token holding only this
policy.

## Configuration

See [`examples/config.yaml`](examples/config.yaml). In short:

- `cas`: transit key name and version plus the CA certificate (and an optional
  bundle for rotations). An optional `network` block (`lighthouses` with
  their overlay `address` and public `endpoints`, and `relays`) is returned
  with every certificate of that CA. Its addresses must lie inside the
  certificate network of each rule using the CA, or hosts could not reach
  them over the overlay.
- `issuers`: `kind: people` or `kind: kubernetes`, `issuer`, `audience`,
  `jwks` (`discovery: true` or `file:`), `max_token_age`, `algorithms`.
  - people: `username_claim` (default `preferred_username`), `groups_claim`
    (default `groups`), `acr_values` / `amr_values` (one of them required).
    The certificate name is `<username>/<device>`.
  - kubernetes: the `sub` must be `system:serviceaccount:<ns>:<sa>` and agree
    with the `kubernetes.io` claim, and the token must be bound to a pod and
    live at most `max_token_lifetime` (default 1h). The certificate name is
    `<ns>/<sa>/<pod>`.
- `grant` per issuer (required): the `groups` and `networks` its logins may
  ever receive. Every rule must fit inside it. Grants of different issuers
  must not share group names or overlap in networks, and must not contain a
  top-level `reserved_groups` entry.
- `rules` per issuer, first match wins, no match is a 403. people rules match
  `groups` (any of); kubernetes rules match `namespace` and `service_account`
  globs. A rule sets the certificate's `groups`, the `ca`, an address `pool`,
  the `network_bits` (prefix length in the certificate) and `duration`
  (capped to the CA's expiry).

Unknown keys are errors. Pools must lie inside their grant and their CA's
networks, and rule groups inside the grant and the CA's groups.

**Addresses** are leased per (issuer, subject, device). For people the device
is the client-supplied device name; for pods it is the pod UID. A lease is kept
while it renews and released `lease_grace` after its certificate expired. An
exhausted pool gives a 503 naming the pool.

## API

`POST /v1/sign`

```json
{"public_key": "-----BEGIN NEBULA X25519 PUBLIC KEY-----…", "token": "eyJ…", "device": "laptop"}
```

`device` is required for people and must be absent for Kubernetes tokens
(1–32 characters of `a-z`, `0-9`, inner `-`). The response:

```json
{"certificate": "-----BEGIN NEBULA CERTIFICATE V2-----…", "ca_bundle": "…", "not_after": "2030-01-01T12:00:00Z",
 "network": {"lighthouses": [{"address": "10.99.255.1", "endpoints": ["lighthouse1.example.com:4242"]}], "relays": ["10.99.255.1"]}}
```

`network` is present only when the CA has a `network` block.

Errors are `{"error": "…"}` with 400 (bad request), 401 (invalid token), 403
(policy), 413 (body too large), 429 (rate limited), 502 (transit) or 503 (pool
exhausted, issuer keys unavailable). `GET /healthz` returns `ok`. Nothing else
is served.

## Running

```sh
nebula-oidc-signer serve --config /etc/nebula-oidc-signer/config.yaml
```

### Client

The client generates the X25519 key locally (the private key is never sent),
gets a token, calls the signer, checks the result and writes `host.crt`,
`host.key` (0600) and `ca.crt` atomically. It reuses an existing `host.key`
unless `--rotate-key` is set. With `--pidfile` it sends nebula a SIGHUP after
renewing.

A person (opens the browser; auth code + PKCE with a loopback redirect, so
register `http://127.0.0.1` as a redirect URI for a public client):

```sh
nebula-oidc-signer client --server https://signer.example.com \
  --issuer https://idm.example.com/oauth2/openid/nebula --client-id nebula \
  --scopes openid,profile,groups --device laptop \
  --out-dir /etc/nebula --write-config /etc/nebula/config.d/00-signer.yml \
  --pidfile /run/nebula.pid
```

A pod (sidecar), with a projected token
(`audience: nebula-signer`, `expirationSeconds: 3600`):

```sh
nebula-oidc-signer client --server https://signer.example.com \
  --token-file /var/run/secrets/nebula/token --out-dir /etc/nebula \
  --renew-before 20m --watch 1m --pidfile /run/nebula/nebula.pid
```

With `--write-config FILE` the client also writes a nebula config: `pki`
pointing at the files in `--out-dir`, `static_host_map`, `lighthouse.hosts`
and `relay` from the signer, outbound open and inbound closed except ICMP.
The file is overwritten on every renewal. For your own settings, such as
inbound firewall rules, write the file into a directory
(`--write-config /etc/nebula/config.d/00-signer.yml`), add your own files
next to it and run `nebula -config /etc/nebula/config.d`. Nebula merges the
files in lexical order and appends lists, so your `firewall.inbound` rules
add to the generated ones. The tests check the generated config with
nebula's own config test (`nebula -test`).

`--renew-before D` makes a run a no-op while the current certificate is valid
for longer than `D`, which suits a systemd timer. `--watch I` keeps checking
every `I`.

## Development

```sh
go test -race ./...                       # unit + end-to-end (fake IdP, fake transit)
NEBULA_SIGNER_ACC=1 go test -run TestAcc ./...   # against `bao server -dev`, needs bao on PATH
```

The end-to-end test runs `serve` on a loopback port plus the CLI client for a
person (browser flow against the fake IdP) and for a pod.

## Next steps (not in the MVP)

- NixOS module
- sidecar container image and example Kubernetes manifests
- TokenReview liveness check for Kubernetes tokens (a deleted pod's token is
  currently valid until it expires)
- blocklist/revocation (relies on short-lived certificates for now)
- HA (the lease database is a local SQLite file)
- trusted-proxy handling for per-IP rate limits

## License

MIT, see [LICENSE](LICENSE).
