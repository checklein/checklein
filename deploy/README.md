# Deploying Checklein in front of an app

`checklein serve` is a forward-auth server: your existing reverse proxy asks it about each request before passing the request on. You don't change the app.

```
client ──► proxy (nginx / Traefik / Caddy) ──► your app
              │  ▲
              ▼  │ 200 + Checklein-* headers, or 403
          checklein serve
```

## What the proxy gets back

| Status | When |
| --- | --- |
| 200 | Let the request through. Copy the `Checklein-*` headers upstream. |
| 403 | The decision is `deny`, or is listed with `--deny-on` (for example `--deny-on challenge`). |
| 400 | The proxy sent no host, or a URI that is not a path. |

Headers on every 200 and 403. All five are always present (`none` for an unknown operator or no flags), so a proxy copying them overwrites client-sent copies:

| Header | Example |
| --- | --- |
| `Checklein-Decision` | `allow`, `rate_limit`, `challenge`, `pass`, `deny` |
| `Checklein-Assurance` | `0`–`4` |
| `Checklein-Operator` | `https://chatgpt.com` |
| `Checklein-Flags` | `unverified_agent_claim` |
| `Checklein-Verdict` | `ck_6774a1d0_0` (matches the receipt) |

By default only `deny` blocks. `rate_limit`, `challenge` and `pass` are reported, and your proxy or bot defenses act on `Checklein-Decision`. Checklein never makes a site less protected than it was.

## Which forwarding headers Checklein reads

| Original | Read from |
| --- | --- |
| Method | `X-Forwarded-Method`, else `X-Original-Method`, else `GET` |
| Scheme | `X-Forwarded-Proto`, else `https` |
| Host | `X-Forwarded-Host`, else `Host` |
| Path and query | `X-Forwarded-Uri`, else `X-Original-URI`, else `/` |

Every other header is treated as part of the original request; Web Bot Auth reads `Signature`, `Signature-Input` and `Signature-Agent` from them. Bodies are not forwarded, so a signature covering `Content-Digest` cannot be checked in this mode.

**Trust boundary:** forwarding headers are believed as sent. Expose `checklein serve` only to the proxy: the default `--listen` is `127.0.0.1:8787`, and in Docker keep the port off the public network.

## Examples

| Proxy | Files | Verified live (2026-11-07) |
| --- | --- | --- |
| nginx 1.27 | [`nginx/nginx.conf`](nginx/nginx.conf), [`nginx/compose.yml`](nginx/compose.yml) | Yes: all four demo cases |
| Traefik v3.5 | [`traefik/dynamic.yml`](traefik/dynamic.yml), [`traefik/compose.yml`](traefik/compose.yml) | Yes: all four demo cases, plus a 403 with `--deny-on challenge` |
| Caddy 2.10 | [`caddy/Caddyfile`](caddy/Caddyfile), [`caddy/compose.yml`](caddy/compose.yml) | Yes: all four demo cases |

The Traefik example uses the file provider rather than Docker labels. It works outside Docker, and it avoids Traefik v3.5's Docker provider failing against Docker Engine 29 (API version mismatch).

Try one (needs Docker and a Rust toolchain for the signed request):

```bash
docker compose -f deploy/nginx/compose.yml up -d    # or traefik / caddy; pulls ghcr.io/checklein/checklein
deploy/demo.sh
```

The whoami app echoes the request it received, so the output shows what your app would see:

| Case | `Checklein-Decision` | `Checklein-Assurance` | Notes |
| --- | --- | --- | --- |
| Claims to be ChatGPT, no signature | `pass` | `0` | `Checklein-Flags: unverified_agent_claim` |
| Signed by a trusted operator | `allow` | `2` | `Checklein-Operator: https://signature-agent.test` |
| Same signed request replayed | `challenge` | `0` | 403 instead with `--deny-on challenge` |
| Client sends forged `Checklein-*` headers | `pass` | `0` | Forged values overwritten; the app sees one copy |

To sign your own test requests: `cargo run -q -p checklein-webbotauth --example sign-test-request -- <host:port>`. It uses the published RFC 9421 test key, so it is for demos only.

## Protecting an MCP server

Put Checklein in front of an MCP server to verify OAuth access tokens and require a user-delegated token:

```bash
checklein serve \
  --mcp-config mcp-config.json \
  --require-delegation \
  --resource-metadata https://mcp.example.com/.well-known/oauth-protected-resource
```

`mcp-config.json` (see [`examples/mcp-config.json`](../examples/mcp-config.json)):

```json
{
  "resource": ["https://mcp.example.com/mcp"],
  "issuers": [{ "issuer": "https://auth.example.com", "jwks_uri": "https://auth.example.com/.well-known/jwks.json" }],
  "subject_key": "<32 hex characters from: openssl rand -hex 16>"
}
```

| Request | Answer |
| --- | --- |
| Valid user token for this resource | `200`, `Checklein-Assurance: 3`, `Checklein-Decision: allow` |
| Valid machine (client-credentials) token | `401` step-up when `--require-delegation` is set, otherwise `200` at assurance 2 |
| No token | `401`, `WWW-Authenticate: Bearer resource_metadata="..."` |
| Expired, wrong audience, untrusted issuer, forged | `401`, `WWW-Authenticate: Bearer error="invalid_token", resource_metadata="..."` |

`resource` must match the `aud` your authorization server puts in tokens for this MCP server (RFC 8707). Keep `subject_key` stable: it pseudonymizes user IDs, so the same user maps to the same `subject_ref` across restarts. The raw subject never leaves Checklein.

**Provider notes**

| Authorization server | Settings |
| --- | --- |
| Keycloak | Client attribute `access.token.header.type.rfc9068: true` (issues `at+jwt`); an audience mapper for `resource`; `"machine_token_claims": [{"claim": "preferred_username", "prefix": "service-account-"}]`. Verified with `scripts/interop-keycloak.sh` |
| Auth0 | `"accept_jwt_typ": true` (Auth0 issues `typ: JWT`); machine tokens are detected from `gty: client-credentials` |
| Okta | Machine tokens use `sub == client_id` and are detected automatically; set `accept_jwt_typ` if your tokens use `typ: JWT` |

Auth0 and Okta rows follow their published token formats and have not been tested live yet.

## Check your own deployment

`checklein selftest` sends a spoofed agent, a signed test request, a replay and forged `Checklein-*` headers, and reports PASS, FAIL or SKIP for each:

```bash
# The serve endpoint directly, playing the proxy
checklein selftest --serve http://127.0.0.1:8787

# The whole path through your proxy, to an endpoint that echoes request headers
# (for example traefik/whoami routed at /checklein-echo)
checklein selftest --via https://staging.example.com/checklein-echo

# The same, with nothing installed but Docker
docker run --rm ghcr.io/checklein/checklein:0.2 selftest --via https://staging.example.com/checklein-echo
```

The signed check uses the public RFC 9421 test key, so it reports SKIP unless that key is trusted (as in `examples/trust-list.json`). In production, SKIP is the correct result. Any FAIL exits non-zero, so `selftest` can run in a deploy pipeline.

## Useful flags

```bash
checklein serve \
  --listen 127.0.0.1:8787 \
  --trust-list trust-list.json \
  --fetch \
  --receipts receipts.jwsl --receipt-key receipt-key.hex --rp https://your.site \
  --deny-on challenge
```
