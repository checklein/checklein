# Checklein

An open-source, neutral verifier for AI agent traffic.

Agents reach sites, APIs and MCP servers carrying credentials from several incompatible schemes: Web Bot Auth, Visa TAP and Mastercard Agent Pay signature variants, MCP OAuth tokens, A2A signed cards. Checklein runs on the receiving side. In one call it checks every credential on a request and returns one normalized verdict with an assurance level. It then applies your policy and writes a signed, hash-chained receipt you can use in disputes and audits.

It issues no identities, invents no new credential format, and does no KYC.

> **Status: early.** Web Bot Auth and MCP OAuth are implemented end to end. Payment-network schemes and policy-engine hooks are planned. Run it in shadow mode (observe and label, don't block) before relying on it.

## What works today

| Piece | State |
| --- | --- |
| RFC 9421 HTTP Message Signatures (Ed25519) | Verified against RFC 9421 Appendix B.2.6 |
| Web Bot Auth adapter (draft-01) | Dictionary `Signature-Agent` form and Cloudflare's string form; `@authority` or `@target-uri` coverage |
| Replay protection | On by default: each signature (or keyid + nonce) is remembered until it expires |
| MCP OAuth adapter (`--mcp-config`) | JWT access tokens (RS256, ES256, EdDSA and more): trusted issuers, RFC 8707 audience, RFC 9068 `at+jwt`, RFC 8693 delegation chains, client identity from Client ID Metadata Document URLs, machine vs user tokens, subjects pseudonymized. Verified against real Keycloak tokens |
| Step-up for MCP clients | `--require-delegation` + `--resource-metadata`: `401` with `WWW-Authenticate` (RFC 9728), and `error="invalid_token"` for bad tokens |
| Assurance ladder L0–L3 | L4 (human-bound) needs identity attestations |
| Key resolution | Pinned keys, then trust lists, then operator directories, with revocation |
| Signed trust lists | `checklein trust-list sign` / `verify`; lists are JWS-signed by a publisher key you pin (`--trust-list-key`), must carry an expiry, and are refused when tampered, expired or signed by anyone else. `--require-signed-trust-lists` refuses unsigned files |
| Live directory fetch (`--fetch`) | HTTPS only, public addresses only (checked at connect time), no redirects or proxies, size/time caps, `max-age` caching, negative caching |
| Interop with Cloudflare's `web-bot-auth` crate | Their published vector verifies here; their signer's output verifies here; their verifier agrees with ours on every vector |
| Built-in threshold policy | Cedar and OPA hooks not yet |
| Signed, hash-chained receipts | Compact JWS (EdDSA); `verify-chain` detects edits and dropped entries |
| Receipt checkpoints | `--checkpoints FILE --checkpoint-every N`: signed checkpoints on separate storage; `verify-chain --checkpoints` detects a log cut short or rewritten |
| Forward-auth server (`serve`) | For nginx `auth_request`, Traefik `ForwardAuth`, Caddy `forward_auth`: answers 200 or 403 with `Checklein-*` headers. See [`deploy/`](deploy/README.md) |
| Docker image | Multi-stage build to a distroless, non-root image (about 55 MB) |
| Live proxy demos | nginx, Traefik and Caddy verified end to end with `deploy/demo.sh` |
| Conformance vectors | 16 Web Bot Auth vectors in `vectors/web-bot-auth/`, 21 MCP OAuth vectors in `vectors/mcp-oauth/` |
| CLI | `verify`, `serve`, `selftest`, `conformance`, `verify-chain`, `trust-list sign/verify`, `keygen` |
| Fuzzing | `cargo-fuzz` targets for every parser that sees untrusted input; runs weekly in CI |

## Install

Docker (linux/amd64 and linux/arm64):

```bash
docker pull ghcr.io/checklein/checklein:0.3
docker run --rm -p 127.0.0.1:8787:8787 ghcr.io/checklein/checklein:0.3 serve --listen 0.0.0.0:8787
```

Prebuilt binaries for Linux (static, x86_64 and aarch64) and macOS (Apple silicon and Intel) are on the [releases page](https://github.com/checklein/checklein/releases), each with a `.sha256` checksum. The macOS binaries are not notarized yet: if you downloaded one with a browser, run `xattr -d com.apple.quarantine checklein` before the first launch. To build from source you need Rust 1.95 or newer: `cargo build --release -p checklein-cli`.

## Try it

From a clone of the repo:

```bash
cargo build
./target/debug/checklein conformance vectors/web-bot-auth
./target/debug/checklein verify examples/signed-request.http --trust-list examples/trust-list.json --now 1735689600
./target/debug/checklein verify examples/spoofed-request.http --now 1735689600
```

In front of an existing proxy:

```bash
./target/debug/checklein serve --trust-list examples/trust-list.json --fetch
curl -i http://127.0.0.1:8787/check -H "X-Forwarded-Host: site.example" -H "User-Agent: ChatGPT-User/1.0"
```

Proxy configs (nginx, Traefik, Caddy) and Docker Compose demos are in [`deploy/`](deploy/README.md).

Live checks against Cloudflare's public test deployment (network required):

```bash
cargo test -p checklein-fetch --test fetch -- --ignored live
cargo test -p checklein-interop --test cloudflare -- --ignored live
```

Receipts:

```bash
./target/debug/checklein keygen --out receipt-key.hex      # prints the public JWK; note its "x"
./target/debug/checklein verify examples/signed-request.http --trust-list examples/trust-list.json \
  --now 1735689600 --receipts receipts.jwsl --receipt-key receipt-key.hex --rp https://site.example
./target/debug/checklein verify-chain receipts.jwsl --public-key <x>
```

## Assurance

| Level | Meaning |
| --- | --- |
| 0 | Declared: only a User-Agent string. A known agent name with no credential is flagged `unverified_agent_claim`. |
| 1 | Signed: valid signature, but the key was found only in the operator's own directory. |
| 2 | Trusted operator: the key is pinned or on a loaded trust list. |
| 3 | Delegated: a valid access token from a trusted issuer, for this resource, on behalf of a user (MCP OAuth). |
| 4 | Human-bound: plus an identity attestation (not yet implemented). |

The default policy allows L2 and above, rate-limits L1, and passes L0 through to your existing bot defenses. It challenges invalid credentials and denies operator conflicts. Checklein never makes a site less protected than it was.

## Layout

```
crates/checklein-core        request view, findings, assurance, policy, receipts, verifier
crates/checklein-httpsig     RFC 9421 parsing, signature base, Ed25519 verify and sign
crates/checklein-webbotauth  Web Bot Auth adapter and the conformance-vector runner
crates/checklein-fetch       live key-directory fetching with SSRF guards and caching
crates/checklein-mcp         MCP OAuth adapter (JWT access tokens, delegation) and its vector runner
crates/checklein-interop     interop tests against Cloudflare's web-bot-auth crate
crates/checklein-serve       forward-auth HTTP server behind `checklein serve`, and `selftest`
crates/checklein-cli         the `checklein` binary
vectors/                     conformance vectors, usable by any verifier
examples/                    sample requests and trust list
deploy/                      nginx, Traefik and Caddy configs; Docker Compose demos
fuzz/                        cargo-fuzz targets and seed corpora (nightly toolchain)
scripts/                     interop-keycloak.sh: real tokens from a throwaway Keycloak
```

## Known gaps

- The replay cache is per process. Several instances behind a load balancer need a shared store (plug one in with `WebBotAuth::with_replay_guard`).
- A fetched directory's own response signature is not verified yet. Keys from fetched directories stay at L1, which limits the impact.
- Directory fetching is synchronous (blocking, 500 ms default cap). An async resolver for servers is planned.
- In `serve` mode, request bodies are not forwarded, so signatures covering `Content-Digest` cannot be checked.
- Unsigned trust lists are still accepted, with a warning, unless `--require-signed-trust-lists` is set.
- A signed trust list can be replayed until it expires (keep validity short, 7 days by default); there is no version-rollback check yet.
- Receipts written after the latest checkpoint are only hash-linked: cutting them off is detectable only up to that checkpoint.
- Web Bot Auth accepts Ed25519 keys only.
- MCP OAuth: opaque tokens (introspection) and sender-constrained tokens (DPoP, mTLS `cnf`) are refused rather than accepted unbound.
- MCP OAuth: authorization servers that don't follow RFC 9068 for machine tokens need a `machine_token_claims` rule (see `deploy/README.md`), or a machine token can look like a user.

## What Checklein does not claim

A valid verdict means "this operator signed this request, with this key provenance". It does not mean the agent is acting on its user's wishes. Checklein cannot detect prompt injection, and it does not catch agents that sign nothing.

## License and contributing

Apache-2.0. Contributions use the [Developer Certificate of Origin](CONTRIBUTING.md): sign off each commit with `git commit -s`.
