# Changelog

All notable changes to Checklein. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/). Before 1.0, minor versions may change APIs and formats.

## [Unreleased]

## [0.3.0] - 2026-11-09

Adds MCP OAuth (user-delegated access tokens, assurance L3) and hardens trust: signed trust lists and receipt checkpoints.

### Added

- **MCP OAuth adapter** (`--mcp-config`): verifies JWT access tokens from configured issuers (RS256/384/512, PS256/384/512, ES256/384, EdDSA; never HMAC or `none`); RFC 8707 audience, RFC 9068 `at+jwt`, `exp`/`nbf`/`iat` against the injected clock; RFC 8693 delegation chains (depth-bounded); client identity from Client ID Metadata Document URLs; machine vs user tokens (RFC 9068 `sub == client_id`, `gty`, per-issuer rules); subjects pseudonymized with a keyed hash. Issuer keys inline or from `jwks_uri` through the SSRF-guarded fetcher, with rate-limited refetching.
- **Assurance L3** (delegated) with principal, delegation chain and scopes in the verdict.
- **Step-up for OAuth clients:** `--require-delegation` and `--resource-metadata` make `serve` answer `401` with `WWW-Authenticate` (RFC 9728), and `error="invalid_token"` for bad tokens.
- 21 MCP OAuth conformance vectors; `scripts/interop-keycloak.sh` verifies real Keycloak tokens; a `bearer` fuzz target.

### Security

- **Signed trust lists:** `checklein trust-list sign` / `verify`; `--trust-list-key` pins publisher keys; signed lists must carry `expires_at` and are refused when tampered, expired, not yet valid or signed by another key; `--require-signed-trust-lists` refuses unsigned files.
- **Receipt checkpoints:** `--checkpoints FILE --checkpoint-every N` write signed checkpoints (count + head) to separate storage; `verify-chain --checkpoints` detects a log cut short or rewritten under a checkpoint.
- Receipts, checkpoints and trust lists share one compact-JWS implementation with a distinct `typ` per artifact, so one can never be passed off as another.
- `serve` isolates panics per request; fuzzing found and fixed a remote panic on non-ASCII `Authorization` headers.

### Changed

- Loading an unsigned trust list now prints a warning (use `--require-signed-trust-lists` to refuse them).
- Library: `ReceiptChain::resume` now takes the existing receipt count as well as the head, so checkpoints continue correctly across restarts.
- Demo Compose files use the `0.3` image.

## [0.2.0] - 2026-11-07

Adds a way for operators to check their own deployment, and continuous fuzzing.

### Added

- `checklein selftest`: checks a deployment directly (`--serve`) and through the proxy (`--via`, against an endpoint that echoes request headers): spoofed agent, signed test request, replay, forged headers.
- Fuzzing: `cargo-fuzz` targets for request parsing, structured signature fields, forward-auth reconstruction, key material and receipt logs, seeded from the conformance vectors; a weekly CI job keeps a growing corpus.

### Changed

- Demo Compose files pull the published image (`ghcr.io/checklein/checklein:0.2`) instead of building locally.

## [0.1.0] - 2026-11-07

First release: Web Bot Auth verification end to end, usable in front of an existing reverse proxy.

### Added

- **Verifier core:** normalized verdict (`checklein/schema/v0`) with assurance levels L0–L2, operator-conflict detection, a built-in threshold policy, and spoofed-agent flagging (`unverified_agent_claim`).
- **RFC 9421 HTTP Message Signatures** (Ed25519), verified against RFC 9421 Appendix B.2.6.
- **Web Bot Auth adapter** (draft-ietf-webbotauth-httpsig-protocol-01): dictionary and Cloudflare string `Signature-Agent` forms; `@authority` or `@target-uri` coverage; validity window and clock-skew checks.
- **Replay protection**, on by default (keyid + nonce, else signature bytes).
- **Key resolution:** pinned keys, then trust lists, then operator directories, with revocation. Keys found only in an operator's own directory cap at L1.
- **Live key-directory fetching** (`--fetch`): HTTPS only, public addresses checked at connect time, no redirects or proxies, size and time caps, `max-age` and negative caching.
- **Signed, hash-chained receipts** (compact JWS, EdDSA) and `verify-chain` to detect edits and dropped entries.
- **Forward-auth server** (`checklein serve`) for nginx `auth_request`, Traefik `ForwardAuth` and Caddy `forward_auth`, with `Checklein-*` headers that clients cannot forge.
- **CLI:** `verify`, `serve`, `conformance`, `verify-chain`, `keygen`.
- **16 conformance vectors**, and interop tests against Cloudflare's `web-bot-auth` crate (0.7.0) in both directions.
- **Deployment:** distroless Docker image; nginx, Traefik and Caddy examples verified live; `deploy/demo.sh`.

### Known limitations

- Replay cache is per process; trust lists and fetched directories are not signature-checked yet; no receipt checkpoints; Ed25519 only; request bodies are not checked in `serve` mode.

[Unreleased]: https://github.com/checklein/checklein/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/checklein/checklein/releases/tag/v0.3.0
[0.2.0]: https://github.com/checklein/checklein/releases/tag/v0.2.0
[0.1.0]: https://github.com/checklein/checklein/releases/tag/v0.1.0
