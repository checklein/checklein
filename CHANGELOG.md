# Changelog

All notable changes to Checklein. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/). Before 1.0, minor versions may change APIs and formats.

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

[0.1.0]: https://github.com/checklein/checklein/releases/tag/v0.1.0
