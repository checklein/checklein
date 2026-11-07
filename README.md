# Checklein

An open-source, neutral verifier for AI agent traffic.

Agents reach sites, APIs and MCP servers carrying credentials from several incompatible schemes: Web Bot Auth, Visa TAP and Mastercard Agent Pay signature variants, MCP OAuth tokens, A2A signed cards. Checklein runs on the receiving side. In one call it checks every credential on a request and returns one normalized verdict with an assurance level. It then applies your policy and writes a signed, hash-chained receipt you can use in disputes and audits.

It issues no identities, invents no new credential format, and does no KYC.

> **Status: v0.1.0, early.** Web Bot Auth is implemented end to end. MCP OAuth delegation, payment-network schemes and policy-engine hooks are planned. Run it in shadow mode (observe and label, don't block) before relying on it.

## What works today

| Piece | State |
| --- | --- |
| RFC 9421 HTTP Message Signatures (Ed25519) | Verified against RFC 9421 Appendix B.2.6 |
| Web Bot Auth adapter (draft-01) | Dictionary `Signature-Agent` form and Cloudflare's string form; `@authority` or `@target-uri` coverage |
| Replay protection | On by default: each signature (or keyid + nonce) is remembered until it expires |
| Assurance ladder L0–L2 | L3 (delegated) and L4 (human-bound) need the MCP OAuth and IDV adapters |
| Key resolution | Pinned keys, then trust lists, then operator directories, with revocation |
| Live directory fetch (`--fetch`) | HTTPS only, public addresses only (checked at connect time), no redirects or proxies, size/time caps, `max-age` caching, negative caching |
| Interop with Cloudflare's `web-bot-auth` crate | Their published vector verifies here; their signer's output verifies here; their verifier agrees with ours on every vector |
| Built-in threshold policy | Cedar and OPA hooks not yet |
| Signed, hash-chained receipts | Compact JWS (EdDSA); `verify-chain` detects edits and dropped entries |
| Forward-auth server (`serve`) | For nginx `auth_request`, Traefik `ForwardAuth`, Caddy `forward_auth`: answers 200 or 403 with `Checklein-*` headers. See [`deploy/`](deploy/README.md) |
| Docker image | Multi-stage build to a distroless, non-root image (about 55 MB) |
| Live proxy demos | nginx, Traefik and Caddy verified end to end with `deploy/demo.sh` |
| Conformance vectors | 16 Web Bot Auth vectors in `vectors/web-bot-auth/` |
| CLI | `verify`, `serve`, `conformance`, `verify-chain`, `keygen` |

## Install

Docker (linux/amd64 and linux/arm64):

```bash
docker pull ghcr.io/checklein/checklein:0.1
docker run --rm -p 127.0.0.1:8787:8787 ghcr.io/checklein/checklein:0.1 serve --listen 0.0.0.0:8787
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
| 3 | Delegated: plus a delegated-principal credential (not yet implemented). |
| 4 | Human-bound: plus an identity attestation (not yet implemented). |

The default policy allows L2 and above, rate-limits L1, and passes L0 through to your existing bot defenses. It challenges invalid credentials and denies operator conflicts. Checklein never makes a site less protected than it was.

## Layout

```
crates/checklein-core        request view, findings, assurance, policy, receipts, verifier
crates/checklein-httpsig     RFC 9421 parsing, signature base, Ed25519 verify and sign
crates/checklein-webbotauth  Web Bot Auth adapter and the conformance-vector runner
crates/checklein-fetch       live key-directory fetching with SSRF guards and caching
crates/checklein-interop     interop tests against Cloudflare's web-bot-auth crate
crates/checklein-serve       forward-auth HTTP server behind `checklein serve`
crates/checklein-cli         the `checklein` binary
vectors/                     conformance vectors, usable by any verifier
examples/                    sample requests and trust list
deploy/                      nginx, Traefik and Caddy configs; Docker Compose demos
```

## Known gaps

- The replay cache is per process. Several instances behind a load balancer need a shared store (plug one in with `WebBotAuth::with_replay_guard`).
- A fetched directory's own response signature is not verified yet. Keys from fetched directories stay at L1, which limits the impact.
- Directory fetching is synchronous (blocking, 500 ms default cap). An async resolver for servers is planned.
- In `serve` mode, request bodies are not forwarded, so signatures covering `Content-Digest` cannot be checked.
- Trust lists are not signature-checked yet (JWS planned).
- Receipt checkpoints are not implemented, so truncating the newest entries is not detectable yet.
- Only Ed25519 keys are accepted.

## What Checklein does not claim

A valid verdict means "this operator signed this request, with this key provenance". It does not mean the agent is acting on its user's wishes. Checklein cannot detect prompt injection, and it does not catch agents that sign nothing.

## License and contributing

Apache-2.0. Contributions use the [Developer Certificate of Origin](CONTRIBUTING.md): sign off each commit with `git commit -s`.
