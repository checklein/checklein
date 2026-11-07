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

## Useful flags

```bash
checklein serve \
  --listen 127.0.0.1:8787 \
  --trust-list trust-list.json \
  --fetch \
  --receipts receipts.jwsl --receipt-key receipt-key.hex --rp https://your.site \
  --deny-on challenge
```
