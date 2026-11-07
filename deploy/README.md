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

| Proxy | Files | Status |
| --- | --- | --- |
| nginx | [`nginx/nginx.conf`](nginx/nginx.conf), [`nginx/compose.yml`](nginx/compose.yml) | Header contract covered by Checklein's tests; not yet run against a live nginx |
| Traefik | [`traefik/compose.yml`](traefik/compose.yml) | Header contract covered by Checklein's tests; not yet run against a live Traefik |
| Caddy | [`caddy/Caddyfile`](caddy/Caddyfile) | Untested |

Try one (needs Docker):

```bash
docker compose -f deploy/nginx/compose.yml up --build
curl -i http://localhost:8080/ -A "Mozilla/5.0 (compatible; ChatGPT-User/1.0)"
```

The whoami app echoes the request it received, so you can see `Checklein-Decision: pass` and `Checklein-Flags: unverified_agent_claim` arrive upstream.

## Useful flags

```bash
checklein serve \
  --listen 127.0.0.1:8787 \
  --trust-list trust-list.json \
  --fetch \
  --receipts receipts.jwsl --receipt-key receipt-key.hex --rp https://your.site \
  --deny-on challenge
```
