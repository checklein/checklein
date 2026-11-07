#!/usr/bin/env bash
# Sends four requests through a running demo stack and shows what the app received.
#
#   docker compose -f deploy/nginx/compose.yml up -d --build   # or traefik / caddy
#   deploy/demo.sh                                              # default: localhost:8080
#
# The signed request uses the published RFC 9421 test key, which
# examples/trust-list.json trusts. Demo only: that private key is public.
set -euo pipefail

HOST="${1:-localhost:8080}"
cd "$(dirname "$0")/.."
HEADERS="$(mktemp)"
trap 'rm -f "$HEADERS"' EXIT

show() { tr -d '\r' | grep -iE '^HTTP|^Checklein-' || true; }

echo "== 1. Claims to be ChatGPT, no signature"
curl -s -i "http://$HOST/" -A "Mozilla/5.0 (compatible; ChatGPT-User/1.0)" | show

cargo run -q -p checklein-webbotauth --example sign-test-request -- "$HOST" > "$HEADERS"
echo
echo "== 2. Signed by a trusted agent operator"
curl -s -i "http://$HOST/" -H @"$HEADERS" | show

echo
echo "== 3. The same signed request, replayed"
curl -s -i "http://$HOST/" -H @"$HEADERS" | show

echo
echo "== 4. Client forges Checklein headers"
curl -s -i "http://$HOST/" -H "Checklein-Assurance: 4" -H "Checklein-Operator: https://trusted.example" | show
