#!/usr/bin/env bash
# Interop: real access tokens from Keycloak, verified by `checklein verify`.
#
#   scripts/interop-keycloak.sh            # needs Docker and a built checklein (cargo build)
#
# Starts a throwaway Keycloak (dev mode, localhost only), creates a realm, an MCP client
# that issues RFC 9068 at+jwt tokens with this resource as audience, and a test user.
# Every credential here is a local test value for this container only.
set -euo pipefail

cd "$(dirname "$0")/.."
CK="${CK:-./target/debug/checklein}"
KC_IMAGE="${KC_IMAGE:-quay.io/keycloak/keycloak:26.4}"
PORT=8180
KC="http://localhost:$PORT"
REALM=checklein
RESOURCE="https://mcp.example/mcp"
WORK="$(mktemp -d)"
NAME="checklein-keycloak-interop"
ADMIN_PW="admin-$(openssl rand -hex 8)"
CLIENT_SECRET="secret-$(openssl rand -hex 16)"
USER_PW="user-$(openssl rand -hex 8)"
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT

json() { python3 -I -c "import sys,json; d=json.load(sys.stdin); print(eval(sys.argv[1], {'d': d}))" "$1"; }

echo "== starting Keycloak ($KC_IMAGE)"
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" -p "127.0.0.1:$PORT:8080" \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD="$ADMIN_PW" \
  "$KC_IMAGE" start-dev >/dev/null
for _ in $(seq 1 120); do curl -sf "$KC/realms/master" >/dev/null && break; sleep 1; done
curl -sf "$KC/realms/master" >/dev/null || { echo "Keycloak did not start"; docker logs "$NAME" | tail -20; exit 1; }

ADMIN_TOKEN=$(curl -sf "$KC/realms/master/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=admin-cli -d username=admin --data-urlencode "password=$ADMIN_PW" | json "d['access_token']")
api() { curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" "$@"; }

echo "== creating realm, MCP client and test user"
api -X POST "$KC/admin/realms" -d "{\"realm\":\"$REALM\",\"enabled\":true}"
api -X POST "$KC/admin/realms/$REALM/clients" -d @- <<JSON
{
  "clientId": "mcp-client",
  "enabled": true,
  "publicClient": false,
  "secret": "$CLIENT_SECRET",
  "serviceAccountsEnabled": true,
  "directAccessGrantsEnabled": true,
  "standardFlowEnabled": false,
  "attributes": { "access.token.header.type.rfc9068": "true" },
  "protocolMappers": [{
    "name": "mcp-audience",
    "protocol": "openid-connect",
    "protocolMapper": "oidc-audience-mapper",
    "config": { "included.custom.audience": "$RESOURCE", "access.token.claim": "true", "id.token.claim": "false" }
  }]
}
JSON
api -X POST "$KC/admin/realms/$REALM/users" -d @- <<JSON
{
  "username": "alice", "enabled": true, "emailVerified": true,
  "email": "alice@example.test", "firstName": "Alice", "lastName": "Test",
  "credentials": [{ "type": "password", "value": "$USER_PW", "temporary": false }]
}
JSON

token() { curl -sf "$KC/realms/$REALM/protocol/openid-connect/token" -d client_id=mcp-client --data-urlencode "client_secret=$CLIENT_SECRET" "$@" | json "d['access_token']"; }
MACHINE=$(token -d grant_type=client_credentials)
USER=$(token -d grant_type=password -d username=alice --data-urlencode "password=$USER_PW" -d scope=openid)

ISS="$KC/realms/$REALM"
curl -sf "$ISS/protocol/openid-connect/certs" > "$WORK/jwks.json"
config() { # $1 = resource
  python3 -I - "$ISS" "$1" "$WORK/jwks.json" > "$WORK/mcp.json" <<'PY'
import json, sys
iss, resource, jwks = sys.argv[1], sys.argv[2], json.load(open(sys.argv[3]))
rule = {"claim": "preferred_username", "prefix": "service-account-"}  # Keycloak service accounts
print(json.dumps({"resource": [resource], "issuers": [{"issuer": iss, "jwks": jwks, "machine_token_claims": [rule]}],
                  "subject_key": "000102030405060708090a0b0c0d0e0f"}))
PY
}
request() { printf 'POST /mcp HTTP/1.1\r\nHost: mcp.example\r\nAuthorization: Bearer %s\r\n\r\n' "$1" > "$WORK/req.http"; }
verdict() { "$CK" verify "$WORK/req.http" --mcp-config "$WORK/mcp.json" | json "$1"; }

fail=0
check() { # name, got, want
  if [[ "$2" == "$3" ]]; then echo "PASS  $1 ($2)"; else echo "FAIL  $1: got $2, want $3"; fail=1; fi
}

if [[ -n "${DUMP_CLAIMS:-}" ]]; then
  for t in "$MACHINE" "$USER"; do
    python3 -I -c "import sys,base64,json;p=sys.argv[1].split('.')[1];print(json.dumps({k:v for k,v in json.loads(base64.urlsafe_b64decode(p+'='*(-len(p)%4))).items() if k in ('sub','client_id','azp','preferred_username','typ','aud','scope')}))" "$t"
  done
fi
echo "== header typ of Keycloak tokens: $(python3 -I -c "import sys,base64,json;h=sys.argv[1].split('.')[0];print(json.loads(base64.urlsafe_b64decode(h+'='*(-len(h)%4)))['typ'])" "$USER")"
config "$RESOURCE"
request "$USER"
check "user token (password grant) is L3" "$(verdict "d['context']['assurance']")" "3"
check "user token has a principal" "$(verdict "d['context'].get('principal') is not None")" "True"
check "user token key source" "$(verdict "d['context']['agent']['key_source']")" "issuer:$ISS"
request "$MACHINE"
check "machine token (client credentials) is L2" "$(verdict "d['context']['assurance']")" "2"
config "https://other.example/mcp"
request "$USER"
check "token for another resource is rejected" "$(verdict "d['decision']")" "challenge"
check "rejection reason" "$(verdict "'audience' in d['context']['evidence'][0]['reason']")" "True"

exit $fail
