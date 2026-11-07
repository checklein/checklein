//! Runs every vector in `vectors/mcp-oauth/`.
//!
//! Regenerate with:
//!   cargo test -p checklein-mcp --test conformance -- --ignored generate_vectors

use std::fs;
use std::path::PathBuf;

use checklein_core::Decision;
use checklein_mcp::vectors::{Expect, Vector, run};
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};

const NOW: i64 = 1_790_000_000;
const ISS: &str = "https://auth.example";
const RESOURCE: &str = "https://mcp.example/mcp";
const CLIENT: &str = "https://client.example/oauth/client-metadata.json";

fn pem(name: &str) -> Vec<u8> {
    fs::read(format!(
        "{}/tests/keys/{name}.pem",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn enc(alg: Algorithm) -> EncodingKey {
    match alg {
        Algorithm::RS256 => EncodingKey::from_rsa_pem(&pem("rsa")).unwrap(),
        Algorithm::ES256 => EncodingKey::from_ec_pem(&pem("ec")).unwrap(),
        Algorithm::EdDSA => EncodingKey::from_ed_pem(&pem("ed25519")).unwrap(),
        _ => unreachable!(),
    }
}

fn kid(alg: Algorithm) -> &'static str {
    match alg {
        Algorithm::RS256 => "rsa-1",
        Algorithm::ES256 => "ec-1",
        Algorithm::EdDSA => "ed-1",
        _ => unreachable!(),
    }
}

fn mcp_config() -> Value {
    let keys: Vec<Jwk> = [Algorithm::RS256, Algorithm::ES256, Algorithm::EdDSA]
        .into_iter()
        .map(|alg| {
            let mut jwk = Jwk::from_encoding_key(&enc(alg), alg).unwrap();
            jwk.common.key_id = Some(kid(alg).into());
            jwk
        })
        .collect();
    json!({
        "resource": [RESOURCE],
        "issuers": [{ "issuer": ISS, "jwks": JwkSet { keys } }],
        "subject_key": "000102030405060708090a0b0c0d0e0f"
    })
}

fn claims() -> Value {
    json!({
        "iss": ISS, "aud": RESOURCE, "sub": "user-123", "client_id": CLIENT,
        "scope": "tools:read tools:call", "iat": NOW - 10, "exp": NOW + 300
    })
}

fn token(alg: Algorithm, typ: &str, kid_: &str, claims: &Value, key: &EncodingKey) -> String {
    let mut h = Header::new(alg);
    h.typ = Some(typ.into());
    h.kid = Some(kid_.into());
    encode(&h, claims, key).unwrap()
}

fn ok_token(alg: Algorithm, claims: &Value) -> String {
    token(alg, "at+jwt", kid(alg), claims, &enc(alg))
}

fn request(token: Option<&str>) -> String {
    let auth = token
        .map(|t| format!("authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    format!(
        "POST /mcp HTTP/1.1\r\nhost: mcp.example\r\ncontent-type: application/json\r\n{auth}\r\n"
    )
}

fn vector(
    name: &str,
    description: &str,
    token: Option<&str>,
    require_delegation: bool,
    expect: Expect,
) -> Vector {
    Vector {
        name: name.into(),
        description: description.into(),
        request: request(token),
        now: NOW,
        mcp_config: mcp_config(),
        require_delegation,
        expect,
    }
}

fn l3() -> Expect {
    Expect {
        assurance: 3,
        decision: Decision::Allow,
        operator: Some("https://client.example".into()),
        scope: vec!["tools:read".into(), "tools:call".into()],
        has_principal: true,
        ..Default::default()
    }
}

fn invalid(reason: &str) -> Expect {
    Expect {
        assurance: 0,
        decision: Decision::Challenge,
        reason_contains: Some(reason.into()),
        ..Default::default()
    }
}

fn with(mut c: Value, key: &str, v: Value) -> Value {
    c[key] = v;
    c
}

fn build_vectors() -> Vec<Vector> {
    let mut v = Vec::new();
    for (alg, name) in [
        (Algorithm::RS256, "rs256"),
        (Algorithm::ES256, "es256"),
        (Algorithm::EdDSA, "eddsa"),
    ] {
        v.push(vector(
            &format!("valid-{name}-user-delegated"),
            "A user-delegated access token for this resource from a trusted issuer: L3.",
            Some(&ok_token(alg, &claims())),
            false,
            l3(),
        ));
    }
    let mut cc = claims();
    cc.as_object_mut().unwrap().remove("sub");
    v.push(vector(
        "valid-client-credentials",
        "A machine token (no sub): the issuer vouches for the client, not a user. L2.",
        Some(&ok_token(Algorithm::RS256, &cc)),
        false,
        Expect {
            assurance: 2,
            decision: Decision::Allow,
            operator: Some("https://client.example".into()),
            ..Default::default()
        },
    ));
    let m2m = |sub: Value, extra: Option<(&str, Value)>| {
        let mut c = with(claims(), "sub", sub);
        if let Some((k, val)) = extra {
            c[k] = val;
        }
        ok_token(Algorithm::RS256, &c)
    };
    let machine = Expect {
        assurance: 2,
        decision: Decision::Allow,
        operator: Some("https://client.example".into()),
        ..Default::default()
    };
    v.push(vector(
        "machine-sub-equals-client-id",
        "RFC 9068: sub equals client_id, so there is no user: L2.",
        Some(&m2m(json!(CLIENT), None)),
        false,
        machine.clone(),
    ));
    v.push(vector(
        "machine-gty-client-credentials",
        "gty client-credentials (Auth0 style): L2.",
        Some(&m2m(
            json!("abc123@clients"),
            Some(("gty", json!("client-credentials"))),
        )),
        false,
        machine.clone(),
    ));
    let mut kc = vector(
        "machine-issuer-rule",
        "A per-issuer rule (Keycloak service accounts) marks the token as a machine token: L2.",
        Some(&m2m(
            json!("ace598d5-411a-49ad-b61d-b7748fc0b6b2"),
            Some(("preferred_username", json!("service-account-mcp-client"))),
        )),
        false,
        machine,
    );
    kc.mcp_config["issuers"][0]["machine_token_claims"] =
        json!([{"claim": "preferred_username", "prefix": "service-account-"}]);
    v.push(kc);
    v.push(vector(
        "valid-delegation-chain",
        "RFC 8693 act chain: agent-a delegated to agent-b, oldest first.",
        Some(&ok_token(
            Algorithm::RS256,
            &with(
                claims(),
                "act",
                json!({"sub": "agent-b", "act": {"sub": "agent-a"}}),
            ),
        )),
        false,
        Expect {
            delegation: vec!["agent-a".into(), "agent-b".into()],
            ..l3()
        },
    ));
    v.push(vector(
        "step-up-missing-token",
        "The resource requires delegation and the request has no token: step_up (401 in serve).",
        None,
        true,
        Expect {
            assurance: 0,
            decision: Decision::StepUp,
            ..Default::default()
        },
    ));
    v.push(vector(
        "step-up-client-credentials",
        "The resource requires a user; a machine token is not enough: step_up.",
        Some(&ok_token(Algorithm::RS256, &cc)),
        true,
        Expect {
            assurance: 2,
            decision: Decision::StepUp,
            operator: Some("https://client.example".into()),
            ..Default::default()
        },
    ));
    v.push(vector(
        "invalid-audience",
        "Token issued for a different resource (RFC 8707).",
        Some(&ok_token(
            Algorithm::RS256,
            &with(claims(), "aud", json!("https://other.example/mcp")),
        )),
        false,
        invalid("audience"),
    ));
    v.push(vector(
        "invalid-expired",
        "exp two minutes ago, beyond the 60 s skew.",
        Some(&ok_token(
            Algorithm::RS256,
            &with(claims(), "exp", json!(NOW - 120)),
        )),
        false,
        invalid("expired"),
    ));
    v.push(vector(
        "invalid-not-yet-valid",
        "nbf ten minutes ahead.",
        Some(&ok_token(
            Algorithm::RS256,
            &with(claims(), "nbf", json!(NOW + 600)),
        )),
        false,
        invalid("nbf"),
    ));
    v.push(vector(
        "invalid-untrusted-issuer",
        "Issuer not in the config.",
        Some(&ok_token(
            Algorithm::RS256,
            &with(claims(), "iss", json!("https://evil.example")),
        )),
        false,
        invalid("not trusted"),
    ));
    let other = EncodingKey::from_rsa_pem(&pem("rsa-other")).unwrap();
    v.push(vector(
        "invalid-forged-signature",
        "Signed by another key that claims the trusted kid.",
        Some(&token(
            Algorithm::RS256,
            "at+jwt",
            "rsa-1",
            &claims(),
            &other,
        )),
        false,
        invalid("does not verify"),
    ));
    v.push(vector(
        "invalid-typ-jwt",
        "Header typ JWT, not at+jwt: could be an ID token (RFC 9068).",
        Some(&token(
            Algorithm::RS256,
            "JWT",
            "rsa-1",
            &claims(),
            &enc(Algorithm::RS256),
        )),
        false,
        invalid("at+jwt"),
    ));
    let hs = encode(
        &Header::new(Algorithm::HS256),
        &claims(),
        &EncodingKey::from_secret(b"shared"),
    )
    .unwrap();
    v.push(vector(
        "invalid-hmac-algorithm",
        "HS256: symmetric algorithms are refused.",
        Some(&hs),
        false,
        invalid("not allowed"),
    ));
    let b64 = |s: &str| checklein_core::encoding::b64url(s.as_bytes());
    let none = format!(
        "{}.{}.",
        b64(r#"{"alg":"none","typ":"at+jwt"}"#),
        b64(&claims().to_string())
    );
    v.push(vector(
        "invalid-alg-none",
        "alg none with an empty signature.",
        Some(&none),
        false,
        Expect {
            assurance: 0,
            decision: Decision::Challenge,
            ..Default::default()
        },
    ));
    v.push(vector("invalid-delegation-too-deep", "Five nested act entries; the limit is four.",
        Some(&ok_token(Algorithm::RS256, &with(claims(), "act", json!({"sub":"5","act":{"sub":"4","act":{"sub":"3","act":{"sub":"2","act":{"sub":"1"}}}}})))),
        false, invalid("too deep")));
    v.push(vector(
        "invalid-sender-constrained",
        "cnf present (DPoP or mTLS binding): not supported yet, so refused.",
        Some(&ok_token(
            Algorithm::RS256,
            &with(claims(), "cnf", json!({"jkt": "abc"})),
        )),
        false,
        invalid("sender-constrained"),
    ));
    v.push(vector(
        "invalid-opaque-token",
        "Not a JWT: would need introspection.",
        Some("opaque-token-value"),
        false,
        invalid("opaque"),
    ));
    v
}

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/mcp-oauth")
}

#[test]
#[ignore = "writes vectors/mcp-oauth/*.json"]
fn generate_vectors() {
    fs::create_dir_all(dir()).unwrap();
    for v in build_vectors() {
        fs::write(
            dir().join(format!("{}.json", v.name)),
            serde_json::to_string_pretty(&v).unwrap() + "\n",
        )
        .unwrap();
    }
}

#[test]
fn generated_vectors_pass_in_memory() {
    for v in build_vectors() {
        run(&v).unwrap_or_else(|e| panic!("{}: {e}", v.name));
    }
}

#[test]
fn vector_files_pass() {
    let mut paths: Vec<_> = fs::read_dir(dir())
        .expect("vectors dir")
        .flatten()
        .map(|e| e.path())
        .collect();
    paths.sort();
    let mut n = 0;
    for p in paths
        .iter()
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
    {
        let v: Vector = serde_json::from_str(&fs::read_to_string(p).unwrap()).unwrap();
        run(&v).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
        n += 1;
    }
    assert!(n >= 15, "found {n} vectors");
}
