//! MCP OAuth adapter behavior with real RS256, ES256 and EdDSA tokens.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use checklein_core::{
    Assurance, Checklein, Decision, FixedClock, RequestView, StaticResolver, Verdict,
};
use checklein_mcp::{IssuerConfig, JsonFetcher, McpConfig, McpOAuth};
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};

const NOW: i64 = 1_790_000_000;
const ISS: &str = "https://auth.example";
const RESOURCE: &str = "https://mcp.example/mcp";
const CLIENT: &str = "https://client.example/oauth/client-metadata.json";

fn pem(name: &str) -> Vec<u8> {
    std::fs::read(format!(
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

fn jwks() -> JwkSet {
    let keys = [Algorithm::RS256, Algorithm::ES256, Algorithm::EdDSA]
        .into_iter()
        .map(|alg| {
            let mut jwk = Jwk::from_encoding_key(&enc(alg), alg).unwrap();
            jwk.common.key_id = Some(kid(alg).into());
            jwk
        })
        .collect();
    JwkSet { keys }
}

fn config() -> McpConfig {
    McpConfig {
        resource: vec![RESOURCE.into()],
        issuers: vec![IssuerConfig {
            issuer: ISS.into(),
            jwks: Some(jwks()),
            jwks_uri: None,
            accept_jwt_typ: false,
            machine_token_claims: vec![],
        }],
        clock_skew_secs: 60,
        max_delegation_depth: 4,
        subject_key: Some("000102030405060708090a0b0c0d0e0f".into()),
    }
}

fn claims() -> Value {
    json!({
        "iss": ISS,
        "aud": RESOURCE,
        "sub": "user-123",
        "client_id": CLIENT,
        "scope": "tools:read tools:call",
        "iat": NOW - 10,
        "exp": NOW + 300,
    })
}

fn mint_with(alg: Algorithm, typ: &str, kid_: &str, claims: &Value, key: &EncodingKey) -> String {
    let mut h = Header::new(alg);
    h.typ = Some(typ.into());
    h.kid = Some(kid_.into());
    encode(&h, claims, key).unwrap()
}

fn mint(alg: Algorithm, claims: &Value) -> String {
    mint_with(alg, "at+jwt", kid(alg), claims, &enc(alg))
}

fn verify_with(cfg: McpConfig, token: &str) -> Verdict {
    let req = RequestView::new("POST", "https", "mcp.example", "/mcp")
        .with_header("Authorization", &format!("Bearer {token}"));
    Checklein::new(StaticResolver::new())
        .adapter(McpOAuth::new(cfg).unwrap())
        .clock(FixedClock(NOW))
        .verify(&req)
        .unwrap()
}

fn verify(token: &str) -> Verdict {
    verify_with(config(), token)
}

fn reason(v: &Verdict) -> String {
    v.context
        .evidence
        .iter()
        .filter_map(|e| e.reason.clone())
        .collect::<Vec<_>>()
        .join("; ")
}

fn assert_invalid(v: &Verdict, contains: &str) {
    assert_eq!(v.context.assurance, Assurance::L0Declared);
    assert_eq!(v.decision, Decision::Challenge);
    assert!(
        reason(v).contains(contains),
        "reason {:?} lacks {contains:?}",
        reason(v)
    );
}

#[test]
fn valid_tokens_reach_l3_for_every_algorithm() {
    for alg in [Algorithm::RS256, Algorithm::ES256, Algorithm::EdDSA] {
        let v = verify(&mint(alg, &claims()));
        assert_eq!(
            v.context.assurance,
            Assurance::L3Delegated,
            "{alg:?}: {}",
            reason(&v)
        );
        assert_eq!(v.decision, Decision::Allow);
        assert_eq!(
            v.context.agent.operator.as_deref(),
            Some("https://client.example")
        );
        assert_eq!(
            v.context.agent.key_source.as_deref(),
            Some("issuer:https://auth.example")
        );
        let p = v.context.principal.as_ref().unwrap();
        assert_eq!(p.issuer, ISS);
        assert!(p.subject_ref.starts_with("hmac:"));
        let intent = v.context.intent.as_ref().unwrap();
        assert_eq!(intent.scope, vec!["tools:read", "tools:call"]);
    }
}

#[test]
fn raw_subject_never_leaves_the_adapter() {
    let v = verify(&mint(Algorithm::RS256, &claims()));
    let json = serde_json::to_string(&v).unwrap();
    assert!(!json.contains("user-123"), "{json}");
}

#[test]
fn subject_ref_is_stable_and_issuer_scoped() {
    let a = verify(&mint(Algorithm::RS256, &claims()))
        .context
        .principal
        .unwrap()
        .subject_ref;
    let b = verify(&mint(Algorithm::ES256, &claims()))
        .context
        .principal
        .unwrap()
        .subject_ref;
    assert_eq!(a, b, "same issuer + subject + key => same pseudonym");
    let mut cfg = config();
    cfg.subject_key = Some("ffffffffffffffffffffffffffffffff".into());
    let c = verify_with(cfg, &mint(Algorithm::RS256, &claims()))
        .context
        .principal
        .unwrap()
        .subject_ref;
    assert_ne!(a, c, "a different relying-party key => unlinkable");
}

#[test]
fn client_credentials_token_is_l2() {
    let mut c = claims();
    c.as_object_mut().unwrap().remove("sub");
    let v = verify(&mint(Algorithm::RS256, &c));
    assert_eq!(
        v.context.assurance,
        Assurance::L2TrustedOperator,
        "{}",
        reason(&v)
    );
    assert!(v.context.principal.is_none());
}

#[test]
fn delegation_chain_oldest_first_and_bounded() {
    let mut c = claims();
    c["act"] = json!({ "sub": "agent-b", "act": { "sub": "agent-a" } });
    let v = verify(&mint(Algorithm::RS256, &c));
    let chain: Vec<_> = v
        .context
        .delegation
        .iter()
        .map(|a| a.actor.as_str())
        .collect();
    assert_eq!(chain, vec!["agent-a", "agent-b"]);

    let mut deep = claims();
    deep["act"] =
        json!({"sub":"5","act":{"sub":"4","act":{"sub":"3","act":{"sub":"2","act":{"sub":"1"}}}}});
    assert_invalid(&verify(&mint(Algorithm::RS256, &deep)), "too deep");
}

#[test]
fn wrong_audience_is_rejected() {
    let mut c = claims();
    c["aud"] = json!(["https://other.example/mcp"]);
    assert_invalid(&verify(&mint(Algorithm::RS256, &c)), "audience");
    c["aud"] = json!(["https://other.example/mcp", RESOURCE]);
    assert_eq!(
        verify(&mint(Algorithm::RS256, &c)).context.assurance,
        Assurance::L3Delegated
    );
}

#[test]
fn time_checks_use_the_injected_clock() {
    let mut c = claims();
    c["exp"] = json!(NOW - 120);
    assert_invalid(&verify(&mint(Algorithm::RS256, &c)), "expired");
    let mut c = claims();
    c["nbf"] = json!(NOW + 600);
    assert_invalid(&verify(&mint(Algorithm::RS256, &c)), "nbf");
    let mut c = claims();
    c.as_object_mut().unwrap().remove("exp");
    assert_invalid(&verify(&mint(Algorithm::RS256, &c)), "no exp");
}

#[test]
fn untrusted_issuer_and_wrong_key_are_rejected() {
    let mut c = claims();
    c["iss"] = json!("https://evil.example");
    assert_invalid(
        &verify(&mint(Algorithm::RS256, &c)),
        "issuer is not trusted",
    );

    // Signed by a different RSA key that claims the trusted kid.
    let other = EncodingKey::from_rsa_pem(&pem("rsa-other")).unwrap();
    let forged = mint_with(Algorithm::RS256, "at+jwt", "rsa-1", &claims(), &other);
    assert_invalid(&verify(&forged), "does not verify");
}

#[test]
fn typ_must_be_at_jwt_unless_issuer_opts_in() {
    let t = mint_with(
        Algorithm::RS256,
        "JWT",
        "rsa-1",
        &claims(),
        &enc(Algorithm::RS256),
    );
    assert_invalid(&verify(&t), "at+jwt");
    let mut cfg = config();
    cfg.issuers[0].accept_jwt_typ = true;
    assert_eq!(
        verify_with(cfg, &t).context.assurance,
        Assurance::L3Delegated
    );
}

#[test]
fn symmetric_and_none_algorithms_are_refused() {
    let hs = encode(
        &Header::new(Algorithm::HS256),
        &claims(),
        &EncodingKey::from_secret(b"shared"),
    )
    .unwrap();
    assert_invalid(&verify(&hs), "not allowed");
    // alg "none": header {"alg":"none"} with an empty signature.
    let b64 = |s: &str| checklein_core::encoding::b64url(s.as_bytes());
    let none = format!(
        "{}.{}.",
        b64(r#"{"alg":"none","typ":"at+jwt"}"#),
        b64(&claims().to_string())
    );
    let v = verify(&none);
    assert_eq!(v.context.assurance, Assurance::L0Declared);
    assert_eq!(v.decision, Decision::Challenge);
}

#[test]
fn sender_constrained_and_opaque_tokens_fail_closed() {
    let mut c = claims();
    c["cnf"] = json!({"jkt": "abc"});
    assert_invalid(&verify(&mint(Algorithm::RS256, &c)), "sender-constrained");
    assert_invalid(&verify("opaque-token-value"), "opaque");
}

#[test]
fn consistent_web_bot_auth_operator_is_fine_and_a_mismatch_conflicts() {
    use checklein_core::finding::KeyTrust;
    use checklein_core::{Finding, FindingResult, SchemeAdapter};
    // A stand-in adapter reporting a trusted operator signature.
    struct Signed(&'static str);
    impl SchemeAdapter for Signed {
        fn id(&self) -> &str {
            "stub"
        }
        fn detect(&self, _: &RequestView) -> bool {
            true
        }
        fn verify(
            &self,
            _: &RequestView,
            _: &dyn checklein_core::KeyResolver,
            _: &dyn checklein_core::Clock,
        ) -> Vec<Finding> {
            let mut f = Finding::new("stub@1", FindingResult::Valid);
            f.operator = Some(self.0.into());
            f.key_trust = Some(KeyTrust::Pinned);
            vec![f]
        }
    }
    let token = mint(Algorithm::RS256, &claims());
    let req = RequestView::new("POST", "https", "mcp.example", "/mcp")
        .with_header("Authorization", &format!("Bearer {token}"));
    let run = |op: &'static str| {
        Checklein::new(StaticResolver::new())
            .adapter(McpOAuth::new(config()).unwrap())
            .adapter(Signed(op))
            .clock(FixedClock(NOW))
            .verify(&req)
            .unwrap()
    };
    assert_eq!(
        run("https://client.example").context.assurance,
        Assurance::L3Delegated
    );
    let conflict = run("https://someone-else.example");
    assert_eq!(conflict.context.assurance, Assurance::L0Declared);
    assert_eq!(conflict.decision, Decision::Deny);
}

struct CountingFetcher {
    body: Vec<u8>,
    calls: AtomicUsize,
}

impl JsonFetcher for CountingFetcher {
    fn get(&self, _url: &str) -> Result<(Vec<u8>, Duration), String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok((self.body.clone(), Duration::from_secs(300)))
    }
}

#[test]
fn jwks_uri_is_fetched_once_and_unknown_kids_do_not_refetch() {
    let fetcher = Arc::new(CountingFetcher {
        body: serde_json::to_vec(&jwks()).unwrap(),
        calls: AtomicUsize::new(0),
    });
    let mut cfg = config();
    cfg.issuers[0].jwks = None;
    cfg.issuers[0].jwks_uri = Some("https://auth.example/jwks".into());
    let adapter = McpOAuth::new(cfg).unwrap().with_fetcher(fetcher.clone());
    let ck = Checklein::new(StaticResolver::new())
        .adapter(adapter)
        .clock(FixedClock(NOW));
    let req = |t: &str| {
        RequestView::new("POST", "https", "mcp.example", "/mcp")
            .with_header("Authorization", &format!("Bearer {t}"))
    };

    for _ in 0..3 {
        let v = ck.verify(&req(&mint(Algorithm::ES256, &claims()))).unwrap();
        assert_eq!(v.context.assurance, Assurance::L3Delegated);
    }
    let unknown = mint_with(
        Algorithm::RS256,
        "at+jwt",
        "rotated-away",
        &claims(),
        &enc(Algorithm::RS256),
    );
    for _ in 0..5 {
        assert_eq!(
            ck.verify(&req(&unknown)).unwrap().decision,
            Decision::Challenge
        );
    }
    assert_eq!(
        fetcher.calls.load(Ordering::SeqCst),
        1,
        "fetched once; unknown kids rate-limited"
    );
}

#[test]
fn machine_tokens_never_become_users() {
    // RFC 9068: sub == client_id.
    let mut c = claims();
    c["sub"] = json!(CLIENT);
    assert_eq!(
        verify(&mint(Algorithm::RS256, &c)).context.assurance,
        Assurance::L2TrustedOperator
    );
    // Auth0: gty client-credentials.
    let mut c = claims();
    c["sub"] = json!("abc123@clients");
    c["gty"] = json!("client-credentials");
    assert_eq!(
        verify(&mint(Algorithm::RS256, &c)).context.assurance,
        Assurance::L2TrustedOperator
    );
    // Keycloak: service-account username, via a per-issuer rule.
    let mut c = claims();
    c["sub"] = json!("ace598d5-411a-49ad-b61d-b7748fc0b6b2");
    c["preferred_username"] = json!("service-account-mcp-client");
    assert_eq!(
        verify(&mint(Algorithm::RS256, &c)).context.assurance,
        Assurance::L3Delegated,
        "without the rule it looks like a user"
    );
    let mut cfg = config();
    cfg.issuers[0].machine_token_claims = vec![
        serde_json::from_value(
            json!({"claim": "preferred_username", "prefix": "service-account-"}),
        )
        .unwrap(),
    ];
    assert_eq!(
        verify_with(cfg, &mint(Algorithm::RS256, &c))
            .context
            .assurance,
        Assurance::L2TrustedOperator
    );
}
