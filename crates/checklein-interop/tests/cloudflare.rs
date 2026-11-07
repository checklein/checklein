//! Interop with Cloudflare's `web-bot-auth` crate (pinned), in both directions.
//!
//! 1. Cloudflare's own published test vector verifies in Checklein.
//! 2. Requests signed by Cloudflare's signer verify in Checklein.
//! 3. Every Checklein conformance vector is run through Cloudflare's verifier, and
//!    each verdict must agree with ours on cryptography. Where Checklein rejects a
//!    request that Cloudflare's crypto accepts, the reason must be a policy check
//!    Cloudflare leaves to the caller (time window, revocation, operator binding).

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use checklein_core::encoding::{b64url, b64url_decode};
use checklein_core::keys::{EntryStatus, Jwk, TrustEntry, TrustList, jwk_thumbprint_ed25519};
use checklein_core::{Checklein, Decision, FixedClock, RequestView, StaticResolver};
use checklein_webbotauth::WebBotAuth;
use checklein_webbotauth::vectors::Vector;
use indexmap::IndexMap;
use web_bot_auth::WebBotAuthVerifier;
use web_bot_auth::components::{
    CoveredComponent, DerivedComponent, HTTPField, HTTPFieldParameters, HTTPFieldParametersSet,
};
use web_bot_auth::keyring::{Algorithm, KeyRing};
use web_bot_auth::message_signatures::{MessageSigner, SignedMessage, UnsignedMessage};

const TEST_KEY_D: &str = "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU";
const OPERATOR: &str = "https://signature-agent.test";

fn seed() -> [u8; 32] {
    b64url_decode(TEST_KEY_D).unwrap().try_into().unwrap()
}

fn public_key() -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(&seed())
        .verifying_key()
        .to_bytes()
}

fn keyid() -> String {
    jwk_thumbprint_ed25519(&public_key())
}

fn trusted_resolver() -> StaticResolver {
    let mut r = StaticResolver::new();
    r.load_trust_list(&TrustList {
        list: "interop".into(),
        version: "1".into(),
        previous: None,
        issued_at: None,
        expires_at: None,
        entries: vec![TrustEntry {
            operator: OPERATOR.into(),
            display_name: None,
            schemes: vec![],
            keys: vec![Jwk::from_ed25519(&public_key())],
            status: EntryStatus::Active,
        }],
    })
    .unwrap();
    r
}

/// Cloudflare's view of one of our requests.
struct CfMessage<'a>(&'a RequestView);

impl SignedMessage for CfMessage<'_> {
    fn lookup_component(&self, name: &CoveredComponent) -> Vec<String> {
        let req = self.0;
        match name {
            CoveredComponent::HTTP(HTTPField { name, parameters }) => {
                let key = parameters.0.iter().find_map(|p| match p {
                    HTTPFieldParameters::Key(k) => Some(k.clone()),
                    _ => None,
                });
                match key {
                    Some(k) => checklein_httpsig::dictionary_member(req, name, &k)
                        .into_iter()
                        .collect(),
                    None => req.header(name).into_iter().collect(),
                }
            }
            CoveredComponent::Derived(d) => match d {
                DerivedComponent::Authority { req: false } => vec![req.authority.clone()],
                DerivedComponent::TargetUri { req: false } => vec![req.target_uri()],
                DerivedComponent::Method { req: false } => vec![req.method.clone()],
                DerivedComponent::Path { req: false } => vec![req.path.clone()],
                _ => vec![],
            },
        }
    }
}

/// Cloudflare's crypto verdict for a request, given the keys a relying party holds.
fn cloudflare_verifies(req: &RequestView, keys: &[[u8; 32]]) -> Result<(), String> {
    let mut ring = KeyRing::default();
    for pk in keys {
        ring.import_raw(jwk_thumbprint_ed25519(pk), Algorithm::Ed25519, pk.to_vec());
    }
    let verifier = WebBotAuthVerifier::parse(&CfMessage(req)).map_err(|e| format!("parse: {e}"))?;
    verifier
        .verify(&ring, None)
        .map(|_| ())
        .map_err(|e| format!("verify: {e}"))
}

/// Something Cloudflare's signer can sign: our request plus the components to cover.
struct CfUnsigned {
    components: IndexMap<CoveredComponent, String>,
    input: String,
    signature: String,
}

impl UnsignedMessage for CfUnsigned {
    fn fetch_components_to_cover(&self) -> IndexMap<CoveredComponent, String> {
        self.components.clone()
    }
    fn register_header_contents(&mut self, signature_input: String, signature_header: String) {
        self.input = format!("sig1={signature_input}");
        self.signature = format!("sig1={signature_header}");
    }
}

fn cloudflare_sign(req: RequestView, with_agent: bool) -> RequestView {
    let mut components = IndexMap::new();
    components.insert(
        CoveredComponent::Derived(DerivedComponent::Authority { req: false }),
        req.authority.clone(),
    );
    let req = if with_agent {
        components.insert(
            CoveredComponent::HTTP(HTTPField {
                name: "signature-agent".into(),
                parameters: HTTPFieldParametersSet(vec![HTTPFieldParameters::Key("agent1".into())]),
            }),
            format!("\"{OPERATOR}\""),
        );
        req.with_header("Signature-Agent", &format!("agent1=\"{OPERATOR}\""))
    } else {
        req
    };
    let mut msg = CfUnsigned {
        components,
        input: String::new(),
        signature: String::new(),
    };
    MessageSigner {
        keyid: keyid(),
        nonce: b64url(&rand_nonce()),
        tag: "web-bot-auth".into(),
    }
    .generate_signature_headers_content(
        &mut msg,
        Duration::from_secs(60),
        Algorithm::Ed25519,
        &seed(),
    )
    .expect("cloudflare signs");
    req.with_header("Signature-Input", &msg.input)
        .with_header("Signature", &msg.signature)
}

fn rand_nonce() -> [u8; 16] {
    let mut n = [0u8; 16];
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    n.copy_from_slice(&t.to_le_bytes());
    n
}

#[test]
fn cloudflare_published_vector_verifies_in_checklein() {
    // From web-bot-auth 0.7.0's own test suite (`test_verifying_as_web_bot_auth`).
    let req = RequestView::new("GET", "https", "example.com", "/")
        .with_header(
            "Signature-Input",
            r#"sig1=("@authority");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="gubxywVx7hzbYKatLgzuKDllDAIXAkz41PydU7aOY7vT+Mb3GJNxW0qD4zJ+IOQ1NVtg+BNbTCRUMt1Ojr5BgA==";tag="web-bot-auth""#,
        )
        .with_header(
            "Signature",
            "sig1=:uz2SAv+VIemw+Oo890bhYh6Xf5qZdLUgv6/PbiQfCFXcX/vt1A8Pf7OcgL2yUDUYXFtffNpkEr5W6dldqFrkDg==:",
        );
    let verdict = Checklein::new(trusted_resolver())
        .adapter(WebBotAuth::default())
        .clock(FixedClock(1_735_689_610))
        .verify(&req)
        .unwrap();
    assert_eq!(
        verdict.decision,
        Decision::Allow,
        "{:?}",
        verdict.context.evidence
    );
    assert_eq!(verdict.context.assurance.level(), 2);
    assert!(cloudflare_verifies(&req, &[public_key()]).is_ok());
}

#[test]
fn cloudflare_signed_requests_verify_in_checklein() {
    for with_agent in [false, true] {
        let req = cloudflare_sign(
            RequestView::new("GET", "https", "site.example", "/page"),
            with_agent,
        );
        let verdict = Checklein::new(trusted_resolver())
            .adapter(WebBotAuth::default())
            .verify(&req)
            .unwrap();
        assert_eq!(
            verdict.decision,
            Decision::Allow,
            "with_agent={with_agent}: {:?} / {:?}",
            verdict.context.evidence,
            req.headers()
        );
        assert_eq!(verdict.context.agent.operator.as_deref(), Some(OPERATOR));
    }
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/web-bot-auth")
}

/// Expected Cloudflare crypto verdict per vector, and why any disagreement is fine.
fn cloudflare_expectation(name: &str) -> (bool, &'static str) {
    match name {
        n if n.starts_with("valid-") => (true, "both accept"),
        "invalid-expired" | "invalid-created-in-future" | "invalid-window-too-long" => (
            true,
            "Cloudflare reports timing as an advisory; Checklein enforces it",
        ),
        "invalid-revoked-operator" => (true, "revocation is trust policy, not crypto"),
        "invalid-operator-mismatch" => {
            (true, "key-to-operator binding is trust policy, not crypto")
        }
        "invalid-authority-not-covered"
        | "invalid-signature-agent-not-covered"
        | "ignored-other-tag" => (false, "both refuse to parse it as Web Bot Auth"),
        "invalid-replayed-to-other-site" => {
            (false, "signature base differs; both fail verification")
        }
        "invalid-unknown-key" => (false, "no key; both fail"),
        "spoofed-user-agent" => (false, "no signature at all"),
        other => panic!("no Cloudflare expectation recorded for vector {other:?}"),
    }
}

#[test]
fn every_vector_agrees_with_cloudflare_on_crypto() {
    let mut paths: Vec<_> = fs::read_dir(vectors_dir())
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    paths.sort();
    assert!(paths.len() >= 15);
    for path in paths {
        let v: Vector = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let req = RequestView::parse_http1(&v.request, "https").unwrap();
        let mut keys: Vec<[u8; 32]> = Vec::new();
        if let Some(tl) = &v.trust_list {
            for e in &tl.entries {
                keys.extend(e.keys.iter().map(|k| k.ed25519_bytes().unwrap()));
            }
        }
        for d in &v.directories {
            keys.extend(d.keys.iter().map(|k| k.ed25519_bytes().unwrap()));
        }
        let (want_ok, why) = cloudflare_expectation(&v.name);
        let got = cloudflare_verifies(&req, &keys);
        assert_eq!(
            got.is_ok(),
            want_ok,
            "{}: Cloudflare said {got:?}; expected ok={want_ok} ({why})",
            v.name
        );
    }
}

/// End to end over the network: a request whose `Signature-Agent` names Cloudflare's
/// public research deployment, signed with the published test key that deployment's
/// directory serves. Checklein fetches the directory live and verifies at L1.
/// Run with: cargo test -p checklein-interop --test cloudflare -- --ignored live
#[test]
#[ignore = "network"]
fn live_directory_fetch_end_to_end() {
    use checklein_fetch::{FetchConfig, FetchingResolver};
    use checklein_httpsig::{Component, SigParams, Signer9421};

    let research = "https://http-message-signatures-example.research.cloudflare.com";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let req = RequestView::new("GET", "https", "site.example", "/")
        .with_header("Signature-Agent", &format!("agent1=\"{research}\""));
    let signer = Signer9421 {
        label: "sig1".into(),
        components: vec![
            Component::new("@authority").unwrap(),
            Component::dictionary_member("signature-agent", "agent1").unwrap(),
        ],
        params: SigParams {
            created: Some(now),
            expires: Some(now + 60),
            keyid: Some(keyid()),
            alg: Some("ed25519".into()),
            nonce: None,
            tag: Some("web-bot-auth".into()),
        },
    };
    let (input, sig) = signer
        .sign(&req, &ed25519_dalek::SigningKey::from_bytes(&seed()))
        .unwrap();
    let req = req
        .with_header("Signature-Input", &input)
        .with_header("Signature", &sig);

    let resolver = FetchingResolver::new(
        StaticResolver::new(),
        FetchConfig {
            timeout: Duration::from_secs(5),
            ..FetchConfig::default()
        },
    );
    let verdict = Checklein::new(resolver)
        .adapter(WebBotAuth::default())
        .verify(&req)
        .unwrap();
    assert_eq!(
        verdict.context.assurance.level(),
        1,
        "{:?}",
        verdict.context.evidence
    );
    assert_eq!(verdict.decision, Decision::RateLimit);
    assert_eq!(verdict.context.agent.operator.as_deref(), Some(research));
    assert_eq!(verdict.context.agent.key_source.as_deref(), Some("in-band"));
}
