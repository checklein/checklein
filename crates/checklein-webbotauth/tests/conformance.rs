//! Runs every vector in `vectors/web-bot-auth/`.
//!
//! Regenerate the files with:
//!   cargo test -p checklein-webbotauth --test conformance -- --ignored generate_vectors

use std::fs;
use std::path::PathBuf;

use checklein_core::encoding::b64url_decode;
use checklein_core::keys::{EntryStatus, Jwk, TrustEntry, TrustList, jwk_thumbprint_ed25519};
use checklein_core::{Decision, RequestView};
use checklein_httpsig::{Component, SigParams, Signer9421};
use checklein_webbotauth::vectors::{Directory, Expect, Vector, render_http1, run};
use ed25519_dalek::SigningKey;

/// Private half of the RFC 9421 Appendix B.1.4 test key (also used by the Web Bot Auth draft).
const TEST_KEY_D: &str = "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU";
const TEST_KEY_X: &str = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs";
const OPERATOR: &str = "https://signature-agent.test";
const NOW: i64 = 1_735_689_600; // 2025-01-01T00:00:00Z

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/web-bot-auth")
}

fn key() -> SigningKey {
    let seed: [u8; 32] = b64url_decode(TEST_KEY_D).unwrap().try_into().unwrap();
    SigningKey::from_bytes(&seed)
}

fn jwk() -> Jwk {
    Jwk::from_ed25519(&key().verifying_key().to_bytes())
}

fn trust_list(status: EntryStatus) -> TrustList {
    TrustList {
        list: "vectors".into(),
        version: "1".into(),
        previous: None,
        entries: vec![TrustEntry {
            operator: OPERATOR.into(),
            display_name: Some("Example signing agent".into()),
            schemes: vec!["web-bot-auth".into()],
            keys: vec![jwk()],
            status,
        }],
    }
}

fn directory() -> Vec<Directory> {
    vec![Directory {
        operator: OPERATOR.into(),
        keys: vec![jwk()],
    }]
}

fn base_request(authority: &str) -> RequestView {
    RequestView::new("GET", "https", authority, "/articles/1")
        .with_header("User-Agent", "Mozilla/5.0 (compatible; ExampleAgent/1.0)")
}

fn params(created: i64, expires: i64, tag: &str) -> SigParams {
    SigParams {
        created: Some(created),
        expires: Some(expires),
        keyid: Some(jwk_thumbprint_ed25519(&key().verifying_key().to_bytes())),
        alg: Some("ed25519".into()),
        nonce: None,
        tag: Some(tag.into()),
    }
}

fn sign(req: RequestView, components: Vec<Component>, p: SigParams) -> RequestView {
    let signer = Signer9421 {
        label: "sig1".into(),
        components,
        params: p,
    };
    let (input, sig) = signer.sign(&req, &key()).unwrap();
    req.with_header("Signature-Input", &input)
        .with_header("Signature", &sig)
}

fn authority() -> Component {
    Component::new("@authority").unwrap()
}

fn agent_member() -> Component {
    Component::dictionary_member("signature-agent", "agent1").unwrap()
}

fn dict_agent(req: RequestView, url: &str) -> RequestView {
    req.with_header("Signature-Agent", &format!("agent1=\"{url}\""))
}

fn ok_params() -> SigParams {
    params(NOW - 10, NOW + 50, "web-bot-auth")
}

fn expect(assurance: u8, decision: Decision) -> Expect {
    Expect {
        assurance,
        decision,
        ..Default::default()
    }
}

fn vector(
    name: &str,
    description: &str,
    req: &RequestView,
    tl: Option<TrustList>,
    dirs: Vec<Directory>,
    expect: Expect,
) -> Vector {
    Vector {
        name: name.into(),
        description: description.into(),
        request: render_http1(req),
        now: NOW,
        trust_list: tl,
        directories: dirs,
        expect,
    }
}

fn build_vectors() -> Vec<Vector> {
    let trusted = || Some(trust_list(EntryStatus::Active));
    let signed_dict = sign(
        dict_agent(base_request("site.example"), OPERATOR),
        vec![authority(), agent_member()],
        ok_params(),
    );

    let mut v = Vec::new();

    v.push(vector(
        "valid-trusted-dictionary-form",
        "Draft-01 dictionary Signature-Agent; key on a loaded trust list. Reaches L2 and is allowed.",
        &signed_dict,
        trusted(),
        vec![],
        Expect { operator: Some(OPERATOR.into()), ..expect(2, Decision::Allow) },
    ));

    v.push(vector(
        "valid-in-band-key-only",
        "Same request, but the key is known only from the operator's own directory. Capped at L1 and rate-limited.",
        &signed_dict,
        None,
        directory(),
        Expect { operator: Some(OPERATOR.into()), ..expect(1, Decision::RateLimit) },
    ));

    let string_form = sign(
        base_request("site.example").with_header("Signature-Agent", &format!("\"{OPERATOR}\"")),
        vec![authority(), Component::new("signature-agent").unwrap()],
        ok_params(),
    );
    v.push(vector(
        "valid-cloudflare-string-form",
        "Cloudflare's structured-string Signature-Agent. Accepted with a warning.",
        &string_form,
        trusted(),
        vec![],
        Expect {
            warnings: vec!["signature_agent_string_form".into()],
            ..expect(2, Decision::Allow)
        },
    ));

    let no_agent = sign(base_request("site.example"), vec![authority()], ok_params());
    v.push(vector(
        "valid-no-signature-agent",
        "No Signature-Agent header; the keyid alone resolves to a trust-list key.",
        &no_agent,
        trusted(),
        vec![],
        Expect {
            operator: Some(OPERATOR.into()),
            ..expect(2, Decision::Allow)
        },
    ));

    let target_uri = sign(
        base_request("site.example"),
        vec![Component::new("@target-uri").unwrap()],
        ok_params(),
    );
    v.push(vector(
        "valid-target-uri-instead-of-authority",
        "Covers @target-uri, which binds the host, instead of @authority. Cloudflare's verifier accepts this too.",
        &target_uri,
        trusted(),
        vec![],
        expect(2, Decision::Allow),
    ));

    let invalid = |reason: &str| Expect {
        reason_contains: Some(reason.into()),
        flags: vec!["invalid_credential:web-bot-auth@draft-01".into()],
        ..expect(0, Decision::Challenge)
    };

    let expired = sign(
        dict_agent(base_request("site.example"), OPERATOR),
        vec![authority(), agent_member()],
        params(NOW - 600, NOW - 300, "web-bot-auth"),
    );
    v.push(vector(
        "invalid-expired",
        "Signature expired five minutes ago, beyond the 60 s skew.",
        &expired,
        trusted(),
        vec![],
        invalid("expired"),
    ));

    let future = sign(
        dict_agent(base_request("site.example"), OPERATOR),
        vec![authority(), agent_member()],
        params(NOW + 300, NOW + 360, "web-bot-auth"),
    );
    v.push(vector(
        "invalid-created-in-future",
        "created is five minutes ahead of the verifier's clock.",
        &future,
        trusted(),
        vec![],
        invalid("future"),
    ));

    let long = sign(
        dict_agent(base_request("site.example"), OPERATOR),
        vec![authority(), agent_member()],
        params(NOW - 10, NOW + 2 * 86400, "web-bot-auth"),
    );
    v.push(vector(
        "invalid-window-too-long",
        "A two-day validity window exceeds the 24 h maximum.",
        &long,
        trusted(),
        vec![],
        invalid("too long"),
    ));

    let no_authority = sign(
        dict_agent(base_request("site.example"), OPERATOR),
        vec![agent_member()],
        ok_params(),
    );
    v.push(vector(
        "invalid-authority-not-covered",
        "@authority is not covered, so the signature could be replayed to another site.",
        &no_authority,
        trusted(),
        vec![],
        invalid("@authority"),
    ));

    let not_covered = sign(
        dict_agent(base_request("site.example"), OPERATOR),
        vec![authority()],
        ok_params(),
    );
    v.push(vector(
        "invalid-signature-agent-not-covered",
        "Signature-Agent is present but outside the signature, so it could be swapped.",
        &not_covered,
        trusted(),
        vec![],
        invalid("not covered"),
    ));

    let mut replayed = RequestView::new("GET", "https", "other.example", "/articles/1");
    for (n, val) in signed_dict.headers() {
        replayed.push_header(n, val);
    }
    v.push(vector(
        "invalid-replayed-to-other-site",
        "A valid signature for site.example presented to other.example.",
        &replayed,
        trusted(),
        vec![],
        invalid("does not verify"),
    ));

    v.push(vector(
        "invalid-unknown-key",
        "The keyid matches no pinned, listed or directory key.",
        &signed_dict,
        None,
        vec![],
        invalid("unknown"),
    ));

    v.push(vector(
        "invalid-revoked-operator",
        "The operator is revoked in a loaded trust list; its own directory no longer counts.",
        &signed_dict,
        Some(trust_list(EntryStatus::Revoked)),
        directory(),
        invalid("revoked"),
    ));

    let mismatch = sign(
        dict_agent(base_request("site.example"), "https://evil.test"),
        vec![authority(), agent_member()],
        ok_params(),
    );
    v.push(vector(
        "invalid-operator-mismatch",
        "Signature-Agent names evil.test but the key belongs to signature-agent.test on the trust list.",
        &mismatch,
        trusted(),
        vec![],
        invalid("different operator"),
    ));

    let other_tag = sign(
        dict_agent(base_request("site.example"), OPERATOR),
        vec![authority(), agent_member()],
        params(NOW - 10, NOW + 50, "some-other-profile"),
    );
    v.push(vector(
        "ignored-other-tag",
        "A signature for another profile is not Web Bot Auth: no finding, L0, no opinion.",
        &other_tag,
        trusted(),
        vec![],
        expect(0, Decision::Pass),
    ));

    let spoofed = RequestView::new("GET", "https", "site.example", "/articles/1")
        .with_header("User-Agent", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ChatGPT-User/1.0; +https://openai.com/bot)");
    v.push(vector(
        "spoofed-user-agent",
        "Claims to be ChatGPT-User with no signature. Stays L0 and is flagged for existing bot defenses.",
        &spoofed,
        trusted(),
        vec![],
        Expect { flags: vec!["unverified_agent_claim".into()], ..expect(0, Decision::Pass) },
    ));

    v
}

#[test]
fn test_key_matches_published_public_key() {
    assert_eq!(jwk().x, TEST_KEY_X);
}

#[test]
#[ignore = "writes vectors/web-bot-auth/*.json"]
fn generate_vectors() {
    let dir = vectors_dir();
    fs::create_dir_all(&dir).unwrap();
    for v in build_vectors() {
        let json = serde_json::to_string_pretty(&v).unwrap();
        fs::write(dir.join(format!("{}.json", v.name)), json + "\n").unwrap();
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
    let dir = vectors_dir();
    let mut count = 0;
    let mut entries: Vec<_> = fs::read_dir(&dir).expect("vectors dir").flatten().collect();
    entries.sort_by_key(|e| e.path());
    for entry in entries {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json") {
            let v: Vector = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
            run(&v).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            count += 1;
        }
    }
    assert!(count >= 10, "expected the vector set, found {count} files");
}
