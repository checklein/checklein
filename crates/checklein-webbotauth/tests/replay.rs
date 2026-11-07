//! Replay protection needs two requests, so it lives outside the single-request vectors.

use checklein_core::encoding::b64url_decode;
use checklein_core::keys::{EntryStatus, Jwk, TrustEntry, TrustList, jwk_thumbprint_ed25519};
use checklein_core::{Checklein, Decision, FixedClock, RequestView, StaticResolver};
use checklein_httpsig::{Component, SigParams, Signer9421};
use checklein_webbotauth::{WebBotAuth, warnings};
use ed25519_dalek::SigningKey;

const NOW: i64 = 1_735_689_600;

fn key() -> SigningKey {
    let seed: [u8; 32] = b64url_decode("n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU")
        .unwrap()
        .try_into()
        .unwrap();
    SigningKey::from_bytes(&seed)
}

fn resolver() -> StaticResolver {
    let mut r = StaticResolver::new();
    r.load_trust_list(&TrustList {
        list: "t".into(),
        version: "1".into(),
        previous: None,
        entries: vec![TrustEntry {
            operator: "https://signature-agent.test".into(),
            display_name: None,
            schemes: vec![],
            keys: vec![Jwk::from_ed25519(&key().verifying_key().to_bytes())],
            status: EntryStatus::Active,
        }],
    })
    .unwrap();
    r
}

fn signed(nonce: Option<&str>, path: &str) -> RequestView {
    let req = RequestView::new("GET", "https", "site.example", path);
    let signer = Signer9421 {
        label: "sig1".into(),
        components: vec![Component::new("@authority").unwrap()],
        params: SigParams {
            created: Some(NOW - 10),
            expires: Some(NOW + 50),
            keyid: Some(jwk_thumbprint_ed25519(&key().verifying_key().to_bytes())),
            alg: Some("ed25519".into()),
            nonce: nonce.map(str::to_string),
            tag: Some("web-bot-auth".into()),
        },
    };
    let (input, sig) = signer.sign(&req, &key()).unwrap();
    req.with_header("Signature-Input", &input)
        .with_header("Signature", &sig)
}

fn checklein(adapter: WebBotAuth, now: i64) -> Checklein {
    Checklein::new(resolver())
        .adapter(adapter)
        .clock(FixedClock(now))
}

#[test]
fn same_signature_twice_is_rejected() {
    let ck = checklein(WebBotAuth::default(), NOW);
    let req = signed(None, "/a");
    assert_eq!(ck.verify(&req).unwrap().decision, Decision::Allow);
    let second = ck.verify(&req).unwrap();
    assert_eq!(second.decision, Decision::Challenge);
    assert_eq!(
        second.context.evidence[0].reason.as_deref(),
        Some("replayed signature")
    );
}

#[test]
fn reused_nonce_is_rejected_even_with_a_new_signature() {
    let ck = checklein(WebBotAuth::default(), NOW);
    // With a nonce, the replay key is keyid + nonce, so any second request reusing it fails.
    let first = signed(Some("n-123"), "/a");
    assert_eq!(ck.verify(&first).unwrap().decision, Decision::Allow);
    let mut second = signed(Some("n-123"), "/b");
    second.push_header("User-Agent", "different request, same nonce");
    assert_eq!(ck.verify(&second).unwrap().decision, Decision::Challenge);
    // A fresh nonce is accepted.
    assert_eq!(
        ck.verify(&signed(Some("n-456"), "/c")).unwrap().decision,
        Decision::Allow
    );
}

#[test]
fn disabled_guard_is_visible_in_findings() {
    let ck = checklein(WebBotAuth::default().without_replay_guard(), NOW);
    let req = signed(None, "/a");
    assert_eq!(ck.verify(&req).unwrap().decision, Decision::Allow);
    let again = ck.verify(&req).unwrap();
    assert_eq!(again.decision, Decision::Allow);
    assert!(
        again.findings[0]
            .warnings
            .contains(&warnings::REPLAY_NOT_CHECKED.to_string())
    );
}
