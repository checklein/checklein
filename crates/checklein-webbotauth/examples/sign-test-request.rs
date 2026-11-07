//! Prints Web Bot Auth headers for a request signed *now* with the published
//! RFC 9421 test key, whose public half is trusted by `examples/trust-list.json`.
//!
//! For demos and testing only: the private key is public, so anyone can produce
//! these signatures. Never trust this key in production.
//!
//!   cargo run -q -p checklein-webbotauth --example sign-test-request -- localhost:8080 > agent-headers.txt
//!   curl -i http://localhost:8080/ -H @agent-headers.txt

use std::time::{SystemTime, UNIX_EPOCH};

use checklein_core::RequestView;
use checklein_core::encoding::b64url_decode;
use checklein_core::keys::jwk_thumbprint_ed25519;
use checklein_httpsig::{Component, SigParams, Signer9421};

const TEST_KEY_D: &str = "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU";
const OPERATOR: &str = "https://signature-agent.test";

fn main() {
    let authority = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "localhost:8080".into());

    let seed: [u8; 32] = b64url_decode(TEST_KEY_D).unwrap().try_into().unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let nonce = format!(
        "demo-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    let agent = format!("agent1=\"{OPERATOR}\"");
    let req =
        RequestView::new("GET", "http", &authority, "/").with_header("Signature-Agent", &agent);
    let signer = Signer9421 {
        label: "sig1".into(),
        components: vec![
            Component::new("@authority").unwrap(),
            Component::dictionary_member("signature-agent", "agent1").unwrap(),
        ],
        params: SigParams {
            created: Some(now),
            expires: Some(now + 60),
            keyid: Some(jwk_thumbprint_ed25519(&key.verifying_key().to_bytes())),
            alg: Some("ed25519".into()),
            nonce: Some(nonce),
            tag: Some("web-bot-auth".into()),
        },
    };
    let (input, sig) = signer.sign(&req, &key).expect("sign");
    let headers = [
        ("Signature-Agent", agent.as_str()),
        ("Signature-Input", input.as_str()),
        ("Signature", sig.as_str()),
    ];
    for (n, v) in headers {
        println!("{n}: {v}");
    }
}
