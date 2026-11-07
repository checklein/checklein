//! Shared setup: a verifier that trusts the RFC 9421 test key, at a fixed time.

use checklein_core::keys::{EntryStatus, Jwk, TrustEntry, TrustList};
use checklein_core::{Checklein, FixedClock, StaticResolver};
use checklein_webbotauth::WebBotAuth;

pub const NOW: i64 = 1_735_689_600;

pub fn resolver() -> StaticResolver {
    let mut r = StaticResolver::new();
    r.load_trust_list(&TrustList {
        list: "fuzz".into(),
        version: "1".into(),
        previous: None,
        entries: vec![TrustEntry {
            operator: "https://signature-agent.test".into(),
            display_name: None,
            schemes: vec![],
            keys: vec![Jwk {
                kty: "OKP".into(),
                crv: "Ed25519".into(),
                x: "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs".into(),
                kid: None,
            }],
            status: EntryStatus::Active,
        }],
    })
    .expect("static trust list");
    r
}

pub fn verifier() -> Checklein {
    Checklein::new(resolver())
        .adapter(WebBotAuth::default())
        .clock(FixedClock(NOW))
}
