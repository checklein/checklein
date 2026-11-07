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
    let mcp: checklein_mcp::McpConfig = serde_json::from_str(
        r#"{"resource":["https://example.com/mcp"],
            "issuers":[{"issuer":"https://auth.example","accept_jwt_typ":true,
              "jwks":{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"ed-1",
                "x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}]}}],
            "subject_key":"000102030405060708090a0b0c0d0e0f"}"#,
    )
    .expect("static config");
    Checklein::new(resolver())
        .adapter(WebBotAuth::default())
        .adapter(checklein_mcp::McpOAuth::new(mcp).expect("valid config"))
        .clock(FixedClock(NOW))
}
