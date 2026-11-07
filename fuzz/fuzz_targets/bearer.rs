//! MCP OAuth: arbitrary Authorization header values (JWT splitting, base64, JSON,
//! header and claim handling) against a configured issuer.
#![no_main]

use checklein_core::{Checklein, FixedClock, RequestView, StaticResolver};
use checklein_mcp::{McpConfig, McpOAuth};
use libfuzzer_sys::fuzz_target;

fn verifier() -> Checklein {
    let cfg: McpConfig = serde_json::from_str(
        r#"{"resource":["https://mcp.example/mcp"],
            "issuers":[{"issuer":"https://auth.example","accept_jwt_typ":true,
              "jwks":{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"ed-1",
                "x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}]}}],
            "subject_key":"000102030405060708090a0b0c0d0e0f"}"#,
    )
    .expect("static config");
    Checklein::new(StaticResolver::new())
        .adapter(McpOAuth::new(cfg).expect("valid config"))
        .clock(FixedClock(1_790_000_000))
}

fuzz_target!(|data: &[u8]| {
    let value = String::from_utf8_lossy(data);
    let req = RequestView::new("POST", "https", "mcp.example", "/mcp")
        .with_header("Authorization", &value);
    let verdict = verifier().verify(&req).expect("no receipts configured");
    // Nothing an attacker can type reaches L3 without the issuer's private key.
    assert!(verdict.context.assurance.level() < 3);
});
