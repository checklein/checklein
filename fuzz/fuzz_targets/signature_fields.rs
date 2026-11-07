//! Targets the structured-field parsing directly: the input is split on '\n' into
//! Signature-Input, Signature and Signature-Agent values on a fixed request.
#![no_main]

use checklein_core::RequestView;
use checklein_httpsig::{parse_signatures, signature_base};
use libfuzzer_sys::fuzz_target;

#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let mut parts = text.splitn(3, '\n');
    let mut req = RequestView::new("GET", "https", "example.com", "/");
    for name in ["signature-input", "signature", "signature-agent"] {
        if let Some(v) = parts.next() {
            req.push_header(name, v);
        }
    }
    if let Ok(entries) = parse_signatures(&req) {
        for e in &entries {
            if let Ok(base) = signature_base(&req, e) {
                // The base ends with the @signature-params line, never a newline.
                assert!(!base.ends_with('\n'));
                assert!(base.contains("\"@signature-params\": "));
            }
        }
    }
    let _ = common::verifier().verify(&req);
});
