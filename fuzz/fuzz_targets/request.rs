//! Whole pipeline on an arbitrary HTTP/1.1 request head: parse, verify every scheme,
//! normalize, decide. Must never panic, whatever the bytes.
#![no_main]

use checklein_core::RequestView;
use libfuzzer_sys::fuzz_target;

#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    let raw = String::from_utf8_lossy(data);
    let Ok(req) = RequestView::parse_http1(&raw, "https") else {
        return;
    };
    let verdict = common::verifier()
        .verify(&req)
        .expect("no receipts configured");
    // Invariants: L2+ only with a valid finding whose key is trusted.
    if verdict.context.assurance.level() >= 2 {
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.is_valid() && f.key_trust.as_ref().is_some_and(|t| t.is_trusted()))
        );
    }
    // Downstream headers are always complete and never empty.
    let headers = verdict.downstream_headers();
    assert_eq!(headers.len(), 5);
    assert!(headers.iter().all(|(_, v)| !v.is_empty()));
});
