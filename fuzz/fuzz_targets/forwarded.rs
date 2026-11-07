//! Forward-auth request reconstruction from arbitrary proxy headers, then a decision.
#![no_main]

use checklein_serve::{decide, reconstruct};
use libfuzzer_sys::fuzz_target;

#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let headers: Vec<(String, String)> = text
        .lines()
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_string(), v.trim().to_string()))
        .collect();
    if let Ok(req) = reconstruct(&headers) {
        // Spoofable downstream headers never survive into the verified request.
        let out = decide(&common::verifier(), &req, &[]);
        assert!(out.status == 200 || out.status == 403);
        let assurance = out
            .headers
            .iter()
            .find(|(n, _)| n == "checklein-assurance")
            .map(|(_, v)| v.as_str());
        assert!(matches!(assurance, Some("0" | "1" | "2" | "3" | "4")));
    }
});
