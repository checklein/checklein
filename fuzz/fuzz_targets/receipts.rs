//! Receipt-log verification on arbitrary lines (JWS splitting, base64, JSON, links).
#![no_main]

use checklein_core::receipt::{ReceiptChain, verify_chain};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let lines: Vec<&str> = text.lines().collect();
    let key = ReceiptChain::new([7u8; 32]).verifying_key();
    // Arbitrary input can never be a valid chain signed by this key.
    if !lines.is_empty() {
        assert!(verify_chain(&lines, &key).is_err());
    }
});
