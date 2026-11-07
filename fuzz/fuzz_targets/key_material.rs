//! Untrusted key material: fetched directory bodies and trust-list files.
#![no_main]

use checklein_core::keys::TrustList;
use checklein_core::{KeyHint, KeyResolver, StaticResolver};
use checklein_fetch::parse_directory;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Signed trust lists: arbitrary input must never verify against a pinned key.
    let publisher = checklein_core::receipt::ReceiptChain::new([3u8; 32]).verifying_key();
    let text = String::from_utf8_lossy(data);
    assert!(TrustList::verify_signed(&text, &[publisher], 1_790_000_000, 60).is_err());

    if let Ok(keys) = parse_directory(data) {
        for k in &keys {
            let _ = checklein_core::keys::jwk_thumbprint_ed25519(k);
        }
    }
    if let Ok(list) = serde_json::from_slice::<TrustList>(data) {
        let mut r = StaticResolver::new();
        if r.load_trust_list(&list).is_ok() {
            for e in &list.entries {
                let _ = r.resolve(
                    "any-key",
                    &KeyHint {
                        operator: Some(&e.operator),
                    },
                );
                let _ = r.is_revoked(&e.operator);
            }
        }
    }
});
