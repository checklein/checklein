use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use checklein_core::finding::KeyTrust;
use checklein_core::keys::{EntryStatus, Jwk, TrustEntry, TrustList};
use checklein_core::{KeyHint, KeyResolver, StaticResolver};
use checklein_fetch::{DirectoryFetcher, FetchConfig, FetchError, FetchingResolver};

const X: &str = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs";
const KEYID: &str = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";

/// Serves one JWKS forever on 127.0.0.1 and counts requests.
fn directory_server() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            counter.fetch_add(1, Ordering::SeqCst);
            let body = format!(
                r#"{{"keys":[{{"kty":"RSA","n":"x","e":"AQAB"}},{{"kty":"OKP","crv":"Ed25519","x":"{X}"}}]}}"#
            );
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/http-message-signatures-directory+json\r\ncache-control: max-age=120\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes());
        }
    });
    (origin, hits)
}

fn local_cfg() -> FetchConfig {
    FetchConfig {
        allow_local_http: true,
        ..FetchConfig::default()
    }
}

#[test]
fn fetches_once_and_resolves_in_band() {
    let (origin, hits) = directory_server();
    let r = FetchingResolver::new(StaticResolver::new(), local_cfg());
    let hint = KeyHint {
        operator: Some(&origin),
    };

    let k = r.resolve(KEYID, &hint).expect("key from fetched directory");
    assert_eq!(k.trust, KeyTrust::InBand);
    assert_eq!(k.operator.as_deref(), Some(origin.as_str()));

    assert!(r.resolve(KEYID, &hint).is_some());
    assert!(r.resolve("unknown-key-id", &hint).is_none());
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "cached for max-age; unknown keyids must not refetch"
    );
}

#[test]
fn trust_list_wins_without_fetching() {
    let (origin, hits) = directory_server();
    let mut base = StaticResolver::new();
    base.load_trust_list(&TrustList {
        list: "t".into(),
        version: "1".into(),
        previous: None,
        entries: vec![TrustEntry {
            operator: origin.clone(),
            display_name: None,
            schemes: vec![],
            keys: vec![Jwk {
                kty: "OKP".into(),
                crv: "Ed25519".into(),
                x: X.into(),
                kid: None,
            }],
            status: EntryStatus::Active,
        }],
    })
    .unwrap();
    let r = FetchingResolver::new(base, local_cfg());
    let k = r
        .resolve(
            KEYID,
            &KeyHint {
                operator: Some(&origin),
            },
        )
        .unwrap();
    assert!(k.trust.is_trusted());
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[test]
fn revoked_operator_is_never_fetched() {
    let (origin, hits) = directory_server();
    let mut base = StaticResolver::new();
    base.load_trust_list(&TrustList {
        list: "block".into(),
        version: "1".into(),
        previous: None,
        entries: vec![TrustEntry {
            operator: origin.clone(),
            display_name: None,
            schemes: vec![],
            keys: vec![],
            status: EntryStatus::Revoked,
        }],
    })
    .unwrap();
    let r = FetchingResolver::new(base, local_cfg());
    assert!(
        r.resolve(
            KEYID,
            &KeyHint {
                operator: Some(&origin)
            }
        )
        .is_none()
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[test]
fn default_config_refuses_local_targets() {
    let (origin, hits) = directory_server();
    let f = DirectoryFetcher::new(FetchConfig::default());
    // Plain http is refused outright.
    assert!(matches!(f.fetch(&origin), Err(FetchError::BadOrigin(_))));
    // https to a loopback address is refused at connect time.
    let port = origin.rsplit(':').next().unwrap();
    assert!(matches!(
        f.fetch(&format!("https://127.0.0.1:{port}")),
        Err(FetchError::BlockedAddress)
    ));
    assert!(matches!(
        f.fetch("https://localhost"),
        Err(FetchError::BlockedAddress)
    ));
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

/// Live network check against Cloudflare's public Web Bot Auth test deployment.
/// Run with: cargo test -p checklein-fetch --test fetch -- --ignored live_cloudflare
#[test]
#[ignore = "network"]
fn live_cloudflare_research_directory() {
    let f = DirectoryFetcher::new(FetchConfig {
        timeout: std::time::Duration::from_secs(5),
        ..FetchConfig::default()
    });
    let d = f
        .fetch("https://http-message-signatures-example.research.cloudflare.com")
        .expect("fetch");
    assert!(
        !d.keys.is_empty(),
        "directory should list at least one Ed25519 key"
    );
    let thumbs: Vec<String> = d
        .keys
        .iter()
        .map(checklein_core::keys::jwk_thumbprint_ed25519)
        .collect();
    println!("keys: {thumbs:?}, ttl: {:?}", d.ttl);
}
