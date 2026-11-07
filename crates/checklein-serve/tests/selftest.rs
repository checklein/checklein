//! `selftest` against a real server, with and without the test key trusted.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

use checklein_core::keys::{EntryStatus, Jwk, TrustEntry, TrustList};
use checklein_core::{Checklein, StaticResolver};
use checklein_serve::selftest::{Outcome, check_serve, check_via};
use checklein_serve::{ServeConfig, start};
use checklein_webbotauth::WebBotAuth;

fn server(trust_test_key: bool) -> checklein_serve::Running {
    let mut r = StaticResolver::new();
    if trust_test_key {
        r.load_trust_list(&TrustList {
            list: "t".into(),
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
        .unwrap();
    }
    let ck = Checklein::new(r).adapter(WebBotAuth::default());
    start(
        Arc::new(ck),
        ServeConfig {
            listen: "127.0.0.1:0".into(),
            workers: 2,
            deny_on: vec![],
            access_log: false,
            resource_metadata: None,
        },
    )
    .unwrap()
}

fn summary(checks: &[checklein_serve::selftest::Check]) -> String {
    checks
        .iter()
        .map(|c| format!("{:?} {} ({})", c.outcome, c.name, c.detail))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn all_serve_checks_pass_when_test_key_is_trusted() {
    let srv = server(true);
    let checks = check_serve(&format!("http://{}", srv.addr), "site.example");
    assert_eq!(checks.len(), 5, "{}", summary(&checks));
    assert!(
        checks.iter().all(|c| c.outcome == Outcome::Pass),
        "{}",
        summary(&checks)
    );
    srv.shutdown();
}

#[test]
fn signed_check_is_skipped_when_test_key_is_not_trusted() {
    let srv = server(false);
    let checks = check_serve(&format!("http://{}", srv.addr), "site.example");
    let signed = checks.iter().find(|c| c.name.contains("signed")).unwrap();
    assert_eq!(signed.outcome, Outcome::Skip, "{}", summary(&checks));
    assert!(
        checks.iter().all(|c| c.outcome != Outcome::Fail),
        "{}",
        summary(&checks)
    );
    srv.shutdown();
}

#[test]
fn unreachable_serve_fails_cleanly() {
    let checks = check_serve("http://127.0.0.1:1", "site.example");
    assert_eq!(checks.len(), 1);
    assert_eq!(checks[0].outcome, Outcome::Fail);
}

/// An app that echoes its request headers but sits behind no Checklein at all.
#[test]
fn via_detects_a_proxy_that_does_not_call_checklein() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for s in listener.incoming().flatten().take(4) {
            let mut s = s;
            let mut buf = [0u8; 8192];
            let n = s.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let body: String = req.lines().skip(1).map(|l| format!("{l}\n")).collect();
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes());
        }
    });
    let checks = check_via(&format!("http://{addr}/"));
    assert_eq!(checks[0].outcome, Outcome::Fail, "{}", summary(&checks));
    assert!(checks[0].detail.contains("no Checklein-Decision"));
}
