//! End-to-end forward-auth contract: a real server on an ephemeral port, driven the
//! way Traefik (X-Forwarded-*) and nginx (X-Original-* + Host) call it.

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use checklein_core::{Checklein, Decision, FixedClock, RequestView, StaticResolver};
use checklein_serve::{Running, ServeConfig, start};
use checklein_webbotauth::WebBotAuth;
use checklein_webbotauth::vectors::Vector;

fn vector(name: &str) -> Vector {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(format!("../../vectors/web-bot-auth/{name}.json"));
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn server_for(v: &Vector, deny_on: Vec<Decision>) -> Running {
    let mut r = StaticResolver::new();
    if let Some(tl) = &v.trust_list {
        r.load_trust_list(tl).unwrap();
    }
    let ck = Checklein::new(r)
        .adapter(WebBotAuth::default())
        .clock(FixedClock(v.now));
    start(
        Arc::new(ck),
        ServeConfig {
            listen: "127.0.0.1:0".into(),
            workers: 4,
            deny_on,
            access_log: false,
            resource_metadata: None,
        },
    )
    .unwrap()
}

struct Reply {
    status: u16,
    headers: HashMap<String, String>,
    body: String,
}

fn send(addr: SocketAddr, path: &str, headers: &[(String, String)]) -> Reply {
    let mut s = TcpStream::connect(addr).unwrap();
    let mut req = format!("GET {path} HTTP/1.1\r\n");
    for (n, v) in headers {
        req.push_str(&format!("{n}: {v}\r\n"));
    }
    req.push_str("Connection: close\r\n\r\n");
    s.write_all(req.as_bytes()).unwrap();
    let mut raw = String::new();
    s.read_to_string(&mut raw).unwrap();
    let (head, body) = raw.split_once("\r\n\r\n").unwrap();
    let mut lines = head.lines();
    let status = lines
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    Reply {
        status,
        headers,
        body: body.to_string(),
    }
}

/// What Traefik's ForwardAuth sends: original headers plus X-Forwarded-*.
fn traefik(req: &RequestView) -> Vec<(String, String)> {
    let mut h = vec![
        ("Host".into(), "checklein:8787".into()),
        ("X-Forwarded-Method".into(), req.method.clone()),
        ("X-Forwarded-Proto".into(), "https".into()),
        ("X-Forwarded-Host".into(), req.authority.clone()),
        ("X-Forwarded-Uri".into(), req.request_target()),
        ("X-Forwarded-For".into(), "203.0.113.7".into()),
    ];
    h.extend(req.headers().iter().filter(|(n, _)| n != "host").cloned());
    h
}

/// What the example nginx config sends: Host kept, X-Original-* set.
fn nginx(req: &RequestView) -> Vec<(String, String)> {
    let mut h = vec![
        ("Host".into(), req.authority.clone()),
        ("X-Original-Method".into(), req.method.clone()),
        ("X-Original-URI".into(), req.request_target()),
    ];
    h.extend(req.headers().iter().filter(|(n, _)| n != "host").cloned());
    h
}

fn request_of(v: &Vector) -> RequestView {
    RequestView::parse_http1(&v.request, "https").unwrap()
}

#[test]
fn traefik_signed_agent_is_allowed_with_headers() {
    let v = vector("valid-trusted-dictionary-form");
    let srv = server_for(&v, vec![]);
    let r = send(srv.addr, "/check", &traefik(&request_of(&v)));
    assert_eq!(r.status, 200);
    assert_eq!(r.headers["checklein-decision"], "allow");
    assert_eq!(r.headers["checklein-assurance"], "2");
    assert_eq!(
        r.headers["checklein-operator"],
        "https://signature-agent.test"
    );
    assert!(r.headers["checklein-verdict"].starts_with("ck_"));
    assert_eq!(r.headers["checklein-flags"], "none");
    srv.shutdown();
}

#[test]
fn nginx_signed_agent_is_allowed() {
    let v = vector("valid-trusted-dictionary-form");
    let srv = server_for(&v, vec![]);
    let r = send(srv.addr, "/auth", &nginx(&request_of(&v)));
    assert_eq!(r.status, 200);
    assert_eq!(r.headers["checklein-decision"], "allow");
    srv.shutdown();
}

#[test]
fn replayed_request_is_challenged_and_can_be_denied() {
    let v = vector("valid-trusted-dictionary-form");
    let srv = server_for(&v, vec![Decision::Challenge]);
    let headers = traefik(&request_of(&v));
    assert_eq!(send(srv.addr, "/check", &headers).status, 200);
    let again = send(srv.addr, "/check", &headers);
    assert_eq!(again.status, 403, "second use of the same signature");
    assert_eq!(again.headers["checklein-decision"], "challenge");
    assert!(again.body.contains("\"decision\":\"challenge\""));
    srv.shutdown();
}

#[test]
fn spoofed_user_agent_passes_through_flagged() {
    let v = vector("spoofed-user-agent");
    let srv = server_for(&v, vec![]);
    let r = send(srv.addr, "/check", &traefik(&request_of(&v)));
    assert_eq!(r.status, 200, "no opinion: existing bot defenses decide");
    assert_eq!(r.headers["checklein-decision"], "pass");
    assert_eq!(r.headers["checklein-assurance"], "0");
    assert_eq!(r.headers["checklein-flags"], "unverified_agent_claim");
    srv.shutdown();
}

#[test]
fn client_cannot_forge_checklein_headers() {
    let v = vector("spoofed-user-agent");
    let srv = server_for(&v, vec![]);
    let mut h = traefik(&request_of(&v));
    h.push(("Checklein-Assurance".into(), "4".into()));
    h.push((
        "Checklein-Operator".into(),
        "https://trusted.example".into(),
    ));
    let r = send(srv.addr, "/check", &h);
    assert_eq!(r.headers["checklein-assurance"], "0");
    assert_eq!(
        r.headers["checklein-operator"], "none",
        "always sent, so proxies overwrite client copies"
    );
    assert_eq!(r.headers["checklein-flags"], "unverified_agent_claim");
    srv.shutdown();
}

#[test]
fn health_and_bad_requests() {
    let v = vector("spoofed-user-agent");
    let srv = server_for(&v, vec![]);
    let health = send(srv.addr, "/healthz", &[("Host".into(), "x".into())]);
    assert_eq!((health.status, health.body.as_str()), (200, "ok"));
    let bad = send(
        srv.addr,
        "/check",
        &[
            ("Host".into(), "x".into()),
            ("X-Forwarded-Uri".into(), "http://evil/".into()),
        ],
    );
    assert_eq!(bad.status, 400);
    srv.shutdown();
}

#[test]
fn concurrent_requests_are_all_answered() {
    let v = vector("spoofed-user-agent");
    let srv = server_for(&v, vec![]);
    let addr = srv.addr;
    let headers = traefik(&request_of(&v));
    let handles: Vec<_> = (0..64)
        .map(|_| {
            let h = headers.clone();
            thread::spawn(move || send(addr, "/check", &h).status)
        })
        .collect();
    assert!(handles.into_iter().all(|t| t.join().unwrap() == 200));
    srv.shutdown();
}

const PRM: &str = "https://mcp.example/.well-known/oauth-protected-resource";

/// An MCP resource that requires a user-delegated token.
fn mcp_server() -> Running {
    use checklein_core::ThresholdPolicy;
    use checklein_mcp::{McpConfig, McpOAuth};
    let cfg: McpConfig = serde_json::from_value(serde_json::json!({
        "resource": ["https://mcp.example/mcp"],
        "issuers": [{ "issuer": "https://auth.example", "jwks": { "keys": [] } }]
    }))
    .unwrap();
    let ck = Checklein::new(StaticResolver::new())
        .adapter(McpOAuth::new(cfg).unwrap())
        .policy(ThresholdPolicy {
            require_delegation: true,
            ..ThresholdPolicy::default()
        });
    start(
        Arc::new(ck),
        ServeConfig {
            listen: "127.0.0.1:0".into(),
            workers: 2,
            deny_on: vec![],
            access_log: false,
            resource_metadata: Some(PRM.into()),
        },
    )
    .unwrap()
}

fn mcp_request(extra: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut h = vec![
        ("Host".to_string(), "checklein:8787".to_string()),
        ("X-Forwarded-Method".to_string(), "POST".to_string()),
        ("X-Forwarded-Host".to_string(), "mcp.example".to_string()),
        ("X-Forwarded-Uri".to_string(), "/mcp".to_string()),
    ];
    h.extend(extra.iter().map(|(a, b)| (a.to_string(), b.to_string())));
    h
}

#[test]
fn missing_token_gets_401_pointing_to_resource_metadata() {
    let srv = mcp_server();
    let r = send(srv.addr, "/check", &mcp_request(&[]));
    assert_eq!(r.status, 401);
    assert_eq!(r.headers["checklein-decision"], "step_up");
    assert_eq!(
        r.headers["www-authenticate"],
        format!("Bearer resource_metadata=\"{PRM}\"")
    );
    srv.shutdown();
}

#[test]
fn invalid_token_gets_401_invalid_token() {
    let srv = mcp_server();
    let r = send(
        srv.addr,
        "/check",
        &mcp_request(&[("Authorization", "Bearer not.a.token")]),
    );
    assert_eq!(r.status, 401);
    assert_eq!(
        r.headers["www-authenticate"],
        format!("Bearer error=\"invalid_token\", resource_metadata=\"{PRM}\"")
    );
    srv.shutdown();
}
