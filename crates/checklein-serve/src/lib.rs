//! Forward-auth server: lets an existing reverse proxy ask Checklein about each request.
//!
//! Works with nginx `auth_request`, Traefik `ForwardAuth` and Caddy `forward_auth`.
//! The proxy sends the original request's headers plus forwarding headers describing
//! its method, host and URI; Checklein answers:
//!
//! - **200** to let the request through, with `Checklein-*` headers the proxy can
//!   copy upstream (decision, assurance, operator, flags, verdict id)
//! - **403** when the decision is `deny`, or is listed in `deny_on`
//!
//! `rate_limit`, `challenge` and `pass` answer 200 by default: Checklein reports, the
//! proxy and your existing bot defenses act on `Checklein-Decision`. Checklein never
//! makes a site less protected than it was.
//!
//! **Security:** forwarding headers are trusted. Listen only where the proxy, and
//! nothing else, can reach (the default is 127.0.0.1).

pub mod selftest;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use checklein_core::{Checklein, Decision, RequestView};

#[derive(Debug, Clone)]
pub struct ServeConfig {
    pub listen: String,
    pub workers: usize,
    /// Decisions answered with 403 in addition to `deny`.
    pub deny_on: Vec<Decision>,
    /// Print one access-log line per request to stderr.
    pub access_log: bool,
    /// OAuth Protected Resource Metadata URL (RFC 9728). When set, `step_up` and
    /// invalid bearer tokens answer `401` with a `WWW-Authenticate` header pointing
    /// OAuth/MCP clients to it.
    pub resource_metadata: Option<String>,
}

impl Default for ServeConfig {
    fn default() -> Self {
        ServeConfig {
            listen: "127.0.0.1:8787".into(),
            workers: 4,
            deny_on: Vec::new(),
            access_log: true,
            resource_metadata: None,
        }
    }
}

/// Headers describing the hop to Checklein, never part of the original request.
fn is_forwarding_header(name: &str) -> bool {
    name.starts_with("x-forwarded-")
        || name.starts_with("x-original-")
        || name.starts_with("proxy-")
        || matches!(
            name,
            "host"
                | "x-real-ip"
                | "forwarded"
                | "connection"
                | "keep-alive"
                | "transfer-encoding"
                | "te"
                | "trailer"
                | "upgrade"
                | "content-length"
        )
}

fn first_value(v: &str) -> &str {
    v.split(',').next().unwrap_or("").trim()
}

/// Rebuilds the original request from what the proxy forwarded.
///
/// Method: `X-Forwarded-Method`, `X-Original-Method`, else `GET`.
/// Scheme: `X-Forwarded-Proto`, else `https`.
/// Host: `X-Forwarded-Host`, else `Host`.
/// Target: `X-Forwarded-Uri`, `X-Original-URI`, else `/`.
pub fn reconstruct(headers: &[(String, String)]) -> Result<RequestView, String> {
    let get = |name: &str| {
        headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| first_value(v).to_string())
            .filter(|v| !v.is_empty())
    };
    let method = get("x-forwarded-method")
        .or_else(|| get("x-original-method"))
        .unwrap_or_else(|| "GET".into());
    let scheme = get("x-forwarded-proto").unwrap_or_else(|| "https".into());
    let authority = get("x-forwarded-host")
        .or_else(|| get("host"))
        .ok_or("no X-Forwarded-Host or Host header")?;
    let target = get("x-forwarded-uri")
        .or_else(|| get("x-original-uri"))
        .unwrap_or_else(|| "/".into());
    if !target.starts_with('/') {
        return Err(format!("forwarded URI must be origin-form, got {target:?}"));
    }
    let mut req = RequestView::new(&method, &scheme, &authority, &target);
    for (n, v) in headers {
        let lower = n.to_ascii_lowercase();
        if !is_forwarding_header(&lower) {
            req.push_header(&lower, v);
        }
    }
    Ok(req)
}

/// What to send back to the proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

pub fn decide(ck: &Checklein, req: &RequestView, deny_on: &[Decision]) -> Outcome {
    decide_with(ck, req, deny_on, None)
}

/// Like [`decide`], with OAuth-aware answers when `resource_metadata` is set.
pub fn decide_with(
    ck: &Checklein,
    req: &RequestView,
    deny_on: &[Decision],
    resource_metadata: Option<&str>,
) -> Outcome {
    let verdict = match ck.verify(req) {
        Ok(v) => v,
        Err(e) => {
            return Outcome {
                status: 500,
                headers: vec![],
                body: format!("{{\"error\":{}}}", serde_json::Value::String(e.to_string())),
            };
        }
    };
    let mut headers: Vec<(String, String)> = verdict
        .downstream_headers()
        .into_iter()
        .map(|(n, v)| (n.to_string(), v))
        .collect();

    let bad_bearer = verdict
        .context
        .flags
        .iter()
        .any(|f| f.starts_with("invalid_credential:mcp-oauth"));
    let body = |decision: Decision| {
        serde_json::json!({
            "decision": decision.as_str(),
            "verdict": verdict.context.verdict_id,
            "flags": verdict.context.flags,
        })
        .to_string()
    };
    let challenge = |error: Option<&str>| {
        let mut parts = Vec::new();
        if let Some(e) = error {
            parts.push(format!("error=\"{e}\""));
        }
        if let Some(url) = resource_metadata {
            parts.push(format!("resource_metadata=\"{url}\""));
        }
        if parts.is_empty() {
            "Bearer".to_string()
        } else {
            format!("Bearer {}", parts.join(", "))
        }
    };

    let d = verdict.decision;
    let (status, out_body) = if d == Decision::Deny {
        (403, body(d))
    } else if d == Decision::StepUp {
        headers.push(("www-authenticate".into(), challenge(None)));
        (401, body(d))
    } else if d == Decision::Challenge && bad_bearer && resource_metadata.is_some() {
        headers.push(("www-authenticate".into(), challenge(Some("invalid_token"))));
        (401, body(d))
    } else if deny_on.contains(&d) {
        (403, body(d))
    } else {
        (200, String::new())
    };
    Outcome {
        status,
        headers,
        body: out_body,
    }
}

fn header_pairs(req: &tiny_http::Request) -> Vec<(String, String)> {
    req.headers()
        .iter()
        .map(|h| {
            (
                h.field.as_str().as_str().to_string(),
                h.value.as_str().to_string(),
            )
        })
        .collect()
}

fn respond(req: tiny_http::Request, out: &Outcome) {
    let mut resp = tiny_http::Response::from_string(out.body.clone()).with_status_code(out.status);
    for (n, v) in &out.headers {
        if let Ok(h) = tiny_http::Header::from_bytes(n.as_bytes(), v.as_bytes()) {
            resp = resp.with_header(h);
        }
    }
    if !out.body.is_empty()
        && let Ok(h) = tiny_http::Header::from_bytes(&b"content-type"[..], &b"application/json"[..])
    {
        resp = resp.with_header(h);
    }
    let _ = req.respond(resp);
}

fn handle(ck: &Checklein, cfg: &ServeConfig, req: tiny_http::Request) {
    let path = req.url().split('?').next().unwrap_or("/");
    if path == "/healthz" {
        let _ = req.respond(tiny_http::Response::from_string("ok"));
        return;
    }
    let out = match reconstruct(&header_pairs(&req)) {
        Ok(view) => {
            let out = decide_with(ck, &view, &cfg.deny_on, cfg.resource_metadata.as_deref());
            if cfg.access_log {
                let h = |name: &str| {
                    out.headers
                        .iter()
                        .find(|(n, _)| n == name)
                        .map(|(_, v)| v.as_str())
                        .unwrap_or("-")
                };
                eprintln!(
                    "{} {} {}{} -> {} decision={} assurance={} operator={} flags={}",
                    h("checklein-verdict"),
                    view.method,
                    view.authority,
                    view.request_target(),
                    out.status,
                    h("checklein-decision"),
                    h("checklein-assurance"),
                    h("checklein-operator"),
                    h("checklein-flags"),
                );
            }
            out
        }
        Err(e) => Outcome {
            status: 400,
            headers: vec![],
            body: format!("{{\"error\":{}}}", serde_json::Value::String(e)),
        },
    };
    respond(req, &out);
}

/// A running server: its bound address and worker threads.
pub struct Running {
    pub addr: SocketAddr,
    server: Arc<tiny_http::Server>,
    workers: Vec<JoinHandle<()>>,
}

impl Running {
    /// Blocks until the server stops.
    pub fn join(self) {
        for w in self.workers {
            let _ = w.join();
        }
    }

    /// Stops accepting requests and waits for workers to finish.
    pub fn shutdown(self) {
        for _ in &self.workers {
            self.server.unblock();
        }
        self.join();
    }
}

/// Binds and starts worker threads. Use `listen = "127.0.0.1:0"` for an ephemeral port.
pub fn start(ck: Arc<Checklein>, cfg: ServeConfig) -> io::Result<Running> {
    let server = tiny_http::Server::http(&cfg.listen).map_err(io::Error::other)?;
    let addr = server
        .server_addr()
        .to_ip()
        .ok_or_else(|| io::Error::other("not an IP listener"))?;
    let server = Arc::new(server);
    let cfg = Arc::new(cfg);
    let workers = (0..cfg.workers.max(1))
        .map(|_| {
            let (server, ck, cfg) = (server.clone(), ck.clone(), cfg.clone());
            thread::spawn(move || {
                while let Ok(req) = server.recv() {
                    // A bug in one request must never take a worker down: isolate panics.
                    // The connection of a panicking request is dropped; the worker lives on.
                    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        handle(&ck, &cfg, req);
                    }));
                    if outcome.is_err() && cfg.access_log {
                        eprintln!("checklein: request handler panicked; request dropped");
                    }
                }
            })
        })
        .collect();
    Ok(Running {
        addr,
        server,
        workers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    }

    #[test]
    fn reconstructs_traefik_style() {
        let r = reconstruct(&h(&[
            ("Host", "checklein:8787"),
            ("X-Forwarded-Method", "POST"),
            ("X-Forwarded-Proto", "https"),
            ("X-Forwarded-Host", "Shop.Example"),
            ("X-Forwarded-Uri", "/cart?id=1"),
            ("X-Forwarded-For", "203.0.113.9"),
            ("Signature-Agent", "agent1=\"https://op.example\""),
        ]))
        .unwrap();
        assert_eq!(r.method, "POST");
        assert_eq!(r.authority, "shop.example");
        assert_eq!(r.target_uri(), "https://shop.example/cart?id=1");
        assert_eq!(
            r.headers().len(),
            1,
            "only the original request's headers survive"
        );
    }

    #[test]
    fn reconstructs_nginx_style() {
        let r = reconstruct(&h(&[
            ("Host", "site.example"),
            ("X-Original-Method", "GET"),
            ("X-Original-URI", "/articles/1"),
        ]))
        .unwrap();
        assert_eq!(r.target_uri(), "https://site.example/articles/1");
    }

    #[test]
    fn rejects_absolute_uri_and_missing_host() {
        assert!(reconstruct(&h(&[("Host", "a"), ("X-Forwarded-Uri", "http://evil/")])).is_err());
        assert!(reconstruct(&h(&[("X-Forwarded-Uri", "/")])).is_err());
    }
}
