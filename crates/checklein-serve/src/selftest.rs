//! `checklein selftest`: checks a deployment the way an attacker and a real agent would.
//!
//! Two targets, either or both:
//!
//! - **`serve` endpoint** (`http://127.0.0.1:8787`): talks to `checklein serve` the way a
//!   proxy does, and checks its verdicts and headers.
//! - **through the proxy** (`via`, an endpoint behind your proxy that echoes request
//!   headers, such as `traefik/whoami`): checks that the proxy asks Checklein, copies the
//!   verdict upstream, and overwrites forged `Checklein-*` headers.
//!
//! The signed test request uses the published RFC 9421 test key. It reaches L2 only
//! where `examples/trust-list.json` (or that key) is trusted; elsewhere that check is
//! reported as skipped, which is the correct production behavior.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use checklein_core::RequestView;
use checklein_core::encoding::b64url_decode;
use checklein_core::keys::jwk_thumbprint_ed25519;
use checklein_httpsig::{Component, SigParams, Signer9421};

/// Private half of the RFC 9421 Appendix B.1.4 test key. Public by design: test use only.
const TEST_KEY_D: &str = "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU";
const TEST_OPERATOR: &str = "https://signature-agent.test";
const SPOOFED_UA: &str = "Mozilla/5.0 (compatible; ChatGPT-User/1.0; checklein-selftest)";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Pass,
    Fail,
    Skip,
}

#[derive(Debug, Clone)]
pub struct Check {
    pub name: String,
    pub outcome: Outcome,
    pub detail: String,
}

impl Check {
    fn new(name: &str, outcome: Outcome, detail: impl Into<String>) -> Self {
        Check {
            name: name.into(),
            outcome,
            detail: detail.into(),
        }
    }
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Values of `Name: value` lines echoed in the body (whoami-style), case-insensitive.
    fn echoed(&self, name: &str) -> Vec<String> {
        let prefix = format!("{}:", name.to_ascii_lowercase());
        self.body
            .lines()
            .filter(|l| l.to_ascii_lowercase().starts_with(&prefix))
            .map(|l| l[prefix.len()..].trim().to_string())
            .collect()
    }
}

fn agent() -> ureq::Agent {
    let config = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(10)))
        .build();
    ureq::Agent::new_with_config(config)
}

fn get(agent: &ureq::Agent, url: &str, headers: &[(String, String)]) -> Result<Reply, String> {
    let mut req = agent.get(url);
    for (n, v) in headers {
        req = req.header(n.as_str(), v.as_str());
    }
    let mut resp = req.call().map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let headers = resp
        .headers()
        .iter()
        .map(|(n, v)| (n.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let body = resp
        .body_mut()
        .with_config()
        .limit(256 * 1024)
        .read_to_string()
        .unwrap_or_default();
    Ok(Reply {
        status,
        headers,
        body,
    })
}

/// `host[:port]` of a URL, as the server will see it in `Host` / `@authority`.
fn authority_of(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let host = rest.split(['/', '?', '#']).next()?;
    (!host.is_empty()).then(|| host.to_string())
}

/// Headers of a request signed now, for `authority`, with the test key.
pub fn signed_test_headers(authority: &str) -> Vec<(String, String)> {
    let seed: [u8; 32] = b64url_decode(TEST_KEY_D)
        .and_then(|v| v.try_into().ok())
        .expect("test key");
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let nonce = format!(
        "selftest-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let agent = format!("agent1=\"{TEST_OPERATOR}\"");
    let req =
        RequestView::new("GET", "https", authority, "/").with_header("Signature-Agent", &agent);
    let signer = Signer9421 {
        label: "sig1".into(),
        components: vec![
            Component::new("@authority").expect("static"),
            Component::dictionary_member("signature-agent", "agent1").expect("static"),
        ],
        params: SigParams {
            created: Some(now),
            expires: Some(now + 60),
            keyid: Some(jwk_thumbprint_ed25519(&key.verifying_key().to_bytes())),
            alg: Some("ed25519".into()),
            nonce: Some(nonce),
            tag: Some("web-bot-auth".into()),
        },
    };
    let (input, sig) = signer.sign(&req, &key).expect("sign test request");
    vec![
        ("Signature-Agent".into(), agent),
        ("Signature-Input".into(), input),
        ("Signature".into(), sig),
    ]
}

/// Checks a `checklein serve` endpoint directly, playing the proxy.
pub fn check_serve(base: &str, host: &str) -> Vec<Check> {
    let base = base.trim_end_matches('/');
    let agent = agent();
    let mut out = Vec::new();
    let forwarded = |extra: Vec<(String, String)>| {
        let mut h = vec![
            ("X-Forwarded-Method".to_string(), "GET".to_string()),
            ("X-Forwarded-Proto".to_string(), "https".to_string()),
            ("X-Forwarded-Host".to_string(), host.to_string()),
            ("X-Forwarded-Uri".to_string(), "/".to_string()),
        ];
        h.extend(extra);
        h
    };

    match get(&agent, &format!("{base}/healthz"), &[]) {
        Ok(r) if r.status == 200 && r.body.trim() == "ok" => out.push(Check::new(
            "serve: health",
            Outcome::Pass,
            "GET /healthz -> ok",
        )),
        Ok(r) => out.push(Check::new(
            "serve: health",
            Outcome::Fail,
            format!("GET /healthz -> {}", r.status),
        )),
        Err(e) => {
            out.push(Check::new(
                "serve: health",
                Outcome::Fail,
                format!("cannot reach {base}: {e}"),
            ));
            return out;
        }
    }

    let check_url = format!("{base}/check");
    match get(
        &agent,
        &check_url,
        &forwarded(vec![("User-Agent".into(), SPOOFED_UA.into())]),
    ) {
        Ok(r) => {
            let flags = r.header("checklein-flags").unwrap_or("");
            let ok = r.header("checklein-assurance") == Some("0")
                && flags.contains("unverified_agent_claim");
            out.push(Check::new(
                "serve: spoofed agent is flagged",
                if ok { Outcome::Pass } else { Outcome::Fail },
                format!(
                    "status {}, assurance {}, flags {flags}",
                    r.status,
                    r.header("checklein-assurance").unwrap_or("-")
                ),
            ));
        }
        Err(e) => out.push(Check::new(
            "serve: spoofed agent is flagged",
            Outcome::Fail,
            e,
        )),
    }

    let signed = forwarded(signed_test_headers(host));
    match get(&agent, &check_url, &signed) {
        Ok(r) => {
            let assurance = r.header("checklein-assurance").unwrap_or("?").to_string();
            if assurance == "2" && r.header("checklein-decision") == Some("allow") {
                out.push(Check::new(
                    "serve: signed test agent is verified",
                    Outcome::Pass,
                    "allow, assurance 2",
                ));
                match get(&agent, &check_url, &signed) {
                    Ok(again) => {
                        let decision = again.header("checklein-decision").unwrap_or("?");
                        let ok = decision == "challenge" || again.status == 403;
                        out.push(Check::new(
                            "serve: replayed signature is rejected",
                            if ok { Outcome::Pass } else { Outcome::Fail },
                            format!("status {}, decision {decision}", again.status),
                        ));
                    }
                    Err(e) => out.push(Check::new(
                        "serve: replayed signature is rejected",
                        Outcome::Fail,
                        e,
                    )),
                }
            } else {
                out.push(Check::new(
                    "serve: signed test agent is verified",
                    Outcome::Skip,
                    format!("assurance {assurance}: the test key isn't trusted here (expected in production; load examples/trust-list.json to exercise this)"),
                ));
            }
        }
        Err(e) => out.push(Check::new(
            "serve: signed test agent is verified",
            Outcome::Fail,
            e,
        )),
    }

    let forged = forwarded(vec![
        ("Checklein-Assurance".into(), "4".into()),
        ("Checklein-Operator".into(), "https://forged.example".into()),
        ("Checklein-Decision".into(), "allow".into()),
    ]);
    match get(&agent, &check_url, &forged) {
        Ok(r) => {
            let ok = r.header("checklein-assurance") == Some("0")
                && r.header("checklein-operator") == Some("none")
                && r.header("checklein-decision") != Some("allow");
            out.push(Check::new(
                "serve: forged Checklein headers are ignored",
                if ok { Outcome::Pass } else { Outcome::Fail },
                format!(
                    "assurance {}, operator {}, decision {}",
                    r.header("checklein-assurance").unwrap_or("-"),
                    r.header("checklein-operator").unwrap_or("-"),
                    r.header("checklein-decision").unwrap_or("-")
                ),
            ));
        }
        Err(e) => out.push(Check::new(
            "serve: forged Checklein headers are ignored",
            Outcome::Fail,
            e,
        )),
    }
    out
}

/// Checks the full path through a proxy to an endpoint that echoes request headers.
pub fn check_via(url: &str) -> Vec<Check> {
    let agent = agent();
    let mut out = Vec::new();
    let Some(authority) = authority_of(url) else {
        return vec![Check::new(
            "proxy: target URL",
            Outcome::Fail,
            format!("not a URL: {url}"),
        )];
    };

    match get(&agent, url, &[("User-Agent".into(), SPOOFED_UA.into())]) {
        Ok(r) => {
            let decisions = r.echoed("checklein-decision");
            let flags = r.echoed("checklein-flags");
            if decisions.is_empty() {
                out.push(Check::new(
                    "proxy: app receives the verdict",
                    Outcome::Fail,
                    format!("status {}; no Checklein-Decision in the echoed request. Is the proxy calling Checklein and copying its headers, and does this endpoint echo request headers?", r.status),
                ));
                return out;
            }
            out.push(Check::new(
                "proxy: app receives the verdict",
                Outcome::Pass,
                format!("Checklein-Decision: {}", decisions.join(", ")),
            ));
            let ok = flags.iter().any(|f| f.contains("unverified_agent_claim"));
            out.push(Check::new(
                "proxy: spoofed agent is flagged upstream",
                if ok { Outcome::Pass } else { Outcome::Fail },
                format!("Checklein-Flags: {}", flags.join(", ")),
            ));
        }
        Err(e) => {
            out.push(Check::new(
                "proxy: app receives the verdict",
                Outcome::Fail,
                format!("cannot reach {url}: {e}"),
            ));
            return out;
        }
    }

    match get(&agent, url, &signed_test_headers(&authority)) {
        Ok(r) => {
            let decision = r.echoed("checklein-decision").join(", ");
            if decision == "allow" {
                out.push(Check::new(
                    "proxy: signed test agent is allowed",
                    Outcome::Pass,
                    "Checklein-Decision: allow",
                ));
            } else {
                out.push(Check::new(
                    "proxy: signed test agent is allowed",
                    Outcome::Skip,
                    format!(
                        "decision {}: the test key isn't trusted here (expected in production)",
                        if decision.is_empty() {
                            "-"
                        } else {
                            decision.as_str()
                        }
                    ),
                ));
            }
        }
        Err(e) => out.push(Check::new(
            "proxy: signed test agent is allowed",
            Outcome::Fail,
            e,
        )),
    }

    let forged = vec![
        ("Checklein-Assurance".to_string(), "4".to_string()),
        (
            "Checklein-Operator".to_string(),
            "https://forged.example".to_string(),
        ),
    ];
    match get(&agent, url, &forged) {
        Ok(r) => {
            let assurance = r.echoed("checklein-assurance");
            let operator = r.echoed("checklein-operator");
            let ok = assurance.len() == 1
                && assurance[0] != "4"
                && !operator.iter().any(|o| o.contains("forged.example"));
            out.push(Check::new(
                "proxy: forged headers never reach the app",
                if ok { Outcome::Pass } else { Outcome::Fail },
                format!(
                    "app saw Checklein-Assurance [{}], Checklein-Operator [{}]",
                    assurance.join(", "),
                    operator.join(", ")
                ),
            ));
        }
        Err(e) => out.push(Check::new(
            "proxy: forged headers never reach the app",
            Outcome::Fail,
            e,
        )),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_parsing() {
        assert_eq!(
            authority_of("http://localhost:8080/x").as_deref(),
            Some("localhost:8080")
        );
        assert_eq!(
            authority_of("https://app.example").as_deref(),
            Some("app.example")
        );
        assert_eq!(authority_of("localhost"), None);
    }
}
