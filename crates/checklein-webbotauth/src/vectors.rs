//! Conformance vectors: a raw request, the keys a relying party knows, a frozen clock,
//! and the expected verdict. The same files are meant to be run by any verifier.

use checklein_core::context::AgentContext;
use checklein_core::keys::{Jwk, Jwks, TrustList};
use checklein_core::{Checklein, Decision, FixedClock, RequestView, StaticResolver};
use serde::{Deserialize, Serialize};

use crate::WebBotAuth;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Directory {
    pub operator: String,
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Expect {
    pub assurance: u8,
    pub decision: Decision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    /// Substring of the Web Bot Auth finding's failure reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_contains: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vector {
    pub name: String,
    pub description: String,
    /// Raw HTTP/1.1 request head, received over https.
    pub request: String,
    /// Verification time, Unix seconds.
    pub now: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_list: Option<TrustList>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub directories: Vec<Directory>,
    pub expect: Expect,
}

/// Runs one vector. `Err` describes the first mismatch.
pub fn run(v: &Vector) -> Result<AgentContext, String> {
    let mut resolver = StaticResolver::new();
    if let Some(list) = &v.trust_list {
        resolver.load_trust_list(list).map_err(|e| e.to_string())?;
    }
    for d in &v.directories {
        resolver
            .add_directory(
                &d.operator,
                &Jwks {
                    keys: d.keys.clone(),
                },
            )
            .map_err(|e| e.to_string())?;
    }
    let req = RequestView::parse_http1(&v.request, "https").map_err(|e| e.to_string())?;
    let verdict = Checklein::new(resolver)
        .adapter(WebBotAuth::default())
        .clock(FixedClock(v.now))
        .verify(&req)
        .map_err(|e| e.to_string())?;
    let ctx = verdict.context.clone();
    let e = &v.expect;

    let mismatch =
        |what: &str, want: String, got: String| Err(format!("{what}: expected {want}, got {got}"));
    if ctx.assurance.level() != e.assurance {
        return mismatch(
            "assurance",
            e.assurance.to_string(),
            ctx.assurance.level().to_string(),
        );
    }
    if verdict.decision != e.decision {
        return mismatch(
            "decision",
            format!("{:?}", e.decision),
            format!("{:?}", verdict.decision),
        );
    }
    if e.operator.is_some() && ctx.agent.operator != e.operator {
        return mismatch(
            "operator",
            format!("{:?}", e.operator),
            format!("{:?}", ctx.agent.operator),
        );
    }
    if let Some(want) = &e.reason_contains {
        let reasons: Vec<&str> = ctx
            .evidence
            .iter()
            .filter_map(|ev| ev.reason.as_deref())
            .collect();
        if !reasons.iter().any(|r| r.contains(want.as_str())) {
            return mismatch("reason", want.clone(), format!("{reasons:?}"));
        }
    }
    for f in &e.flags {
        if !ctx.flags.contains(f) {
            return mismatch("flag", f.clone(), format!("{:?}", ctx.flags));
        }
    }
    let got: Vec<&String> = verdict.findings.iter().flat_map(|f| &f.warnings).collect();
    for w in &e.warnings {
        if !got.contains(&w) {
            return mismatch("warning", w.clone(), format!("{got:?}"));
        }
    }
    Ok(ctx)
}

/// Renders a request view back to HTTP/1.1 text (Host first).
pub fn render_http1(req: &RequestView) -> String {
    let mut s = format!(
        "{} {} HTTP/1.1\r\nhost: {}\r\n",
        req.method,
        req.request_target(),
        req.authority
    );
    for (n, v) in req.headers() {
        if n != "host" {
            s.push_str(&format!("{n}: {v}\r\n"));
        }
    }
    s.push_str("\r\n");
    s
}
