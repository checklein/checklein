//! Conformance vectors for the MCP OAuth adapter: a raw request carrying a bearer
//! token, the relying party's MCP config (with the issuer's public keys inline), a
//! frozen clock, and the expected verdict.

use checklein_core::context::AgentContext;
use checklein_core::{
    Checklein, Decision, FixedClock, RequestView, StaticResolver, ThresholdPolicy,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{McpConfig, McpOAuth};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Expect {
    pub assurance: u8,
    pub decision: Decision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_contains: Option<String>,
    /// Delegation chain, oldest actor first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegation: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scope: Vec<String>,
    #[serde(default)]
    pub has_principal: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vector {
    pub name: String,
    pub description: String,
    pub request: String,
    pub now: i64,
    /// Same shape as `--mcp-config`.
    pub mcp_config: Value,
    #[serde(default)]
    pub require_delegation: bool,
    pub expect: Expect,
}

pub fn run(v: &Vector) -> Result<AgentContext, String> {
    let cfg: McpConfig = serde_json::from_value(v.mcp_config.clone()).map_err(|e| e.to_string())?;
    let req = RequestView::parse_http1(&v.request, "https").map_err(|e| e.to_string())?;
    let mut ck = Checklein::new(StaticResolver::new())
        .adapter(McpOAuth::new(cfg)?)
        .clock(FixedClock(v.now));
    if v.require_delegation {
        ck = ck.policy(ThresholdPolicy {
            require_delegation: true,
            ..ThresholdPolicy::default()
        });
    }
    let verdict = ck.verify(&req).map_err(|e| e.to_string())?;
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
    let chain: Vec<String> = ctx.delegation.iter().map(|a| a.actor.clone()).collect();
    if chain != e.delegation {
        return mismatch(
            "delegation",
            format!("{:?}", e.delegation),
            format!("{chain:?}"),
        );
    }
    let scope = ctx
        .intent
        .as_ref()
        .map(|i| i.scope.clone())
        .unwrap_or_default();
    if !e.scope.is_empty() && scope != e.scope {
        return mismatch("scope", format!("{:?}", e.scope), format!("{scope:?}"));
    }
    if ctx.principal.is_some() != e.has_principal {
        return mismatch(
            "principal",
            e.has_principal.to_string(),
            ctx.principal.is_some().to_string(),
        );
    }
    Ok(ctx)
}
