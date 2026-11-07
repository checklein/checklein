//! The normalized verdict: who is acting, for whom, with what authority, at what assurance.

use std::collections::BTreeSet;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::finding::{Finding, IntentKind};
use crate::request::RequestView;

/// The assurance ladder from the design doc. Ordered: higher is stronger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Assurance {
    /// Only a self-declared User-Agent (network hints may add flags).
    L0Declared = 0,
    /// A valid signature or token whose key was found in-band only.
    L1Signed = 1,
    /// L1, and the key is pinned or on a configured trust list.
    L2TrustedOperator = 2,
    /// L2, plus a valid delegated-principal credential for this audience.
    L3Delegated = 3,
    /// L3, plus an attestation binding the principal to a verified person or entity.
    L4HumanBound = 4,
}

impl Assurance {
    pub fn level(self) -> u8 {
        self as u8
    }

    pub fn from_level(level: u8) -> Option<Self> {
        Some(match level {
            0 => Assurance::L0Declared,
            1 => Assurance::L1Signed,
            2 => Assurance::L2TrustedOperator,
            3 => Assurance::L3Delegated,
            4 => Assurance::L4HumanBound,
            _ => return None,
        })
    }
}

impl Serialize for Assurance {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u8(self.level())
    }
}

impl<'de> Deserialize<'de> for Assurance {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let level = u8::deserialize(d)?;
        Assurance::from_level(level)
            .ok_or_else(|| serde::de::Error::custom("assurance must be 0-4"))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_thumbprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    pub kind: String,
    pub issuer: String,
    /// Keyed hash of the subject, linkable within one relying party only.
    pub subject_ref: String,
    pub human_bound: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    pub actor: String,
    pub via: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Intent {
    pub kind: IntentKind,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scope: Vec<String>,
    pub mandate: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRef {
    pub scheme: String,
    pub result: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentContext {
    pub schema: String,
    pub verdict_id: String,
    /// Unix seconds.
    pub evaluated_at: i64,
    pub assurance: Assurance,
    pub agent: AgentInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal: Option<Principal>,
    #[serde(default)]
    pub delegation: Vec<Actor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent: Option<Intent>,
    pub evidence: Vec<EvidenceRef>,
    #[serde(default)]
    pub conflicts: Vec<String>,
    #[serde(default)]
    pub flags: Vec<String>,
}

pub const SCHEMA_ID: &str = "checklein/schema/v0";

/// Flags set by [`normalize`].
pub mod flags {
    /// The User-Agent names a known AI agent but no credential proves it.
    pub const UNVERIFIED_AGENT_CLAIM: &str = "unverified_agent_claim";
    /// Valid findings name different operators.
    pub const OPERATOR_CONFLICT: &str = "operator_conflict";
    /// A credential was present but failed verification (suffixed with `:<scheme>`).
    pub const INVALID_CREDENTIAL: &str = "invalid_credential";
}

#[derive(Debug, Clone)]
pub struct NormalizeConfig {
    /// User-Agent tokens of well-known AI agents. A match without a valid
    /// credential sets [`flags::UNVERIFIED_AGENT_CLAIM`].
    pub known_agent_ua_tokens: Vec<String>,
}

impl Default for NormalizeConfig {
    fn default() -> Self {
        NormalizeConfig {
            known_agent_ua_tokens: [
                "ChatGPT-User",
                "GPTBot",
                "OAI-SearchBot",
                "ClaudeBot",
                "Claude-User",
                "PerplexityBot",
                "Perplexity-User",
                "Meta-ExternalAgent",
                "Google-Agent",
            ]
            .map(String::from)
            .to_vec(),
        }
    }
}

/// Merges findings into one context. Assurance comes from the strongest consistent
/// chain of findings; any operator conflict caps it at L0.
pub fn normalize(
    findings: &[Finding],
    req: &RequestView,
    now: i64,
    verdict_id: String,
    cfg: &NormalizeConfig,
) -> AgentContext {
    let mut flag_set = BTreeSet::new();
    let mut conflicts = Vec::new();

    let valid: Vec<&Finding> = findings.iter().filter(|f| f.is_valid()).collect();
    for f in findings.iter().filter(|f| !f.is_valid()) {
        flag_set.insert(format!("{}:{}", flags::INVALID_CREDENTIAL, f.scheme));
    }

    let operators: BTreeSet<&str> = valid.iter().filter_map(|f| f.operator.as_deref()).collect();
    if operators.len() > 1 {
        conflicts.push(format!(
            "operators disagree: {}",
            operators.iter().copied().collect::<Vec<_>>().join(", ")
        ));
        flag_set.insert(flags::OPERATOR_CONFLICT.to_string());
    }

    // Prefer a finding whose key is trusted; otherwise any valid finding.
    let best = valid
        .iter()
        .copied()
        .find(|f| f.key_trust.as_ref().is_some_and(|t| t.is_trusted()))
        .or_else(|| valid.first().copied());

    let mut assurance = match best {
        Some(f) if f.key_trust.as_ref().is_some_and(|t| t.is_trusted()) => {
            Assurance::L2TrustedOperator
        }
        Some(_) => Assurance::L1Signed,
        None => Assurance::L0Declared,
    };
    if !conflicts.is_empty() {
        assurance = Assurance::L0Declared;
    }

    let user_agent = req.header("user-agent");
    if valid.is_empty()
        && let Some(ua) = &user_agent
        && cfg
            .known_agent_ua_tokens
            .iter()
            .any(|t| ua.contains(t.as_str()))
    {
        flag_set.insert(flags::UNVERIFIED_AGENT_CLAIM.to_string());
    }

    let agent = AgentInfo {
        operator: if conflicts.is_empty() {
            best.and_then(|f| f.operator.clone())
        } else {
            None
        },
        software: user_agent,
        key_thumbprint: best.and_then(|f| f.key_thumbprint.clone()),
        key_source: best.and_then(|f| f.key_trust.as_ref().map(|t| t.label())),
    };

    let intent = best.and_then(|f| f.intent).map(|kind| Intent {
        kind,
        scope: vec![],
        mandate: None,
    });

    let evidence = findings
        .iter()
        .map(|f| EvidenceRef {
            scheme: f.scheme.clone(),
            result: match f.result {
                crate::finding::FindingResult::Valid => "valid",
                crate::finding::FindingResult::Invalid { .. } => "invalid",
                crate::finding::FindingResult::Unsupported { .. } => "unsupported",
            }
            .to_string(),
            reason: f.reason().map(str::to_string),
            digest: f.digest.clone(),
        })
        .collect();

    AgentContext {
        schema: SCHEMA_ID.to_string(),
        verdict_id,
        evaluated_at: now,
        assurance,
        agent,
        principal: None,
        delegation: Vec::new(),
        intent,
        evidence,
        conflicts,
        flags: flag_set.into_iter().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{FindingResult, KeyTrust};

    fn valid(op: &str, trust: KeyTrust) -> Finding {
        let mut f = Finding::new("test@1", FindingResult::Valid);
        f.operator = Some(op.into());
        f.key_trust = Some(trust);
        f
    }

    fn req(ua: &str) -> RequestView {
        RequestView::new("GET", "https", "site.example", "/").with_header("User-Agent", ua)
    }

    fn run(findings: &[Finding], ua: &str) -> AgentContext {
        normalize(
            findings,
            &req(ua),
            0,
            "ck_test".into(),
            &NormalizeConfig::default(),
        )
    }

    #[test]
    fn spoofed_user_agent_is_l0_and_flagged() {
        let ctx = run(&[], "Mozilla/5.0 (compatible; ChatGPT-User/1.0)");
        assert_eq!(ctx.assurance, Assurance::L0Declared);
        assert_eq!(ctx.flags, vec![flags::UNVERIFIED_AGENT_CLAIM]);
    }

    #[test]
    fn in_band_key_caps_at_l1_and_trusted_reaches_l2() {
        assert_eq!(
            run(&[valid("https://a.example", KeyTrust::InBand)], "x").assurance,
            Assurance::L1Signed
        );
        let trusted = KeyTrust::TrustList {
            list: "c".into(),
            version: "1".into(),
        };
        let ctx = run(&[valid("https://a.example", trusted)], "x");
        assert_eq!(ctx.assurance, Assurance::L2TrustedOperator);
        assert_eq!(ctx.agent.key_source.as_deref(), Some("trust-list:c@1"));
    }

    #[test]
    fn operator_conflict_caps_at_l0() {
        let ctx = run(
            &[
                valid("https://a.example", KeyTrust::Pinned),
                valid("https://b.example", KeyTrust::Pinned),
            ],
            "x",
        );
        assert_eq!(ctx.assurance, Assurance::L0Declared);
        assert!(ctx.flags.contains(&flags::OPERATOR_CONFLICT.to_string()));
        assert_eq!(ctx.agent.operator, None);
    }

    #[test]
    fn assurance_serializes_as_number() {
        assert_eq!(
            serde_json::to_string(&Assurance::L2TrustedOperator).unwrap(),
            "2"
        );
    }
}
