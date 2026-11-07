use serde::{Deserialize, Serialize};

use crate::context::{AgentContext, Assurance, flags};
use crate::request::RequestView;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    /// Ask for a stronger credential (e.g. a delegated token).
    StepUp,
    RateLimit,
    /// Fall back to the site's existing bot challenge.
    Challenge,
    Deny,
    /// No opinion: forward with `Checklein-*` headers and let existing defenses decide.
    #[default]
    Pass,
}

impl Decision {
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::StepUp => "step_up",
            Decision::RateLimit => "rate_limit",
            Decision::Challenge => "challenge",
            Decision::Deny => "deny",
            Decision::Pass => "pass",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(
            match s.trim().to_ascii_lowercase().replace('-', "_").as_str() {
                "allow" => Decision::Allow,
                "step_up" => Decision::StepUp,
                "rate_limit" => Decision::RateLimit,
                "challenge" => Decision::Challenge,
                "deny" => Decision::Deny,
                "pass" => Decision::Pass,
                _ => return None,
            },
        )
    }
}

pub trait Policy: Send + Sync {
    /// Identifier and version recorded in receipts.
    fn id(&self) -> (&str, &str);
    fn decide(&self, ctx: &AgentContext, req: &RequestView) -> Decision;
}

/// The built-in policy and the safe default: never makes a site less protected than before.
#[derive(Debug, Clone)]
pub struct ThresholdPolicy {
    pub allow_at: Assurance,
    pub rate_limit_at: Assurance,
}

impl Default for ThresholdPolicy {
    fn default() -> Self {
        ThresholdPolicy {
            allow_at: Assurance::L2TrustedOperator,
            rate_limit_at: Assurance::L1Signed,
        }
    }
}

impl Policy for ThresholdPolicy {
    fn id(&self) -> (&str, &str) {
        ("builtin-threshold", "1")
    }

    fn decide(&self, ctx: &AgentContext, _req: &RequestView) -> Decision {
        if ctx.flags.iter().any(|f| f == flags::OPERATOR_CONFLICT) {
            return Decision::Deny;
        }
        if ctx
            .flags
            .iter()
            .any(|f| f.starts_with(flags::INVALID_CREDENTIAL))
        {
            return Decision::Challenge;
        }
        if ctx.assurance >= self.allow_at {
            Decision::Allow
        } else if ctx.assurance >= self.rate_limit_at {
            Decision::RateLimit
        } else {
            Decision::Pass
        }
    }
}
