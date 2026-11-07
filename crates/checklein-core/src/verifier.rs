//! The one-call entry point.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;

use crate::adapter::SchemeAdapter;
use crate::clock::{Clock, SystemClock};
use crate::context::{AgentContext, NormalizeConfig, normalize};
use crate::finding::Finding;
use crate::keys::KeyResolver;
use crate::policy::{Decision, Policy, ThresholdPolicy};
use crate::receipt::{ChainError, Receipt, ReceiptChain};
use crate::request::RequestView;

/// Headers Checklein sets for downstream services. Incoming copies are stripped first.
pub const DOWNSTREAM_HEADERS: [&str; 4] = [
    "checklein-assurance",
    "checklein-operator",
    "checklein-flags",
    "checklein-verdict",
];

#[derive(Debug, Clone, Serialize)]
pub struct Verdict {
    pub decision: Decision,
    pub context: AgentContext,
    /// Per-scheme findings behind the context (warnings, key provenance).
    pub findings: Vec<Finding>,
    /// The receipt JWS, when a receipt chain is configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<String>,
}

impl Verdict {
    /// Headers to forward downstream so services need no Checklein code.
    pub fn downstream_headers(&self) -> Vec<(&'static str, String)> {
        let mut h = vec![
            (
                "checklein-assurance",
                self.context.assurance.level().to_string(),
            ),
            ("checklein-verdict", self.context.verdict_id.clone()),
        ];
        if let Some(op) = &self.context.agent.operator {
            h.push(("checklein-operator", op.clone()));
        }
        if !self.context.flags.is_empty() {
            h.push(("checklein-flags", self.context.flags.join(",")));
        }
        h
    }
}

pub struct Checklein {
    adapters: Vec<Box<dyn SchemeAdapter>>,
    resolver: Box<dyn KeyResolver>,
    clock: Box<dyn Clock>,
    policy: Box<dyn Policy>,
    normalize: NormalizeConfig,
    receipts: Option<(String, Mutex<ReceiptChain>)>,
    counter: AtomicU64,
}

impl Checklein {
    pub fn new(resolver: impl KeyResolver + 'static) -> Self {
        Checklein {
            adapters: Vec::new(),
            resolver: Box::new(resolver),
            clock: Box::new(SystemClock),
            policy: Box::new(ThresholdPolicy::default()),
            normalize: NormalizeConfig::default(),
            receipts: None,
            counter: AtomicU64::new(0),
        }
    }

    pub fn adapter(mut self, a: impl SchemeAdapter + 'static) -> Self {
        self.adapters.push(Box::new(a));
        self
    }

    pub fn clock(mut self, c: impl Clock + 'static) -> Self {
        self.clock = Box::new(c);
        self
    }

    pub fn policy(mut self, p: impl Policy + 'static) -> Self {
        self.policy = Box::new(p);
        self
    }

    pub fn normalize_config(mut self, cfg: NormalizeConfig) -> Self {
        self.normalize = cfg;
        self
    }

    /// Enables receipts. `rp` identifies this relying party in each receipt.
    pub fn receipts(mut self, rp: &str, chain: ReceiptChain) -> Self {
        self.receipts = Some((rp.to_string(), Mutex::new(chain)));
        self
    }

    /// Strips spoofable `Checklein-*` headers, runs every adapter, normalizes,
    /// decides, and records a receipt.
    pub fn verify(&self, req: &RequestView) -> Result<Verdict, ChainError> {
        let mut req = req.clone();
        for h in DOWNSTREAM_HEADERS {
            req.remove_header(h);
        }
        let now = self.clock.now_unix();
        let findings: Vec<_> = self
            .adapters
            .iter()
            .filter(|a| a.detect(&req))
            .flat_map(|a| a.verify(&req, self.resolver.as_ref(), self.clock.as_ref()))
            .collect();

        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let verdict_id = format!("ck_{now:x}_{n:x}");
        let context = normalize(&findings, &req, now, verdict_id, &self.normalize);
        let decision = self.policy.decide(&context, &req);

        let receipt = match &self.receipts {
            Some((rp, chain)) => {
                let r = Receipt::from_decision(rp, &req, &context, self.policy.id(), decision);
                let mut chain = chain.lock().expect("receipt chain lock");
                Some(chain.append(r)?)
            }
            None => None,
        };
        Ok(Verdict {
            decision,
            context,
            findings,
            receipt,
        })
    }
}
