//! Checklein core: the scheme-independent half of the verifier.
//!
//! A request flows through [`verifier::Checklein::verify`]:
//! scheme adapters produce [`finding::Finding`]s, [`context::normalize`] merges them
//! into one [`context::AgentContext`] with an [`context::Assurance`] level, a
//! [`policy::Policy`] turns that into a [`policy::Decision`], and
//! [`receipt::ReceiptChain`] records a signed, hash-chained receipt.

pub mod adapter;
pub mod clock;
pub mod context;
pub mod encoding;
pub mod finding;
pub mod jws;
pub mod keys;
pub mod policy;
pub mod receipt;
pub mod replay;
pub mod request;
pub mod verifier;

pub use adapter::SchemeAdapter;
pub use clock::{Clock, FixedClock, SystemClock};
pub use context::{AgentContext, Assurance};
pub use finding::{Finding, FindingResult, IntentKind, KeyTrust};
pub use keys::{KeyHint, KeyResolver, ResolvedKey, StaticResolver};
pub use policy::{Decision, Policy, ThresholdPolicy};
pub use replay::{MemoryReplayGuard, ReplayGuard};
pub use request::RequestView;
pub use verifier::{Checklein, Verdict};
