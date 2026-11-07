use crate::clock::Clock;
use crate::finding::Finding;
use crate::keys::KeyResolver;
use crate::request::RequestView;

/// One credential scheme (Web Bot Auth, MCP OAuth, A2A cards, ...).
///
/// Adapters are pure: given the same request, keys and clock they return the same
/// findings, which is what makes verdicts replayable for disputes.
///
/// Synchronous for now: key resolution is served from a pre-populated cache.
/// Async fetch-on-miss arrives with the network resolver.
pub trait SchemeAdapter: Send + Sync {
    /// Scheme and version, e.g. `web-bot-auth@draft-01`.
    fn id(&self) -> &str;

    /// Cheap check for whether this scheme's evidence is present at all.
    fn detect(&self, req: &RequestView) -> bool;

    /// Verifies every credential of this scheme on the request.
    fn verify(&self, req: &RequestView, keys: &dyn KeyResolver, clock: &dyn Clock) -> Vec<Finding>;
}
