//! Web Bot Auth adapter (draft-ietf-webbotauth-httpsig-protocol-01).
//!
//! Accepts both `Signature-Agent` forms seen in the wild:
//! - the draft's dictionary form, covered as `"signature-agent";key="<member>"`
//! - Cloudflare's earlier structured-string form, covered as `"signature-agent"`
//!   (accepted with the warning `signature_agent_string_form`)
//!
//! Not yet: nonce replay cache, live fetch of the operator's key directory
//! (directories are supplied pre-fetched through the resolver), Visa TAP and
//! Mastercard Agent Pay tag profiles.

pub mod vectors;

use checklein_core::encoding::sha256_label;
use checklein_core::{
    Clock, Finding, FindingResult, KeyHint, KeyResolver, RequestView, SchemeAdapter,
};
use checklein_httpsig::{SignatureEntry, parse_signatures, signature_base, verify_ed25519};
use sfv::{Dictionary, Item, ListEntry, Parser};

pub const SCHEME: &str = "web-bot-auth@draft-01";
pub const TAG: &str = "web-bot-auth";
/// Well-known path of an operator's key directory.
pub const DIRECTORY_PATH: &str = "/.well-known/http-message-signatures-directory";

pub mod warnings {
    pub const STRING_FORM: &str = "signature_agent_string_form";
    pub const NONCE_NOT_CHECKED: &str = "nonce_not_checked";
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Longest accepted `expires - created`.
    pub max_validity_secs: i64,
    /// Tolerated clock difference with the signer.
    pub clock_skew_secs: i64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            max_validity_secs: 24 * 3600,
            clock_skew_secs: 60,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct WebBotAuth {
    pub cfg: Config,
}

impl WebBotAuth {
    pub fn new(cfg: Config) -> Self {
        WebBotAuth { cfg }
    }
}

impl SchemeAdapter for WebBotAuth {
    fn id(&self) -> &str {
        SCHEME
    }

    fn detect(&self, req: &RequestView) -> bool {
        req.has_header("signature-input") && req.has_header("signature")
    }

    fn verify(&self, req: &RequestView, keys: &dyn KeyResolver, clock: &dyn Clock) -> Vec<Finding> {
        let entries = match parse_signatures(req) {
            Ok(e) => e,
            // We cannot tell whose signature this was; report it rather than pass silently.
            Err(e) => return vec![Finding::invalid(SCHEME, e.to_string())],
        };
        let now = clock.now_unix();
        entries
            .iter()
            .filter(|e| e.params.tag.as_deref() == Some(TAG))
            .map(|e| self.verify_entry(req, e, keys, now))
            .collect()
    }
}

impl WebBotAuth {
    fn verify_entry(
        &self,
        req: &RequestView,
        e: &SignatureEntry,
        keys: &dyn KeyResolver,
        now: i64,
    ) -> Finding {
        let invalid = |reason: &str| Finding::invalid(SCHEME, reason);
        let p = &e.params;

        if let Some(alg) = &p.alg
            && alg != "ed25519"
        {
            return invalid(&format!("unsupported alg {alg:?}"));
        }
        let (Some(created), Some(expires)) = (p.created, p.expires) else {
            return invalid("created and expires are required");
        };
        if expires <= created {
            return invalid("expires is not after created");
        }
        if expires - created > self.cfg.max_validity_secs {
            return invalid("validity window too long");
        }
        if created > now + self.cfg.clock_skew_secs {
            return invalid("created is in the future");
        }
        if expires < now - self.cfg.clock_skew_secs {
            return invalid("signature expired");
        }
        if !e.covers("@authority") {
            return invalid("@authority is not covered");
        }
        let Some(keyid) = &p.keyid else {
            return invalid("keyid is required");
        };

        let mut warnings = Vec::new();
        let claimed_operator = match signature_agent(req, e, &mut warnings) {
            Ok(op) => op,
            Err(reason) => return invalid(&reason),
        };

        let hint = KeyHint {
            operator: claimed_operator.as_deref(),
        };
        let Some(key) = keys.resolve(keyid, &hint) else {
            return invalid("unknown or revoked key");
        };
        if let (Some(claimed), Some(owner)) = (&claimed_operator, &key.operator)
            && claimed != owner
        {
            return invalid("key belongs to a different operator than Signature-Agent names");
        }

        let base = match signature_base(req, e) {
            Ok(b) => b,
            Err(err) => return invalid(&err.to_string()),
        };
        let digest = sha256_label(base.as_bytes());
        if verify_ed25519(&base, &e.signature, &key.public_key).is_err() {
            let mut f = invalid("signature does not verify");
            f.digest = Some(digest);
            return f;
        }
        if p.nonce.is_some() {
            warnings.push(warnings::NONCE_NOT_CHECKED.to_string());
        }

        let mut f = Finding::new(SCHEME, FindingResult::Valid);
        f.operator = key.operator.clone().or(claimed_operator);
        f.key_thumbprint = Some(key.thumbprint);
        f.key_trust = Some(key.trust);
        f.digest = Some(digest);
        f.warnings = warnings;
        f
    }
}

/// Extracts the operator origin named by a covered `Signature-Agent` header.
fn signature_agent(
    req: &RequestView,
    e: &SignatureEntry,
    warnings: &mut Vec<String>,
) -> Result<Option<String>, String> {
    let Some(raw) = req.header("signature-agent") else {
        return Ok(None);
    };
    let Some(component) = e.components.iter().find(|c| c.name == "signature-agent") else {
        return Err("Signature-Agent is present but not covered by the signature".into());
    };
    let url = match &component.key {
        Some(member) => {
            let dict: Dictionary = Parser::new(&raw)
                .parse()
                .map_err(|_| "malformed Signature-Agent")?;
            match dict.get(member.as_str()) {
                Some(ListEntry::Item(item)) => {
                    item_string(item).ok_or("Signature-Agent member is not a string")?
                }
                _ => return Err("Signature-Agent member named by key is missing".into()),
            }
        }
        None => {
            let item: Item = Parser::new(&raw)
                .parse()
                .map_err(|_| "Signature-Agent must be a string or a dictionary member")?;
            warnings.push(warnings::STRING_FORM.to_string());
            item_string(&item).ok_or("Signature-Agent is not a string")?
        }
    };
    origin(&url)
        .map(Some)
        .ok_or_else(|| "Signature-Agent must be an https URL".into())
}

fn item_string(item: &Item) -> Option<String> {
    item.bare_item.as_string().map(|s| s.as_str().to_string())
}

/// `https://Host[:port]/path` → `https://host[:port]`.
pub fn origin(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://")?;
    let host = rest.split(['/', '?', '#']).next()?;
    if host.is_empty() || host.contains('@') {
        return None;
    }
    Some(format!("https://{}", host.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_extraction() {
        assert_eq!(
            origin("https://Op.Example/dir?x"),
            Some("https://op.example".into())
        );
        assert_eq!(origin("http://op.example"), None);
        assert_eq!(origin("https://user@op.example"), None);
    }
}
