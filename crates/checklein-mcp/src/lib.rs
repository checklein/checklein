//! MCP OAuth adapter: verifies OAuth 2.1 JWT access tokens the way the MCP
//! authorization spec (2026-07-28) expects a resource server to.
//!
//! A valid token from a configured issuer proves that the authorization server issued
//! it **for this resource** (RFC 8707 audience), to a given **client** (a Client ID
//! Metadata Document URL identifies the operator), on behalf of a **principal**
//! (`sub`), possibly through a **chain of agents** (RFC 8693 `act`), with given
//! **scopes**. With a principal that is assurance L3; a client-credentials token
//! (no principal) is L2.
//!
//! Checks, all against Checklein's injected clock so verdicts are replayable:
//! issuer is configured; signature with an asymmetric algorithm (no `none`, no HMAC);
//! `typ` is `at+jwt` (RFC 9068) unless the issuer opts into plain `JWT`; `aud`
//! contains this resource; `exp` required; `nbf` and `iat` honored; delegation depth
//! bounded. The raw subject never leaves the adapter: it becomes a keyed hash.
//!
//! Not yet: opaque tokens (introspection), sender-constrained tokens (DPoP, mTLS
//! `cnf`), which are rejected rather than accepted unbound.

pub mod vectors;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use checklein_core::encoding::{hex, sha256_label};
use checklein_core::finding::KeyTrust;
use checklein_core::{
    Clock, Finding, FindingResult, IntentKind, KeyResolver, RequestView, SchemeAdapter,
};
use hmac::{Hmac, KeyInit, Mac};
use jsonwebtoken::dangerous::insecure_decode;
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use serde_json::Value;
use sha2::Sha256;

pub const SCHEME: &str = "mcp-oauth@2026-07-28";

/// Asymmetric algorithms only: HMAC would let anyone holding the shared secret mint
/// tokens, and `none` is never acceptable.
const ALLOWED_ALGS: [Algorithm; 9] = [
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

#[derive(Debug, Clone, Deserialize)]
pub struct IssuerConfig {
    /// Exact `iss` value.
    pub issuer: String,
    /// Inline keys. Use this or `jwks_uri`.
    #[serde(default)]
    pub jwks: Option<JwkSet>,
    /// Where to fetch the issuer's keys (needs a [`JsonFetcher`]).
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// Also accept header `typ: JWT` (some servers don't use RFC 9068's `at+jwt`).
    #[serde(default)]
    pub accept_jwt_typ: bool,
    /// Extra rules marking a token as a machine (client-credentials) token, for servers
    /// that don't follow RFC 9068's `sub == client_id`. Example for Keycloak:
    /// `{"claim": "preferred_username", "prefix": "service-account-"}`.
    #[serde(default)]
    pub machine_token_claims: Vec<ClaimMatch>,
}

/// Matches a string claim: any of `equals`, `prefix`, `suffix` that is set must hold.
#[derive(Debug, Clone, Deserialize)]
pub struct ClaimMatch {
    pub claim: String,
    #[serde(default)]
    pub equals: Option<String>,
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default)]
    pub suffix: Option<String>,
}

impl ClaimMatch {
    fn matches(&self, claims: &Value) -> bool {
        let Some(v) = claims.get(&self.claim).and_then(Value::as_str) else {
            return false;
        };
        let set = self.equals.is_some() || self.prefix.is_some() || self.suffix.is_some();
        set && self.equals.as_deref().is_none_or(|e| v == e)
            && self.prefix.as_deref().is_none_or(|p| v.starts_with(p))
            && self.suffix.as_deref().is_none_or(|x| v.ends_with(x))
    }
}

/// A token with no resource owner: client credentials. Built-in signals are RFC 9068's
/// `sub == client_id` and Auth0's `gty: client-credentials`; issuers can add more.
fn is_machine_token(claims: &Value, issuer: &IssuerConfig) -> bool {
    let s = |k: &str| claims.get(k).and_then(Value::as_str);
    let sub = s("sub");
    (sub.is_some() && (sub == s("client_id") || sub == s("azp")))
        || s("gty") == Some("client-credentials")
        || issuer
            .machine_token_claims
            .iter()
            .any(|m| m.matches(claims))
}

#[derive(Debug, Clone, Deserialize)]
pub struct McpConfig {
    /// This resource's identifiers. A token must name one in `aud` (RFC 8707).
    pub resource: Vec<String>,
    pub issuers: Vec<IssuerConfig>,
    #[serde(default = "default_skew")]
    pub clock_skew_secs: i64,
    #[serde(default = "default_depth")]
    pub max_delegation_depth: usize,
    /// Hex secret for pseudonymizing subjects. Keep it stable to link a user's requests
    /// across restarts; without it a random per-process key is used.
    #[serde(default)]
    pub subject_key: Option<String>,
}

fn default_skew() -> i64 {
    60
}

fn default_depth() -> usize {
    4
}

/// Fetches JSON over HTTP(S). Implemented outside this crate so the SSRF-guarded
/// fetcher (`checklein-fetch`) can be plugged in. Returns the body and a cache TTL.
pub trait JsonFetcher: Send + Sync {
    fn get(&self, url: &str) -> Result<(Vec<u8>, Duration), String>;
}

struct CachedKeys {
    keys: JwkSet,
    until: Instant,
    fetched: Instant,
}

/// The MCP OAuth adapter.
pub struct McpOAuth {
    cfg: McpConfig,
    subject_key: Vec<u8>,
    fetcher: Option<Arc<dyn JsonFetcher>>,
    cache: Mutex<HashMap<String, CachedKeys>>,
}

/// Minimum time between refetches of one issuer's keys, even on an unknown `kid`, so a
/// stream of tokens with random key ids cannot become a stream of fetches.
const MIN_REFETCH: Duration = Duration::from_secs(60);

impl McpOAuth {
    pub fn new(cfg: McpConfig) -> Result<Self, String> {
        if cfg.resource.is_empty() {
            return Err("at least one resource identifier is required".into());
        }
        for i in &cfg.issuers {
            if i.jwks.is_none() && i.jwks_uri.is_none() {
                return Err(format!("issuer {}: set jwks or jwks_uri", i.issuer));
            }
        }
        let subject_key = match &cfg.subject_key {
            Some(h) => checklein_core::encoding::hex_decode(h)
                .filter(|k| k.len() >= 16)
                .ok_or("subject_key must be at least 16 bytes of hex")?,
            None => random_key(),
        };
        Ok(McpOAuth {
            cfg,
            subject_key,
            fetcher: None,
            cache: Mutex::new(HashMap::new()),
        })
    }

    pub fn with_fetcher(mut self, f: Arc<dyn JsonFetcher>) -> Self {
        self.fetcher = Some(f);
        self
    }

    fn subject_ref(&self, issuer: &str, sub: &str) -> String {
        let mut mac =
            <Hmac<Sha256> as KeyInit>::new_from_slice(&self.subject_key).expect("any key length");
        mac.update(issuer.as_bytes());
        mac.update(&[0]);
        mac.update(sub.as_bytes());
        format!("hmac:{}", &hex(&mac.finalize().into_bytes())[..32])
    }

    /// Candidate keys for this issuer and `kid`, fetching (rate-limited) when needed.
    fn keys(&self, issuer: &IssuerConfig, kid: Option<&str>) -> Vec<Jwk> {
        let pick = |set: &JwkSet| -> Vec<Jwk> {
            match kid {
                Some(k) => set.find(k).cloned().into_iter().collect(),
                None => set.keys.clone(),
            }
        };
        if let Some(set) = &issuer.jwks {
            return pick(set);
        }
        let (Some(uri), Some(fetcher)) = (&issuer.jwks_uri, &self.fetcher) else {
            return Vec::new();
        };
        let mut cache = self.cache.lock().expect("key cache lock");
        let now = Instant::now();
        if let Some(c) = cache.get(&issuer.issuer) {
            let found = pick(&c.keys);
            let fresh = c.until > now;
            let may_refetch = now.duration_since(c.fetched) >= MIN_REFETCH;
            if (fresh && !found.is_empty()) || !may_refetch {
                return found;
            }
        }
        match fetcher.get(uri).ok().and_then(|(body, ttl)| {
            serde_json::from_slice::<JwkSet>(&body)
                .ok()
                .map(|set| (set, ttl))
        }) {
            Some((set, ttl)) => {
                let found = pick(&set);
                cache.insert(
                    issuer.issuer.clone(),
                    CachedKeys {
                        keys: set,
                        until: now + ttl,
                        fetched: now,
                    },
                );
                found
            }
            None => {
                // Remember the failure so it is not retried on every request.
                let stale = cache
                    .get(&issuer.issuer)
                    .map(|c| c.keys.clone())
                    .unwrap_or(JwkSet { keys: vec![] });
                let found = pick(&stale);
                cache.insert(
                    issuer.issuer.clone(),
                    CachedKeys {
                        keys: stale,
                        until: now,
                        fetched: now,
                    },
                );
                found
            }
        }
    }

    fn verify_token(&self, token: &str, now: i64) -> Finding {
        let invalid = |reason: &str| Finding::invalid(SCHEME, reason);
        if token.split('.').count() != 3 {
            return invalid(
                "not a JWT access token (opaque tokens need introspection, not supported yet)",
            );
        }
        let header = match decode_header(token) {
            Ok(h) => h,
            Err(_) => return invalid("malformed token header"),
        };
        if !ALLOWED_ALGS.contains(&header.alg) {
            return invalid(&format!("algorithm {:?} not allowed", header.alg));
        }
        // Routing only: which issuer's keys to try. Nothing here is trusted yet.
        let unverified_iss = insecure_decode::<Value>(token).ok().and_then(|t| {
            t.claims
                .get("iss")
                .and_then(Value::as_str)
                .map(str::to_string)
        });
        let Some(issuer) = unverified_iss
            .as_deref()
            .and_then(|iss| self.cfg.issuers.iter().find(|i| i.issuer == iss))
        else {
            return invalid("token issuer is not trusted");
        };
        let typ = header.typ.as_deref().map(str::to_ascii_lowercase);
        let typ_ok = matches!(typ.as_deref(), Some("at+jwt" | "application/at+jwt"))
            || (issuer.accept_jwt_typ && matches!(typ.as_deref(), Some("jwt") | None));
        if !typ_ok {
            return invalid(
                "token typ is not at+jwt; refusing a token that may not be an access token (RFC 9068)",
            );
        }

        let mut validation = Validation::new(header.alg);
        validation.validate_exp = false; // checked below against the injected clock
        validation.validate_nbf = false;
        validation.validate_aud = false;
        validation.required_spec_claims.clear();
        let mut claims = None;
        let mut kid_used = None;
        for jwk in self.keys(issuer, header.kid.as_deref()) {
            if jwk
                .common
                .key_algorithm
                .is_some_and(|a| a.to_string() != format!("{:?}", header.alg))
            {
                continue;
            }
            let Ok(key) = DecodingKey::from_jwk(&jwk) else {
                continue;
            };
            if let Ok(data) = decode::<Value>(token, &key, &validation) {
                kid_used = jwk.common.key_id.clone();
                claims = Some(data.claims);
                break;
            }
        }
        let Some(c) = claims else {
            return invalid("token signature does not verify with the issuer's keys");
        };

        if c.get("iss").and_then(Value::as_str) != Some(issuer.issuer.as_str()) {
            return invalid("issuer mismatch");
        }
        let aud_ok = match c.get("aud") {
            Some(Value::String(a)) => self.cfg.resource.iter().any(|r| r == a),
            Some(Value::Array(list)) => list
                .iter()
                .filter_map(Value::as_str)
                .any(|a| self.cfg.resource.iter().any(|r| r == a)),
            _ => false,
        };
        if !aud_ok {
            return invalid("token audience is not this resource (RFC 8707)");
        }
        let skew = self.cfg.clock_skew_secs;
        let Some(exp) = c.get("exp").and_then(Value::as_i64) else {
            return invalid("token has no exp");
        };
        if now > exp + skew {
            return invalid("token expired");
        }
        if c.get("nbf")
            .and_then(Value::as_i64)
            .is_some_and(|nbf| now + skew < nbf)
        {
            return invalid("token not yet valid (nbf)");
        }
        if c.get("iat")
            .and_then(Value::as_i64)
            .is_some_and(|iat| iat > now + skew)
        {
            return invalid("token issued in the future (iat)");
        }
        if c.get("cnf").is_some() {
            return invalid("sender-constrained token (cnf: DPoP or mTLS) not supported yet");
        }

        // RFC 8693 `act`: outermost is the current actor; nesting goes back in time.
        let mut actors = Vec::new();
        let mut act = c.get("act");
        while let Some(a) = act {
            let Some(sub) = a.get("sub").and_then(Value::as_str) else {
                return invalid("delegation entry without sub");
            };
            actors.push(sub.to_string());
            if actors.len() > self.cfg.max_delegation_depth {
                return invalid("delegation chain too deep");
            }
            act = a.get("act");
        }
        actors.reverse(); // principal outward: oldest actor first

        let client_id = c
            .get("client_id")
            .or_else(|| c.get("azp"))
            .and_then(Value::as_str)
            .map(str::to_string);
        let mut f = Finding::new(SCHEME, FindingResult::Valid);
        f.operator = client_id.as_deref().and_then(cimd_origin);
        f.client_id = client_id;
        f.issuer = Some(issuer.issuer.clone());
        // A machine token has no principal, however its `sub` looks.
        f.subject_ref = c
            .get("sub")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && !is_machine_token(&c, issuer))
            .map(|sub| self.subject_ref(&issuer.issuer, sub));
        f.actors = actors;
        f.scope = c
            .get("scope")
            .and_then(Value::as_str)
            .map(|s| s.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default();
        f.intent = Some(IntentKind::ToolCall);
        f.key_trust = Some(KeyTrust::Issuer {
            issuer: issuer.issuer.clone(),
        });
        f.key_thumbprint = kid_used;
        f.digest = Some(sha256_label(token.as_bytes()));
        f
    }
}

/// The token after a case-insensitive `Bearer ` prefix. Compares bytes, so a header
/// with multi-byte characters can never cause a slice inside a character.
fn bearer_token(value: &str) -> Option<&str> {
    let prefix = value.as_bytes().get(..7)?;
    if !prefix.eq_ignore_ascii_case(b"bearer ") {
        return None;
    }
    // The first 7 bytes are ASCII, so byte 7 is a character boundary.
    let token = value.get(7..)?.trim();
    (!token.is_empty()).then_some(token)
}

/// A Client ID Metadata Document URL identifies the client by origin.
fn cimd_origin(client_id: &str) -> Option<String> {
    let rest = client_id.strip_prefix("https://")?;
    let host = rest.split(['/', '?', '#']).next()?;
    (!host.is_empty() && !host.contains('@'))
        .then(|| format!("https://{}", host.to_ascii_lowercase()))
}

fn random_key() -> Vec<u8> {
    use std::io::Read;
    let mut k = vec![0u8; 32];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut k))
        .is_err()
    {
        // Fall back to a time-derived key: unlinkable across processes either way.
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        k = sha256_label(&t.to_le_bytes()).into_bytes();
    }
    k
}

impl SchemeAdapter for McpOAuth {
    fn id(&self) -> &str {
        SCHEME
    }

    fn detect(&self, req: &RequestView) -> bool {
        req.header("authorization")
            .is_some_and(|v| bearer_token(&v).is_some())
    }

    fn verify(
        &self,
        req: &RequestView,
        _keys: &dyn KeyResolver,
        clock: &dyn Clock,
    ) -> Vec<Finding> {
        let Some(value) = req.header("authorization") else {
            return vec![];
        };
        if value.contains(',') {
            return vec![Finding::invalid(SCHEME, "multiple Authorization values")];
        }
        let Some(token) = bearer_token(&value) else {
            return vec![];
        };
        vec![self.verify_token(token, clock.now_unix())]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_prefix_is_safe_on_any_input() {
        assert_eq!(bearer_token("Bearer abc"), Some("abc"));
        assert_eq!(bearer_token("bEaReR  abc "), Some("abc"));
        assert_eq!(bearer_token("Bearer "), None);
        assert_eq!(bearer_token("Basic abc"), None);
        // Regression (found by fuzzing): a multi-byte character across byte 7.
        assert_eq!(bearer_token("Be\u{FFFD}\u{FFFD}\u{FFFD}aBearer x"), None);
        assert_eq!(bearer_token("\u{FFFD}\u{FFFD}\u{FFFD}"), None);
    }

    #[test]
    fn cimd_origins() {
        assert_eq!(
            cimd_origin("https://Client.example/oauth/metadata.json").as_deref(),
            Some("https://client.example")
        );
        assert_eq!(cimd_origin("my-client"), None);
        assert_eq!(cimd_origin("http://client.example/x"), None);
    }
}
