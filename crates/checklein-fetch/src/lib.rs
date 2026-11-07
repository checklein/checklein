//! Live key-directory fetching.
//!
//! [`FetchingResolver`] wraps any [`KeyResolver`]. When the inner resolver does not
//! know a key, it fetches the operator's directory from
//! `<operator>/.well-known/http-message-signatures-directory`, caches it, and looks
//! the key up there. Keys found this way are [`KeyTrust::InBand`], so they cap at L1:
//! a self-hosted directory cannot buy trust.
//!
//! SSRF guards: HTTPS only; every resolved address is checked and private, loopback,
//! link-local, CGNAT, multicast, documentation and reserved ranges are refused at
//! connect time (not before, so DNS rebinding cannot slip through); no proxies; no
//! redirects; response size and time caps. Failures are cached briefly so a stream of
//! requests naming a dead or hostile operator does not become a stream of fetches.
//!
//! Not yet: verifying the directory's own response signature (draft
//! `http-message-signatures-directory` tag), async fetch.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use checklein_core::finding::KeyTrust;
use checklein_core::keys::{Jwk, jwk_thumbprint_ed25519};
use checklein_core::{KeyHint, KeyResolver, ResolvedKey};
use thiserror::Error;
use ureq::config::Config;
use ureq::http::Uri;
use ureq::unversioned::resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::{DefaultConnector, NextTimeout};

pub const WELL_KNOWN_PATH: &str = "/.well-known/http-message-signatures-directory";

#[derive(Debug, Clone)]
pub struct FetchConfig {
    /// Total time for one fetch, connect included.
    pub timeout: Duration,
    pub max_bytes: u64,
    /// `Cache-Control: max-age` is clamped to [min_ttl, max_ttl].
    pub min_ttl: Duration,
    pub max_ttl: Duration,
    /// How long a failed fetch is remembered.
    pub negative_ttl: Duration,
    /// Test-only escape hatch: allow `http://` and private addresses.
    pub allow_local_http: bool,
}

impl Default for FetchConfig {
    fn default() -> Self {
        FetchConfig {
            timeout: Duration::from_millis(500),
            max_bytes: 64 * 1024,
            min_ttl: Duration::from_secs(60),
            max_ttl: Duration::from_secs(3600),
            negative_ttl: Duration::from_secs(60),
            allow_local_http: false,
        }
    }
}

#[derive(Debug, Error)]
pub enum FetchError {
    #[error("operator must be an https origin, got {0:?}")]
    BadOrigin(String),
    #[error("refusing to connect to a non-public address")]
    BlockedAddress,
    #[error("http: {0}")]
    Http(String),
    #[error("directory is not a JSON Web Key Set")]
    BadDirectory,
}

/// A fetched directory: the Ed25519 keys it holds and how long to keep them.
#[derive(Debug, Clone)]
pub struct Directory {
    pub keys: Vec<[u8; 32]>,
    pub ttl: Duration,
}

/// Returns true when `ip` is a public unicast address we may connect to.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_v4(v4);
            }
            let s = v6.segments();
            let nat64 = s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0];
            if nat64 {
                let v4 =
                    Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8);
                return is_public_v4(v4);
            }
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // unique local
                || (s[0] & 0xffc0) == 0xfe80 // link local
                || (s[0] == 0x2001 && s[1] == 0x0db8)) // documentation
        }
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        || o[0] == 0 // "this network"
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10 CGNAT
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18.0.0/15 benchmarking
        || o[0] >= 240) // reserved
}

/// Resolver that drops every non-public address after DNS resolution.
#[derive(Debug, Default)]
struct PublicOnlyResolver {
    inner: DefaultResolver,
}

#[derive(Debug)]
struct Blocked;

impl fmt::Display for Blocked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("blocked non-public address")
    }
}

impl std::error::Error for Blocked {}

impl Resolver for PublicOnlyResolver {
    fn resolve(
        &self,
        uri: &Uri,
        config: &Config,
        timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let all = self.inner.resolve(uri, config, timeout)?;
        let mut allowed = self.empty();
        for addr in all.iter().filter(|a| is_public(a.ip())) {
            allowed.push(*addr);
        }
        if allowed.is_empty() {
            return Err(ureq::Error::Other(Box::new(Blocked)));
        }
        Ok(allowed)
    }
}

pub struct DirectoryFetcher {
    agent: ureq::Agent,
    cfg: FetchConfig,
}

impl DirectoryFetcher {
    pub fn new(cfg: FetchConfig) -> Self {
        let config = ureq::Agent::config_builder()
            .https_only(!cfg.allow_local_http)
            .max_redirects(0)
            .proxy(None)
            .timeout_global(Some(cfg.timeout))
            .user_agent(concat!("checklein/", env!("CARGO_PKG_VERSION")))
            .build();
        let agent = if cfg.allow_local_http {
            ureq::Agent::with_parts(
                config,
                DefaultConnector::default(),
                DefaultResolver::default(),
            )
        } else {
            ureq::Agent::with_parts(
                config,
                DefaultConnector::default(),
                PublicOnlyResolver::default(),
            )
        };
        DirectoryFetcher { agent, cfg }
    }

    /// The directory URL for an operator origin such as `https://op.example`.
    pub fn directory_url(&self, operator: &str) -> Result<String, FetchError> {
        let ok_scheme = operator.starts_with("https://")
            || (self.cfg.allow_local_http && operator.starts_with("http://"));
        let host = operator.split_once("://").map(|(_, h)| h).unwrap_or("");
        if !ok_scheme || host.is_empty() || host.contains(['/', '?', '#', '@']) {
            return Err(FetchError::BadOrigin(operator.to_string()));
        }
        Ok(format!("{operator}{WELL_KNOWN_PATH}"))
    }

    pub fn fetch(&self, operator: &str) -> Result<Directory, FetchError> {
        let url = self.directory_url(operator)?;
        let (body, ttl) = self.get(
            &url,
            "application/http-message-signatures-directory+json, application/jwk-set+json, application/json",
        )?;
        Ok(Directory {
            keys: parse_directory(&body)?,
            ttl,
        })
    }

    /// GETs any HTTPS URL (an authorization server's `jwks_uri`, for example) under the
    /// same guards: public addresses only, no redirects or proxies, size and time caps.
    /// Returns the body and a TTL from `Cache-Control: max-age`, clamped.
    pub fn get_json(&self, url: &str) -> Result<(Vec<u8>, Duration), FetchError> {
        let ok_scheme = url.starts_with("https://")
            || (self.cfg.allow_local_http && url.starts_with("http://"));
        let authority = url
            .split_once("://")
            .map(|(_, rest)| rest.split(['/', '?', '#']).next().unwrap_or(""))
            .unwrap_or("");
        if !ok_scheme || authority.is_empty() || authority.contains('@') {
            return Err(FetchError::BadOrigin(url.to_string()));
        }
        self.get(url, "application/jwk-set+json, application/json")
    }

    fn get(&self, url: &str, accept: &str) -> Result<(Vec<u8>, Duration), FetchError> {
        let mut resp = self
            .agent
            .get(url)
            .header("Accept", accept)
            .call()
            .map_err(|e| match e {
                ureq::Error::Other(inner) if inner.is::<Blocked>() => FetchError::BlockedAddress,
                other => FetchError::Http(other.to_string()),
            })?;
        let max_age = resp
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok())
            .and_then(parse_max_age);
        let body = resp
            .body_mut()
            .with_config()
            .limit(self.cfg.max_bytes)
            .read_to_vec()
            .map_err(|e| FetchError::Http(e.to_string()))?;
        let ttl = max_age
            .map(Duration::from_secs)
            .unwrap_or(self.cfg.min_ttl)
            .clamp(self.cfg.min_ttl, self.cfg.max_ttl);
        Ok((body, ttl))
    }
}

fn parse_max_age(cache_control: &str) -> Option<u64> {
    cache_control
        .split(',')
        .find_map(|d| d.trim().strip_prefix("max-age=")?.trim().parse().ok())
}

/// Keeps the OKP/Ed25519 keys of a JWKS and skips the rest (RSA, EC, ...).
pub fn parse_directory(body: &[u8]) -> Result<Vec<[u8; 32]>, FetchError> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| FetchError::BadDirectory)?;
    let keys = v
        .get("keys")
        .and_then(|k| k.as_array())
        .ok_or(FetchError::BadDirectory)?;
    Ok(keys
        .iter()
        .filter_map(|k| serde_json::from_value::<Jwk>(k.clone()).ok())
        .filter_map(|jwk| jwk.ed25519_bytes().ok())
        .collect())
}

struct CacheEntry {
    keys: Vec<[u8; 32]>,
    until: Instant,
}

/// A [`KeyResolver`] that falls back to fetching operator directories.
pub struct FetchingResolver<R: KeyResolver> {
    inner: R,
    fetcher: DirectoryFetcher,
    slots: Mutex<HashMap<String, Arc<Mutex<Option<CacheEntry>>>>>,
    max_operators: usize,
}

impl<R: KeyResolver> FetchingResolver<R> {
    pub fn new(inner: R, cfg: FetchConfig) -> Self {
        FetchingResolver {
            inner,
            fetcher: DirectoryFetcher::new(cfg),
            slots: Mutex::new(HashMap::new()),
            max_operators: 10_000,
        }
    }

    fn slot(&self, operator: &str) -> Arc<Mutex<Option<CacheEntry>>> {
        let mut slots = self.slots.lock().expect("slots lock");
        if slots.len() >= self.max_operators && !slots.contains_key(operator) {
            slots.clear(); // crude bound; entries refill on demand
        }
        slots.entry(operator.to_string()).or_default().clone()
    }

    /// Keys for `operator`, fetching at most once per TTL. Concurrent callers for the
    /// same operator wait on one fetch.
    fn directory_keys(&self, operator: &str) -> Vec<[u8; 32]> {
        let slot = self.slot(operator);
        let mut entry = slot.lock().expect("slot lock");
        if let Some(e) = entry.as_ref()
            && e.until > Instant::now()
        {
            return e.keys.clone();
        }
        let (keys, ttl) = match self.fetcher.fetch(operator) {
            Ok(d) => (d.keys, d.ttl),
            Err(_) => (Vec::new(), self.fetcher.cfg.negative_ttl),
        };
        *entry = Some(CacheEntry {
            keys: keys.clone(),
            until: Instant::now() + ttl,
        });
        keys
    }
}

impl<R: KeyResolver> KeyResolver for FetchingResolver<R> {
    fn resolve(&self, keyid: &str, hint: &KeyHint<'_>) -> Option<ResolvedKey> {
        if let Some(k) = self.inner.resolve(keyid, hint) {
            return Some(k);
        }
        let operator = hint.operator?;
        if self.inner.is_revoked(operator) {
            return None;
        }
        self.directory_keys(operator).into_iter().find_map(|pk| {
            let thumbprint = jwk_thumbprint_ed25519(&pk);
            (thumbprint == keyid).then(|| ResolvedKey {
                public_key: pk,
                thumbprint,
                operator: Some(operator.to_string()),
                trust: KeyTrust::InBand,
            })
        })
    }

    fn is_revoked(&self, operator: &str) -> bool {
        self.inner.is_revoked(operator)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_policy() {
        for blocked in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "198.18.0.1",
            "240.0.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "64:ff9b::a9fe:a9fe",
            "2001:db8::1",
        ] {
            assert!(
                !is_public(blocked.parse().unwrap()),
                "{blocked} should be blocked"
            );
        }
        for public in [
            "1.1.1.1",
            "104.16.0.1",
            "2606:4700::1111",
            "64:ff9b::101:101",
        ] {
            assert!(
                is_public(public.parse().unwrap()),
                "{public} should be allowed"
            );
        }
    }

    #[test]
    fn origin_validation() {
        let f = DirectoryFetcher::new(FetchConfig::default());
        assert!(f.directory_url("https://op.example").is_ok());
        for bad in [
            "http://op.example",
            "https://op.example/x",
            "https://u@op.example",
            "ftp://x",
            "https://",
        ] {
            assert!(f.directory_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn parses_mixed_directory() {
        let body = br#"{"keys":[
            {"kty":"RSA","n":"abc","e":"AQAB"},
            {"kty":"OKP","crv":"Ed25519","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}
        ]}"#;
        assert_eq!(parse_directory(body).unwrap().len(), 1);
        assert!(parse_directory(b"[]").is_err());
    }

    #[test]
    fn max_age_parsing() {
        assert_eq!(parse_max_age("public, max-age=300"), Some(300));
        assert_eq!(parse_max_age("no-store"), None);
    }
}
