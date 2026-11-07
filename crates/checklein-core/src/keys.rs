//! Key resolution: pinned keys, then trust lists, then in-band directories.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::encoding::{b64url, b64url_decode};
use crate::finding::KeyTrust;

/// A verification key the resolver vouches for, with its provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedKey {
    /// Raw Ed25519 public key.
    pub public_key: [u8; 32],
    /// RFC 7638 JWK thumbprint (base64url SHA-256).
    pub thumbprint: String,
    /// Operator origin this key belongs to, when known.
    pub operator: Option<String>,
    pub trust: KeyTrust,
}

/// What the adapter already knows about the key's owner.
#[derive(Debug, Default, Clone, Copy)]
pub struct KeyHint<'a> {
    /// Operator origin named in-band, e.g. by a `Signature-Agent` header.
    pub operator: Option<&'a str>,
}

pub trait KeyResolver: Send + Sync {
    fn resolve(&self, keyid: &str, hint: &KeyHint<'_>) -> Option<ResolvedKey>;
}

/// An OKP/Ed25519 JSON Web Key. Other key types are rejected for now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyError {
    #[error("unsupported key type {kty}/{crv}; only OKP/Ed25519 is supported")]
    Unsupported { kty: String, crv: String },
    #[error("invalid Ed25519 public key encoding")]
    Encoding,
}

impl Jwk {
    pub fn from_ed25519(public_key: &[u8; 32]) -> Self {
        Jwk {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: b64url(public_key),
            kid: Some(jwk_thumbprint_ed25519(public_key)),
        }
    }

    pub fn ed25519_bytes(&self) -> Result<[u8; 32], KeyError> {
        if self.kty != "OKP" || self.crv != "Ed25519" {
            return Err(KeyError::Unsupported {
                kty: self.kty.clone(),
                crv: self.crv.clone(),
            });
        }
        b64url_decode(&self.x)
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
            .ok_or(KeyError::Encoding)
    }
}

/// RFC 7638 thumbprint of an Ed25519 key: base64url(SHA-256 of the canonical JWK members).
pub fn jwk_thumbprint_ed25519(public_key: &[u8; 32]) -> String {
    let canonical = format!(
        r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#,
        b64url(public_key)
    );
    b64url(&Sha256::digest(canonical.as_bytes()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EntryStatus {
    #[default]
    Active,
    Revoked,
}

/// One operator in a trust list (see the design doc's trust-list format).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEntry {
    pub operator: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default)]
    pub schemes: Vec<String>,
    /// Inline keys. Thumbprint-only pins that require fetching a directory come later.
    #[serde(default)]
    pub keys: Vec<Jwk>,
    #[serde(default)]
    pub status: EntryStatus,
}

/// A trust list. Signature verification of the list itself (JWS) is not implemented yet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustList {
    pub list: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<String>,
    pub entries: Vec<TrustEntry>,
}

/// An offline resolver built from pinned keys, trust lists and pre-fetched directories.
///
/// Precedence: pinned > trust lists (in load order) > in-band directories.
/// A `revoked` entry in any loaded list removes that operator everywhere.
#[derive(Debug, Default, Clone)]
pub struct StaticResolver {
    trusted: HashMap<String, ResolvedKey>,
    revoked: HashSet<String>,
    directories: HashMap<String, Vec<[u8; 32]>>,
}

impl StaticResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn pin(&mut self, jwk: &Jwk, operator: Option<&str>) -> Result<String, KeyError> {
        let pk = jwk.ed25519_bytes()?;
        let thumbprint = jwk_thumbprint_ed25519(&pk);
        self.trusted.insert(
            thumbprint.clone(),
            ResolvedKey {
                public_key: pk,
                thumbprint: thumbprint.clone(),
                operator: operator.map(str::to_string),
                trust: KeyTrust::Pinned,
            },
        );
        Ok(thumbprint)
    }

    pub fn load_trust_list(&mut self, list: &TrustList) -> Result<(), KeyError> {
        for entry in &list.entries {
            if entry.status == EntryStatus::Revoked {
                self.revoked.insert(entry.operator.clone());
                continue;
            }
            for jwk in &entry.keys {
                let pk = jwk.ed25519_bytes()?;
                let thumbprint = jwk_thumbprint_ed25519(&pk);
                // Earlier sources (pins, earlier lists) keep precedence.
                self.trusted
                    .entry(thumbprint.clone())
                    .or_insert(ResolvedKey {
                        public_key: pk,
                        thumbprint,
                        operator: Some(entry.operator.clone()),
                        trust: KeyTrust::TrustList {
                            list: list.list.clone(),
                            version: list.version.clone(),
                        },
                    });
            }
        }
        Ok(())
    }

    /// Registers the contents of an operator's key directory, as if fetched from its
    /// well-known URI. Keys found only this way resolve as [`KeyTrust::InBand`].
    pub fn add_directory(&mut self, operator: &str, jwks: &Jwks) -> Result<(), KeyError> {
        let keys = jwks
            .keys
            .iter()
            .map(Jwk::ed25519_bytes)
            .collect::<Result<Vec<_>, _>>()?;
        self.directories
            .entry(operator.to_string())
            .or_default()
            .extend(keys);
        Ok(())
    }
}

impl KeyResolver for StaticResolver {
    fn resolve(&self, keyid: &str, hint: &KeyHint<'_>) -> Option<ResolvedKey> {
        if let Some(k) = self.trusted.get(keyid) {
            if k.operator
                .as_ref()
                .is_some_and(|op| self.revoked.contains(op))
            {
                return None;
            }
            return Some(k.clone());
        }
        let operator = hint.operator?;
        if self.revoked.contains(operator) {
            return None;
        }
        self.directories.get(operator)?.iter().find_map(|pk| {
            let thumbprint = jwk_thumbprint_ed25519(pk);
            (thumbprint == keyid).then(|| ResolvedKey {
                public_key: *pk,
                thumbprint,
                operator: Some(operator.to_string()),
                trust: KeyTrust::InBand,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 9421 Appendix B.1.4 test key; its RFC 7638 thumbprint is the `keyid`
    // used throughout the Web Bot Auth draft's examples.
    const RFC_X: &str = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs";
    const RFC_THUMBPRINT: &str = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";

    fn rfc_jwk() -> Jwk {
        Jwk {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: RFC_X.into(),
            kid: None,
        }
    }

    #[test]
    fn thumbprint_matches_web_bot_auth_examples() {
        let pk = rfc_jwk().ed25519_bytes().unwrap();
        assert_eq!(jwk_thumbprint_ed25519(&pk), RFC_THUMBPRINT);
    }

    #[test]
    fn precedence_and_revocation() {
        let mut r = StaticResolver::new();
        r.add_directory(
            "https://op.example",
            &Jwks {
                keys: vec![rfc_jwk()],
            },
        )
        .unwrap();
        let hint = KeyHint {
            operator: Some("https://op.example"),
        };
        assert_eq!(
            r.resolve(RFC_THUMBPRINT, &hint).unwrap().trust,
            KeyTrust::InBand
        );

        let list = TrustList {
            list: "community".into(),
            version: "1".into(),
            previous: None,
            entries: vec![TrustEntry {
                operator: "https://op.example".into(),
                display_name: None,
                schemes: vec![],
                keys: vec![rfc_jwk()],
                status: EntryStatus::Active,
            }],
        };
        r.load_trust_list(&list).unwrap();
        assert!(r.resolve(RFC_THUMBPRINT, &hint).unwrap().trust.is_trusted());

        let mut revoked = list.clone();
        revoked.list = "blocklist".into();
        revoked.entries[0].status = EntryStatus::Revoked;
        r.load_trust_list(&revoked).unwrap();
        assert!(r.resolve(RFC_THUMBPRINT, &hint).is_none());
    }

    #[test]
    fn rejects_non_ed25519() {
        let jwk = Jwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: "AA".into(),
            kid: None,
        };
        assert!(matches!(
            jwk.ed25519_bytes(),
            Err(KeyError::Unsupported { .. })
        ));
    }
}
