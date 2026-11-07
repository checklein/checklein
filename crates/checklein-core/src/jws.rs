//! Compact JWS (RFC 7515) with EdDSA over Ed25519: the only way Checklein signs
//! anything (receipts, checkpoints, trust lists).
//!
//! Every artifact type has its own `typ`, and verification requires the exact `typ`,
//! so a receipt can never be replayed as a trust list or the other way round.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::Deserialize;
use thiserror::Error;

use crate::encoding::{b64url, b64url_decode};
use crate::keys::jwk_thumbprint_ed25519;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum JwsError {
    #[error("malformed JWS")]
    Malformed,
    #[error("unexpected JWS type {found:?} (expected {expected:?})")]
    WrongType { expected: String, found: String },
    #[error("unsupported JWS algorithm {0:?}")]
    Algorithm(String),
    #[error("no trusted key matches the JWS key id")]
    UnknownKey,
    #[error("JWS signature does not verify")]
    BadSignature,
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    #[serde(default)]
    typ: Option<String>,
    #[serde(default)]
    kid: Option<String>,
}

/// A verified JWS: its payload and the key that signed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub payload: Vec<u8>,
    pub key: [u8; 32],
    pub kid: Option<String>,
}

/// Signs `payload` as a compact JWS with header `{"alg":"EdDSA","typ":typ,"kid":<thumbprint>}`.
pub fn sign(typ: &str, payload: &[u8], key: &SigningKey) -> String {
    let kid = jwk_thumbprint_ed25519(&key.verifying_key().to_bytes());
    let header = format!(r#"{{"alg":"EdDSA","typ":"{typ}","kid":"{kid}"}}"#);
    let signing_input = format!("{}.{}", b64url(header.as_bytes()), b64url(payload));
    let sig: Signature = key.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", b64url(&sig.to_bytes()))
}

/// Verifies a compact JWS of the given `typ` against any of `keys` (strict Ed25519).
/// When the header names a `kid`, only the key with that RFC 7638 thumbprint is tried.
pub fn verify(jws: &str, typ: &str, keys: &[VerifyingKey]) -> Result<Verified, JwsError> {
    let jws = jws.trim();
    let mut parts = jws.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(JwsError::Malformed);
    };
    let header: Header = b64url_decode(h)
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or(JwsError::Malformed)?;
    if header.alg != "EdDSA" {
        return Err(JwsError::Algorithm(header.alg));
    }
    let found = header.typ.unwrap_or_default();
    if found != typ {
        return Err(JwsError::WrongType {
            expected: typ.into(),
            found,
        });
    }
    let sig_bytes = b64url_decode(s).ok_or(JwsError::Malformed)?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| JwsError::Malformed)?;
    let payload = b64url_decode(p).ok_or(JwsError::Malformed)?;
    let signing_input = &jws[..h.len() + 1 + p.len()];

    let candidates: Vec<&VerifyingKey> = keys
        .iter()
        .filter(|k| {
            header
                .kid
                .as_deref()
                .is_none_or(|kid| jwk_thumbprint_ed25519(&k.to_bytes()) == kid)
        })
        .collect();
    if candidates.is_empty() {
        return Err(JwsError::UnknownKey);
    }
    for k in candidates {
        if k.verify_strict(signing_input.as_bytes(), &sig).is_ok() {
            return Ok(Verified {
                payload,
                key: k.to_bytes(),
                kid: header.kid,
            });
        }
    }
    Err(JwsError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_type_binding() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let jws = sign("a+jws", b"{\"x\":1}", &key);
        let v = verify(&jws, "a+jws", &[key.verifying_key()]).unwrap();
        assert_eq!(v.payload, b"{\"x\":1}");
        assert!(matches!(
            verify(&jws, "b+jws", &[key.verifying_key()]),
            Err(JwsError::WrongType { .. })
        ));
        let other = SigningKey::from_bytes(&[8u8; 32]).verifying_key();
        assert_eq!(verify(&jws, "a+jws", &[other]), Err(JwsError::UnknownKey));
    }

    #[test]
    fn tampering_is_detected() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let jws = sign("a+jws", b"{\"x\":1}", &key);
        let mut parts: Vec<String> = jws.split('.').map(str::to_string).collect();
        parts[1] = b64url(b"{\"x\":2}");
        assert_eq!(
            verify(&parts.join("."), "a+jws", &[key.verifying_key()]),
            Err(JwsError::BadSignature)
        );
        assert_eq!(
            verify("a.b", "a+jws", &[key.verifying_key()]),
            Err(JwsError::Malformed)
        );
        let hs = format!(
            "{}.{}.{}",
            b64url(br#"{"alg":"HS256","typ":"a+jws"}"#),
            b64url(b"{}"),
            b64url(b"sig")
        );
        assert!(matches!(
            verify(&hs, "a+jws", &[key.verifying_key()]),
            Err(JwsError::Algorithm(_))
        ));
    }
}
