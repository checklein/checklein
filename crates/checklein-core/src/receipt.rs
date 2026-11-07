//! Signed, hash-chained receipts: one per decision.
//!
//! Each receipt is a compact JWS (EdDSA) whose payload names the hash of the previous
//! receipt's JWS, so deleting or editing any entry breaks every later link.
//! Receipts hold digests and thumbprints, never raw tokens, bodies or user identifiers.

use std::io::Write;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::context::{AgentContext, Assurance, EvidenceRef};
use crate::encoding::{b64url, b64url_decode, sha256_label};
use crate::keys::jwk_thumbprint_ed25519;
use crate::policy::Decision;
use crate::request::RequestView;

pub const GENESIS: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const JWS_TYP: &str = "checklein-receipt+jws";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestDigest {
    pub method: String,
    pub authority: String,
    pub path_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerdictSummary {
    pub verdict_id: String,
    pub assurance: Assurance,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_source: Option<String>,
    #[serde(default)]
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRef {
    pub id: String,
    pub version: String,
    pub decision: Decision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub rid: String,
    /// Unix seconds.
    pub ts: i64,
    /// Relying party identifier.
    pub rp: String,
    pub req: RequestDigest,
    pub verdict: VerdictSummary,
    pub evidence: Vec<EvidenceRef>,
    pub policy: PolicyRef,
    /// Hash of the previous receipt's JWS; set by [`ReceiptChain::append`].
    pub prev: String,
}

impl Receipt {
    pub fn from_decision(
        rp: &str,
        req: &RequestView,
        ctx: &AgentContext,
        policy: (&str, &str),
        decision: Decision,
    ) -> Self {
        Receipt {
            rid: format!("{}_r", ctx.verdict_id),
            ts: ctx.evaluated_at,
            rp: rp.to_string(),
            req: RequestDigest {
                method: req.method.clone(),
                authority: req.authority.clone(),
                path_hash: sha256_label(req.request_target().as_bytes()),
            },
            verdict: VerdictSummary {
                verdict_id: ctx.verdict_id.clone(),
                assurance: ctx.assurance,
                operator: ctx.agent.operator.clone(),
                key_source: ctx.agent.key_source.clone(),
                flags: ctx.flags.clone(),
            },
            evidence: ctx.evidence.clone(),
            policy: PolicyRef {
                id: policy.0.into(),
                version: policy.1.into(),
                decision,
            },
            prev: String::new(),
        }
    }
}

#[derive(Debug, Error)]
pub enum ChainError {
    #[error("entry {0}: malformed JWS")]
    Malformed(usize),
    #[error("entry {0}: bad signature")]
    Signature(usize),
    #[error("entry {index}: chain broken (expected prev {expected}, found {found})")]
    Broken {
        index: usize,
        expected: String,
        found: String,
    },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Appends receipts, optionally mirroring each JWS as one line to a writer (JSONL-style log).
pub struct ReceiptChain {
    key: SigningKey,
    kid: String,
    head: String,
    sink: Option<Box<dyn Write + Send>>,
}

impl ReceiptChain {
    /// `seed` is the 32-byte Ed25519 secret. Keep it in a KMS/HSM in production.
    pub fn new(seed: [u8; 32]) -> Self {
        let key = SigningKey::from_bytes(&seed);
        let kid = jwk_thumbprint_ed25519(&key.verifying_key().to_bytes());
        ReceiptChain {
            key,
            kid,
            head: GENESIS.to_string(),
            sink: None,
        }
    }

    /// Continues an existing log whose last entry hashed to `head`.
    pub fn resume(mut self, head: String) -> Self {
        self.head = head;
        self
    }

    pub fn with_sink(mut self, sink: Box<dyn Write + Send>) -> Self {
        self.sink = Some(sink);
        self
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    pub fn head(&self) -> &str {
        &self.head
    }

    /// Signs `receipt` chained to the current head and returns the JWS.
    pub fn append(&mut self, mut receipt: Receipt) -> Result<String, ChainError> {
        receipt.prev = self.head.clone();
        let header = format!(
            r#"{{"alg":"EdDSA","typ":"{JWS_TYP}","kid":"{}"}}"#,
            self.kid
        );
        let payload = serde_json::to_vec(&receipt).expect("receipt serializes");
        let signing_input = format!("{}.{}", b64url(header.as_bytes()), b64url(&payload));
        let sig: Signature = self.key.sign(signing_input.as_bytes());
        let jws = format!("{signing_input}.{}", b64url(&sig.to_bytes()));
        self.head = sha256_label(jws.as_bytes());
        if let Some(sink) = self.sink.as_mut() {
            writeln!(sink, "{jws}")?;
            sink.flush()?;
        }
        Ok(jws)
    }
}

/// Verifies signatures and links for a whole log. Returns the decoded receipts.
pub fn verify_chain(jws_lines: &[&str], key: &VerifyingKey) -> Result<Vec<Receipt>, ChainError> {
    let mut expected_prev = GENESIS.to_string();
    let mut out = Vec::with_capacity(jws_lines.len());
    for (i, jws) in jws_lines.iter().enumerate() {
        let mut parts = jws.split('.');
        let (Some(h), Some(p), Some(s), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(ChainError::Malformed(i));
        };
        let sig_bytes = b64url_decode(s).ok_or(ChainError::Malformed(i))?;
        let sig = Signature::from_slice(&sig_bytes).map_err(|_| ChainError::Malformed(i))?;
        key.verify_strict(format!("{h}.{p}").as_bytes(), &sig)
            .map_err(|_| ChainError::Signature(i))?;
        let payload = b64url_decode(p).ok_or(ChainError::Malformed(i))?;
        let receipt: Receipt =
            serde_json::from_slice(&payload).map_err(|_| ChainError::Malformed(i))?;
        if receipt.prev != expected_prev {
            return Err(ChainError::Broken {
                index: i,
                expected: expected_prev,
                found: receipt.prev,
            });
        }
        expected_prev = sha256_label(jws.as_bytes());
        out.push(receipt);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{NormalizeConfig, normalize};

    fn receipt(n: i64) -> Receipt {
        let req = RequestView::new("GET", "https", "rp.example", "/x");
        let ctx = normalize(&[], &req, n, format!("ck_{n}"), &NormalizeConfig::default());
        Receipt::from_decision("https://rp.example", &req, &ctx, ("p", "1"), Decision::Pass)
    }

    #[test]
    fn chain_verifies_and_detects_tampering() {
        let mut chain = ReceiptChain::new([7u8; 32]);
        let a = chain.append(receipt(1)).unwrap();
        let b = chain.append(receipt(2)).unwrap();
        let c = chain.append(receipt(3)).unwrap();
        let vk = chain.verifying_key();

        let ok = verify_chain(&[&a, &b, &c], &vk).unwrap();
        assert_eq!(ok.len(), 3);
        assert_eq!(ok[0].prev, GENESIS);

        // Dropping an entry breaks the link.
        assert!(matches!(
            verify_chain(&[&a, &c], &vk),
            Err(ChainError::Broken { index: 1, .. })
        ));

        // A different key fails the signature check.
        let other = ReceiptChain::new([8u8; 32]).verifying_key();
        assert!(matches!(
            verify_chain(&[&a], &other),
            Err(ChainError::Signature(0))
        ));
    }
}
