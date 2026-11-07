//! Signed, hash-chained receipts: one per decision.
//!
//! Each receipt is a compact JWS (EdDSA) whose payload names the hash of the previous
//! receipt's JWS, so deleting or editing any entry breaks every later link.
//! Receipts hold digests and thumbprints, never raw tokens, bodies or user identifiers.
//!
//! Hash links catch edits and gaps, but not a log cut short at the end. For that the
//! chain emits signed **checkpoints** (receipt count + head hash) to a separate sink,
//! ideally on other storage: [`verify_checkpoints`] then proves the log still holds at
//! least every receipt a checkpoint vouched for.

use std::io::Write;

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::context::{AgentContext, Assurance, EvidenceRef};
use crate::encoding::sha256_label;
use crate::jws;
use crate::policy::Decision;
use crate::request::RequestView;

pub const GENESIS: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
pub const RECEIPT_TYP: &str = "checklein-receipt+jws";
pub const CHECKPOINT_TYP: &str = "checklein-checkpoint+jws";

/// A signed statement that the log held `count` receipts ending at `head`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub count: u64,
    pub head: String,
    /// Unix seconds.
    pub ts: i64,
}

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
    #[error("checkpoint {0}: malformed or bad signature")]
    Checkpoint(usize),
    #[error("log truncated: a checkpoint vouches for {vouched} receipts, the log has {found}")]
    Truncated { vouched: u64, found: usize },
    #[error("checkpoint at receipt {count} does not match the log (log was rewritten)")]
    CheckpointMismatch { count: u64 },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Appends receipts, optionally mirroring each JWS as one line to a writer (JSONL-style log).
pub struct ReceiptChain {
    key: SigningKey,
    head: String,
    count: u64,
    sink: Option<Box<dyn Write + Send>>,
    checkpoint_every: u64,
    checkpoint_sink: Option<Box<dyn Write + Send>>,
}

impl ReceiptChain {
    /// `seed` is the 32-byte Ed25519 secret. Keep it in a KMS/HSM in production.
    pub fn new(seed: [u8; 32]) -> Self {
        ReceiptChain {
            key: SigningKey::from_bytes(&seed),
            head: GENESIS.to_string(),
            count: 0,
            sink: None,
            checkpoint_every: 0,
            checkpoint_sink: None,
        }
    }

    /// Continues an existing log of `count` receipts whose last entry hashed to `head`.
    pub fn resume(mut self, head: String, count: u64) -> Self {
        self.head = head;
        self.count = count;
        self
    }

    pub fn with_sink(mut self, sink: Box<dyn Write + Send>) -> Self {
        self.sink = Some(sink);
        self
    }

    /// Writes a signed checkpoint to `sink` after every `every` receipts.
    pub fn with_checkpoints(mut self, every: u64, sink: Box<dyn Write + Send>) -> Self {
        self.checkpoint_every = every.max(1);
        self.checkpoint_sink = Some(sink);
        self
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    pub fn head(&self) -> &str {
        &self.head
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    /// Signs `receipt` chained to the current head and returns the JWS.
    pub fn append(&mut self, mut receipt: Receipt) -> Result<String, ChainError> {
        receipt.prev = self.head.clone();
        let ts = receipt.ts;
        let payload = serde_json::to_vec(&receipt).expect("receipt serializes");
        let jws = jws::sign(RECEIPT_TYP, &payload, &self.key);
        self.head = sha256_label(jws.as_bytes());
        self.count += 1;
        if let Some(sink) = self.sink.as_mut() {
            writeln!(sink, "{jws}")?;
            sink.flush()?;
        }
        if self.checkpoint_sink.is_some() && self.count.is_multiple_of(self.checkpoint_every) {
            self.checkpoint(ts)?;
        }
        Ok(jws)
    }

    /// Signs and writes a checkpoint for the current head (also call on shutdown).
    pub fn checkpoint(&mut self, ts: i64) -> Result<Option<String>, ChainError> {
        let Some(sink) = self.checkpoint_sink.as_mut() else {
            return Ok(None);
        };
        let cp = Checkpoint {
            count: self.count,
            head: self.head.clone(),
            ts,
        };
        let jws = jws::sign(
            CHECKPOINT_TYP,
            &serde_json::to_vec(&cp).expect("serializes"),
            &self.key,
        );
        writeln!(sink, "{jws}")?;
        sink.flush()?;
        Ok(Some(jws))
    }
}

/// Verifies signatures and links for a whole log. Returns the decoded receipts.
pub fn verify_chain(jws_lines: &[&str], key: &VerifyingKey) -> Result<Vec<Receipt>, ChainError> {
    let mut expected_prev = GENESIS.to_string();
    let mut out = Vec::with_capacity(jws_lines.len());
    for (i, line) in jws_lines.iter().enumerate() {
        let v = jws::verify(line, RECEIPT_TYP, std::slice::from_ref(key)).map_err(|e| match e {
            jws::JwsError::BadSignature | jws::JwsError::UnknownKey => ChainError::Signature(i),
            _ => ChainError::Malformed(i),
        })?;
        let receipt: Receipt =
            serde_json::from_slice(&v.payload).map_err(|_| ChainError::Malformed(i))?;
        if receipt.prev != expected_prev {
            return Err(ChainError::Broken {
                index: i,
                expected: expected_prev,
                found: receipt.prev,
            });
        }
        expected_prev = sha256_label(line.trim().as_bytes());
        out.push(receipt);
    }
    Ok(out)
}

/// What a checkpointed log proves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointReport {
    pub receipts: usize,
    pub checkpoints: usize,
    /// Receipts covered by the latest checkpoint. Entries after it are only hash-linked.
    pub covered: u64,
}

/// Verifies the log, then every checkpoint against it: a log cut short below a
/// checkpoint's count, or rewritten under one, fails.
pub fn verify_checkpoints(
    log_lines: &[&str],
    checkpoint_lines: &[&str],
    key: &VerifyingKey,
) -> Result<CheckpointReport, ChainError> {
    verify_chain(log_lines, key)?;
    let heads: Vec<String> = log_lines
        .iter()
        .map(|l| sha256_label(l.trim().as_bytes()))
        .collect();
    let mut covered = 0;
    for (i, line) in checkpoint_lines.iter().enumerate() {
        let v = jws::verify(line, CHECKPOINT_TYP, std::slice::from_ref(key))
            .map_err(|_| ChainError::Checkpoint(i))?;
        let cp: Checkpoint =
            serde_json::from_slice(&v.payload).map_err(|_| ChainError::Checkpoint(i))?;
        if cp.count == 0 {
            continue;
        }
        if cp.count as usize > log_lines.len() {
            return Err(ChainError::Truncated {
                vouched: cp.count,
                found: log_lines.len(),
            });
        }
        if heads[cp.count as usize - 1] != cp.head {
            return Err(ChainError::CheckpointMismatch { count: cp.count });
        }
        covered = covered.max(cp.count);
    }
    Ok(CheckpointReport {
        receipts: log_lines.len(),
        checkpoints: checkpoint_lines.len(),
        covered,
    })
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

        // Checkpoints: see the dedicated test below.
        // A different key fails the signature check.
        let other = ReceiptChain::new([8u8; 32]).verifying_key();
        assert!(matches!(
            verify_chain(&[&a], &other),
            Err(ChainError::Signature(0))
        ));
    }

    #[derive(Clone, Default)]
    struct Shared(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Shared {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn checkpoints_detect_truncation_and_rewrites() {
        let cps = Shared::default();
        let mut chain = ReceiptChain::new([7u8; 32]).with_checkpoints(2, Box::new(cps.clone()));
        let lines: Vec<String> = (1..=5).map(|n| chain.append(receipt(n)).unwrap()).collect();
        let vk = chain.verifying_key();
        let cp_text = String::from_utf8(cps.0.lock().unwrap().clone()).unwrap();
        let cp_lines: Vec<&str> = cp_text.lines().collect();
        assert_eq!(cp_lines.len(), 2, "checkpoints after receipts 2 and 4");
        let all: Vec<&str> = lines.iter().map(String::as_str).collect();

        let ok = verify_checkpoints(&all, &cp_lines, &vk).unwrap();
        assert_eq!((ok.receipts, ok.covered), (5, 4));

        // Cutting the log to 3 entries passes verify_chain, but not the checkpoints.
        assert!(verify_chain(&all[..3], &vk).is_ok());
        assert!(matches!(
            verify_checkpoints(&all[..3], &cp_lines, &vk),
            Err(ChainError::Truncated {
                vouched: 4,
                found: 3
            })
        ));

        // A rewritten log (same key, different receipts) fails at the checkpoint.
        let mut forged = ReceiptChain::new([7u8; 32]);
        let fake: Vec<String> = (10..=14)
            .map(|n| forged.append(receipt(n)).unwrap())
            .collect();
        let fake: Vec<&str> = fake.iter().map(String::as_str).collect();
        assert!(matches!(
            verify_checkpoints(&fake, &cp_lines, &vk),
            Err(ChainError::CheckpointMismatch { count: 2 })
        ));

        // A receipt line can't be passed off as a checkpoint.
        assert!(matches!(
            verify_checkpoints(&all, &all[..1], &vk),
            Err(ChainError::Checkpoint(0))
        ));
    }
}
