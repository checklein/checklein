use serde::{Deserialize, Serialize};

/// Where a verification key came from. Drives the assurance ceiling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KeyTrust {
    /// Pinned in local configuration.
    Pinned,
    /// Listed in a loaded trust list.
    TrustList { list: String, version: String },
    /// Discovered in-band (e.g. a `Signature-Agent` directory) and on no trust list.
    InBand,
    /// Published by an authorization server the relying party configured as trusted.
    Issuer { issuer: String },
}

impl KeyTrust {
    pub fn is_trusted(&self) -> bool {
        !matches!(self, KeyTrust::InBand)
    }

    pub fn label(&self) -> String {
        match self {
            KeyTrust::Pinned => "pinned".into(),
            KeyTrust::TrustList { list, version } => format!("trust-list:{list}@{version}"),
            KeyTrust::InBand => "in-band".into(),
            KeyTrust::Issuer { issuer } => format!("issuer:{issuer}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum FindingResult {
    Valid,
    Invalid { reason: String },
    Unsupported { reason: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentKind {
    Browse,
    ToolCall,
    Purchase,
    Other,
}

/// One scheme adapter's conclusion about one credential on the request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Scheme and version, e.g. `web-bot-auth@draft-01`.
    pub scheme: String,
    #[serde(flatten)]
    pub result: FindingResult,
    /// Operator origin, e.g. `https://operator.example`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_thumbprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_trust: Option<KeyTrust>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent: Option<IntentKind>,
    /// `sha256:` digest of the exact bytes verified (e.g. the RFC 9421 signature base).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// For delegated credentials: keyed hash of the principal (never the raw subject).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_ref: Option<String>,
    /// Token issuer, for delegated credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// OAuth client the credential was issued to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Delegation chain from the principal outward (RFC 8693 `act`), oldest first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actors: Vec<String>,
    /// Granted scopes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scope: Vec<String>,
}

impl Finding {
    pub fn new(scheme: &str, result: FindingResult) -> Self {
        Finding {
            scheme: scheme.to_string(),
            result,
            operator: None,
            key_thumbprint: None,
            key_trust: None,
            intent: None,
            digest: None,
            warnings: Vec::new(),
            subject_ref: None,
            issuer: None,
            client_id: None,
            actors: Vec::new(),
            scope: Vec::new(),
        }
    }

    pub fn invalid(scheme: &str, reason: impl Into<String>) -> Self {
        Finding::new(
            scheme,
            FindingResult::Invalid {
                reason: reason.into(),
            },
        )
    }

    pub fn is_valid(&self) -> bool {
        matches!(self.result, FindingResult::Valid)
    }

    pub fn reason(&self) -> Option<&str> {
        match &self.result {
            FindingResult::Valid => None,
            FindingResult::Invalid { reason } | FindingResult::Unsupported { reason } => {
                Some(reason)
            }
        }
    }
}
