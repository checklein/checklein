//! RFC 9421 HTTP Message Signatures: parsing, signature-base construction and
//! Ed25519 verification. Profile-agnostic: Web Bot Auth, Visa TAP and Mastercard
//! Agent Pay adapters all build on this crate.
//!
//! Supported derived components: `@method`, `@authority`, `@scheme`, `@target-uri`,
//! `@request-target`, `@path`, `@query`. Header components, including dictionary
//! members via the `key` parameter. Not yet: `@query-param`, `@status`, and the
//! `sf`, `bs`, `req`, `tr` parameters (rejected, never silently ignored).

use checklein_core::RequestView;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sfv::{
    BareItem, Dictionary, FieldType, InnerList, Item, KeyRef, ListEntry, Parameters, Parser,
};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HttpSigError {
    #[error("missing {0} header")]
    MissingHeader(&'static str),
    #[error("malformed {0} header")]
    Malformed(&'static str),
    #[error("signature label {0:?} has no matching Signature entry")]
    MissingSignature(String),
    #[error("covered component {0:?} is not present on the request")]
    MissingComponent(String),
    #[error("covered component {0:?} is listed twice")]
    DuplicateComponent(String),
    #[error("unsupported component or parameter: {0}")]
    Unsupported(String),
    #[error("signature parameter {0} has the wrong type")]
    ParamType(&'static str),
    #[error("signature does not verify")]
    BadSignature,
    #[error("invalid public key")]
    BadKey,
}

/// A covered component, e.g. `"@authority"` or `"signature-agent";key="agent1"`.
#[derive(Debug, Clone, PartialEq)]
pub struct Component {
    pub name: String,
    /// Dictionary member selected with the `key` parameter.
    pub key: Option<String>,
    item: Item,
}

impl Component {
    pub fn new(name: &str) -> Result<Self, HttpSigError> {
        let s = sfv::String::from_string(name.to_ascii_lowercase())
            .map_err(|_| HttpSigError::Unsupported(name.into()))?;
        Ok(Component {
            name: name.to_ascii_lowercase(),
            key: None,
            item: Item::new(s),
        })
    }

    pub fn dictionary_member(name: &str, key: &str) -> Result<Self, HttpSigError> {
        let mut c = Component::new(name)?;
        let k = sfv::String::from_string(key.to_string())
            .map_err(|_| HttpSigError::Unsupported(key.into()))?;
        c.item.params.insert(
            KeyRef::from_str("key").expect("static key").to_owned(),
            BareItem::String(k),
        );
        c.key = Some(key.to_string());
        Ok(c)
    }

    /// The component identifier as serialized in the signature base.
    pub fn identifier(&self) -> String {
        self.item.serialize()
    }
}

/// Signature parameters (RFC 9421 §2.3).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SigParams {
    pub created: Option<i64>,
    pub expires: Option<i64>,
    pub keyid: Option<String>,
    pub alg: Option<String>,
    pub nonce: Option<String>,
    pub tag: Option<String>,
}

/// One labelled signature: its `Signature-Input` entry joined with its `Signature` bytes.
#[derive(Debug, Clone, PartialEq)]
pub struct SignatureEntry {
    pub label: String,
    pub components: Vec<Component>,
    pub params: SigParams,
    pub signature: Vec<u8>,
    inner: InnerList,
}

impl SignatureEntry {
    pub fn covers(&self, name: &str) -> bool {
        self.components.iter().any(|c| c.name == name)
    }

    /// The `@signature-params` value: the entry re-serialized as an Inner List.
    pub fn signature_params(&self) -> String {
        serialize_inner(&self.inner)
    }
}

fn serialize_inner(inner: &InnerList) -> String {
    let list: sfv::List = vec![ListEntry::InnerList(inner.clone())];
    list.serialize().expect("non-empty list serializes")
}

/// Parses every labelled signature on the request.
pub fn parse_signatures(req: &RequestView) -> Result<Vec<SignatureEntry>, HttpSigError> {
    let input = req
        .header("signature-input")
        .ok_or(HttpSigError::MissingHeader("Signature-Input"))?;
    let sigs = req
        .header("signature")
        .ok_or(HttpSigError::MissingHeader("Signature"))?;
    let input: Dictionary = Parser::new(&input)
        .parse()
        .map_err(|_| HttpSigError::Malformed("Signature-Input"))?;
    let sigs: Dictionary = Parser::new(&sigs)
        .parse()
        .map_err(|_| HttpSigError::Malformed("Signature"))?;

    let mut out = Vec::new();
    for (label, entry) in &input {
        let ListEntry::InnerList(inner) = entry else {
            return Err(HttpSigError::Malformed("Signature-Input"));
        };
        let signature = match sigs.get(label.as_str()) {
            Some(ListEntry::Item(item)) => item
                .bare_item
                .as_byte_sequence()
                .ok_or(HttpSigError::Malformed("Signature"))?
                .to_vec(),
            _ => return Err(HttpSigError::MissingSignature(label.as_str().to_string())),
        };

        let mut components = Vec::with_capacity(inner.items.len());
        for item in &inner.items {
            let name = item
                .bare_item
                .as_string()
                .ok_or(HttpSigError::Malformed("Signature-Input"))?
                .as_str()
                .to_string();
            let mut key = None;
            for (pk, pv) in &item.params {
                match pk.as_str() {
                    "key" => {
                        key = Some(
                            pv.as_string()
                                .ok_or(HttpSigError::ParamType("key"))?
                                .as_str()
                                .to_string(),
                        )
                    }
                    other => {
                        return Err(HttpSigError::Unsupported(format!(
                            "component parameter {other}"
                        )));
                    }
                }
            }
            let c = Component {
                name,
                key,
                item: item.clone(),
            };
            if components
                .iter()
                .any(|e: &Component| e.identifier() == c.identifier())
            {
                return Err(HttpSigError::DuplicateComponent(c.identifier()));
            }
            components.push(c);
        }

        out.push(SignatureEntry {
            label: label.as_str().to_string(),
            components,
            params: parse_params(&inner.params)?,
            signature,
            inner: inner.clone(),
        });
    }
    Ok(out)
}

fn parse_params(params: &Parameters) -> Result<SigParams, HttpSigError> {
    let int = |v: &BareItem, n: &'static str| -> Result<i64, HttpSigError> {
        v.as_integer()
            .map(i64::from)
            .ok_or(HttpSigError::ParamType(n))
    };
    let string = |v: &BareItem, n: &'static str| -> Result<String, HttpSigError> {
        v.as_string()
            .map(|s| s.as_str().to_string())
            .ok_or(HttpSigError::ParamType(n))
    };
    let mut p = SigParams::default();
    for (k, v) in params {
        match k.as_str() {
            "created" => p.created = Some(int(v, "created")?),
            "expires" => p.expires = Some(int(v, "expires")?),
            "keyid" => p.keyid = Some(string(v, "keyid")?),
            "alg" => p.alg = Some(string(v, "alg")?),
            "nonce" => p.nonce = Some(string(v, "nonce")?),
            "tag" => p.tag = Some(string(v, "tag")?),
            _ => {} // Unknown parameters are covered by the signature; ignoring them is safe.
        }
    }
    Ok(p)
}

fn component_value(req: &RequestView, c: &Component) -> Result<String, HttpSigError> {
    let missing = || HttpSigError::MissingComponent(c.identifier());
    if c.name.starts_with('@') {
        if c.key.is_some() {
            return Err(HttpSigError::Unsupported(c.identifier()));
        }
        return Ok(match c.name.as_str() {
            "@method" => req.method.clone(),
            "@authority" => req.authority.clone(),
            "@scheme" => req.scheme.clone(),
            "@target-uri" => req.target_uri(),
            "@request-target" => req.request_target(),
            "@path" => req.path.clone(),
            "@query" => format!("?{}", req.query.as_deref().unwrap_or("")),
            other => return Err(HttpSigError::Unsupported(other.to_string())),
        });
    }
    match &c.key {
        None => req.header(&c.name).ok_or_else(missing),
        Some(key) => dictionary_member(req, &c.name, key).ok_or_else(missing),
    }
}

/// The serialized value of one member of a dictionary-structured header
/// (RFC 9421 §2.1.2, the `key` parameter), or `None` if absent or malformed.
pub fn dictionary_member(req: &RequestView, header: &str, key: &str) -> Option<String> {
    let dict: Dictionary = Parser::new(&req.header(header)?).parse().ok()?;
    Some(match dict.get(key)? {
        ListEntry::Item(item) => item.serialize(),
        ListEntry::InnerList(inner) => serialize_inner(inner),
    })
}

/// Builds the RFC 9421 §2.5 signature base for one entry.
pub fn signature_base(req: &RequestView, entry: &SignatureEntry) -> Result<String, HttpSigError> {
    let mut base = String::new();
    for c in &entry.components {
        let value = component_value(req, c)?;
        if value.contains('\n') {
            return Err(HttpSigError::Malformed("component value"));
        }
        base.push_str(&c.identifier());
        base.push_str(": ");
        base.push_str(&value);
        base.push('\n');
    }
    base.push_str("\"@signature-params\": ");
    base.push_str(&entry.signature_params());
    Ok(base)
}

/// Verifies an Ed25519 signature (strict: rejects malleable and small-order encodings).
pub fn verify_ed25519(
    base: &str,
    signature: &[u8],
    public_key: &[u8; 32],
) -> Result<(), HttpSigError> {
    let vk = VerifyingKey::from_bytes(public_key).map_err(|_| HttpSigError::BadKey)?;
    let sig = Signature::from_slice(signature).map_err(|_| HttpSigError::BadSignature)?;
    vk.verify_strict(base.as_bytes(), &sig)
        .map_err(|_| HttpSigError::BadSignature)
}

/// Signs a request. Used for test vectors and as the seed of an agent-side SDK.
pub struct Signer9421 {
    pub label: String,
    pub components: Vec<Component>,
    pub params: SigParams,
}

impl Signer9421 {
    /// Returns `(Signature-Input value, Signature value)`.
    pub fn sign(
        &self,
        req: &RequestView,
        key: &SigningKey,
    ) -> Result<(String, String), HttpSigError> {
        let mut params = Parameters::new();
        let mut put = |k: &str, v: BareItem| {
            params.insert(KeyRef::from_str(k).expect("static key").to_owned(), v);
        };
        let s = |v: &str| {
            BareItem::String(sfv::String::from_string(v.to_string()).expect("ascii param"))
        };
        let i = |v: i64| BareItem::Integer(sfv::Integer::try_from(v).expect("in range"));
        if let Some(v) = self.params.created {
            put("created", i(v))
        }
        if let Some(v) = self.params.expires {
            put("expires", i(v))
        }
        if let Some(v) = &self.params.keyid {
            put("keyid", s(v))
        }
        if let Some(v) = &self.params.alg {
            put("alg", s(v))
        }
        if let Some(v) = &self.params.nonce {
            put("nonce", s(v))
        }
        if let Some(v) = &self.params.tag {
            put("tag", s(v))
        }

        let inner = InnerList::with_params(
            self.components.iter().map(|c| c.item.clone()).collect(),
            params,
        );
        let entry = SignatureEntry {
            label: self.label.clone(),
            components: self.components.clone(),
            params: self.params.clone(),
            signature: Vec::new(),
            inner,
        };
        let base = signature_base(req, &entry)?;
        let sig = key.sign(base.as_bytes()).to_bytes();
        Ok((
            format!("{}={}", self.label, entry.signature_params()),
            format!(
                "{}=:{}:",
                self.label,
                checklein_core::encoding::b64std(&sig)
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 9421 Appendix B.2.6: "Signing a Request Using ed25519", verified with the
    /// Appendix B.1.4 test key. An external vector: it checks our signature base
    /// construction against the RFC itself, not against our own signer.
    #[test]
    fn rfc9421_b26_ed25519_vector() {
        let raw = "POST /foo?param=Value&Pet=dog HTTP/1.1\r\n\
            Host: example.com\r\n\
            Date: Tue, 20 Apr 2021 02:07:55 GMT\r\n\
            Content-Type: application/json\r\n\
            Content-Digest: sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:\r\n\
            Content-Length: 18\r\n\
            Signature-Input: sig-b26=(\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");created=1618884473;keyid=\"test-key-ed25519\"\r\n\
            Signature: sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:\r\n\
            \r\n\
            {\"hello\": \"world\"}";
        let req = RequestView::parse_http1(raw, "https").unwrap();
        let entries = parse_signatures(&req).unwrap();
        assert_eq!(entries.len(), 1);
        let base = signature_base(&req, &entries[0]).unwrap();
        assert_eq!(
            base,
            "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\
             \"@method\": POST\n\
             \"@path\": /foo\n\
             \"@authority\": example.com\n\
             \"content-type\": application/json\n\
             \"content-length\": 18\n\
             \"@signature-params\": (\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");created=1618884473;keyid=\"test-key-ed25519\""
        );
        let spki = checklein_core::encoding::b64std_decode(
            "MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=",
        )
        .unwrap();
        let pk: [u8; 32] = spki[12..].try_into().unwrap();
        verify_ed25519(&base, &entries[0].signature, &pk).unwrap();

        let mut tampered = entries[0].signature.clone();
        tampered[0] ^= 1;
        assert_eq!(
            verify_ed25519(&base, &tampered, &pk),
            Err(HttpSigError::BadSignature)
        );
    }

    #[test]
    fn rejects_duplicate_and_unsupported_components() {
        let base = RequestView::new("GET", "https", "a.example", "/");
        let dup = base
            .clone()
            .with_header("Signature-Input", r#"s=("@path" "@path");created=1"#)
            .with_header("Signature", "s=:AAAA:");
        assert!(matches!(
            parse_signatures(&dup),
            Err(HttpSigError::DuplicateComponent(_))
        ));
        let sf = base
            .with_header("Signature-Input", r#"s=("x-a";sf);created=1"#)
            .with_header("Signature", "s=:AAAA:");
        assert!(matches!(
            parse_signatures(&sf),
            Err(HttpSigError::Unsupported(_))
        ));
    }

    #[test]
    fn sign_then_verify_round_trip_with_dictionary_member() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let req = RequestView::new("GET", "https", "site.example", "/page")
            .with_header("Signature-Agent", r#"agent1="https://op.example""#);
        let signer = Signer9421 {
            label: "sig1".into(),
            components: vec![
                Component::new("@authority").unwrap(),
                Component::dictionary_member("signature-agent", "agent1").unwrap(),
            ],
            params: SigParams {
                created: Some(10),
                expires: Some(70),
                tag: Some("web-bot-auth".into()),
                ..Default::default()
            },
        };
        let (input, sig) = signer.sign(&req, &key).unwrap();
        assert_eq!(
            input,
            r#"sig1=("@authority" "signature-agent";key="agent1");created=10;expires=70;tag="web-bot-auth""#
        );
        let req = req
            .with_header("Signature-Input", &input)
            .with_header("Signature", &sig);
        let entry = &parse_signatures(&req).unwrap()[0];
        let base = signature_base(&req, entry).unwrap();
        assert!(base.contains("\"signature-agent\";key=\"agent1\": \"https://op.example\"\n"));
        verify_ed25519(&base, &entry.signature, &key.verifying_key().to_bytes()).unwrap();
    }
}
