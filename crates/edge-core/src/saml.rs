//! The SAML operations of the parser worker (OP-155 m.3 (c), (d), §10.6.1, IDI-8): what a gateway
//! asks a worker to read and verify, and the facts the worker returns. The worker reads the
//! untrusted message, verifies its signature against the certificates the gateway names (the
//! service provider's pinned ones, never a certificate the message carries) and returns facts
//! read from the very element whose signature it verified. Sans-I/O.

use suiss_crypto::dcbor::{self, Limits, Value};

use crate::ipc::FrameError;

/// Most certificates a service provider pins.
pub const MAX_CERTS: usize = 8;

/// Largest pinned certificate.
pub const MAX_CERT: usize = 8 * 1024;

/// Most `RequesterID`s or `SessionIndex`es kept from one message.
pub const MAX_LIST: usize = 16;

/// Longest text field kept from a message.
pub const MAX_TEXT: usize = 2048;

/// What a gateway asks the worker to do with one SAML message.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Context {
    /// The message is raw DEFLATE (HTTP-Redirect binding) and is inflated first.
    pub inflate: bool,
    /// The service provider's pinned certificates, DER; empty when it is not known yet.
    pub certs: Vec<Vec<u8>>,
    /// A message without a valid enveloped signature is refused.
    pub require_signature: bool,
}

/// A detached HTTP-Redirect signature to verify (SAML Bindings §3.4.4.1).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Redirect {
    /// The service provider's pinned certificates, DER.
    pub certs: Vec<Vec<u8>>,
    /// `SigAlg`, decoded.
    pub sig_alg: String,
    /// The signed octets: the original URL-encoded `SAMLRequest`, `RelayState` and `SigAlg`.
    pub signed: Vec<u8>,
    /// `Signature`, base64-decoded.
    pub signature: Vec<u8>,
}

/// The kind of message read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `samlp:AuthnRequest`.
    Authn,
    /// `samlp:LogoutRequest`.
    Logout,
}

/// What the worker found about the message's signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signed {
    /// No enveloped signature (and none was required).
    Absent,
    /// An enveloped signature over the message element verified with a pinned certificate, with
    /// this `SignatureMethod`.
    Verified(String),
}

/// The facts of one request, read from the element whose signature was verified (IDI-8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Facts {
    /// The message kind.
    pub kind: Kind,
    /// `ID`.
    pub id: String,
    /// `IssueInstant`, as written.
    pub issue_instant: String,
    /// `Destination`.
    pub destination: Option<String>,
    /// `saml:Issuer`.
    pub issuer: String,
    /// `AssertionConsumerServiceURL`.
    pub acs_url: Option<String>,
    /// `AssertionConsumerServiceIndex`.
    pub acs_index: Option<u64>,
    /// `ProtocolBinding`.
    pub protocol_binding: Option<String>,
    /// `ForceAuthn`.
    pub force_authn: bool,
    /// `IsPassive`.
    pub is_passive: bool,
    /// `NameIDPolicy/@Format`.
    pub nameid_format: Option<String>,
    /// `NameIDPolicy/@AllowCreate`.
    pub allow_create: Option<bool>,
    /// `NameIDPolicy/@SPNameQualifier`.
    pub sp_name_qualifier: Option<String>,
    /// `Scoping/RequesterID`s.
    pub requester_ids: Vec<String>,
    /// `Scoping/@ProxyCount`.
    pub proxy_count: Option<u64>,
    /// The signature.
    pub signed: Signed,
    /// `saml:NameID` of a `LogoutRequest`.
    pub name_id: Option<String>,
    /// `SessionIndex`es of a `LogoutRequest`.
    pub session_indexes: Vec<String>,
    /// The message came in a SOAP envelope (ECP, PAOS).
    pub soap: bool,
}

fn put(out: &mut Vec<u8>, part: &[u8]) -> Result<(), FrameError> {
    let len = u32::try_from(part.len()).map_err(|_| FrameError::TooLarge)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(part);
    Ok(())
}

fn split(input: &[u8]) -> Result<(Value, &[u8]), FrameError> {
    let (prefix, rest) = input
        .split_first_chunk::<4>()
        .ok_or(FrameError::Truncated)?;
    let n = crate::ipc::length(*prefix, crate::ipc::MAX_HEADER.saturating_mul(32))?;
    if rest.len() < n {
        return Err(FrameError::Truncated);
    }
    let (head, doc) = rest.split_at(n);
    let v = dcbor::decode(head, Limits::CEILING).map_err(|_| FrameError::Malformed)?;
    Ok((v, doc))
}

fn certs_value(certs: &[Vec<u8>]) -> Value {
    Value::Array(certs.iter().map(|c| Value::Bytes(c.clone())).collect())
}

fn certs_of(v: &Value) -> Result<Vec<Vec<u8>>, FrameError> {
    let Some(Value::Array(list)) = v.get("certs") else {
        return Err(FrameError::Malformed);
    };
    if list.len() > MAX_CERTS {
        return Err(FrameError::TooLarge);
    }
    list.iter()
        .map(|c| match c {
            Value::Bytes(b) if !b.is_empty() && b.len() <= MAX_CERT => Ok(b.clone()),
            _ => Err(FrameError::Malformed),
        })
        .collect()
}

fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (Value::text(k), v))
            .collect(),
    )
}

fn encoded(v: &Value) -> Result<Vec<u8>, FrameError> {
    dcbor::encode(v, Limits::CEILING).map_err(|_| FrameError::TooLarge)
}

fn flag(v: &Value, key: &str) -> Result<bool, FrameError> {
    match v.get(key) {
        Some(Value::Bool(b)) => Ok(*b),
        _ => Err(FrameError::Malformed),
    }
}

fn bytes(v: &Value, key: &str) -> Result<Vec<u8>, FrameError> {
    match v.get(key) {
        Some(Value::Bytes(b)) => Ok(b.clone()),
        _ => Err(FrameError::Malformed),
    }
}

fn text(v: &Value, key: &str) -> Result<String, FrameError> {
    match v.get(key) {
        Some(Value::Text(t)) if t.len() <= MAX_TEXT => Ok(t.clone()),
        _ => Err(FrameError::Malformed),
    }
}

fn opt_text(v: &Value, key: &str) -> Result<Option<String>, FrameError> {
    match v.get(key) {
        None => Ok(None),
        Some(_) => text(v, key).map(Some),
    }
}

fn opt_uint(v: &Value, key: &str) -> Result<Option<u64>, FrameError> {
    match v.get(key) {
        None => Ok(None),
        Some(Value::Unsigned(n)) => Ok(Some(*n)),
        Some(_) => Err(FrameError::Malformed),
    }
}

fn texts(v: &Value, key: &str) -> Result<Vec<String>, FrameError> {
    let Some(Value::Array(list)) = v.get(key) else {
        return Err(FrameError::Malformed);
    };
    if list.len() > MAX_LIST {
        return Err(FrameError::TooLarge);
    }
    list.iter()
        .map(|t| match t {
            Value::Text(t) if t.len() <= MAX_TEXT => Ok(t.clone()),
            _ => Err(FrameError::Malformed),
        })
        .collect()
}

fn only(v: &Value, keys: &[&str]) -> Result<(), FrameError> {
    let Value::Map(entries) = v else {
        return Err(FrameError::Malformed);
    };
    if entries
        .iter()
        .all(|(k, _)| matches!(k, Value::Text(t) if keys.contains(&t.as_str())))
    {
        Ok(())
    } else {
        Err(FrameError::Malformed)
    }
}

impl Context {
    /// The worker input: this context, then the message.
    ///
    /// # Errors
    /// [`FrameError::TooLarge`].
    pub fn encode(&self, message: &[u8]) -> Result<Vec<u8>, FrameError> {
        let head = encoded(&map(vec![
            ("inflate", Value::Bool(self.inflate)),
            ("certs", certs_value(&self.certs)),
            ("require_signature", Value::Bool(self.require_signature)),
        ]))?;
        let mut out = Vec::new();
        put(&mut out, &head)?;
        out.extend_from_slice(message);
        Ok(out)
    }

    /// Reads a worker input.
    ///
    /// # Errors
    /// [`FrameError`].
    pub fn decode(input: &[u8]) -> Result<(Self, &[u8]), FrameError> {
        let (v, message) = split(input)?;
        only(&v, &["inflate", "certs", "require_signature"])?;
        Ok((
            Self {
                inflate: flag(&v, "inflate")?,
                certs: certs_of(&v)?,
                require_signature: flag(&v, "require_signature")?,
            },
            message,
        ))
    }
}

impl Redirect {
    /// The worker input.
    ///
    /// # Errors
    /// [`FrameError::TooLarge`].
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let head = encoded(&map(vec![
            ("certs", certs_value(&self.certs)),
            ("sig_alg", Value::text(&self.sig_alg)),
            ("signed", Value::Bytes(self.signed.clone())),
            ("signature", Value::Bytes(self.signature.clone())),
        ]))?;
        let mut out = Vec::new();
        put(&mut out, &head)?;
        Ok(out)
    }

    /// Reads a worker input.
    ///
    /// # Errors
    /// [`FrameError`].
    pub fn decode(input: &[u8]) -> Result<Self, FrameError> {
        let (v, rest) = split(input)?;
        if !rest.is_empty() {
            return Err(FrameError::Malformed);
        }
        only(&v, &["certs", "sig_alg", "signed", "signature"])?;
        Ok(Self {
            certs: certs_of(&v)?,
            sig_alg: text(&v, "sig_alg")?,
            signed: bytes(&v, "signed")?,
            signature: bytes(&v, "signature")?,
        })
    }
}

fn opt(entries: &mut Vec<(&'static str, Value)>, key: &'static str, v: Option<Value>) {
    if let Some(v) = v {
        entries.push((key, v));
    }
}

fn text_list(list: &[String]) -> Value {
    Value::Array(list.iter().map(|t| Value::text(t)).collect())
}

impl Facts {
    /// The worker's output.
    ///
    /// # Errors
    /// [`FrameError::TooLarge`].
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let kind = match self.kind {
            Kind::Authn => "authn",
            Kind::Logout => "logout",
        };
        let mut e = vec![
            ("kind", Value::text(kind)),
            ("id", Value::text(&self.id)),
            ("issue_instant", Value::text(&self.issue_instant)),
            ("issuer", Value::text(&self.issuer)),
            ("force_authn", Value::Bool(self.force_authn)),
            ("is_passive", Value::Bool(self.is_passive)),
            ("requester_ids", text_list(&self.requester_ids)),
            ("session_indexes", text_list(&self.session_indexes)),
            ("soap", Value::Bool(self.soap)),
        ];
        match &self.signed {
            Signed::Absent => {}
            Signed::Verified(alg) => e.push(("signed", Value::text(alg))),
        }
        opt(
            &mut e,
            "destination",
            self.destination.as_deref().map(Value::text),
        );
        opt(&mut e, "acs_url", self.acs_url.as_deref().map(Value::text));
        opt(&mut e, "acs_index", self.acs_index.map(Value::Unsigned));
        opt(
            &mut e,
            "protocol_binding",
            self.protocol_binding.as_deref().map(Value::text),
        );
        opt(
            &mut e,
            "nameid_format",
            self.nameid_format.as_deref().map(Value::text),
        );
        opt(&mut e, "allow_create", self.allow_create.map(Value::Bool));
        opt(
            &mut e,
            "sp_name_qualifier",
            self.sp_name_qualifier.as_deref().map(Value::text),
        );
        opt(&mut e, "proxy_count", self.proxy_count.map(Value::Unsigned));
        opt(&mut e, "name_id", self.name_id.as_deref().map(Value::text));
        encoded(&map(e))
    }

    /// Reads the worker's output.
    ///
    /// # Errors
    /// [`FrameError`].
    pub fn decode(input: &[u8]) -> Result<Self, FrameError> {
        let v = dcbor::decode(input, Limits::CEILING).map_err(|_| FrameError::Malformed)?;
        only(
            &v,
            &[
                "kind",
                "id",
                "issue_instant",
                "issuer",
                "force_authn",
                "is_passive",
                "requester_ids",
                "session_indexes",
                "soap",
                "signed",
                "destination",
                "acs_url",
                "acs_index",
                "protocol_binding",
                "nameid_format",
                "allow_create",
                "sp_name_qualifier",
                "proxy_count",
                "name_id",
            ],
        )?;
        let kind = match text(&v, "kind")?.as_str() {
            "authn" => Kind::Authn,
            "logout" => Kind::Logout,
            _ => return Err(FrameError::Malformed),
        };
        Ok(Self {
            kind,
            id: text(&v, "id")?,
            issue_instant: text(&v, "issue_instant")?,
            destination: opt_text(&v, "destination")?,
            issuer: text(&v, "issuer")?,
            acs_url: opt_text(&v, "acs_url")?,
            acs_index: opt_uint(&v, "acs_index")?,
            protocol_binding: opt_text(&v, "protocol_binding")?,
            force_authn: flag(&v, "force_authn")?,
            is_passive: flag(&v, "is_passive")?,
            nameid_format: opt_text(&v, "nameid_format")?,
            allow_create: match v.get("allow_create") {
                None => None,
                Some(_) => Some(flag(&v, "allow_create")?),
            },
            sp_name_qualifier: opt_text(&v, "sp_name_qualifier")?,
            requester_ids: texts(&v, "requester_ids")?,
            proxy_count: opt_uint(&v, "proxy_count")?,
            signed: opt_text(&v, "signed")?.map_or(Signed::Absent, Signed::Verified),
            name_id: opt_text(&v, "name_id")?,
            session_indexes: texts(&v, "session_indexes")?,
            soap: flag(&v, "soap")?,
        })
    }
}

/// The output of a verified detached signature: its `SigAlg`.
///
/// # Errors
/// [`FrameError::TooLarge`].
pub fn encode_verified(sig_alg: &str) -> Result<Vec<u8>, FrameError> {
    encoded(&map(vec![("verified", Value::text(sig_alg))]))
}

/// Reads [`encode_verified`].
///
/// # Errors
/// [`FrameError`].
pub fn decode_verified(input: &[u8]) -> Result<String, FrameError> {
    let v = dcbor::decode(input, Limits::CEILING).map_err(|_| FrameError::Malformed)?;
    only(&v, &["verified"])?;
    text(&v, "verified")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // OP-155 m.3 (c)
    #[test]
    fn inputs_and_facts_round_trip() {
        let c = Context {
            inflate: true,
            certs: vec![vec![0x30, 0x00]],
            require_signature: true,
        };
        let input = c.encode(b"<a/>").unwrap();
        let (back, doc) = Context::decode(&input).unwrap();
        assert_eq!(back, c);
        assert_eq!(doc, b"<a/>");
        let r = Redirect {
            certs: vec![vec![1]],
            sig_alg: String::from("urn:x"),
            signed: b"SAMLRequest=x".to_vec(),
            signature: vec![2; 3],
        };
        assert_eq!(Redirect::decode(&r.encode().unwrap()).unwrap(), r);
        let f = Facts {
            kind: Kind::Authn,
            id: String::from("_1"),
            issue_instant: String::from("2026-01-01T00:00:00Z"),
            destination: Some(String::from("https://idp/sso")),
            issuer: String::from("https://sp"),
            acs_url: None,
            acs_index: Some(1),
            protocol_binding: None,
            force_authn: true,
            is_passive: false,
            nameid_format: None,
            allow_create: Some(false),
            sp_name_qualifier: None,
            requester_ids: vec![String::from("urn:r")],
            proxy_count: Some(0),
            signed: Signed::Verified(String::from("urn:alg")),
            name_id: None,
            session_indexes: vec![],
            soap: false,
        };
        assert_eq!(Facts::decode(&f.encode().unwrap()).unwrap(), f);
        assert_eq!(
            decode_verified(&encode_verified("a").unwrap()).unwrap(),
            "a"
        );
        let too_many = Context {
            certs: vec![vec![1]; MAX_CERTS + 1],
            ..Context::default()
        };
        assert_eq!(
            Context::decode(&too_many.encode(b"").unwrap()),
            Err(FrameError::TooLarge)
        );
    }
}
