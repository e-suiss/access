//! The facts the parser worker reads from a SAML request (OP-155 m.3 (c), (d), §10.6.1,
//! IDI-8): shared by the worker that writes them, the SAML gateway that carries them and the
//! identity provider that decides on them. Each is one deterministic CBOR map. Sans-I/O.

use suiss_crypto::dcbor::{self, Limits, Value};

pub use crate::edge::WireError;

/// Most certificates a service provider pins.
pub const MAX_CERTS: usize = 8;

/// Largest pinned certificate.
pub const MAX_CERT: usize = 8 * 1024;

/// Most `RequesterID`s or `SessionIndex`es kept from one message.
pub const MAX_LIST: usize = 16;

/// Longest text field kept from a message.
pub const MAX_TEXT: usize = 2048;

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

fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (Value::text(k), v))
            .collect(),
    )
}

fn encoded(v: &Value) -> Result<Vec<u8>, WireError> {
    dcbor::encode(v, Limits::CEILING).map_err(|_| WireError::TooLarge)
}

fn flag(v: &Value, key: &str) -> Result<bool, WireError> {
    match v.get(key) {
        Some(Value::Bool(b)) => Ok(*b),
        _ => Err(WireError::Malformed),
    }
}

fn text(v: &Value, key: &str) -> Result<String, WireError> {
    match v.get(key) {
        Some(Value::Text(t)) if t.len() <= MAX_TEXT => Ok(t.clone()),
        _ => Err(WireError::Malformed),
    }
}

fn opt_text(v: &Value, key: &str) -> Result<Option<String>, WireError> {
    match v.get(key) {
        None => Ok(None),
        Some(_) => text(v, key).map(Some),
    }
}

fn opt_uint(v: &Value, key: &str) -> Result<Option<u64>, WireError> {
    match v.get(key) {
        None => Ok(None),
        Some(Value::Unsigned(n)) => Ok(Some(*n)),
        Some(_) => Err(WireError::Malformed),
    }
}

fn texts(v: &Value, key: &str) -> Result<Vec<String>, WireError> {
    let Some(Value::Array(list)) = v.get(key) else {
        return Err(WireError::Malformed);
    };
    if list.len() > MAX_LIST {
        return Err(WireError::TooLarge);
    }
    list.iter()
        .map(|t| match t {
            Value::Text(t) if t.len() <= MAX_TEXT => Ok(t.clone()),
            _ => Err(WireError::Malformed),
        })
        .collect()
}

fn only(v: &Value, keys: &[&str]) -> Result<(), WireError> {
    let Value::Map(entries) = v else {
        return Err(WireError::Malformed);
    };
    if entries
        .iter()
        .all(|(k, _)| matches!(k, Value::Text(t) if keys.contains(&t.as_str())))
    {
        Ok(())
    } else {
        Err(WireError::Malformed)
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
    /// [`WireError::TooLarge`].
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
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
    /// [`WireError`].
    pub fn decode(input: &[u8]) -> Result<Self, WireError> {
        let v = dcbor::decode(input, Limits::CEILING).map_err(|_| WireError::Malformed)?;
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
            _ => return Err(WireError::Malformed),
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
/// [`WireError::TooLarge`].
pub fn encode_verified(sig_alg: &str) -> Result<Vec<u8>, WireError> {
    encoded(&map(vec![("verified", Value::text(sig_alg))]))
}

/// Reads [`encode_verified`].
///
/// # Errors
/// [`WireError`].
pub fn decode_verified(input: &[u8]) -> Result<String, WireError> {
    let v = dcbor::decode(input, Limits::CEILING).map_err(|_| WireError::Malformed)?;
    only(&v, &["verified"])?;
    text(&v, "verified")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // OP-155 m.3 (c)
    #[test]
    fn facts_round_trip() {
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
    }
}
