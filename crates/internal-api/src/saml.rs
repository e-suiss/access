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

/// P4: most attributes kept from one assertion, and most values of one attribute.
pub const MAX_ATTRIBUTES: usize = 32;

/// P4: the facts of one SAML 2.0 assertion an upstream IdP issued, read from the assertion
/// element whose enveloped signature verified with a pinned IdP certificate (OP-155 m.3 (h),
/// IDI-8). The Response around it, when there was one, is unsigned context: only its status
/// and `InResponseTo` are kept, and nothing is decided on them alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssertionFacts {
    /// The assertion's `ID`.
    pub id: String,
    /// The assertion's `saml:Issuer`, the IdP entity ID.
    pub issuer: String,
    /// `IssueInstant`, as written.
    pub issue_instant: String,
    /// `Subject/NameID`.
    pub name_id: String,
    /// `NameID/@Format`.
    pub name_id_format: Option<String>,
    /// `Conditions/AudienceRestriction/Audience`s.
    pub audiences: Vec<String>,
    /// `Conditions/@NotBefore`.
    pub not_before: Option<String>,
    /// `Conditions/@NotOnOrAfter`.
    pub not_on_or_after: Option<String>,
    /// The bearer `SubjectConfirmationData/@Recipient`.
    pub recipient: Option<String>,
    /// The bearer `SubjectConfirmationData/@NotOnOrAfter`.
    pub confirmation_not_on_or_after: Option<String>,
    /// The bearer `SubjectConfirmationData/@InResponseTo`.
    pub in_response_to: Option<String>,
    /// `AuthnStatement/@AuthnInstant`.
    pub authn_instant: Option<String>,
    /// `AuthnStatement/@SessionIndex`.
    pub session_index: Option<String>,
    /// `AuthnContext/AuthnContextClassRef`.
    pub authn_context: Option<String>,
    /// `AttributeStatement` attributes by `Name`, each with its values, in document order.
    pub attributes: Vec<(String, Vec<String>)>,
    /// The verified `SignatureMethod`.
    pub signed: String,
    /// The assertion came inside a `samlp:Response` whose status was success.
    pub in_response: bool,
}

impl AssertionFacts {
    /// The worker's output.
    ///
    /// # Errors
    /// [`WireError::TooLarge`].
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut e = vec![
            ("id", Value::text(&self.id)),
            ("issuer", Value::text(&self.issuer)),
            ("issue_instant", Value::text(&self.issue_instant)),
            ("name_id", Value::text(&self.name_id)),
            ("audiences", text_list(&self.audiences)),
            (
                "attributes",
                Value::Array(
                    self.attributes
                        .iter()
                        .map(|(n, v)| Value::Array(vec![Value::text(n), text_list(v)]))
                        .collect(),
                ),
            ),
            ("signed", Value::text(&self.signed)),
            ("in_response", Value::Bool(self.in_response)),
        ];
        for (k, v) in [
            ("name_id_format", &self.name_id_format),
            ("not_before", &self.not_before),
            ("not_on_or_after", &self.not_on_or_after),
            ("recipient", &self.recipient),
            (
                "confirmation_not_on_or_after",
                &self.confirmation_not_on_or_after,
            ),
            ("in_response_to", &self.in_response_to),
            ("authn_instant", &self.authn_instant),
            ("session_index", &self.session_index),
            ("authn_context", &self.authn_context),
        ] {
            opt(&mut e, k, v.as_deref().map(Value::text));
        }
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
                "id",
                "issuer",
                "issue_instant",
                "name_id",
                "audiences",
                "attributes",
                "signed",
                "in_response",
                "name_id_format",
                "not_before",
                "not_on_or_after",
                "recipient",
                "confirmation_not_on_or_after",
                "in_response_to",
                "authn_instant",
                "session_index",
                "authn_context",
            ],
        )?;
        let Some(Value::Array(list)) = v.get("attributes") else {
            return Err(WireError::Malformed);
        };
        if list.len() > MAX_ATTRIBUTES {
            return Err(WireError::TooLarge);
        }
        let mut attributes = Vec::with_capacity(list.len());
        for a in list {
            let Value::Array(pair) = a else {
                return Err(WireError::Malformed);
            };
            let (Some(Value::Text(n)), Some(vals), None) = (pair.first(), pair.get(1), pair.get(2))
            else {
                return Err(WireError::Malformed);
            };
            if n.len() > MAX_TEXT {
                return Err(WireError::Malformed);
            }
            let holder = map(vec![("v", vals.clone())]);
            attributes.push((n.clone(), texts(&holder, "v")?));
        }
        Ok(Self {
            id: text(&v, "id")?,
            issuer: text(&v, "issuer")?,
            issue_instant: text(&v, "issue_instant")?,
            name_id: text(&v, "name_id")?,
            name_id_format: opt_text(&v, "name_id_format")?,
            audiences: texts(&v, "audiences")?,
            not_before: opt_text(&v, "not_before")?,
            not_on_or_after: opt_text(&v, "not_on_or_after")?,
            recipient: opt_text(&v, "recipient")?,
            confirmation_not_on_or_after: opt_text(&v, "confirmation_not_on_or_after")?,
            in_response_to: opt_text(&v, "in_response_to")?,
            authn_instant: opt_text(&v, "authn_instant")?,
            session_index: opt_text(&v, "session_index")?,
            authn_context: opt_text(&v, "authn_context")?,
            attributes,
            signed: text(&v, "signed")?,
            in_response: flag(&v, "in_response")?,
        })
    }
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
