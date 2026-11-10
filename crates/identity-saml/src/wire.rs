//! The bodies between access-server and the SAML gateway (OP-155 m.3 (c), (d); IDI-7, IDI-11).
//!
//! access-server keeps the cookies and every decision that needs the session or the store. For
//! each browser request on `/saml/*` or `/wsfed` it opens a flow, and forwards the raw binding
//! values with a fresh one-use attestation handle ([`Forward`]). The gateway has the message read
//! and verified by the parser worker, then makes the edge call `session_attest` ([`Attest`]):
//! `sp` for the pinned certificates, then `issue` with the handle and the verified facts.
//! access-server checks the handle against its own flow (unused, fresh, same realm), decides, and
//! keeps the outcome in the flow; the gateway's answer to the forward only says the flow is done
//! or names a refusal code, so nothing the gateway returns reaches the browser. A forged handle
//! is refused by the channel, so no signed output exists without an authentication (IDI-7).

use suiss_crypto::dcbor::{self, Limits, Value};

/// Media type of the forward.
pub const CONTENT_TYPE: &str = "application/cbor";

/// The forward's path on the gateway.
pub const FORWARD_PATH: &str = "/saml/v1/forward";

/// Longest raw value forwarded (a deflated or posted message).
pub const MAX_VALUE: usize = 60 * 1024;

/// Why a body was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("malformed SAML edge body")]
pub struct Malformed;

/// How the browser's request arrived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Binding {
    /// HTTP-Redirect (query).
    Redirect,
    /// HTTP-POST (form).
    Post,
    /// ECP (PAOS/SOAP body).
    Soap,
    /// IdP-initiated SSO to one registration.
    Unsolicited,
    /// WS-Federation passive requestor.
    Wsfed,
}

const BINDINGS: [(&str, Binding); 5] = [
    ("redirect", Binding::Redirect),
    ("post", Binding::Post),
    ("soap", Binding::Soap),
    ("unsolicited", Binding::Unsolicited),
    ("wsfed", Binding::Wsfed),
];

impl Binding {
    /// Its name.
    #[must_use]
    pub fn name(self) -> &'static str {
        BINDINGS
            .iter()
            .find(|(_, b)| *b == self)
            .map_or("", |(n, _)| n)
    }

    fn parse(s: &str) -> Option<Self> {
        BINDINGS.iter().find(|(n, _)| *n == s).map(|(_, b)| *b)
    }
}

/// What access-server forwards to the gateway: the raw values as received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Forward {
    /// The realm slug.
    pub realm: String,
    /// The one-use attestation handle of this forward.
    pub handle: [u8; 32],
    /// The binding.
    pub binding: Binding,
    /// `SAMLRequest`: still URL-encoded for HTTP-Redirect, the form value for HTTP-POST, the
    /// SOAP body for ECP.
    pub message: Option<String>,
    /// `RelayState`, raw.
    pub relay_state: Option<String>,
    /// `SigAlg`, raw.
    pub sig_alg: Option<String>,
    /// `Signature`, raw.
    pub signature: Option<String>,
}

/// The gateway's answer to a forward.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Done {
    /// access-server holds the outcome in its flow.
    Done,
    /// The message was refused before access-server decided; the code is shown to the user.
    Refused(String),
}

/// `session_attest` bodies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Attest {
    /// The pinned certificates of the registration `entity`.
    Sp {
        /// The realm slug.
        realm: String,
        /// The entity ID the message names.
        entity: String,
    },
    /// Decide the flow of `handle` with the verified facts.
    Issue {
        /// The realm slug.
        realm: String,
        /// The attestation handle.
        handle: [u8; 32],
        /// The worker's facts (`access_edge_core::saml::Facts`), when a message was read.
        facts: Option<Vec<u8>>,
        /// A detached HTTP-Redirect signature verified with a pinned certificate.
        redirect_signed: bool,
    },
}

/// The answer to [`Attest::Sp`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpAnswer {
    /// Whether a live registration has the entity ID.
    pub found: bool,
    /// Its pinned certificates, DER.
    pub certs: Vec<Vec<u8>>,
    /// `AuthnRequestsSigned`.
    pub requests_signed: bool,
}

fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (Value::text(k), v))
            .collect(),
    )
}

fn enc(v: &Value) -> Vec<u8> {
    dcbor::encode(v, Limits::CEILING).unwrap_or_default()
}

fn dec(b: &[u8]) -> Result<Value, Malformed> {
    let v = dcbor::decode(b, Limits::CEILING).map_err(|_| Malformed)?;
    if matches!(v, Value::Map(_)) {
        Ok(v)
    } else {
        Err(Malformed)
    }
}

fn only(v: &Value, keys: &[&str]) -> Result<(), Malformed> {
    let Value::Map(entries) = v else {
        return Err(Malformed);
    };
    if entries
        .iter()
        .all(|(k, _)| matches!(k, Value::Text(t) if keys.contains(&t.as_str())))
    {
        Ok(())
    } else {
        Err(Malformed)
    }
}

fn text(v: &Value, k: &str, max: usize) -> Result<String, Malformed> {
    match v.get(k) {
        Some(Value::Text(t)) if t.len() <= max => Ok(t.clone()),
        _ => Err(Malformed),
    }
}

fn opt_text(v: &Value, k: &str, max: usize) -> Result<Option<String>, Malformed> {
    match v.get(k) {
        None => Ok(None),
        Some(_) => text(v, k, max).map(Some),
    }
}

fn handle(v: &Value) -> Result<[u8; 32], Malformed> {
    match v.get("handle") {
        Some(Value::Bytes(b)) => <[u8; 32]>::try_from(b.as_slice()).map_err(|_| Malformed),
        _ => Err(Malformed),
    }
}

fn flag(v: &Value, k: &str) -> Result<bool, Malformed> {
    match v.get(k) {
        Some(Value::Bool(b)) => Ok(*b),
        _ => Err(Malformed),
    }
}

fn push_opt(e: &mut Vec<(&'static str, Value)>, k: &'static str, v: Option<&String>) {
    if let Some(v) = v {
        e.push((k, Value::text(v)));
    }
}

impl Forward {
    /// The body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut e = vec![
            ("realm", Value::text(&self.realm)),
            ("handle", Value::Bytes(self.handle.to_vec())),
            ("binding", Value::text(self.binding.name())),
        ];
        push_opt(&mut e, "message", self.message.as_ref());
        push_opt(&mut e, "relay_state", self.relay_state.as_ref());
        push_opt(&mut e, "sig_alg", self.sig_alg.as_ref());
        push_opt(&mut e, "signature", self.signature.as_ref());
        enc(&map(e))
    }

    /// Reads the body.
    ///
    /// # Errors
    /// [`Malformed`].
    pub fn decode(b: &[u8]) -> Result<Self, Malformed> {
        let v = dec(b)?;
        only(
            &v,
            &[
                "realm",
                "handle",
                "binding",
                "message",
                "relay_state",
                "sig_alg",
                "signature",
            ],
        )?;
        Ok(Self {
            realm: text(&v, "realm", 64)?,
            handle: handle(&v)?,
            binding: Binding::parse(&text(&v, "binding", 16)?).ok_or(Malformed)?,
            message: opt_text(&v, "message", MAX_VALUE)?,
            relay_state: opt_text(&v, "relay_state", 2048)?,
            sig_alg: opt_text(&v, "sig_alg", 256)?,
            signature: opt_text(&v, "signature", 2048)?,
        })
    }
}

impl Done {
    /// The body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Done => enc(&map(vec![("done", Value::Bool(true))])),
            Self::Refused(c) => enc(&map(vec![("refused", Value::text(c))])),
        }
    }

    /// Reads the body; a refusal code is lower-case ASCII with `-`.
    ///
    /// # Errors
    /// [`Malformed`].
    pub fn decode(b: &[u8]) -> Result<Self, Malformed> {
        let v = dec(b)?;
        if v.get("done").is_some() {
            only(&v, &["done"])?;
            return if flag(&v, "done")? {
                Ok(Self::Done)
            } else {
                Err(Malformed)
            };
        }
        only(&v, &["refused"])?;
        let c = text(&v, "refused", 48)?;
        if c.is_empty()
            || !c
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(Malformed);
        }
        Ok(Self::Refused(c))
    }
}

impl Attest {
    /// The body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Sp { realm, entity } => enc(&map(vec![
                ("op", Value::text("sp")),
                ("realm", Value::text(realm)),
                ("entity", Value::text(entity)),
            ])),
            Self::Issue {
                realm,
                handle,
                facts,
                redirect_signed,
            } => {
                let mut e = vec![
                    ("op", Value::text("issue")),
                    ("realm", Value::text(realm)),
                    ("handle", Value::Bytes(handle.to_vec())),
                    ("redirect_signed", Value::Bool(*redirect_signed)),
                ];
                if let Some(f) = facts {
                    e.push(("facts", Value::Bytes(f.clone())));
                }
                enc(&map(e))
            }
        }
    }

    /// Reads the body.
    ///
    /// # Errors
    /// [`Malformed`].
    pub fn decode(b: &[u8]) -> Result<Self, Malformed> {
        let v = dec(b)?;
        match text(&v, "op", 8)?.as_str() {
            "sp" => {
                only(&v, &["op", "realm", "entity"])?;
                Ok(Self::Sp {
                    realm: text(&v, "realm", 64)?,
                    entity: text(&v, "entity", 1024)?,
                })
            }
            "issue" => {
                only(&v, &["op", "realm", "handle", "facts", "redirect_signed"])?;
                Ok(Self::Issue {
                    realm: text(&v, "realm", 64)?,
                    handle: handle(&v)?,
                    facts: match v.get("facts") {
                        None => None,
                        Some(Value::Bytes(f)) => Some(f.clone()),
                        Some(_) => return Err(Malformed),
                    },
                    redirect_signed: flag(&v, "redirect_signed")?,
                })
            }
            _ => Err(Malformed),
        }
    }
}

impl SpAnswer {
    /// The body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        enc(&map(vec![
            ("found", Value::Bool(self.found)),
            (
                "certs",
                Value::Array(self.certs.iter().map(|c| Value::Bytes(c.clone())).collect()),
            ),
            ("requests_signed", Value::Bool(self.requests_signed)),
        ]))
    }

    /// Reads the body.
    ///
    /// # Errors
    /// [`Malformed`].
    pub fn decode(b: &[u8]) -> Result<Self, Malformed> {
        let v = dec(b)?;
        only(&v, &["found", "certs", "requests_signed"])?;
        let Some(Value::Array(list)) = v.get("certs") else {
            return Err(Malformed);
        };
        if list.len() > access_edge_core::saml::MAX_CERTS {
            return Err(Malformed);
        }
        let certs = list
            .iter()
            .map(|c| match c {
                Value::Bytes(b) => Ok(b.clone()),
                _ => Err(Malformed),
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            found: flag(&v, "found")?,
            certs,
            requests_signed: flag(&v, "requests_signed")?,
        })
    }
}

/// The answer to [`Attest::Issue`]: always `{"decided": true}`; a refusal is a problem.
#[must_use]
pub fn decided() -> Vec<u8> {
    enc(&map(vec![("decided", Value::Bool(true))]))
}

/// Reads [`decided`].
///
/// # Errors
/// [`Malformed`].
pub fn decode_decided(b: &[u8]) -> Result<(), Malformed> {
    let v = dec(b)?;
    only(&v, &["decided"])?;
    if flag(&v, "decided")? {
        Ok(())
    } else {
        Err(Malformed)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // OP-155 m.3 (c): the SAML edge bodies round-trip and refuse unknown members.
    #[test]
    fn bodies_round_trip() {
        let f = Forward {
            realm: String::from("acme"),
            handle: [7; 32],
            binding: Binding::Redirect,
            message: Some(String::from("fZ%2B")),
            relay_state: None,
            sig_alg: Some(String::from("x")),
            signature: Some(String::from("y")),
        };
        assert_eq!(Forward::decode(&f.encode()).unwrap(), f);
        for d in [Done::Done, Done::Refused(String::from("xml-doctype"))] {
            assert_eq!(Done::decode(&d.encode()).unwrap(), d);
        }
        assert!(Done::decode(&Done::Refused(String::from("<script>")).encode()).is_err());
        for a in [
            Attest::Sp {
                realm: String::from("acme"),
                entity: String::from("https://sp"),
            },
            Attest::Issue {
                realm: String::from("acme"),
                handle: [1; 32],
                facts: Some(vec![0xa0]),
                redirect_signed: true,
            },
        ] {
            assert_eq!(Attest::decode(&a.encode()).unwrap(), a);
        }
        let s = SpAnswer {
            found: true,
            certs: vec![vec![0x30]],
            requests_signed: false,
        };
        assert_eq!(SpAnswer::decode(&s.encode()).unwrap(), s);
        assert!(decode_decided(&decided()).is_ok());
    }
}
