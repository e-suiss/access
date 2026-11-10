//! The edge channel between a protocol gateway and access-server (OP-155 m.3 (c), MD-1, IDP-26,
//! IDI-11). A gateway is never an issuer: it names who authenticated and how, and the realm
//! issuer inside access-server makes the Claim. Each body is one deterministic CBOR map.
//! Sans-I/O: the transport (mTLS) lives in the gateway's edge core and in the HTTP layer.

use suiss_crypto::dcbor::{self, Limits, Value};

pub mod kerberos;
pub mod ldap;
pub mod radius;

/// Path prefix of every edge call on access-server.
pub const PREFIX: &str = "/edge/v1/";

/// Media type of every edge body.
pub const CONTENT_TYPE: &str = "application/cbor";

/// Largest edge request or answer body.
pub const MAX_BODY: usize = 64 * 1024;

/// SAN URI prefix of a gateway's client certificate.
pub const URI_PREFIX: &str = "urn:suiss:access:gw:";

/// Longest gateway name.
pub const MAX_NAME: usize = 63;

/// Longest subject identifier a gateway looks up.
pub const MAX_IDENTIFIER: usize = 256;

/// Longest audit event code.
pub const MAX_EVENT: usize = 32;

/// Longest audit outcome code.
pub const MAX_OUTCOME: usize = 16;

/// The kind of a protocol gateway (OP-155 m.3 (c)).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GatewayKind {
    /// SAML 2.0 identity provider and WS-Federation (`bins/access-gw-saml`).
    Saml,
    /// LDAP (`bins/access-gw-ldap`).
    Ldap,
    /// Kerberos/SPNEGO (`bins/access-gw-kerberos`).
    Kerberos,
    /// RADIUS over TLS (`bins/access-gw-radius`).
    Radius,
}

const KINDS: [(&str, GatewayKind); 4] = [
    ("saml", GatewayKind::Saml),
    ("ldap", GatewayKind::Ldap),
    ("kerberos", GatewayKind::Kerberos),
    ("radius", GatewayKind::Radius),
];

impl GatewayKind {
    /// The kind's name in the SAN URI and the registry.
    #[must_use]
    pub fn name(self) -> &'static str {
        KINDS
            .iter()
            .find(|(_, k)| *k == self)
            .map_or("", |(n, _)| n)
    }

    /// The kind named `name`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        KINDS.iter().find(|(n, _)| *n == name).map(|(_, k)| *k)
    }

    /// The authentication method this kind may report, as the Kernel names it; `None` when the
    /// kind authenticates nobody itself (§13.2 blast radius, OP-155 m.3 (c)).
    #[must_use]
    pub const fn method(self) -> Option<&'static str> {
        match self {
            Self::Saml => None,
            Self::Ldap => Some("ldap-bind"),
            Self::Kerberos => Some("kerberos"),
            Self::Radius => Some("password"),
        }
    }
}

/// A gateway's internal identity, `urn:suiss:access:gw:<kind>:<name>` (OP-155 m.3 (c)).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GatewayUri {
    /// Its kind.
    pub kind: GatewayKind,
    /// Its name: lower-case letters, digits and `-`, starting with a letter.
    pub name: String,
}

/// Whether `name` is a gateway name.
#[must_use]
pub fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    name.len() <= MAX_NAME
        && chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

impl GatewayUri {
    /// Reads a SAN URI; `None` for anything that is not exactly a gateway URI.
    #[must_use]
    pub fn parse(uri: &str) -> Option<Self> {
        let rest = uri.strip_prefix(URI_PREFIX)?;
        let (kind, name) = rest.split_once(':')?;
        let kind = GatewayKind::parse(kind)?;
        valid_name(name).then(|| Self {
            kind,
            name: String::from(name),
        })
    }

    /// The SAN URI.
    #[must_use]
    pub fn uri(&self) -> String {
        let mut s = String::from(URI_PREFIX);
        s.push_str(self.kind.name());
        s.push(':');
        s.push_str(&self.name);
        s
    }
}

/// One call a gateway makes (OP-155 m.3 (c): the channel offers these and nothing else).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Call {
    /// Who the gateway is: its registration and realm.
    Hello,
    /// Checks a legacy credential (LDAP bind, RADIUS PAP) or Kerberos acceptance facts; its body
    /// is the gateway kind's ([`ldap`], [`radius`], [`kerberos`]).
    Authenticate,
    /// Asks the realm issuer for the `authentication` Claim of a user the gateway authenticated.
    IssueClaim,
    /// Looks a subject up by the identifier a legacy protocol carries.
    SubjectLookup,
    /// A browser session access-server attests to the gateway (SAML); the SAML lane fills it.
    SessionAttest,
    /// Directory reads for LDAP; the LDAP lane fills it.
    DirectoryRead,
    /// An audit event of the gateway.
    Audit,
}

const CALLS: [(&str, Call); 7] = [
    ("hello", Call::Hello),
    ("authenticate", Call::Authenticate),
    ("issue_claim", Call::IssueClaim),
    ("subject_lookup", Call::SubjectLookup),
    ("session_attest", Call::SessionAttest),
    ("directory_read", Call::DirectoryRead),
    ("audit", Call::Audit),
];

impl Call {
    /// The call's path segment.
    #[must_use]
    pub fn name(self) -> &'static str {
        CALLS
            .iter()
            .find(|(_, c)| *c == self)
            .map_or("", |(n, _)| n)
    }

    /// The call named `name`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        CALLS.iter().find(|(n, _)| *n == name).map(|(_, c)| *c)
    }

    /// The call's full path.
    #[must_use]
    pub fn path(self) -> String {
        let mut s = String::from(PREFIX);
        s.push_str(self.name());
        s
    }

    /// The largest answer of the call: [`ldap::MAX_DIRECTORY_BODY`] for directory reads,
    /// [`MAX_BODY`] for every other call.
    #[must_use]
    pub const fn max_answer(self) -> usize {
        match self {
            Self::DirectoryRead => ldap::MAX_DIRECTORY_BODY,
            _ => MAX_BODY,
        }
    }

    /// Every call.
    #[must_use]
    pub fn all() -> [Self; 7] {
        CALLS.map(|(_, c)| c)
    }
}

/// Why an edge body was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// Larger than [`MAX_BODY`].
    #[error("edge body too large")]
    TooLarge,
    /// Not a body of this call.
    #[error("malformed edge body")]
    Malformed,
}

/// The answer to [`Call::Hello`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hello {
    /// The gateway's identity.
    pub gateway: GatewayUri,
    /// The slug of the one realm it serves.
    pub realm: String,
}

/// [`Call::SubjectLookup`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubjectLookup {
    /// The realm the gateway asks in; it must be its own.
    pub realm: String,
    /// The login identifier the protocol carried (user name or e-mail).
    pub identifier: String,
}

/// The answer to [`SubjectLookup`]: an active subject, or none. A suspended or unknown
/// identifier answers the same (§12 enumeration).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Subject {
    /// The subject, when an active account has the identifier.
    pub subject: Option<[u8; 16]>,
}

/// [`Call::IssueClaim`]: the facts of one authentication the gateway made. The gateway signs
/// nothing; the realm issuer signs the Claim (IDP-26, P-ID-5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssueClaim {
    /// The realm; it must be the gateway's own.
    pub realm: String,
    /// The subject.
    pub subject: [u8; 16],
    /// The method, as the Kernel names it; it must be its kind's.
    pub method: String,
    /// When the user authenticated, milliseconds since the epoch.
    pub auth_time: u64,
    /// Digest of the raw protocol evidence, when there is one.
    pub evidence: Option<[u8; 32]>,
}

/// The answer to [`IssueClaim`]: the Claim is queued for the realm issuer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Issued {
    /// Always `true`; a refusal is a problem answer.
    pub queued: bool,
}

/// [`Call::Audit`]: one event, codes only (OP-47: no body, no personal data).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Audit {
    /// The realm; it must be the gateway's own.
    pub realm: String,
    /// Event code, e.g. `ldap.bind`.
    pub event: String,
    /// Outcome code, e.g. `ok`, `refused`.
    pub outcome: String,
    /// The subject, when the event names one.
    pub subject: Option<[u8; 16]>,
}

/// The answer to [`Audit`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Audited {
    /// Always `true`.
    pub recorded: bool,
}

fn limits() -> Limits {
    Limits::CEILING
}

fn decode_map(body: &[u8]) -> Result<Value, WireError> {
    decode_map_within(body, MAX_BODY)
}

fn decode_map_within(body: &[u8], max: usize) -> Result<Value, WireError> {
    if body.len() > max {
        return Err(WireError::TooLarge);
    }
    let v = dcbor::decode(body, limits()).map_err(|_| WireError::Malformed)?;
    if !matches!(v, Value::Map(_)) {
        return Err(WireError::Malformed);
    }
    Ok(v)
}

fn only(v: &Value, keys: &[&str]) -> Result<(), WireError> {
    let Value::Map(entries) = v else {
        return Err(WireError::Malformed);
    };
    let known = entries
        .iter()
        .all(|(k, _)| matches!(k, Value::Text(t) if keys.contains(&t.as_str())));
    if known {
        Ok(())
    } else {
        Err(WireError::Malformed)
    }
}

fn text(v: &Value, key: &str, max: usize) -> Result<String, WireError> {
    match v.get(key) {
        Some(Value::Text(t)) if !t.is_empty() && t.len() <= max => Ok(t.clone()),
        _ => Err(WireError::Malformed),
    }
}

fn fixed<const N: usize>(v: Option<&Value>) -> Result<Option<[u8; N]>, WireError> {
    match v {
        None => Ok(None),
        Some(Value::Bytes(b)) => <[u8; N]>::try_from(b.as_slice())
            .map(Some)
            .map_err(|_| WireError::Malformed),
        Some(_) => Err(WireError::Malformed),
    }
}

fn required<const N: usize>(v: &Value, key: &str) -> Result<[u8; N], WireError> {
    fixed::<N>(v.get(key))?.ok_or(WireError::Malformed)
}

fn encode(entries: Vec<(&str, Value)>) -> Vec<u8> {
    let map = Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (Value::text(k), v))
            .collect(),
    );
    dcbor::encode(&map, limits()).unwrap_or_default()
}

fn opt_bytes<const N: usize>(
    entries: &mut Vec<(&str, Value)>,
    key: &'static str,
    b: Option<[u8; N]>,
) {
    if let Some(b) = b {
        entries.push((key, Value::Bytes(b.to_vec())));
    }
}

/// A [`Call::Hello`] request body: an empty map.
#[must_use]
pub fn hello_request() -> Vec<u8> {
    encode(Vec::new())
}

/// Reads a [`Call::Hello`] request.
///
/// # Errors
/// [`WireError`].
pub fn decode_hello_request(body: &[u8]) -> Result<(), WireError> {
    let v = decode_map(body)?;
    only(&v, &[])
}

impl Hello {
    /// The body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        encode(vec![
            ("gateway", Value::text(&self.gateway.uri())),
            ("realm", Value::text(&self.realm)),
        ])
    }

    /// Reads the body.
    ///
    /// # Errors
    /// [`WireError`].
    pub fn decode(body: &[u8]) -> Result<Self, WireError> {
        let v = decode_map(body)?;
        only(&v, &["gateway", "realm"])?;
        Ok(Self {
            gateway: GatewayUri::parse(&text(&v, "gateway", 256)?).ok_or(WireError::Malformed)?,
            realm: text(&v, "realm", 64)?,
        })
    }
}

impl SubjectLookup {
    /// The body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        encode(vec![
            ("realm", Value::text(&self.realm)),
            ("identifier", Value::text(&self.identifier)),
        ])
    }

    /// Reads the body.
    ///
    /// # Errors
    /// [`WireError`].
    pub fn decode(body: &[u8]) -> Result<Self, WireError> {
        let v = decode_map(body)?;
        only(&v, &["realm", "identifier"])?;
        Ok(Self {
            realm: text(&v, "realm", 64)?,
            identifier: text(&v, "identifier", MAX_IDENTIFIER)?,
        })
    }
}

impl Subject {
    /// The body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut entries = Vec::new();
        opt_bytes(&mut entries, "subject", self.subject);
        encode(entries)
    }

    /// Reads the body.
    ///
    /// # Errors
    /// [`WireError`].
    pub fn decode(body: &[u8]) -> Result<Self, WireError> {
        let v = decode_map(body)?;
        only(&v, &["subject"])?;
        Ok(Self {
            subject: fixed::<16>(v.get("subject"))?,
        })
    }
}

impl IssueClaim {
    /// The body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut entries = vec![
            ("realm", Value::text(&self.realm)),
            ("subject", Value::Bytes(self.subject.to_vec())),
            ("method", Value::text(&self.method)),
            ("auth_time", Value::Unsigned(self.auth_time)),
        ];
        opt_bytes(&mut entries, "evidence", self.evidence);
        encode(entries)
    }

    /// Reads the body.
    ///
    /// # Errors
    /// [`WireError`].
    pub fn decode(body: &[u8]) -> Result<Self, WireError> {
        let v = decode_map(body)?;
        only(&v, &["realm", "subject", "method", "auth_time", "evidence"])?;
        let Some(Value::Unsigned(auth_time)) = v.get("auth_time") else {
            return Err(WireError::Malformed);
        };
        Ok(Self {
            realm: text(&v, "realm", 64)?,
            subject: required::<16>(&v, "subject")?,
            method: text(&v, "method", 32)?,
            auth_time: *auth_time,
            evidence: fixed::<32>(v.get("evidence"))?,
        })
    }
}

impl Issued {
    /// The body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        encode(vec![("queued", Value::Bool(self.queued))])
    }

    /// Reads the body.
    ///
    /// # Errors
    /// [`WireError`].
    pub fn decode(body: &[u8]) -> Result<Self, WireError> {
        let v = decode_map(body)?;
        only(&v, &["queued"])?;
        match v.get("queued") {
            Some(Value::Bool(queued)) => Ok(Self { queued: *queued }),
            _ => Err(WireError::Malformed),
        }
    }
}

fn code(v: &Value, key: &str, max: usize) -> Result<String, WireError> {
    let t = text(v, key, max)?;
    let mut chars = t.chars();
    if chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_'))
    {
        Ok(t)
    } else {
        Err(WireError::Malformed)
    }
}

impl Audit {
    /// The body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut entries = vec![
            ("realm", Value::text(&self.realm)),
            ("event", Value::text(&self.event)),
            ("outcome", Value::text(&self.outcome)),
        ];
        opt_bytes(&mut entries, "subject", self.subject);
        encode(entries)
    }

    /// Reads the body; codes are lower-case ASCII words with `.` and `_`, starting with a
    /// letter.
    ///
    /// # Errors
    /// [`WireError`].
    pub fn decode(body: &[u8]) -> Result<Self, WireError> {
        let v = decode_map(body)?;
        only(&v, &["realm", "event", "outcome", "subject"])?;
        Ok(Self {
            realm: text(&v, "realm", 64)?,
            event: code(&v, "event", MAX_EVENT)?,
            outcome: code(&v, "outcome", MAX_OUTCOME)?,
            subject: fixed::<16>(v.get("subject"))?,
        })
    }
}

impl Audited {
    /// The body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        encode(vec![("recorded", Value::Bool(self.recorded))])
    }

    /// Reads the body.
    ///
    /// # Errors
    /// [`WireError`].
    pub fn decode(body: &[u8]) -> Result<Self, WireError> {
        let v = decode_map(body)?;
        only(&v, &["recorded"])?;
        match v.get("recorded") {
            Some(Value::Bool(recorded)) => Ok(Self {
                recorded: *recorded,
            }),
            _ => Err(WireError::Malformed),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // OP-155 m.3 (c)
    #[test]
    fn gateway_uris_are_exact() {
        let u = GatewayUri::parse("urn:suiss:access:gw:ldap:corp-1").unwrap();
        assert_eq!(u.kind, GatewayKind::Ldap);
        assert_eq!(u.uri(), "urn:suiss:access:gw:ldap:corp-1");
        for bad in [
            "urn:suiss:access:gw:ldap:",
            "urn:suiss:access:gw:ldap:Corp",
            "urn:suiss:access:gw:ldap:1corp",
            "urn:suiss:access:gw:ftp:corp",
            "urn:suiss:access:gw:ldap:corp:x",
            "spiffe://corp/gw",
        ] {
            assert!(GatewayUri::parse(bad).is_none(), "{bad}");
        }
    }

    // OP-155 m.3 (c)
    #[test]
    fn bodies_round_trip_and_refuse_unknown_fields() {
        let c = IssueClaim {
            realm: String::from("corp"),
            subject: [1; 16],
            method: String::from("ldap-bind"),
            auth_time: 5,
            evidence: Some([2; 32]),
        };
        assert_eq!(IssueClaim::decode(&c.encode()).unwrap(), c);
        let a = Audit {
            realm: String::from("corp"),
            event: String::from("ldap.bind"),
            outcome: String::from("ok"),
            subject: None,
        };
        assert_eq!(Audit::decode(&a.encode()).unwrap(), a);
        let extra = encode(vec![
            ("realm", Value::text("corp")),
            ("identifier", Value::text("alice")),
            ("password", Value::text("x")),
        ]);
        assert_eq!(SubjectLookup::decode(&extra), Err(WireError::Malformed));
        assert_eq!(
            SubjectLookup::decode(&vec![0; MAX_BODY + 1]),
            Err(WireError::TooLarge)
        );
        let bad = Audit {
            event: String::from("Ldap Bind"),
            ..a
        };
        assert_eq!(Audit::decode(&bad.encode()), Err(WireError::Malformed));
    }

    // OP-155 m.3 (c)
    #[test]
    fn only_the_six_channel_calls_and_hello_exist() {
        let names: Vec<&str> = Call::all().iter().map(|c| c.name()).collect();
        assert_eq!(
            names,
            [
                "hello",
                "authenticate",
                "issue_claim",
                "subject_lookup",
                "session_attest",
                "directory_read",
                "audit"
            ]
        );
        assert_eq!(Call::parse("exercise"), None);
    }
}
