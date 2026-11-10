//! `idp.signal.*` changes (catalog 6, OP-156 m.3 (a), (r)): registering and retiring a signal
//! source. A source names the issuer Party whose Claims it sends; registering it gives those
//! Claims no effect, which comes only from the domain's own Acceptance (E38). Sans-I/O: the
//! REST body becomes one change, which the intent binds (EI-25).

use access_internal_api::idp::IdpAction;
use access_kernel::json::{b64url_decode, b64url_encode};
use serde_json::Value as Json;
use suiss_crypto::dcbor::Value;

/// Longest provider display name.
pub const MAX_PROVIDER: usize = 64;

/// Longest transmitter issuer.
pub const MAX_TRANSMITTER: usize = 2048;

/// How often a source is expected to be heard from when it declares nothing: a day.
pub const DEFAULT_INTERVAL_S: u32 = 86_400;

/// Why a body is not an `idp.signal.*` change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid signal source: {0}")]
pub struct SourceError(pub &'static str);

/// What a source tells.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// Identity verification (`identity_proofing`).
    Kyc,
    /// Device management (`posture_mdm`).
    Mdm,
    /// Risk and fraud, biometrics, RASP and bot management (`risk_external`).
    Risk,
    /// Data classification (`data_label`).
    Dlp,
}

impl Kind {
    /// Every kind.
    pub const ALL: [Self; 4] = [Self::Kyc, Self::Mdm, Self::Risk, Self::Dlp];

    /// The stored and wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Kyc => "kyc",
            Self::Mdm => "mdm",
            Self::Risk => "risk",
            Self::Dlp => "dlp",
        }
    }

    /// The kind of a name.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.name() == s)
    }

    /// The Claim class its Claims carry.
    #[must_use]
    pub const fn class(self) -> &'static str {
        use access_internal_api::signals as s;
        match self {
            Self::Kyc => s::IDENTITY_PROOFING,
            Self::Mdm => s::POSTURE_MDM,
            Self::Risk => s::RISK_EXTERNAL,
            Self::Dlp => s::DATA_LABEL,
        }
    }
}

/// The form a source's answers arrive in before they are mapped to its Claim class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Format {
    /// Claims signed by the source itself, through Claim Ingest.
    Claim,
    /// Microsoft Intune `managedDevice`.
    Intune,
    /// Jamf Pro computer inventory.
    Jamf,
    /// Okta's SSF transmitter (CAEP).
    OktaSsf,
    /// An Onfido check.
    Onfido,
    /// A Persona inquiry.
    Persona,
}

impl Format {
    /// Every format.
    pub const ALL: [Self; 6] = [
        Self::Claim,
        Self::Intune,
        Self::Jamf,
        Self::OktaSsf,
        Self::Onfido,
        Self::Persona,
    ];

    /// The stored and wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Claim => "claim",
            Self::Intune => "intune",
            Self::Jamf => "jamf",
            Self::OktaSsf => "okta-ssf",
            Self::Onfido => "onfido",
            Self::Persona => "persona",
        }
    }

    /// The format of a name.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|f| f.name() == s)
    }

    /// Whether answers in this format can be of `kind`.
    #[must_use]
    pub const fn carries(self, kind: Kind) -> bool {
        matches!(
            (self, kind),
            (Self::Claim, _)
                | (Self::Intune | Self::Jamf, Kind::Mdm)
                | (Self::OktaSsf, Kind::Mdm | Kind::Risk)
                | (Self::Onfido | Self::Persona, Kind::Kyc)
        )
    }
}

/// A signal source as `idp.signal.source_register` declares it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Source {
    /// Its name, never reused.
    pub name: String,
    /// What it tells.
    pub kind: Kind,
    /// The provider as people read it: "Acme MDM".
    pub provider: String,
    /// The issuer Party its Claims are signed as.
    pub issuer: [u8; 16],
    /// The form its answers arrive in.
    pub format: Format,
    /// The SSF transmitter (`iss`) it is heard through, when it has one.
    pub transmitter: Option<String>,
    /// How often it is expected to be heard from, seconds (60 s to 30 days).
    pub expected_interval_s: u32,
}

/// An `idp.signal.*` change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceChange {
    /// `idp.signal.source_register` (CT2).
    Register(Source),
    /// `idp.signal.source_retire` (CT1).
    Retire(String),
}

/// Whether `s` is a source name: a lower-case letter and up to 62 lower-case letters, digits
/// and `-`.
#[must_use]
pub fn name_ok(s: &str) -> bool {
    let mut b = s.bytes();
    b.next().is_some_and(|c| c.is_ascii_lowercase())
        && s.len() <= 63
        && b.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

fn text<'a>(
    m: &'a serde_json::Map<String, Json>,
    k: &'static str,
) -> Result<Option<&'a str>, SourceError> {
    match m.get(k) {
        None | Some(Json::Null) => Ok(None),
        Some(Json::String(s)) => Ok(Some(s)),
        Some(_) => Err(SourceError(k)),
    }
}

impl SourceChange {
    /// `registerSignalSource`: `{"name", "kind", "provider", "issuer", "format"?,
    /// "transmitter"?, "expected_interval_s"?}`; `issuer` is the base64url of the Party's 16
    /// bytes.
    ///
    /// # Errors
    /// [`SourceError`].
    pub fn register(body: &Json) -> Result<Self, SourceError> {
        let m = body.as_object().ok_or(SourceError("body"))?;
        if m.keys().any(|k| {
            !matches!(
                k.as_str(),
                "name"
                    | "kind"
                    | "provider"
                    | "issuer"
                    | "format"
                    | "transmitter"
                    | "expected_interval_s"
            )
        }) {
            return Err(SourceError("body"));
        }
        let req = |k: &'static str| text(m, k)?.ok_or(SourceError(k));
        let kind = Kind::parse(req("kind")?).ok_or(SourceError("kind"))?;
        let issuer = b64url_decode(req("issuer")?)
            .ok()
            .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
            .ok_or(SourceError("issuer"))?;
        let format = match text(m, "format")? {
            None => Format::Claim,
            Some(f) => Format::parse(f).ok_or(SourceError("format"))?,
        };
        let expected_interval_s = match m.get("expected_interval_s") {
            None | Some(Json::Null) => DEFAULT_INTERVAL_S,
            Some(n) => n
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or(SourceError("expected_interval_s"))?,
        };
        let c = Self::Register(Source {
            name: String::from(req("name")?),
            kind,
            provider: String::from(req("provider")?),
            issuer,
            format,
            transmitter: text(m, "transmitter")?.map(String::from),
            expected_interval_s,
        });
        c.check()?;
        Ok(c)
    }

    /// `retireSignalSource` of `name`: an empty body.
    ///
    /// # Errors
    /// [`SourceError`].
    pub fn retire(name: &str, body: &Json) -> Result<Self, SourceError> {
        if !body.as_object().ok_or(SourceError("body"))?.is_empty() {
            return Err(SourceError("body"));
        }
        let c = Self::Retire(String::from(name));
        c.check()?;
        Ok(c)
    }

    /// The action that authorizes it.
    #[must_use]
    pub const fn action(&self) -> IdpAction {
        match self {
            Self::Register(_) => IdpAction::SignalSourceRegister,
            Self::Retire(_) => IdpAction::SignalSourceRetire,
        }
    }

    /// Whether it is inside the rules: a source name; a provider of 1 to 64 characters
    /// without control characters; a format that can carry the kind; an `https` transmitter
    /// only for a format heard over SSF; an interval of 60 s to 30 days.
    ///
    /// # Errors
    /// [`SourceError`].
    pub fn check(&self) -> Result<(), SourceError> {
        match self {
            Self::Register(s) => {
                if !name_ok(&s.name) {
                    return Err(SourceError("name"));
                }
                let chars = s.provider.chars().count();
                if chars == 0 || chars > MAX_PROVIDER || s.provider.chars().any(char::is_control) {
                    return Err(SourceError("provider"));
                }
                if !s.format.carries(s.kind) {
                    return Err(SourceError("format"));
                }
                match (&s.transmitter, s.format) {
                    (None, _) => {}
                    (Some(t), Format::OktaSsf | Format::Claim)
                        if t.len() <= MAX_TRANSMITTER && t.starts_with("https://") => {}
                    _ => return Err(SourceError("transmitter")),
                }
                if !(60..=2_592_000).contains(&s.expected_interval_s) {
                    return Err(SourceError("expected_interval_s"));
                }
                if s.issuer == [0; 16] {
                    return Err(SourceError("issuer"));
                }
                Ok(())
            }
            Self::Retire(name) if name_ok(name) => Ok(()),
            Self::Retire(_) => Err(SourceError("name")),
        }
    }

    /// The change's body, which the intent binds (EI-25).
    #[must_use]
    pub fn body(&self) -> Value {
        let m = |e: Vec<(&str, Value)>| {
            Value::Map(e.into_iter().map(|(k, v)| (Value::text(k), v)).collect())
        };
        match self {
            Self::Register(s) => {
                let mut e = vec![
                    ("name", Value::text(&s.name)),
                    ("kind", Value::text(s.kind.name())),
                    ("provider", Value::text(&s.provider)),
                    ("issuer", Value::Bytes(s.issuer.to_vec())),
                    ("format", Value::text(s.format.name())),
                    (
                        "expected_interval_s",
                        Value::Unsigned(u64::from(s.expected_interval_s)),
                    ),
                ];
                if let Some(t) = &s.transmitter {
                    e.push(("transmitter", Value::text(t)));
                }
                m(e)
            }
            Self::Retire(name) => m(vec![("retire", Value::text(name))]),
        }
    }

    /// Its resource path below the realm's slug.
    #[must_use]
    pub fn path(&self) -> Vec<String> {
        match self {
            Self::Register(Source { name, .. }) | Self::Retire(name) => {
                vec![String::from("signal-source"), name.clone()]
            }
        }
    }
}

/// The external id of an issuer Party: the base64url of its 16 bytes.
#[must_use]
pub fn issuer_id(issuer: &[u8; 16]) -> String {
    b64url_encode(issuer)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use serde_json::json;

    use super::*;

    fn body() -> Json {
        json!({
            "name": "acme-mdm",
            "kind": "mdm",
            "provider": "Acme MDM",
            "issuer": issuer_id(&[7; 16]),
            "format": "intune",
        })
    }

    // OP-156 m.3 (a), (r), E38
    #[test]
    fn a_source_registers_as_a_claim_issuer_and_nothing_more() {
        let c = SourceChange::register(&body()).unwrap();
        assert_eq!(c.action(), IdpAction::SignalSourceRegister);
        assert_eq!(c.path(), vec!["signal-source", "acme-mdm"]);
        let SourceChange::Register(s) = &c else {
            panic!("{c:?}");
        };
        assert_eq!(s.kind.class(), "posture_mdm");
        assert_eq!(s.expected_interval_s, DEFAULT_INTERVAL_S);
        assert_eq!(
            SourceChange::retire("acme-mdm", &json!({}))
                .unwrap()
                .action(),
            IdpAction::SignalSourceRetire
        );
        let mut b = body();
        b["kind"] = json!("kyc");
        assert_eq!(SourceChange::register(&b), Err(SourceError("format")));
        let mut b = body();
        b["acceptance"] = json!(true);
        assert!(SourceChange::register(&b).is_err());
        let mut b = body();
        b["issuer"] = json!(issuer_id(&[0; 16]));
        assert!(SourceChange::register(&b).is_err());
        let mut b = body();
        b["transmitter"] = json!("https://okta.example");
        assert!(SourceChange::register(&b).is_err());
        b["format"] = json!("okta-ssf");
        assert!(SourceChange::register(&b).is_ok());
        assert!(SourceChange::retire("Acme", &json!({})).is_err());
    }
}
