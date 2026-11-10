//! The bodies of the signal-source Claim classes (OP-156 m.3 (r), `product-seam.cddl`):
//! `identity_proofing`, `posture_mdm`, `risk_external` and `data_label`. Both planes read them:
//! the identity plane maps a vendor's answer into one, the authority plane reads a recorded
//! Claim's body by the digest its `value` carries (L2-CLB-1). The Kernel does not check these
//! classes (L2-CLB-2); their effect comes only from the domain's Acceptance (E38).

use std::collections::BTreeMap;

use access_kernel::json::Json;

use access_kernel::claim::body::BODY_CONTEXT;
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::context_digest;

/// `identity_proofing`: who verified an identity, how, to which level and when.
pub const IDENTITY_PROOFING: &str = "identity_proofing";
/// `posture_mdm`: a device management system's statement about a device.
pub const POSTURE_MDM: &str = "posture_mdm";
/// `risk_external`: a risk or fraud engine's verdict; it only narrows (CI-2).
pub const RISK_EXTERNAL: &str = "risk_external";
/// `data_label`: a data classification label of a resource.
pub const DATA_LABEL: &str = "data_label";

/// The signal classes, in this order everywhere.
pub const CLASSES: [&str; 4] = [IDENTITY_PROOFING, POSTURE_MDM, RISK_EXTERNAL, DATA_LABEL];

/// The longest risk Claim a decision reads, from its `issued_at`: a day (TN-46). A risk
/// engine cannot lock anyone for longer by declaring a longer validity.
pub const RISK_HORIZON_MS: u64 = 24 * 3_600 * 1_000;

/// Why a body does not read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("signal body: {0}")]
pub struct BodyError(pub &'static str);

/// How an identity was verified (`proofing-method`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Method {
    /// An identity document, looked at.
    Document,
    /// An identity document's chip, read over NFC by the provider.
    DocumentNfc,
    /// A national eID.
    Eid,
    /// A bank's own customer check.
    Bank,
    /// In person.
    InPerson,
    /// A supervised video call.
    Video,
}

const METHODS: [(&str, Method); 6] = [
    ("document", Method::Document),
    ("document_nfc", Method::DocumentNfc),
    ("eid", Method::Eid),
    ("bank", Method::Bank),
    ("in_person", Method::InPerson),
    ("video", Method::Video),
];

impl Method {
    /// The wire name.
    #[must_use]
    pub fn name(self) -> &'static str {
        METHODS
            .iter()
            .find(|(_, m)| *m == self)
            .map_or("document", |(n, _)| n)
    }

    /// The method of a wire name.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        METHODS.iter().find(|(n, _)| *n == s).map(|(_, m)| *m)
    }
}

/// The level a proofing reached: NIST SP 800-63A-4 IAL or an eIDAS level of assurance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProofingLevel {
    /// `ial` 1 to 3.
    Ial(u8),
    /// `loa_eidas` `low` (1), `substantial` (2) or `high` (3).
    Eidas(u8),
}

const EIDAS: [&str; 3] = ["low", "substantial", "high"];

impl ProofingLevel {
    /// The level on the Kernel's `loa_eidas` dimension (1 to 3): IAL1 is low, IAL2 substantial,
    /// IAL3 high. A requirement term's floor on `loa_eidas` reads it.
    #[must_use]
    pub fn loa(self) -> u64 {
        match self {
            Self::Ial(n) | Self::Eidas(n) => u64::from(n),
        }
    }
}

/// `identity_proofing`: an external KYC or identity verification result. Access claims no
/// proofing of its own (IDP-34).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityProofing {
    /// The provider, a `ref`.
    pub provider: String,
    /// How.
    pub method: Method,
    /// To which level.
    pub level: ProofingLevel,
    /// When, Unix ms.
    pub verified_at: u64,
}

/// `posture_mdm`: a device management statement, shown as "Compliant per *provider*
/// (statement)" (§8.10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostureMdm {
    /// Whether the device is managed.
    pub managed: bool,
    /// Whether it is compliant with the provider's policy.
    pub compliant: bool,
    /// The provider, a `ref`.
    pub provider: String,
    /// The provider's own words, 1 to 512 characters.
    pub statement: String,
}

/// A risk level, ordered from the least to the most severe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RiskLevel {
    /// `low`.
    Low,
    /// `medium`.
    Medium,
    /// `high`.
    High,
    /// `critical`.
    Critical,
}

impl RiskLevel {
    /// Every level, least severe first.
    pub const ALL: [Self; 4] = [Self::Low, Self::Medium, Self::High, Self::Critical];

    /// The wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// The level of a wire name; there is no "allow" level (CI-2).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|l| l.name() == s)
    }
}

/// `risk_external`: an external risk or fraud verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RiskExternal {
    /// How severe.
    pub level: RiskLevel,
    /// Why, as a class, a `ref`.
    pub reason_class: String,
}

/// `data_label`: a DLP label, a predicate input of `disclose` decisions (F11).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataLabel {
    /// The label, a `ref`.
    pub label: String,
    /// The labelling scheme, a `ref`.
    pub scheme: String,
}

impl DataLabel {
    /// `scheme:label`, as the restriction context names it.
    #[must_use]
    pub fn qualified(&self) -> String {
        format!("{}:{}", self.scheme, self.label)
    }
}

/// One signal body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signal {
    /// `identity_proofing`.
    Proofing(IdentityProofing),
    /// `posture_mdm`.
    Posture(PostureMdm),
    /// `risk_external`.
    Risk(RiskExternal),
    /// `data_label`.
    Label(DataLabel),
}

/// Whether `s` is a `ref`: `[a-z0-9][a-z0-9._:-]{0,127}`.
#[must_use]
pub fn is_ref(s: &str) -> bool {
    let mut b = s.bytes();
    b.next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && s.len() <= 128
        && b.all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b':' | b'-')
        })
}

struct Fields<'a>(BTreeMap<&'a str, &'a Value>);

impl<'a> Fields<'a> {
    fn of(v: &'a Value) -> Result<Self, BodyError> {
        let Value::Map(entries) = v else {
            return Err(BodyError("map"));
        };
        let mut out = BTreeMap::new();
        for (k, v) in entries {
            let Value::Text(k) = k else {
                return Err(BodyError("key"));
            };
            if out.insert(k.as_str(), v).is_some() {
                return Err(BodyError("key"));
            }
        }
        Ok(Self(out))
    }

    fn take(&mut self, k: &'static str) -> Option<&'a Value> {
        self.0.remove(k)
    }

    fn text(&mut self, k: &'static str) -> Result<&'a str, BodyError> {
        match self.take(k) {
            Some(Value::Text(s)) => Ok(s.as_str()),
            _ => Err(BodyError(k)),
        }
    }

    fn reference(&mut self, k: &'static str) -> Result<String, BodyError> {
        let s = self.text(k)?;
        if is_ref(s) {
            Ok(String::from(s))
        } else {
            Err(BodyError(k))
        }
    }

    fn flag(&mut self, k: &'static str) -> Result<bool, BodyError> {
        match self.take(k) {
            Some(Value::Bool(b)) => Ok(*b),
            _ => Err(BodyError(k)),
        }
    }

    fn uint(&mut self, k: &'static str) -> Result<u64, BodyError> {
        match self.take(k) {
            Some(Value::Unsigned(n)) => Ok(*n),
            _ => Err(BodyError(k)),
        }
    }

    fn done(self) -> Result<(), BodyError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(BodyError("unknown-member"))
        }
    }
}

fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (Value::text(k), v))
            .collect(),
    )
}

impl Signal {
    /// Its Claim class.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::Proofing(_) => IDENTITY_PROOFING,
            Self::Posture(_) => POSTURE_MDM,
            Self::Risk(_) => RISK_EXTERNAL,
            Self::Label(_) => DATA_LABEL,
        }
    }

    /// The body as dCBOR's value model.
    #[must_use]
    pub fn to_value(&self) -> Value {
        match self {
            Self::Proofing(p) => {
                let level = match p.level {
                    ProofingLevel::Ial(n) => ("ial", Value::Unsigned(u64::from(n))),
                    ProofingLevel::Eidas(n) => (
                        "loa_eidas",
                        Value::text(
                            EIDAS
                                .get(usize::from(n.saturating_sub(1)))
                                .copied()
                                .unwrap_or("low"),
                        ),
                    ),
                };
                map(vec![
                    ("provider", Value::text(&p.provider)),
                    ("method", Value::text(p.method.name())),
                    level,
                    ("verified_at", Value::Unsigned(p.verified_at)),
                ])
            }
            Self::Posture(p) => map(vec![
                ("managed", Value::Bool(p.managed)),
                ("compliant", Value::Bool(p.compliant)),
                ("provider", Value::text(&p.provider)),
                ("statement", Value::text(&p.statement)),
            ]),
            Self::Risk(r) => map(vec![
                ("level", Value::text(r.level.name())),
                ("reason_class", Value::text(&r.reason_class)),
            ]),
            Self::Label(l) => map(vec![
                ("label", Value::text(&l.label)),
                ("scheme", Value::text(&l.scheme)),
            ]),
        }
    }

    /// Reads the body of `class` from its value.
    ///
    /// # Errors
    /// [`BodyError`] for another class or a body outside `product-seam.cddl`.
    pub fn from_value(class: &str, v: &Value) -> Result<Self, BodyError> {
        let mut f = Fields::of(v)?;
        let s = match class {
            IDENTITY_PROOFING => {
                let provider = f.reference("provider")?;
                let method = Method::parse(f.text("method")?).ok_or(BodyError("method"))?;
                let level = match (f.take("ial"), f.take("loa_eidas")) {
                    (Some(Value::Unsigned(n @ 1..=3)), None) => {
                        ProofingLevel::Ial(u8::try_from(*n).map_err(|_| BodyError("ial"))?)
                    }
                    (None, Some(Value::Text(t))) => {
                        let i = EIDAS
                            .iter()
                            .position(|e| e == t)
                            .ok_or(BodyError("loa_eidas"))?;
                        ProofingLevel::Eidas(
                            u8::try_from(i.saturating_add(1)).map_err(|_| BodyError("loa"))?,
                        )
                    }
                    _ => return Err(BodyError("level")),
                };
                let verified_at = f.uint("verified_at")?;
                Self::Proofing(IdentityProofing {
                    provider,
                    method,
                    level,
                    verified_at,
                })
            }
            POSTURE_MDM => {
                let managed = f.flag("managed")?;
                let compliant = f.flag("compliant")?;
                let provider = f.reference("provider")?;
                let statement = f.text("statement")?;
                if statement.is_empty() || statement.chars().count() > 512 {
                    return Err(BodyError("statement"));
                }
                Self::Posture(PostureMdm {
                    managed,
                    compliant,
                    provider,
                    statement: String::from(statement),
                })
            }
            RISK_EXTERNAL => {
                let level = RiskLevel::parse(f.text("level")?).ok_or(BodyError("level"))?;
                let reason_class = f.reference("reason_class")?;
                Self::Risk(RiskExternal {
                    level,
                    reason_class,
                })
            }
            DATA_LABEL => Self::Label(DataLabel {
                label: f.reference("label")?,
                scheme: f.reference("scheme")?,
            }),
            _ => return Err(BodyError("class")),
        };
        f.done()?;
        Ok(s)
    }

    /// The body's dCBOR bytes, as they travel beside the Claim.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        dcbor::encode(&self.to_value(), Limits::CEILING).unwrap_or_default()
    }

    /// Reads a body of `class` from its dCBOR bytes.
    ///
    /// # Errors
    /// [`BodyError`].
    pub fn from_bytes(class: &str, bytes: &[u8]) -> Result<Self, BodyError> {
        let v = dcbor::decode(bytes, Limits::CEILING).map_err(|_| BodyError("cbor"))?;
        Self::from_value(class, &v)
    }

    /// The digest the Claim's `value` carries:
    /// `SHA-256("access/claim-body/v1" ‖ 0x00 ‖ dCBOR([class, body]))` (L2-CLB-1).
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let tagged = Value::Array(vec![Value::text(self.class()), self.to_value()]);
        let bytes = dcbor::encode(&tagged, Limits::CEILING).unwrap_or_default();
        context_digest(BODY_CONTEXT, &bytes).0
    }

    /// The assurance the Claim's statement must carry for this body: `loa_eidas` for a
    /// proofing, nothing for any other class (a risk Claim never qualifies, CI-2).
    #[must_use]
    pub fn assurance(&self) -> BTreeMap<String, u64> {
        match self {
            Self::Proofing(p) => BTreeMap::from([(String::from("loa_eidas"), p.level.loa())]),
            _ => BTreeMap::new(),
        }
    }
}

/// Whether `class` is one of the signal classes.
#[must_use]
pub fn is_signal(class: &str) -> bool {
    CLASSES.contains(&class)
}

/// What a recorded or carried Claim of a signal class says, as far as Access can read it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reading {
    /// Its body travelled with it and matches its `value`.
    Read(Signal),
    /// Its body was withheld or does not match: read as the most severe statement of its
    /// class (fail closed).
    Unreadable,
}

/// Reads `body` against a Claim of `class` whose `value` is `digest`.
#[must_use]
pub fn read(class: &str, digest: Option<&[u8]>, body: Option<&[u8]>) -> Reading {
    let (Some(d), Some(b)) = (digest, body) else {
        return Reading::Unreadable;
    };
    match Signal::from_bytes(class, b) {
        Ok(s) if s.digest().as_slice() == d => Reading::Read(s),
        _ => Reading::Unreadable,
    }
}

/// Device posture as the restriction context names it, worst last.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Posture {
    /// No accepted posture statement.
    #[default]
    None,
    /// Managed and compliant.
    Compliant,
    /// Not managed by the provider.
    Unmanaged,
    /// Managed and not compliant, or a statement Access cannot read.
    Noncompliant,
}

impl Posture {
    /// The restriction context's word.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Compliant => "compliant",
            Self::Unmanaged => "unmanaged",
            Self::Noncompliant => "noncompliant",
        }
    }

    /// The posture one reading states.
    #[must_use]
    pub const fn of(r: &Reading) -> Self {
        match r {
            Reading::Read(Signal::Posture(p)) if p.managed && p.compliant => Self::Compliant,
            Reading::Read(Signal::Posture(p)) if !p.managed => Self::Unmanaged,
            _ => Self::Noncompliant,
        }
    }
}

/// The risk a reading states: an unreadable risk Claim is `critical` (fail closed).
#[must_use]
pub const fn risk_of(r: &Reading) -> RiskLevel {
    match r {
        Reading::Read(Signal::Risk(x)) => x.level,
        _ => RiskLevel::Critical,
    }
}

/// The label a reading states: `scheme:label`, or `unreadable`.
#[must_use]
pub fn label_of(r: &Reading) -> String {
    match r {
        Reading::Read(Signal::Label(l)) => l.qualified(),
        _ => String::from("unreadable"),
    }
}

// OP-156 m.3 (r)
/// CAEP `device-compliance-change` (OpenID CAEP 1.0 §3.5).
pub const CAEP_DEVICE_COMPLIANCE: &str =
    "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change";

/// CAEP `risk-level-change` (OpenID CAEP 1.0 §3.4).
pub const CAEP_RISK_LEVEL: &str =
    "https://schemas.openid.net/secevent/caep/event-type/risk-level-change";

/// The reason class of a risk event that names none.
pub const UNSPECIFIED: &str = "unspecified";

fn reason(v: Option<&Json>) -> String {
    v.and_then(Json::as_str)
        .map(str::to_ascii_lowercase)
        .map(|s| {
            s.chars()
                .map(|c| if c == ' ' || c == '_' { '-' } else { c })
                .take(128)
                .collect::<String>()
        })
        .filter(|s| is_ref(s))
        .unwrap_or_else(|| String::from(UNSPECIFIED))
}

/// A CAEP risk level as Access reads it: `low`, `medium` and `high`; CAEP has no `critical`.
#[must_use]
pub fn caep_level(s: &str) -> Option<RiskLevel> {
    match s.to_ascii_lowercase().as_str() {
        "low" => Some(RiskLevel::Low),
        "medium" => Some(RiskLevel::Medium),
        "high" => Some(RiskLevel::High),
        _ => None,
    }
}

/// The signal of one CAEP event of type `uri` with members `body`, from the source whose
/// provider is `provider`; `None` for an event that states no signal.
///
/// - `device-compliance-change`: `posture_mdm`, compliant only for `current_status`
///   `compliant`; Okta's SSF transmitter sends these for devices it manages.
/// - `risk-level-change`: `risk_external` at `current_level`, its reason from
///   `risk_reason` (Okta) or `reason_admin`.
#[must_use]
pub fn caep(uri: &str, body: &Json, provider: &str) -> Option<Signal> {
    if !is_ref(provider) {
        return None;
    }
    match uri {
        CAEP_DEVICE_COMPLIANCE => {
            let status = body.get("current_status")?.as_str()?;
            let compliant = match status {
                "compliant" => true,
                "not-compliant" => false,
                _ => return None,
            };
            Some(Signal::Posture(PostureMdm {
                managed: true,
                compliant,
                provider: String::from(provider),
                statement: format!("Device {status} (CAEP)"),
            }))
        }
        CAEP_RISK_LEVEL => {
            let level = caep_level(body.get("current_level")?.as_str()?)?;
            let why = body
                .get("risk_reason")
                .or_else(|| body.get("reason_admin").and_then(|r| r.get("en")))
                .or_else(|| body.get("reason_admin"));
            Some(Signal::Risk(RiskExternal {
                level,
                reason_class: reason(why),
            }))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests;
