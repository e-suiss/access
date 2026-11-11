//! `idp.support.*` changes (catalog 7, OP-157 m.3 (a), (e), (g)): registering and retiring the
//! support case systems whose `support_case` Claims hold support Grants, and the realm's support
//! artifact policy. Sans-I/O: the REST body becomes one change, which the intent binds (EI-25).

use access_internal_api::idp::IdpAction;
use access_kernel::json::b64url_decode;
use serde_json::{Map, Value as Json};
use suiss_crypto::dcbor::Value;

use super::Invalid;
use super::hr::name_ok;

/// The case system vendors the product twin kit records, in the order they ship (OP-157 m.3
/// (e)).
pub const PROVIDERS: [&str; 4] = [
    "zendesk",
    "freshdesk",
    "servicenow",
    "jira-service-management",
];

/// The `support_case` Claim body formats a case system may state (OP-157 m.3 (e)).
pub const FORMATS: [&str; 1] = ["product-seam/v1"];

/// Largest support artifact a policy may admit, in bytes (PD).
pub const MAX_ARTIFACT_BYTES: u64 = 10 * 1024 * 1024;

/// Longest retention a support artifact policy may name, in days (PD).
pub const MAX_ARTIFACT_RETENTION_DAYS: u32 = 365;

/// One support case system registration (OP-157 m.3 (e)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaseSystem {
    /// Its name, never reused.
    pub name: String,
    /// The issuer Party its `support_case` Claims are signed by.
    pub issuer: [u8; 16],
    /// The vendor, one of [`PROVIDERS`].
    pub provider: String,
    /// The Claim body format, one of [`FORMATS`].
    pub format: String,
}

/// An `idp.support.case_system_*` change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CaseSystemChange {
    /// `idp.support.case_system_register` (CT2).
    Register(CaseSystem),
    /// `idp.support.case_system_retire` (CT1).
    Retire(String),
}

/// The realm's support artifact policy (OP-157 m.3 (g)): `idp.support.artifact_policy` when
/// present, `artifact_policy_close` when absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArtifactPolicy {
    /// Largest artifact, in bytes.
    pub max_bytes: u64,
    /// How long a sealed artifact is kept before it is crypto-shredded, in days.
    pub retention_days: u32,
}

fn own(body: &Json) -> Result<&Map<String, Json>, Invalid> {
    body.as_object().ok_or(Invalid::Body)
}

fn only(m: &Map<String, Json>, keys: &[&str]) -> Result<(), Invalid> {
    if m.keys().all(|k| keys.contains(&k.as_str())) {
        Ok(())
    } else {
        Err(Invalid::Body)
    }
}

fn text<'a>(m: &'a Map<String, Json>, key: &str) -> Result<&'a str, Invalid> {
    m.get(key).and_then(Json::as_str).ok_or(Invalid::Body)
}

impl CaseSystemChange {
    /// `registerCaseSystem`: `{"name", "issuer", "provider", "format"}`, `issuer` the Party's
    /// base64url.
    ///
    /// # Errors
    /// [`Invalid::Body`].
    pub fn register(body: &Json) -> Result<Self, Invalid> {
        let m = own(body)?;
        only(m, &["name", "issuer", "provider", "format"])?;
        let issuer = b64url_decode(text(m, "issuer")?)
            .ok()
            .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
            .ok_or(Invalid::Body)?;
        Ok(Self::Register(CaseSystem {
            name: String::from(text(m, "name")?),
            issuer,
            provider: String::from(text(m, "provider")?),
            format: String::from(text(m, "format")?),
        }))
    }

    /// `retireCaseSystem` of `name`: an empty body.
    ///
    /// # Errors
    /// [`Invalid::Body`].
    pub fn retire(name: &str, body: &Json) -> Result<Self, Invalid> {
        if !own(body)?.is_empty() {
            return Err(Invalid::Body);
        }
        Ok(Self::Retire(String::from(name)))
    }

    /// The action that authorizes it.
    #[must_use]
    pub const fn action(&self) -> IdpAction {
        match self {
            Self::Register(_) => IdpAction::SupportCaseSystemRegister,
            Self::Retire(_) => IdpAction::SupportCaseSystemRetire,
        }
    }

    /// Whether it is inside the rules: a name of lower-case letters, digits and `-`, a known
    /// provider and format.
    ///
    /// # Errors
    /// [`Invalid::Body`].
    pub fn check(&self) -> Result<(), Invalid> {
        let ok = match self {
            Self::Register(c) => {
                name_ok(&c.name)
                    && PROVIDERS.contains(&c.provider.as_str())
                    && FORMATS.contains(&c.format.as_str())
            }
            Self::Retire(n) => name_ok(n),
        };
        if ok { Ok(()) } else { Err(Invalid::Body) }
    }

    /// The change's body, which the intent binds (EI-25).
    #[must_use]
    pub fn body(&self) -> Value {
        match self {
            Self::Register(c) => Value::Map(vec![
                (Value::text("name"), Value::text(&c.name)),
                (Value::text("issuer"), Value::Bytes(c.issuer.to_vec())),
                (Value::text("provider"), Value::text(&c.provider)),
                (Value::text("format"), Value::text(&c.format)),
            ]),
            Self::Retire(n) => Value::Map(vec![(Value::text("retire"), Value::text(n))]),
        }
    }

    /// Its resource path below the realm.
    #[must_use]
    pub fn path(&self) -> [String; 2] {
        let name = match self {
            Self::Register(c) => &c.name,
            Self::Retire(n) => n,
        };
        [String::from("case-system"), name.clone()]
    }
}

impl ArtifactPolicy {
    /// `putSupportArtifactPolicy`: `{"enabled", "max_bytes"?, "retention_days"?}`; `None` when
    /// it closes uploads.
    ///
    /// # Errors
    /// [`Invalid::Body`].
    pub fn parse(body: &Json) -> Result<Option<Self>, Invalid> {
        let m = own(body)?;
        only(m, &["enabled", "max_bytes", "retention_days"])?;
        match m.get("enabled").and_then(Json::as_bool) {
            Some(false) if m.len() == 1 => Ok(None),
            Some(true) => Ok(Some(Self {
                max_bytes: m
                    .get("max_bytes")
                    .and_then(Json::as_u64)
                    .ok_or(Invalid::Body)?,
                retention_days: m
                    .get("retention_days")
                    .and_then(Json::as_u64)
                    .and_then(|d| u32::try_from(d).ok())
                    .ok_or(Invalid::Body)?,
            })),
            _ => Err(Invalid::Body),
        }
    }

    /// Whether it is inside the rules: 1 byte to [`MAX_ARTIFACT_BYTES`], 1 to
    /// [`MAX_ARTIFACT_RETENTION_DAYS`] days.
    ///
    /// # Errors
    /// [`Invalid::Body`].
    pub fn check(&self) -> Result<(), Invalid> {
        if (1..=MAX_ARTIFACT_BYTES).contains(&self.max_bytes)
            && (1..=MAX_ARTIFACT_RETENTION_DAYS).contains(&self.retention_days)
        {
            Ok(())
        } else {
            Err(Invalid::Body)
        }
    }
}

/// The action of a support artifact policy change.
#[must_use]
pub const fn artifact_policy_action(policy: Option<&ArtifactPolicy>) -> IdpAction {
    match policy {
        Some(_) => IdpAction::SupportArtifactPolicy,
        None => IdpAction::SupportArtifactPolicyClose,
    }
}

/// The body of a support artifact policy change, which the intent binds (EI-25).
#[must_use]
pub fn artifact_policy_body(policy: Option<&ArtifactPolicy>) -> Value {
    match policy {
        Some(p) => Value::Map(vec![
            (Value::text("max_bytes"), Value::Unsigned(p.max_bytes)),
            (
                Value::text("retention_days"),
                Value::Unsigned(u64::from(p.retention_days)),
            ),
        ]),
        None => Value::Map(vec![(Value::text("closed"), Value::Bool(true))]),
    }
}
