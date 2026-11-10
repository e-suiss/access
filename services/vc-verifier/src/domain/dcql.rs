//! DCQL (OID4VP 1.0 §6) under the verifier's minimum-attribute profile (IDP-21, Ek B 4833,
//! 4982): every credential query names its format, its type and the exact claims it asks for,
//! and a response may disclose nothing else. `credential_sets`, claim `values` and
//! `claim_sets` are refused, so a query never widens to "any of".

use serde_json::Value;

/// Most credential queries in one request.
pub const MAX_CREDENTIALS: usize = 4;
/// Most claims one credential query asks for.
pub const MAX_CLAIMS: usize = 32;
/// Longest claim path.
pub const MAX_PATH: usize = 8;
/// Longest identifier, type or path element.
pub const MAX_TEXT: usize = 255;

/// A credential format the verifier accepts (HAIP).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// SD-JWT VC (`dc+sd-jwt`).
    SdJwtVc,
    /// ISO 18013-5 mdoc (`mso_mdoc`).
    Mdoc,
}

impl Format {
    /// The DCQL format identifier.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SdJwtVc => "dc+sd-jwt",
            Self::Mdoc => "mso_mdoc",
        }
    }
}

/// One element of a claim path (OID4VP 1.0 §7).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Step {
    /// An object member.
    Key(String),
    /// An array index.
    Index(u64),
    /// Every element of an array (`null`).
    Every,
}

/// A claim path.
pub type Path = Vec<Step>;

/// One credential query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialQuery {
    /// The query's id; the response's `vp_token` is keyed by it.
    pub id: String,
    /// The format.
    pub format: Format,
    /// For SD-JWT VC: the accepted `vct` values; for mdoc: the one `doctype`.
    pub types: Vec<String>,
    /// The claims asked for; never empty.
    pub claims: Vec<Path>,
}

/// A DCQL query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query {
    /// The credential queries, at least one; every one is required.
    pub credentials: Vec<CredentialQuery>,
}

/// Why a query is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DcqlError {
    /// Not a query in this profile.
    #[error("dcql-malformed")]
    Malformed,
    /// A member the profile refuses (`credential_sets`, `values`, `claim_sets`, `trusted_authorities`).
    #[error("dcql-unsupported")]
    Unsupported,
    /// A credential query without claims: the verifier always names what it asks for.
    #[error("dcql-no-claims")]
    NoClaims,
}

impl DcqlError {
    /// Stable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Malformed => "dcql-malformed",
            Self::Unsupported => "dcql-unsupported",
            Self::NoClaims => "dcql-no-claims",
        }
    }
}

fn text(v: &Value) -> Result<String, DcqlError> {
    let s = v.as_str().ok_or(DcqlError::Malformed)?;
    if s.is_empty() || s.len() > MAX_TEXT || s.chars().any(char::is_control) {
        return Err(DcqlError::Malformed);
    }
    Ok(String::from(s))
}

fn id(v: &Value) -> Result<String, DcqlError> {
    let s = text(v)?;
    if s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        Ok(s)
    } else {
        Err(DcqlError::Malformed)
    }
}

fn path(v: &Value, format: Format) -> Result<Path, DcqlError> {
    let items = v.as_array().ok_or(DcqlError::Malformed)?;
    if items.is_empty() || items.len() > MAX_PATH {
        return Err(DcqlError::Malformed);
    }
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        out.push(match item {
            Value::String(_) => Step::Key(text(item)?),
            Value::Number(n) => Step::Index(n.as_u64().ok_or(DcqlError::Malformed)?),
            Value::Null => Step::Every,
            _ => return Err(DcqlError::Malformed),
        });
    }
    // OID4VP §7.2
    if format == Format::Mdoc && !(out.len() == 2 && out.iter().all(|s| matches!(s, Step::Key(_))))
    {
        return Err(DcqlError::Malformed);
    }
    Ok(out)
}

fn credential(v: &Value) -> Result<CredentialQuery, DcqlError> {
    let o = v.as_object().ok_or(DcqlError::Malformed)?;
    for k in o.keys() {
        match k.as_str() {
            "id"
            | "format"
            | "meta"
            | "claims"
            | "require_cryptographic_holder_binding"
            | "multiple" => {}
            "claim_sets" | "trusted_authorities" => return Err(DcqlError::Unsupported),
            _ => return Err(DcqlError::Malformed),
        }
    }
    let format = match o.get("format").and_then(Value::as_str) {
        Some("dc+sd-jwt") => Format::SdJwtVc,
        Some("mso_mdoc") => Format::Mdoc,
        _ => return Err(DcqlError::Unsupported),
    };
    // HAIP, IDP-21
    if o.get("require_cryptographic_holder_binding")
        .is_some_and(|b| b != &Value::Bool(true))
        || o.get("multiple").is_some_and(|b| b != &Value::Bool(false))
    {
        return Err(DcqlError::Unsupported);
    }
    let meta = o
        .get("meta")
        .and_then(Value::as_object)
        .ok_or(DcqlError::Malformed)?;
    let types = match format {
        Format::SdJwtVc => {
            if meta.keys().any(|k| k != "vct_values") {
                return Err(DcqlError::Malformed);
            }
            let values = meta
                .get("vct_values")
                .and_then(Value::as_array)
                .ok_or(DcqlError::Malformed)?;
            if values.is_empty() || values.len() > MAX_CREDENTIALS {
                return Err(DcqlError::Malformed);
            }
            values.iter().map(text).collect::<Result<Vec<_>, _>>()?
        }
        Format::Mdoc => {
            if meta.keys().any(|k| k != "doctype_value") {
                return Err(DcqlError::Malformed);
            }
            vec![text(
                meta.get("doctype_value").ok_or(DcqlError::Malformed)?,
            )?]
        }
    };
    let claims = o
        .get("claims")
        .and_then(Value::as_array)
        .ok_or(DcqlError::NoClaims)?;
    if claims.is_empty() {
        return Err(DcqlError::NoClaims);
    }
    if claims.len() > MAX_CLAIMS {
        return Err(DcqlError::Malformed);
    }
    let mut paths = Vec::with_capacity(claims.len());
    for c in claims {
        let c = c.as_object().ok_or(DcqlError::Malformed)?;
        for k in c.keys() {
            match k.as_str() {
                "id" | "path" | "intent_to_retain" => {}
                "values" => return Err(DcqlError::Unsupported),
                _ => return Err(DcqlError::Malformed),
            }
        }
        if let Some(i) = c.get("id") {
            id(i)?;
        }
        if c.get("intent_to_retain").is_some_and(|b| !b.is_boolean()) {
            return Err(DcqlError::Malformed);
        }
        let p = path(c.get("path").ok_or(DcqlError::Malformed)?, format)?;
        if paths.contains(&p) {
            return Err(DcqlError::Malformed);
        }
        paths.push(p);
    }
    Ok(CredentialQuery {
        id: id(o.get("id").ok_or(DcqlError::Malformed)?)?,
        format,
        types,
        claims: paths,
    })
}

impl Query {
    /// Reads a query in the profile.
    ///
    /// # Errors
    /// [`DcqlError`].
    pub fn parse(v: &Value) -> Result<Self, DcqlError> {
        let o = v.as_object().ok_or(DcqlError::Malformed)?;
        for k in o.keys() {
            match k.as_str() {
                "credentials" => {}
                "credential_sets" => return Err(DcqlError::Unsupported),
                _ => return Err(DcqlError::Malformed),
            }
        }
        let list = o
            .get("credentials")
            .and_then(Value::as_array)
            .ok_or(DcqlError::Malformed)?;
        if list.is_empty() || list.len() > MAX_CREDENTIALS {
            return Err(DcqlError::Malformed);
        }
        let credentials = list.iter().map(credential).collect::<Result<Vec<_>, _>>()?;
        for (i, c) in credentials.iter().enumerate() {
            if credentials
                .iter()
                .skip(i.saturating_add(1))
                .any(|d| d.id == c.id)
            {
                return Err(DcqlError::Malformed);
            }
        }
        Ok(Self { credentials })
    }

    /// The query as the request object carries it.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let creds: Vec<Value> = self
            .credentials
            .iter()
            .map(|c| {
                let meta = match c.format {
                    Format::SdJwtVc => serde_json::json!({ "vct_values": c.types }),
                    Format::Mdoc => serde_json::json!({
                        "doctype_value": c.types.first().cloned().unwrap_or_default()
                    }),
                };
                let claims: Vec<Value> = c
                    .claims
                    .iter()
                    .map(|p| serde_json::json!({ "path": path_json(p) }))
                    .collect();
                serde_json::json!({
                    "id": c.id,
                    "format": c.format.name(),
                    "meta": meta,
                    "claims": claims,
                })
            })
            .collect();
        serde_json::json!({ "credentials": creds })
    }
}

/// A path as JSON.
#[must_use]
pub fn path_json(p: &Path) -> Value {
    Value::Array(
        p.iter()
            .map(|s| match s {
                Step::Key(k) => Value::from(k.as_str()),
                Step::Index(i) => Value::from(*i),
                Step::Every => Value::Null,
            })
            .collect(),
    )
}

fn step_covers(asked: &Step, got: &Step) -> bool {
    match (asked, got) {
        (Step::Every, Step::Index(_)) => true,
        _ => asked == got,
    }
}

/// Whether the asked path covers the disclosed one: the disclosed path lies at or below it.
#[must_use]
pub fn covers(asked: &Path, disclosed: &Path) -> bool {
    asked.len() <= disclosed.len()
        && asked
            .iter()
            .zip(disclosed.iter())
            .all(|(a, d)| step_covers(a, d))
}

/// Whether a disclosed path is needed to reach an asked one: it lies on the way to it.
#[must_use]
pub fn on_the_way(asked: &Path, disclosed: &Path) -> bool {
    disclosed.len() < asked.len()
        && disclosed
            .iter()
            .zip(asked.iter())
            .all(|(d, a)| step_covers(a, d))
}

/// Ek B 4982: every disclosed path is asked for, or is a container on the way to one.
#[must_use]
pub fn minimal(asked: &[Path], disclosed: &[Path]) -> bool {
    disclosed
        .iter()
        .all(|d| asked.iter().any(|a| covers(a, d) || on_the_way(a, d)))
}
