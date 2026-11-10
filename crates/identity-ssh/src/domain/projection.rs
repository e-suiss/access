//! A certificate as a projection of an `ssh.login` Grant (IDP-32, OP-156 m.3 (o), §9.10): the
//! bounds a holder's `projection.issue` names, drafted from its Grant, and the certificate fields
//! derived from the bounds once the authority plane allowed them. The Kernel holds the bounds
//! inside the Grant; this module also holds the certificate inside both, so a principal or an
//! extension the Grant does not name never reaches a certificate (projection ⊆ source, G2).
//!
//! Lifetimes: a person's certificate lives 8 hours unless it asks for less, at most 12; an
//! agent's 15 minutes, at most 1 hour; never past the Grant, the bounds or the decided horizon.

use std::collections::{BTreeMap, BTreeSet};

use access_kernel::model::{
    AuthoritySet, Bound, CanonicalAuthority, ConstraintSet, DelegationTerms, EqValue,
    ResourceSelector, Window,
};
use suiss_crypto::dcbor::Value;

use super::cert::{Extension, Fields, command_ok, principal_ok, source_ok};
use super::key::Ed25519Public;
use super::schema::{self, FORCE_COMMAND, PRINCIPAL, PUBLIC_KEY, SOURCE_ADDRESS};
use crate::SshError;

/// One minute in milliseconds.
const MINUTE_MS: u64 = 60_000;

/// One hour in milliseconds.
const HOUR_MS: u64 = 60 * MINUTE_MS;

/// How far before issuance a certificate becomes valid: the server's clock may lag.
pub const BACKDATE_MS: u64 = MINUTE_MS;

/// Who holds a certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Holder {
    /// A person, signed in with a passkey or MFA.
    Person,
    /// An agent, with its own Instance and its own narrower Grant.
    Agent,
}

impl Holder {
    /// The name in `ssh-cert.cddl`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Person => "person",
            Self::Agent => "agent",
        }
    }

    /// The holder of a name.
    #[must_use]
    pub fn of_name(name: &str) -> Option<Self> {
        [Self::Person, Self::Agent]
            .into_iter()
            .find(|h| h.name() == name)
    }

    /// The lifetime unless less is asked for (OP-156 m.3 (o)).
    #[must_use]
    pub const fn default_ms(self) -> u64 {
        match self {
            Self::Person => 8 * HOUR_MS,
            Self::Agent => 15 * MINUTE_MS,
        }
    }

    /// The longest lifetime (OP-156 m.3 (o)).
    #[must_use]
    pub const fn max_ms(self) -> u64 {
        match self {
            Self::Person => 12 * HOUR_MS,
            Self::Agent => HOUR_MS,
        }
    }
}

/// What a holder asks a draft for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ask {
    /// The server group.
    pub host_group: String,
    /// The ephemeral key.
    pub key: Ed25519Public,
    /// The principals; `None` for every principal the Grant names.
    pub principals: Option<BTreeSet<String>>,
    /// The lifetime in milliseconds; `None` for the holder's default.
    pub lifetime_ms: Option<u64>,
}

fn texts(bound: Option<&Bound>) -> Option<BTreeSet<String>> {
    match bound? {
        Bound::Enum(set) => Some(set.clone()),
        Bound::Eq(EqValue::Text(t)) => Some(BTreeSet::from([t.clone()])),
        _ => None,
    }
}

fn text(bound: Option<&Bound>) -> Result<Option<String>, SshError> {
    match bound {
        None => Ok(None),
        Some(Bound::Eq(EqValue::Text(t))) => Ok(Some(t.clone())),
        Some(_) => Err(SshError::Constraint),
    }
}

fn granted(params: &BTreeMap<String, Bound>, e: Extension) -> bool {
    params.get(e.param()) == Some(&Bound::Flag(true))
}

fn covers_login(set: &AuthoritySet) -> bool {
    let login = schema::login_ref();
    set.actions.exact.contains(&login)
        || set
            .actions
            .prefix
            .iter()
            .any(|(n, _)| n == schema::NAMESPACE)
}

/// The Grant's principals: every principal a certificate of it may carry. A Grant that names
/// none, or names them as anything but text, projects no certificate.
///
/// # Errors
/// [`SshError::NoPrincipal`].
pub fn grant_principals(grant: &CanonicalAuthority) -> Result<BTreeSet<String>, SshError> {
    texts(grant.authority.params.get(PRINCIPAL))
        .filter(|s| !s.is_empty() && s.iter().all(|p| principal_ok(p)))
        .ok_or(SshError::NoPrincipal)
}

/// The bounds of a `projection.issue` for `ask` under `grant`, made at `now_ms` (trusted time):
/// the Grant's constraints carried over, the asked principals within the Grant's, the asked
/// lifetime within the holder's ceiling and the Grant's validity, the key bound in.
///
/// # Errors
/// [`SshError`]: an unknown group, a Grant that does not cover it, a principal it does not
/// name, a lifetime past the ceiling.
pub fn draft(
    grant: &CanonicalAuthority,
    holder: Holder,
    ask: &Ask,
    now_ms: u64,
) -> Result<CanonicalAuthority, SshError> {
    if !schema::group_ok(&ask.host_group) || !covers_login(&grant.authority) {
        return Err(SshError::NotGranted);
    }
    let allowed = grant_principals(grant)?;
    let principals = match &ask.principals {
        None => allowed,
        Some(asked) if !asked.is_empty() && asked.is_subset(&allowed) => asked.clone(),
        Some(_) => return Err(SshError::NoPrincipal),
    };
    let lifetime = ask.lifetime_ms.unwrap_or_else(|| holder.default_ms());
    if lifetime == 0 || lifetime > holder.max_ms() {
        return Err(SshError::Lifetime);
    }
    let from = now_ms.saturating_sub(BACKDATE_MS);
    let until = now_ms
        .saturating_add(lifetime)
        .min(grant.constraints.validity.until);
    if until <= now_ms || from < grant.constraints.validity.from {
        return Err(SshError::Lifetime);
    }
    let g = &grant.authority.params;
    let mut params = BTreeMap::from([
        (String::from(PRINCIPAL), Bound::Enum(principals)),
        (
            String::from(PUBLIC_KEY),
            Bound::Eq(EqValue::Bytes(ask.key.0.to_vec())),
        ),
    ]);
    for name in [FORCE_COMMAND, SOURCE_ADDRESS] {
        if let Some(b) = g.get(name) {
            params.insert(String::from(name), b.clone());
        }
    }
    for e in Extension::ALL {
        if granted(g, e) {
            params.insert(String::from(e.param()), Bound::Flag(true));
        }
    }
    Ok(CanonicalAuthority {
        authority: AuthoritySet {
            actions: access_kernel::model::ActionSet {
                exact: BTreeSet::from([schema::login_ref()]),
                prefix: BTreeSet::new(),
            },
            resource: ResourceSelector::Exact(schema::host_group(&ask.host_group)),
            params,
            recipient: None,
            purpose: None,
        },
        constraints: ConstraintSet {
            validity: Window { from, until },
            conditions: grant.constraints.conditions.clone(),
            budget: grant.constraints.budget.clone(),
        },
        delegation: DelegationTerms::default(),
        requirements: grant.requirements.clone(),
    })
}

/// What the bounds of a request say before the authority plane is asked: the group, the key
/// and the lifetime within the holder's ceiling from `now_ms`. A lifetime past it is refused
/// here, before any decision is recorded.
///
/// # Errors
/// [`SshError`].
pub fn precheck(
    bounds: &CanonicalAuthority,
    holder: Holder,
    now_ms: u64,
) -> Result<(String, Ed25519Public), SshError> {
    let a = &bounds.authority;
    let ResourceSelector::Exact(resource) = &a.resource else {
        return Err(SshError::NotGranted);
    };
    let group = schema::group_of(resource).ok_or(SshError::NotGranted)?;
    if a.actions.exact != BTreeSet::from([schema::login_ref()]) || !a.actions.prefix.is_empty() {
        return Err(SshError::NotGranted);
    }
    let key = match a.params.get(PUBLIC_KEY) {
        Some(Bound::Eq(EqValue::Bytes(b))) => {
            Ed25519Public(<[u8; 32]>::try_from(b.as_slice()).map_err(|_| SshError::Fields)?)
        }
        _ => return Err(SshError::Fields),
    };
    let v = bounds.constraints.validity;
    if v.until <= now_ms || v.until.saturating_sub(now_ms) > holder.max_ms() {
        return Err(SshError::Lifetime);
    }
    Ok((String::from(group), key))
}

/// The certificate projection (`ssh-cert.cddl`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Projection {
    /// The projection's identifier: its `projection.issue` `ExerciseID`.
    pub key_id: String,
    /// 64 bits from the RNG, never 0.
    pub serial: u64,
    /// Who holds it.
    pub holder: Holder,
    /// The ephemeral key.
    pub public_key: Ed25519Public,
    /// The principals.
    pub principals: BTreeSet<String>,
    /// The server group.
    pub host_group: String,
    /// Unix seconds.
    pub valid_after: u64,
    /// Unix seconds.
    pub valid_before: u64,
    /// The `force-command`.
    pub force_command: Option<String>,
    /// The `source-address` entries.
    pub source_address: BTreeSet<String>,
    /// The extensions.
    pub extensions: BTreeSet<Extension>,
}

/// What the issuer draws for one certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Drawn {
    /// The serial, never 0.
    pub serial: u64,
    /// The certificate nonce.
    pub nonce: [u8; 32],
}

/// The certificate of the allowed `bounds` under `grant` for `holder`: principals, constraints
/// and extensions as both name them, valid from the bounds' start until the earliest of the
/// bounds' end, the Grant's end and the decided `horizon_ms`, and never longer than the
/// holder's ceiling.
///
/// # Errors
/// [`SshError`].
pub fn derive(
    grant: &CanonicalAuthority,
    bounds: &CanonicalAuthority,
    holder: Holder,
    key_id: &str,
    horizon_ms: u64,
) -> Result<Projection, SshError> {
    if !covers_login(&grant.authority) {
        return Err(SshError::NotGranted);
    }
    let ResourceSelector::Exact(resource) = &bounds.authority.resource else {
        return Err(SshError::NotGranted);
    };
    let host_group = schema::group_of(resource).ok_or(SshError::NotGranted)?;
    let g = &grant.authority.params;
    let b = &bounds.authority.params;
    // IDP-32, G2
    let allowed = grant_principals(grant)?;
    let principals = texts(b.get(PRINCIPAL)).ok_or(SshError::NoPrincipal)?;
    if principals.is_empty() || !principals.is_subset(&allowed) {
        return Err(SshError::NoPrincipal);
    }
    let force_command = match (text(g.get(FORCE_COMMAND))?, text(b.get(FORCE_COMMAND))?) {
        (Some(gc), Some(bc)) if gc == bc => Some(bc),
        (Some(_), _) => return Err(SshError::Constraint),
        (None, asked) => asked,
    };
    if force_command.as_deref().is_some_and(|c| !command_ok(c)) {
        return Err(SshError::Constraint);
    }
    let source_address = match (g.get(SOURCE_ADDRESS), texts(b.get(SOURCE_ADDRESS))) {
        (Some(gb), Some(asked)) => {
            let within = texts(Some(gb)).ok_or(SshError::Constraint)?;
            if asked.is_empty() || !asked.is_subset(&within) {
                return Err(SshError::Constraint);
            }
            asked
        }
        (Some(_), None) => return Err(SshError::Constraint),
        (None, asked) => asked.unwrap_or_default(),
    };
    if !source_address.iter().all(|a| source_ok(a)) {
        return Err(SshError::Constraint);
    }
    let mut extensions = BTreeSet::new();
    for e in Extension::ALL {
        match b.get(e.param()) {
            Some(Bound::Flag(true)) if granted(g, e) => {
                extensions.insert(e);
            }
            None | Some(Bound::Flag(false)) => {}
            Some(_) => return Err(SshError::Extension),
        }
    }
    let public_key = match b.get(PUBLIC_KEY) {
        Some(Bound::Eq(EqValue::Bytes(k))) => {
            Ed25519Public(<[u8; 32]>::try_from(k.as_slice()).map_err(|_| SshError::Fields)?)
        }
        _ => return Err(SshError::Fields),
    };
    let from = bounds.constraints.validity.from;
    let until = bounds
        .constraints
        .validity
        .until
        .min(grant.constraints.validity.until)
        .min(horizon_ms);
    if until <= from || until.saturating_sub(from) > holder.max_ms().saturating_add(BACKDATE_MS) {
        return Err(SshError::Lifetime);
    }
    Ok(Projection {
        key_id: String::from(key_id),
        serial: 0,
        holder,
        public_key,
        principals,
        host_group: String::from(host_group),
        valid_after: from / 1000,
        valid_before: until / 1000,
        force_command,
        source_address,
        extensions,
    })
}

impl Projection {
    /// The certificate fields under `ca`, with what the issuer drew.
    #[must_use]
    pub fn fields(&self, ca: Ed25519Public, drawn: Drawn) -> Fields {
        Fields {
            nonce: drawn.nonce,
            key: self.public_key,
            serial: drawn.serial,
            key_id: self.key_id.clone(),
            principals: self.principals.clone(),
            valid_after: self.valid_after,
            valid_before: self.valid_before,
            force_command: self.force_command.clone(),
            source_address: self.source_address.clone(),
            extensions: self.extensions.clone(),
            ca,
        }
    }

    /// The `ssh-cert-projection` map, deterministic CBOR order on encoding.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let texts = |s: &BTreeSet<String>| Value::Array(s.iter().map(|t| Value::text(t)).collect());
        let mut m = vec![
            (Value::text("key_id"), Value::text(&self.key_id)),
            (Value::text("serial"), Value::Unsigned(self.serial)),
            (Value::text("holder"), Value::text(self.holder.name())),
            (
                Value::text("public_key"),
                Value::Bytes(self.public_key.0.to_vec()),
            ),
            (Value::text("principals"), texts(&self.principals)),
            (Value::text("host_group"), Value::text(&self.host_group)),
            (
                Value::text("valid_after"),
                Value::Unsigned(self.valid_after),
            ),
            (
                Value::text("valid_before"),
                Value::Unsigned(self.valid_before),
            ),
            (
                Value::text("extensions"),
                Value::Array(
                    self.extensions
                        .iter()
                        .map(|e| Value::text(e.name()))
                        .collect(),
                ),
            ),
        ];
        if let Some(c) = &self.force_command {
            m.push((Value::text("force_command"), Value::text(c)));
        }
        if !self.source_address.is_empty() {
            m.push((Value::text("source_address"), texts(&self.source_address)));
        }
        Value::Map(m)
    }

    /// The projection of an `ssh-cert-projection` map: every rule of the CDDL.
    ///
    /// # Errors
    /// [`SshError::Malformed`].
    pub fn of_value(v: &Value) -> Result<Self, SshError> {
        let Value::Map(entries) = v else {
            return Err(SshError::Malformed);
        };
        let known = [
            "key_id",
            "serial",
            "holder",
            "public_key",
            "principals",
            "host_group",
            "valid_after",
            "valid_before",
            "force_command",
            "source_address",
            "extensions",
        ];
        if entries
            .iter()
            .any(|(k, _)| !matches!(k, Value::Text(t) if known.contains(&t.as_str())))
        {
            return Err(SshError::Malformed);
        }
        let text = |k: &str, max: usize| match v.get(k) {
            Some(Value::Text(t)) if !t.is_empty() && t.len() <= max => Ok(t.clone()),
            _ => Err(SshError::Malformed),
        };
        let uint = |k: &str| match v.get(k) {
            Some(Value::Unsigned(n)) => Ok(*n),
            _ => Err(SshError::Malformed),
        };
        let list = |k: &str| -> Result<Option<Vec<String>>, SshError> {
            match v.get(k) {
                None => Ok(None),
                Some(Value::Array(items)) => items
                    .iter()
                    .map(|i| match i {
                        Value::Text(t) => Ok(t.clone()),
                        _ => Err(SshError::Malformed),
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map(Some),
                Some(_) => Err(SshError::Malformed),
            }
        };
        let principals: BTreeSet<String> = list("principals")?
            .ok_or(SshError::Malformed)?
            .into_iter()
            .collect();
        if principals.is_empty() || principals.iter().any(|p| p.len() > 64 || p.is_empty()) {
            return Err(SshError::Malformed);
        }
        let source_address = match list("source_address")? {
            Some(s) if s.is_empty() || s.iter().any(|a| a.is_empty() || a.len() > 64) => {
                return Err(SshError::Malformed);
            }
            s => s.unwrap_or_default().into_iter().collect(),
        };
        let extensions = list("extensions")?
            .ok_or(SshError::Malformed)?
            .iter()
            .map(|e| Extension::of_name(e).ok_or(SshError::Malformed))
            .collect::<Result<BTreeSet<_>, _>>()?;
        let public_key = match v.get("public_key") {
            Some(Value::Bytes(b)) => {
                Ed25519Public(<[u8; 32]>::try_from(b.as_slice()).map_err(|_| SshError::Malformed)?)
            }
            _ => return Err(SshError::Malformed),
        };
        let force_command = match v.get("force_command") {
            None => None,
            Some(_) => Some(text("force_command", 4096)?),
        };
        Ok(Self {
            key_id: text("key_id", 128)?,
            serial: uint("serial")?,
            holder: Holder::of_name(&text("holder", 8)?).ok_or(SshError::Malformed)?,
            public_key,
            principals,
            host_group: text("host_group", 128)?,
            valid_after: uint("valid_after")?,
            valid_before: uint("valid_before")?,
            force_command,
            source_address,
            extensions,
        })
    }
}

#[cfg(test)]
mod tests;
