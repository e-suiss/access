//! Access's own audit event taxonomy (OP-41, OP-47, §17.8.1): every event the full-taxonomy
//! audit stream carries, with its static OCSF mapping and its CAEP counterpart. The table is
//! `conformance/catalog/audit-taxonomy.toml`, compiled in; an event outside it is never rendered.

use std::sync::LazyLock;

use serde::Deserialize;

/// The taxonomy file, as compiled in.
pub const SOURCE: &str = include_str!("../../../../conformance/catalog/audit-taxonomy.toml");

/// The eight CAEP event types of the action stream (channel A, OP-41).
pub const CAEP_TYPES: [&str; 8] = [
    "session-revoked",
    "token-claims-change",
    "credential-change",
    "assurance-level-change",
    "device-compliance-change",
    "session-established",
    "session-presented",
    "risk-level-change",
];

/// Longest event name, as the audit tables allow.
pub const MAX_EVENT: usize = 64;

/// Which plane writes the event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Plane {
    /// The identity audit log.
    Identity,
    /// The authority record or its operational stream.
    Authority,
}

/// What the event says happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    /// It succeeded.
    Success,
    /// It was refused or failed.
    Failure,
    /// Neither: a step on the way.
    Unknown,
}

impl Outcome {
    /// The word renderings use.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Unknown => "unknown",
        }
    }
}

/// One event of the taxonomy.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// Dotted name, as written in the record.
    pub event: String,
    /// Writing plane.
    pub plane: Plane,
    /// Own taxonomy class.
    pub class: String,
    /// Outcome.
    pub outcome: Outcome,
    /// Fields every rendering carries besides the common ones.
    pub fields: Vec<String>,
    /// OCSF `class_uid`.
    pub ocsf_class: u32,
    /// OCSF `activity_id`.
    pub ocsf_activity: u32,
    /// CAEP counterpart in the action stream; empty when there is none.
    pub caep: String,
    /// Whether the tenant webhook feed carries it as a raw event (IDP-36, IDP-37).
    pub webhook: bool,
}

impl Entry {
    /// OCSF `category_uid`: the class's thousands.
    #[must_use]
    pub const fn ocsf_category(&self) -> u32 {
        self.ocsf_class / 1000
    }

    /// OCSF `type_uid`: `class_uid * 100 + activity_id`.
    #[must_use]
    pub fn ocsf_type(&self) -> Option<u64> {
        u64::from(self.ocsf_class)
            .checked_mul(100)?
            .checked_add(u64::from(self.ocsf_activity))
    }

    /// The CAEP counterpart, if there is one.
    #[must_use]
    pub fn caep(&self) -> Option<&str> {
        (!self.caep.is_empty()).then_some(self.caep.as_str())
    }
}

/// The whole taxonomy.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Taxonomy {
    /// Taxonomy version.
    pub version: u32,
    /// The OCSF schema version the mapping targets.
    pub ocsf_version: String,
    /// The events, in file order.
    #[serde(rename = "event")]
    pub events: Vec<Entry>,
}

impl Taxonomy {
    /// The entry of `event`.
    #[must_use]
    pub fn get(&self, event: &str) -> Option<&Entry> {
        self.events.iter().find(|e| e.event == event)
    }

    /// The events the tenant webhook feed carries as raw events (IDP-36, IDP-37).
    pub fn webhook_feed(&self) -> impl Iterator<Item = &Entry> {
        self.events.iter().filter(|e| e.webhook)
    }
}

/// Why the taxonomy cannot answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TaxonomyError {
    /// The taxonomy source is malformed or breaks one of its rules.
    #[error("taxonomy source: {0}")]
    Source(&'static str),
    /// The event is not in the taxonomy.
    #[error("unknown audit event")]
    Unknown,
}

/// Whether `name` is a valid event name: `[a-z][a-z0-9_.]{0,63}`, as the audit tables check.
#[must_use]
pub fn valid_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    name.len() <= MAX_EVENT
        && bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.')
}

/// Parses and checks a taxonomy: unique valid names, CAEP counterparts among [`CAEP_TYPES`],
/// OCSF classes and activities in range.
///
/// # Errors
/// [`TaxonomyError::Source`].
pub fn parse(source: &str) -> Result<Taxonomy, TaxonomyError> {
    let t: Taxonomy =
        toml::from_str(source).map_err(|_| TaxonomyError::Source("taxonomy is not valid TOML"))?;
    if t.events.is_empty() {
        return Err(TaxonomyError::Source("no events"));
    }
    for (i, e) in t.events.iter().enumerate() {
        if !valid_name(&e.event) {
            return Err(TaxonomyError::Source("event name"));
        }
        if t.events
            .iter()
            .skip(i.saturating_add(1))
            .any(|o| o.event == e.event)
        {
            return Err(TaxonomyError::Source("duplicate event"));
        }
        if e.caep().is_some_and(|c| !CAEP_TYPES.contains(&c)) {
            return Err(TaxonomyError::Source("CAEP counterpart"));
        }
        if !(1000..10_000).contains(&e.ocsf_class) || e.ocsf_activity > 99 {
            return Err(TaxonomyError::Source("OCSF class or activity"));
        }
        if e.class.is_empty() {
            return Err(TaxonomyError::Source("class"));
        }
    }
    Ok(t)
}

static PARSED: LazyLock<Result<Taxonomy, TaxonomyError>> = LazyLock::new(|| parse(SOURCE));

/// The compiled-in taxonomy.
///
/// # Errors
/// [`TaxonomyError::Source`] when the compiled-in file breaks a rule (a test keeps it from
/// shipping so).
pub fn taxonomy() -> Result<&'static Taxonomy, TaxonomyError> {
    PARSED.as_ref().map_err(|e| *e)
}

/// The entry of `event` in the compiled-in taxonomy.
///
/// # Errors
/// [`TaxonomyError::Unknown`] for an event outside it: it is not rendered (fail closed).
pub fn entry(event: &str) -> Result<&'static Entry, TaxonomyError> {
    taxonomy()?.get(event).ok_or(TaxonomyError::Unknown)
}

#[cfg(test)]
mod tests;
