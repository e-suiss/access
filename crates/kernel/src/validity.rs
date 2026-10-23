//! Validity contract (§9.12, OP-108 m.1, m.2).

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use suiss_crypto::dcbor::Value;

use crate::codec::{
    Canonical, Fields, ModelError, ident, map, set_of, set_value, text, uint, unit,
};
use crate::digest::Digest;
use crate::model::{AuthoritySet, RequirementTerm, TrustedTime};

/// Connectivity profile class, frozen (L16).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProfileClass {
    /// Online.
    Online,
    /// Intermittent.
    Intermittent,
    /// Offline.
    Offline,
    /// Long-running.
    LongRunning,
}

/// Connectivity profile variant; each maps to one class (§9.12).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProfileVariant {
    /// `online-strict`.
    OnlineStrict,
    /// `bounded-staleness`.
    BoundedStaleness,
    /// `revalidate-on-reconnect`.
    RevalidateOnReconnect,
    /// `checkpointed-offline`.
    CheckpointedOffline,
    /// `checkpoint-continuation`.
    CheckpointContinuation,
}

impl ProfileVariant {
    /// The class this variant belongs to.
    #[must_use]
    pub const fn class(self) -> ProfileClass {
        match self {
            Self::OnlineStrict => ProfileClass::Online,
            Self::BoundedStaleness | Self::RevalidateOnReconnect => ProfileClass::Intermittent,
            Self::CheckpointedOffline => ProfileClass::Offline,
            Self::CheckpointContinuation => ProfileClass::LongRunning,
        }
    }
}

/// Re-validation conditions.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Revalidation {
    /// Every N uses.
    pub every_uses: Option<u64>,
    /// On every reconnect.
    pub on_reconnect: bool,
    /// For these action classes.
    pub action_classes: BTreeSet<String>,
}

/// Pre-drawn offline budget slice.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OfflineSlice {
    /// Budget term it was drawn from.
    pub budget_term: Digest,
    /// Amount.
    pub amount: u64,
    /// Unit, or `count`.
    pub unit: String,
}

/// Validity contract, the 15 fields of §9.12.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidityContract {
    /// `projection.issue` exercise.
    pub issuing_exercise: Digest,
    /// Authority state basis reference (opaque below audit scope).
    pub basis_ref: Vec<u8>,
    /// Holder key binding.
    pub holder: Digest,
    /// Verifiers it is valid for.
    pub audience: BTreeSet<String>,
    /// Bounded projection.
    pub bounds: AuthoritySet,
    /// Profile class.
    pub class: ProfileClass,
    /// Profile variant.
    pub variant: ProfileVariant,
    /// Profile parameters.
    pub params: alloc::collections::BTreeMap<String, u64>,
    /// Absolute expiry.
    pub horizon: TrustedTime,
    /// Δ for `bounded-staleness`.
    pub max_staleness_ms: Option<u64>,
    /// Freshness sources.
    pub freshness_sources: BTreeSet<String>,
    /// Re-validation conditions.
    pub revalidation: Revalidation,
    /// Offline budget slices.
    pub offline_slice: BTreeSet<OfflineSlice>,
    /// Requirements the verifier can satisfy locally.
    pub local_requirements: BTreeSet<RequirementTerm>,
    /// Verifier profile claim digest.
    pub verifier_profile_ref: Digest,
    /// Clock source class.
    pub clock_source: String,
    /// Clock skew tolerance in milliseconds.
    pub clock_skew_ms: u64,
    /// Extensions the verifier must understand.
    pub must_understand: BTreeSet<String>,
}

const CLASSES: [(&str, ProfileClass); 4] = [
    ("online", ProfileClass::Online),
    ("intermittent", ProfileClass::Intermittent),
    ("offline", ProfileClass::Offline),
    ("long-running", ProfileClass::LongRunning),
];
const VARIANTS: [(&str, ProfileVariant); 5] = [
    ("online-strict", ProfileVariant::OnlineStrict),
    ("bounded-staleness", ProfileVariant::BoundedStaleness),
    (
        "revalidate-on-reconnect",
        ProfileVariant::RevalidateOnReconnect,
    ),
    ("checkpointed-offline", ProfileVariant::CheckpointedOffline),
    (
        "checkpoint-continuation",
        ProfileVariant::CheckpointContinuation,
    ),
];

fn word<T: Copy>(v: &Value, table: &[(&str, T)]) -> Result<T, ModelError> {
    let t = text(v)?;
    table
        .iter()
        .find(|(k, _)| *k == t)
        .map(|(_, x)| *x)
        .ok_or(ModelError::Unknown)
}

fn word_of<T: Copy + PartialEq>(x: T, table: &[(&'static str, T)]) -> Value {
    Value::text(table.iter().find(|(_, y)| *y == x).map_or("", |(k, _)| k))
}

fn texts(s: &BTreeSet<String>) -> Value {
    set_value(s.iter().map(|x| Value::text(x)))
}

fn opt_texts(s: &BTreeSet<String>) -> Option<Value> {
    (!s.is_empty()).then(|| texts(s))
}

fn read_texts(v: Option<&Value>, non_empty: bool) -> Result<BTreeSet<String>, ModelError> {
    match v {
        None if non_empty => Err(ModelError::Missing),
        None => Ok(BTreeSet::new()),
        Some(v) => set_of(v, true, |x| text(x).map(String::from)),
    }
}

impl Canonical for OfflineSlice {
    fn to_value(&self) -> Value {
        map([
            ("budget_term", Some(self.budget_term.to_value())),
            ("amount", Some(Value::Unsigned(self.amount))),
            ("unit", Some(Value::text(&self.unit))),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let s = OfflineSlice {
            budget_term: Canonical::from_value(f.req("budget_term")?)?,
            amount: uint(f.req("amount")?)?,
            unit: unit(f.req("unit")?)?,
        };
        f.done()?;
        Ok(s)
    }
}

impl Canonical for ValidityContract {
    fn to_value(&self) -> Value {
        let profile_params = (!self.params.is_empty()).then(|| {
            Value::Map(
                self.params
                    .iter()
                    .map(|(k, n)| (Value::text(k), Value::Unsigned(*n)))
                    .collect(),
            )
        });
        let revalidation = (self.revalidation != Revalidation::default()).then(|| {
            map([
                (
                    "every_uses",
                    self.revalidation.every_uses.map(Value::Unsigned),
                ),
                (
                    "on_reconnect",
                    self.revalidation.on_reconnect.then_some(Value::Bool(true)),
                ),
                (
                    "action_classes",
                    opt_texts(&self.revalidation.action_classes),
                ),
            ])
        });
        map([
            ("issuing_exercise", Some(self.issuing_exercise.to_value())),
            ("basis_ref", Some(Value::Bytes(self.basis_ref.clone()))),
            ("holder", Some(self.holder.to_value())),
            ("audience", Some(texts(&self.audience))),
            ("bounds", Some(self.bounds.to_value())),
            (
                "profile",
                Some(map([
                    ("class", Some(word_of(self.class, &CLASSES))),
                    ("variant", Some(word_of(self.variant, &VARIANTS))),
                    ("params", profile_params),
                ])),
            ),
            ("horizon", Some(Value::Unsigned(self.horizon))),
            (
                "max_staleness_ms",
                self.max_staleness_ms.map(Value::Unsigned),
            ),
            ("freshness_sources", opt_texts(&self.freshness_sources)),
            ("revalidation", revalidation),
            (
                "offline_slice",
                (!self.offline_slice.is_empty())
                    .then(|| set_value(self.offline_slice.iter().map(Canonical::to_value))),
            ),
            (
                "local_requirements",
                (!self.local_requirements.is_empty())
                    .then(|| set_value(self.local_requirements.iter().map(Canonical::to_value))),
            ),
            (
                "verifier_profile_ref",
                Some(self.verifier_profile_ref.to_value()),
            ),
            (
                "clock",
                Some(map([
                    ("source_class", Some(Value::text(&self.clock_source))),
                    ("skew_ms", Some(Value::Unsigned(self.clock_skew_ms))),
                ])),
            ),
            ("must_understand", opt_texts(&self.must_understand)),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let Value::Bytes(basis_ref) = f.req("basis_ref")? else {
            return Err(ModelError::Shape);
        };
        let mut p = Fields::of(f.req("profile")?)?;
        let class = word(p.req("class")?, &CLASSES)?;
        let variant = word(p.req("variant")?, &VARIANTS)?;
        if variant.class() != class {
            return Err(ModelError::Range);
        }
        let params = match p.opt("params") {
            None => alloc::collections::BTreeMap::new(),
            Some(m) => {
                let mut pf = Fields::of(m)?;
                if pf.is_empty() {
                    return Err(ModelError::Range);
                }
                pf.drain(|k, x| Ok((ident(&Value::text(k))?, uint(x)?)))?
                    .into_iter()
                    .collect()
            }
        };
        p.done()?;
        let revalidation = match f.opt("revalidation") {
            None => Revalidation::default(),
            Some(r) => {
                let mut rf = Fields::of(r)?;
                let rv = Revalidation {
                    every_uses: rf.opt("every_uses").map(uint).transpose()?,
                    on_reconnect: match rf.opt("on_reconnect") {
                        None => false,
                        Some(Value::Bool(true)) => true,
                        Some(_) => return Err(ModelError::Range),
                    },
                    action_classes: rf
                        .opt("action_classes")
                        .map(|a| set_of(a, true, ident))
                        .transpose()?
                        .unwrap_or_default(),
                };
                rf.done()?;
                if rv == Revalidation::default() {
                    return Err(ModelError::Range);
                }
                rv
            }
        };
        let mut clock = Fields::of(f.req("clock")?)?;
        let clock_source = ident(clock.req("source_class")?)?;
        let clock_skew_ms = uint(clock.req("skew_ms")?)?;
        clock.done()?;
        let vc = ValidityContract {
            issuing_exercise: Canonical::from_value(f.req("issuing_exercise")?)?,
            basis_ref: basis_ref.clone(),
            holder: Canonical::from_value(f.req("holder")?)?,
            audience: read_texts(f.opt("audience"), true)?,
            bounds: AuthoritySet::from_value(f.req("bounds")?)?,
            class,
            variant,
            params,
            horizon: uint(f.req("horizon")?)?,
            max_staleness_ms: f.opt("max_staleness_ms").map(uint).transpose()?,
            freshness_sources: read_texts(f.opt("freshness_sources"), false)?,
            revalidation,
            offline_slice: f
                .opt("offline_slice")
                .map(|s| set_of(s, true, OfflineSlice::from_value))
                .transpose()?
                .unwrap_or_default(),
            local_requirements: f
                .opt("local_requirements")
                .map(|s| set_of(s, true, RequirementTerm::from_value))
                .transpose()?
                .unwrap_or_default(),
            verifier_profile_ref: Canonical::from_value(f.req("verifier_profile_ref")?)?,
            clock_source,
            clock_skew_ms,
            must_understand: f
                .opt("must_understand")
                .map(|m| set_of(m, true, ident))
                .transpose()?
                .unwrap_or_default(),
        };
        f.done()?;
        Ok(vc)
    }
}

/// What the verifier knows at the moment of use.
#[derive(Clone, Debug)]
pub struct VerifierContext<'a> {
    /// Verifier's local time.
    pub now: TrustedTime,
    /// Verifier's audience identifier.
    pub audience: &'a str,
    /// Extensions the verifier understands.
    pub understood: &'a BTreeSet<String>,
    /// Last successful status refresh, for `bounded-staleness`.
    pub last_refresh: Option<TrustedTime>,
    /// Whether the verifier is online at the moment of use.
    pub online: bool,
}

/// Why a validity contract does not allow use now.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ValidityError {
    /// Arithmetic overflow makes the contract invalid (OP-108 m.2).
    #[error("arithmetic overflow")]
    Overflow,
    /// Past the horizon plus skew.
    #[error("expired")]
    Expired,
    /// The verifier is not in the audience.
    #[error("wrong audience")]
    Audience,
    /// An extension the verifier does not understand (PI-12).
    #[error("must-understand extension not understood")]
    MustUnderstand,
    /// `bounded-staleness` without Δ, or Δ exceeded while offline.
    #[error("too stale for offline use")]
    Stale,
    /// The profile requires an online decision.
    #[error("online decision required")]
    OnlineRequired,
}

/// Checks a contract at the moment of use (§9.12).
///
/// # Errors
/// The first rule the use breaks.
pub fn check(vc: &ValidityContract, ctx: &VerifierContext<'_>) -> Result<(), ValidityError> {
    if !vc.must_understand.is_subset(ctx.understood) {
        return Err(ValidityError::MustUnderstand);
    }
    if !vc.audience.contains(ctx.audience) {
        return Err(ValidityError::Audience);
    }
    let latest = vc
        .horizon
        .checked_add(vc.clock_skew_ms)
        .ok_or(ValidityError::Overflow)?;
    if ctx.now > latest {
        return Err(ValidityError::Expired);
    }
    if ctx.online {
        return Ok(());
    }
    match vc.variant {
        ProfileVariant::OnlineStrict | ProfileVariant::RevalidateOnReconnect => {
            Err(ValidityError::OnlineRequired)
        }
        ProfileVariant::BoundedStaleness => {
            let delta = vc.max_staleness_ms.ok_or(ValidityError::Stale)?;
            let refreshed = ctx.last_refresh.ok_or(ValidityError::Stale)?;
            let limit = refreshed
                .checked_add(delta)
                .ok_or(ValidityError::Overflow)?;
            if ctx.now > limit {
                Err(ValidityError::Stale)
            } else {
                Ok(())
            }
        }
        ProfileVariant::CheckpointedOffline | ProfileVariant::CheckpointContinuation => Ok(()),
    }
}

/// Horizon = earliest of the dependency bounds and `issued_at + profile_max` (§5.3, OP-108 m.1).
///
/// # Errors
/// Overflow (OP-108 m.2).
pub fn horizon(
    issued_at: TrustedTime,
    dependency_bounds: &[TrustedTime],
    profile_max_ms: u64,
) -> Result<TrustedTime, ValidityError> {
    let profile = issued_at
        .checked_add(profile_max_ms)
        .ok_or(ValidityError::Overflow)?;
    Ok(dependency_bounds
        .iter()
        .copied()
        .fold(profile, TrustedTime::min))
}

#[cfg(test)]
mod tests;
