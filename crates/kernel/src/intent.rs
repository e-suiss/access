//! Intent envelope, its Access-computed digest and coverage by an authority set (§9.5, OP-108 m.12, m.13).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use suiss_crypto::dcbor::{EncodeError, Value};

use crate::algebra::{Catalog, resource_le, subject_le};
use crate::codec::{
    Canonical, Fields, ModelError, boolean, int, map, map_value, opt_param_map, text, uint, unit,
};
use crate::digest::{Context, Digest, digest};
use crate::model::{
    ActionRef, AuthoritySet, Bound, EqValue, Id, PurposeRef, ResourceRef, ResourceSelector,
    SubjectSelector, Window,
};

/// A typed parameter value (OP-109 m.7).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ParamValue {
    /// Member of an enum.
    Enum(String),
    /// Value compared by equality.
    Eq(EqValue),
    /// Amount with unit.
    Amount {
        /// Value in the unit's smallest step.
        value: i64,
        /// Unit.
        unit: String,
    },
    /// Count.
    Count(u64),
    /// Time interval.
    Interval(Window),
    /// Resource.
    Resource(ResourceRef),
    /// Party.
    Subject(Id),
    /// Purpose.
    Purpose(PurposeRef),
    /// Flag.
    Flag(bool),
}

/// Opaque context references (OP-108 m.13).
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContextRefs {
    /// `WorkRef`.
    pub work: Option<Digest>,
    /// `CommitmentRef`.
    pub commitment: Option<Digest>,
    /// `StepRef`.
    pub step: Option<Digest>,
    /// Upstream `ExerciseID`.
    pub upstream_exercise: Option<Digest>,
}

/// Intent envelope; the nonce is outside it (OP-108 m.12).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IntentEnvelope {
    /// Action.
    pub action: ActionRef,
    /// Resources, primary first; never empty.
    pub resources: Vec<ResourceRef>,
    /// Authority-relevant typed parameters.
    pub params: BTreeMap<String, ParamValue>,
    /// Digests of authority-opaque parameters.
    pub opaque: BTreeMap<String, Digest>,
    /// Recipient.
    pub recipient: Option<Id>,
    /// Purpose.
    pub purpose: Option<PurposeRef>,
    /// Context references.
    pub context: ContextRefs,
    /// Validity window.
    pub validity: Window,
}

fn tagged(key: &'static str, v: Value) -> Value {
    map([(key, Some(v))])
}

impl Canonical for ParamValue {
    fn to_value(&self) -> Value {
        match self {
            Self::Enum(s) => tagged("enum", Value::text(s)),
            Self::Eq(e) => tagged("eq", e.to_value()),
            Self::Amount { value, unit } => tagged(
                "amount",
                map([
                    ("value", Some(Value::int(*value))),
                    ("unit", Some(Value::text(unit))),
                ]),
            ),
            Self::Count(n) => tagged("count", Value::Unsigned(*n)),
            Self::Interval(w) => tagged("interval", w.to_value()),
            Self::Resource(r) => tagged("resource", r.to_value()),
            Self::Subject(id) => tagged("subject", id.to_value()),
            Self::Purpose(p) => tagged("purpose", p.to_value()),
            Self::Flag(b) => tagged("flag", Value::Bool(*b)),
        }
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let Value::Map(entries) = v else {
            return Err(ModelError::Shape);
        };
        let [(Value::Text(k), inner)] = entries.as_slice() else {
            return Err(ModelError::Shape);
        };
        Ok(match k.as_str() {
            "enum" => Self::Enum(String::from(text(inner)?)),
            "eq" => Self::Eq(EqValue::from_value(inner)?),
            "amount" => {
                let mut f = Fields::of(inner)?;
                let a = Self::Amount {
                    value: int(f.req("value")?)?,
                    unit: unit(f.req("unit")?)?,
                };
                f.done()?;
                a
            }
            "count" => Self::Count(uint(inner)?),
            "interval" => Self::Interval(Window::from_value(inner)?),
            "resource" => Self::Resource(ResourceRef::from_value(inner)?),
            "subject" => Self::Subject(Id::from_value(inner)?),
            "purpose" => Self::Purpose(PurposeRef::from_value(inner)?),
            "flag" => Self::Flag(boolean(inner)?),
            _ => return Err(ModelError::Unknown),
        })
    }
}

impl Canonical for ContextRefs {
    fn to_value(&self) -> Value {
        map([
            ("work", self.work.as_ref().map(Digest::to_value)),
            ("commitment", self.commitment.as_ref().map(Digest::to_value)),
            ("step", self.step.as_ref().map(Digest::to_value)),
            (
                "upstream_exercise",
                self.upstream_exercise.as_ref().map(Digest::to_value),
            ),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let read = |x: Option<&Value>| x.map(<Digest as Canonical>::from_value).transpose();
        let c = ContextRefs {
            work: read(f.opt("work"))?,
            commitment: read(f.opt("commitment"))?,
            step: read(f.opt("step"))?,
            upstream_exercise: read(f.opt("upstream_exercise"))?,
        };
        f.done()?;
        if c == ContextRefs::default() {
            return Err(ModelError::Range);
        }
        Ok(c)
    }
}

impl Canonical for IntentEnvelope {
    fn to_value(&self) -> Value {
        map([
            ("action", Some(self.action.to_value())),
            (
                "resources",
                Some(Value::Array(
                    self.resources.iter().map(Canonical::to_value).collect(),
                )),
            ),
            ("params", map_value(&self.params, Canonical::to_value)),
            ("opaque", map_value(&self.opaque, Digest::to_value)),
            (
                "recipient",
                self.recipient.as_ref().map(Canonical::to_value),
            ),
            ("purpose", self.purpose.as_ref().map(Canonical::to_value)),
            (
                "context",
                (self.context != ContextRefs::default()).then(|| self.context.to_value()),
            ),
            ("validity", Some(self.validity.to_value())),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let Value::Array(resources) = f.req("resources")? else {
            return Err(ModelError::Shape);
        };
        if resources.is_empty() {
            return Err(ModelError::Range);
        }
        let e = IntentEnvelope {
            action: ActionRef::from_value(f.req("action")?)?,
            resources: resources
                .iter()
                .map(ResourceRef::from_value)
                .collect::<Result<_, _>>()?,
            params: opt_param_map(f.opt("params"), ParamValue::from_value)?,
            opaque: opt_param_map(f.opt("opaque"), <Digest as Canonical>::from_value)?,
            recipient: f.opt("recipient").map(Id::from_value).transpose()?,
            purpose: f.opt("purpose").map(PurposeRef::from_value).transpose()?,
            context: f
                .opt("context")
                .map(ContextRefs::from_value)
                .transpose()?
                .unwrap_or_default(),
            validity: Window::from_value(f.req("validity")?)?,
        };
        f.done()?;
        Ok(e)
    }
}

/// The intent digest; Access computes it, the caller never chooses it (§9.5, OP-106 m.22).
///
/// # Errors
/// The envelope is outside the structural limits.
pub fn intent_digest(envelope: &IntentEnvelope) -> Result<Digest, EncodeError> {
    Ok(digest(Context::Intent, &envelope.to_bytes()?))
}

/// Whether a parameter value satisfies a bound; a type mismatch is not covered (OP-109 m.7).
#[must_use]
pub fn satisfies(value: &ParamValue, bound: &Bound, cat: &Catalog) -> bool {
    match (value, bound) {
        (ParamValue::Enum(v), Bound::Enum(set)) => set.contains(v),
        (ParamValue::Eq(v), Bound::Eq(b)) => v == b,
        (ParamValue::Amount { value, unit }, Bound::Range { min, max, unit: bu }) => {
            unit == bu && min.is_none_or(|m| m <= *value) && max.is_none_or(|m| *value <= m)
        }
        (ParamValue::Count(n), Bound::CountMax(m)) => n <= m,
        (ParamValue::Interval(w), Bound::Interval(b)) => b.from <= w.from && w.until <= b.until,
        (ParamValue::Resource(r), Bound::Resource(sel)) => {
            resource_le(&ResourceSelector::Exact(r.clone()), sel)
        }
        (ParamValue::Subject(id), Bound::Subject(sel)) => {
            subject_le(&SubjectSelector::Party(*id), sel)
        }
        (ParamValue::Purpose(p), Bound::Purpose(set)) => set.iter().any(|q| cat.purpose_le(p, q)),
        (ParamValue::Flag(v), Bound::Flag(b)) => v == b,
        _ => false,
    }
}

/// Whether an authority set covers an intent. Intensional and foreign selectors need claims and
/// are not decided here: they do not cover.
#[must_use]
pub fn covers(set: &AuthoritySet, intent: &IntentEnvelope, cat: &Catalog) -> bool {
    let party_covered =
        |id: &Id, sel: &SubjectSelector| subject_le(&SubjectSelector::Party(*id), sel);
    cat.covered(&set.actions).contains(&intent.action)
        && intent
            .resources
            .iter()
            .all(|r| resource_le(&ResourceSelector::Exact(r.clone()), &set.resource))
        && set
            .params
            .iter()
            .all(|(k, b)| intent.params.get(k).is_some_and(|v| satisfies(v, b, cat)))
        && set.recipient.as_ref().is_none_or(|sel| {
            intent
                .recipient
                .as_ref()
                .is_some_and(|id| party_covered(id, sel))
        })
        && set.purpose.as_ref().is_none_or(|ps| {
            intent
                .purpose
                .as_ref()
                .is_some_and(|p| ps.iter().any(|q| cat.purpose_le(p, q)))
        })
}

#[cfg(test)]
mod tests;
