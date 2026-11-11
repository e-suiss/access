//! Compatibility mappings between action schema versions (§9.13.4, OP-157 m.3 (b), (r)).
//!
//! A mapping turns a `to`-version intent into a `from`-version intent with closed-algebra
//! operations only, so coverage stays decidable (INV-8). Coverage applies only the mappings the
//! caller passes as pinned and only when they do not broaden: `mapping(intent_v2) ⊑
//! AuthoritySet_v1` (§9.13.4, E10, PI-19).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use suiss_crypto::dcbor::{self, Value};
use suiss_crypto::digest::context_digest;

use crate::algebra::Catalog;
use crate::codec::{
    Canonical, Fields, ModelError, ident, map, single, tagged, text, uint, word, word_of,
};
use crate::digest::Digest;
use crate::intent::{IntentEnvelope, ParamValue, covers};
use crate::model::{ActionRef, AuthoritySet, EqValue};

/// Digest context of a mapping (OP-157 m.3 (b)).
pub const CONTEXT: &str = "access/compat-mapping/v1";

/// Most operations one mapping may hold (L0-ENC-13).
pub const MAX_OPS: usize = 64;

/// Most values one enum operation may map.
pub const MAX_ENUM_VALUES: usize = 256;

/// The relation a publisher declares (§7.9.3.2, §9.13.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Relation {
    /// Same meaning, other representation.
    RepresentationEquivalent,
    /// The new version allows less.
    Narrowing,
    /// The new version allows more; never applied.
    Broadening,
    /// No mapping; never applied.
    Incompatible,
}

const RELATIONS: [(&str, Relation); 4] = [
    (
        "representation-equivalent",
        Relation::RepresentationEquivalent,
    ),
    ("narrowing", Relation::Narrowing),
    ("broadening", Relation::Broadening),
    ("incompatible", Relation::Incompatible),
];

impl Relation {
    /// Whether a pinned mapping of this relation may ever be applied (E10).
    #[must_use]
    pub const fn non_broadening(self) -> bool {
        matches!(self, Self::RepresentationEquivalent | Self::Narrowing)
    }
}

/// One closed-algebra operation on an intent's parameters (§9.13.4).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MappingOp {
    /// The `to` field `from` becomes the `from`-version field `to`.
    Rename {
        /// Field in the new version.
        from: String,
        /// Field in the old version.
        to: String,
    },
    /// Enum values of a field are mapped one to one.
    Enum {
        /// Field.
        field: String,
        /// New value to old value.
        values: BTreeMap<String, String>,
    },
    /// A field takes a fixed value.
    Constant {
        /// Field.
        field: String,
        /// Value.
        value: EqValue,
    },
    /// An integer field is multiplied by an exact unit factor.
    Scale {
        /// Field.
        field: String,
        /// Factor, at least 2.
        factor: u64,
    },
    /// An authority-opaque field is dropped.
    Drop {
        /// Field.
        field: String,
    },
}

impl Canonical for MappingOp {
    fn to_value(&self) -> Value {
        match self {
            Self::Rename { from, to } => tagged(
                "rename",
                map([
                    ("from", Some(Value::text(from))),
                    ("to", Some(Value::text(to))),
                ]),
            ),
            Self::Enum { field, values } => tagged(
                "enum",
                map([
                    ("field", Some(Value::text(field))),
                    (
                        "values",
                        Some(Value::Map(
                            values
                                .iter()
                                .map(|(k, v)| (Value::text(k), Value::text(v)))
                                .collect(),
                        )),
                    ),
                ]),
            ),
            Self::Constant { field, value } => tagged(
                "constant",
                map([
                    ("field", Some(Value::text(field))),
                    ("value", Some(value.to_value())),
                ]),
            ),
            Self::Scale { field, factor } => tagged(
                "scale",
                map([
                    ("factor", Some(Value::Unsigned(*factor))),
                    ("field", Some(Value::text(field))),
                ]),
            ),
            Self::Drop { field } => tagged("drop", map([("field", Some(Value::text(field)))])),
        }
    }

    fn from_value(value: &Value) -> Result<Self, ModelError> {
        let (kind, inner) = single(value)?;
        let mut f = Fields::of(inner)?;
        let op = match kind {
            "rename" => {
                let from = ident(f.req("from")?)?;
                let to = ident(f.req("to")?)?;
                if from == to {
                    return Err(ModelError::Range);
                }
                Self::Rename { from, to }
            }
            "enum" => {
                let field = ident(f.req("field")?)?;
                let Value::Map(entries) = f.req("values")? else {
                    return Err(ModelError::Shape);
                };
                if entries.is_empty() || entries.len() > MAX_ENUM_VALUES {
                    return Err(ModelError::Range);
                }
                let mut values = BTreeMap::new();
                for (a, b) in entries {
                    if values.insert(enum_value(a)?, enum_value(b)?).is_some() {
                        return Err(ModelError::SetOrder);
                    }
                }
                Self::Enum { field, values }
            }
            "constant" => Self::Constant {
                field: ident(f.req("field")?)?,
                value: EqValue::from_value(f.req("value")?)?,
            },
            "scale" => {
                let factor = uint(f.req("factor")?)?;
                if factor < 2 {
                    return Err(ModelError::Range);
                }
                Self::Scale {
                    field: ident(f.req("field")?)?,
                    factor,
                }
            }
            "drop" => Self::Drop {
                field: ident(f.req("field")?)?,
            },
            _ => return Err(ModelError::Unknown),
        };
        f.done()?;
        Ok(op)
    }
}

fn enum_value(v: &Value) -> Result<String, ModelError> {
    let t = text(v)?;
    if t.is_empty() || t.len() > 255 {
        return Err(ModelError::Range);
    }
    Ok(String::from(t))
}

/// A publisher's mapping from the `to` action version back to the `from` one (§9.13.4).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Mapping {
    /// The old action version.
    pub from: ActionRef,
    /// The new action version.
    pub to: ActionRef,
    /// The declared relation.
    pub relation: Relation,
    /// Operations in application order.
    pub ops: Vec<MappingOp>,
}

impl Canonical for Mapping {
    fn to_value(&self) -> Value {
        map([
            ("from", Some(self.from.to_value())),
            (
                "ops",
                Some(Value::Array(
                    self.ops.iter().map(Canonical::to_value).collect(),
                )),
            ),
            ("relation", Some(word_of(self.relation, &RELATIONS))),
            ("to", Some(self.to.to_value())),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let from = ActionRef::from_value(f.req("from")?)?;
        let to = ActionRef::from_value(f.req("to")?)?;
        if from.namespace != to.namespace || from.name != to.name || from == to {
            return Err(ModelError::Range);
        }
        let Value::Array(items) = f.req("ops")? else {
            return Err(ModelError::Shape);
        };
        if items.len() > MAX_OPS {
            return Err(ModelError::Range);
        }
        let ops = items
            .iter()
            .map(MappingOp::from_value)
            .collect::<Result<Vec<_>, _>>()?;
        let relation = word(f.req("relation")?, &RELATIONS)?;
        f.done()?;
        Ok(Self {
            from,
            to,
            relation,
            ops,
        })
    }
}

/// `SHA-256("access/compat-mapping/v1" ‖ 0x00 ‖ dCBOR(mapping))`, the identity a domain pins
/// (OP-157 m.3 (b), (r)).
///
/// # Errors
/// The mapping is outside the structural limits.
pub fn mapping_digest(m: &Mapping) -> Result<Digest, dcbor::EncodeError> {
    Ok(context_digest(CONTEXT, &m.to_bytes()?))
}

/// The `from`-version intent `m` maps `intent` to; `None` when `m` is not for its action, would
/// broaden, or an operation does not apply: a renamed field whose new name is taken, an enum
/// value it does not list, a scaled value of another type or out of range, a dropped field that
/// is not authority-opaque (§9.13.4, OP-157 m.3 (b)).
#[must_use]
pub fn apply(m: &Mapping, intent: &IntentEnvelope) -> Option<IntentEnvelope> {
    if m.to != intent.action || !m.relation.non_broadening() {
        return None;
    }
    let mut out = intent.clone();
    out.action = m.from.clone();
    for op in &m.ops {
        match op {
            MappingOp::Rename { from, to } => {
                if let Some(v) = out.params.remove(from) {
                    if out.params.insert(to.clone(), v).is_some() {
                        return None;
                    }
                    if let Some(p) = out.provenance.remove(from) {
                        out.provenance.insert(to.clone(), p);
                    }
                }
            }
            MappingOp::Enum { field, values } => match out.params.get_mut(field) {
                None => {}
                Some(ParamValue::Enum(v)) => *v = values.get(v)?.clone(),
                Some(_) => return None,
            },
            MappingOp::Constant { field, value } => {
                out.params
                    .insert(field.clone(), ParamValue::Eq(value.clone()));
                out.provenance.remove(field);
            }
            MappingOp::Scale { field, factor } => match out.params.get_mut(field) {
                None => {}
                Some(ParamValue::Amount { value, .. }) => {
                    *value = value.checked_mul(i64::try_from(*factor).ok()?)?;
                }
                Some(ParamValue::Count(n)) => *n = n.checked_mul(*factor)?,
                Some(_) => return None,
            },
            MappingOp::Drop { field } => {
                if out.params.contains_key(field) {
                    return None;
                }
                out.opaque.remove(field);
            }
        }
    }
    Some(out)
}

/// Whether `set` covers `intent` directly or through one of the pinned `mappings`
/// (§9.13.4, OP-157 m.3 (b)): an unpinned or broadening mapping changes no coverage.
#[must_use]
pub fn covers_mapped(
    set: &AuthoritySet,
    intent: &IntentEnvelope,
    cat: &Catalog,
    mappings: &[Mapping],
) -> bool {
    covers(set, intent, cat)
        || mappings
            .iter()
            .filter_map(|m| apply(m, intent))
            .any(|mapped| covers(set, &mapped, cat))
}

#[cfg(test)]
mod tests;
