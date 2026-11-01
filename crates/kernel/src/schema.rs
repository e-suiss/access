//! Schema Publication Packages and Action Schemas (§9.13, P23, OP-141 m.35): what an action of a
//! domain or third-party namespace means, pinned by digest.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::context_digest;

use crate::codec::{Canonical, Fields, ModelError, ident, map, set_of, text, uint};
use crate::digest::Digest;
use crate::model::{ActionRef, Id};

/// What an action does to the world (§9.13.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EffectClass {
    /// No effect.
    None,
    /// An effect that can be undone.
    Reversible,
    /// An effect that cannot be undone.
    Irreversible,
}

const EFFECTS: [(&str, EffectClass); 3] = [
    ("none", EffectClass::None),
    ("reversible", EffectClass::Reversible),
    ("irreversible", EffectClass::Irreversible),
];

const PARAM_TYPES: [&str; 7] = ["amount", "int", "text", "bool", "bytes", "id", "opaque"];

/// One Action Schema (OP-141 m.35 (b)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionSchema {
    /// Name.
    pub name: String,
    /// Major version.
    pub major: u64,
    /// Effect class.
    pub effect: EffectClass,
    /// Reserved: only an express Grant covers it.
    pub reserved: bool,
    /// Whether it consumes budget.
    pub consumption_bearing: bool,
    /// Typed parameters.
    pub params: BTreeMap<String, String>,
    /// Resource types.
    pub resource_types: BTreeSet<String>,
    /// Render template.
    pub render: Option<String>,
}

impl Canonical for ActionSchema {
    fn to_value(&self) -> Value {
        map([
            ("name", Some(Value::text(&self.name))),
            ("major", Some(Value::Unsigned(self.major))),
            (
                "effect_class",
                EFFECTS
                    .iter()
                    .find(|(_, e)| *e == self.effect)
                    .map(|(w, _)| Value::text(w)),
            ),
            ("reserved", self.reserved.then_some(Value::Bool(true))),
            (
                "consumption_bearing",
                self.consumption_bearing.then_some(Value::Bool(true)),
            ),
            (
                "params",
                (!self.params.is_empty()).then(|| {
                    Value::Map(
                        self.params
                            .iter()
                            .map(|(k, t)| (Value::text(k), Value::text(t)))
                            .collect(),
                    )
                }),
            ),
            (
                "resource_types",
                (!self.resource_types.is_empty()).then(|| {
                    Value::Array(self.resource_types.iter().map(|t| Value::text(t)).collect())
                }),
            ),
            ("render", self.render.as_deref().map(Value::text)),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let effect = text(f.req("effect_class")?)?;
        let effect = EFFECTS
            .iter()
            .find(|(w, _)| *w == effect)
            .map(|(_, e)| *e)
            .ok_or(ModelError::Unknown)?;
        let flag = |v: Option<&Value>| match v {
            None => Ok(false),
            Some(Value::Bool(true)) => Ok(true),
            Some(_) => Err(ModelError::Shape),
        };
        let mut params = BTreeMap::new();
        if let Some(p) = f.opt("params") {
            let Value::Map(entries) = p else {
                return Err(ModelError::Shape);
            };
            if entries.is_empty() {
                return Err(ModelError::Shape);
            }
            for (k, t) in entries {
                let t = text(t)?;
                if !PARAM_TYPES.contains(&t) {
                    return Err(ModelError::Unknown);
                }
                params.insert(ident(k)?, String::from(t));
            }
        }
        let s = Self {
            name: ident(f.req("name")?)?,
            major: uint(f.req("major")?)?,
            effect,
            reserved: flag(f.opt("reserved"))?,
            consumption_bearing: flag(f.opt("consumption_bearing"))?,
            params,
            resource_types: f
                .opt("resource_types")
                .map(|r| set_of(r, true, ident))
                .transpose()?
                .unwrap_or_default(),
            render: f
                .opt("render")
                .map(|r| text(r).map(String::from))
                .transpose()?,
        };
        f.done()?;
        Ok(s)
    }
}

/// `SHA-256("access/action-schema/v1" ‖ 0x00 ‖ dCBOR(action-schema))` (OP-141 m.35 (b)).
#[must_use]
pub fn action_digest(schema: &ActionSchema) -> Digest {
    let bytes = dcbor::encode(&schema.to_value(), Limits::CEILING).unwrap_or_default();
    Digest(context_digest("access/action-schema/v1", &bytes).0)
}

/// A Schema Publication Package (OP-141 m.35 (a)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spp {
    /// Publisher Party.
    pub publisher: Id,
    /// Namespace.
    pub namespace: String,
    /// Catalog version.
    pub catalog_version: u64,
    /// Action Schemas.
    pub actions: Vec<ActionSchema>,
    /// Retired actions.
    pub retirements: BTreeSet<ActionRef>,
    /// Lowest core spec version it needs.
    pub core_spec_min: Option<u64>,
}

impl Canonical for Spp {
    fn to_value(&self) -> Value {
        map([
            ("publisher", Some(self.publisher.to_value())),
            ("namespace", Some(Value::text(&self.namespace))),
            (
                "catalog_version",
                Some(Value::Unsigned(self.catalog_version)),
            ),
            (
                "actions",
                Some(Value::Array(
                    self.actions.iter().map(Canonical::to_value).collect(),
                )),
            ),
            (
                "retirements",
                (!self.retirements.is_empty()).then(|| {
                    Value::Array(self.retirements.iter().map(Canonical::to_value).collect())
                }),
            ),
            ("core_spec_min", self.core_spec_min.map(Value::Unsigned)),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let Value::Array(items) = f.req("actions")? else {
            return Err(ModelError::Shape);
        };
        if items.is_empty() {
            return Err(ModelError::Shape);
        }
        let actions = items
            .iter()
            .map(ActionSchema::from_value)
            .collect::<Result<Vec<_>, _>>()?;
        let mut seen = BTreeSet::new();
        if !actions
            .iter()
            .all(|a| seen.insert((a.name.clone(), a.major)))
        {
            return Err(ModelError::Shape);
        }
        let s = Self {
            publisher: Id::from_value(f.req("publisher")?)?,
            namespace: crate::codec::namespace(f.req("namespace")?)?,
            catalog_version: uint(f.req("catalog_version")?)?,
            actions,
            retirements: f
                .opt("retirements")
                .map(|r| set_of(r, true, ActionRef::from_value))
                .transpose()?
                .unwrap_or_default(),
            core_spec_min: f.opt("core_spec_min").map(uint).transpose()?,
        };
        f.done()?;
        Ok(s)
    }
}

impl Spp {
    /// The `ActionRef` of each action it publishes, with its schema.
    #[must_use]
    pub fn refs(&self) -> Vec<(ActionRef, &ActionSchema)> {
        self.actions
            .iter()
            .map(|a| {
                (
                    ActionRef {
                        namespace: self.namespace.clone(),
                        name: a.name.clone(),
                        major: a.major,
                        schema: action_digest(a),
                    },
                    a,
                )
            })
            .collect()
    }

    /// `SHA-256("access/catalog/v1" ‖ 0x00 ‖ dCBOR([namespace, catalog_version, refs]))`, refs
    /// sorted by their bytes (OP-141 m.35 (c)).
    #[must_use]
    pub fn catalog_digest(&self) -> Digest {
        let mut refs: Vec<Vec<u8>> = self
            .refs()
            .iter()
            .filter_map(|(r, _)| dcbor::encode(&r.to_value(), Limits::CEILING).ok())
            .collect();
        refs.sort();
        let list: Vec<Value> = refs
            .iter()
            .filter_map(|b| dcbor::decode(b, Limits::CEILING).ok())
            .collect();
        let bytes = dcbor::encode(
            &Value::Array(alloc::vec![
                Value::text(&self.namespace),
                Value::Unsigned(self.catalog_version),
                Value::Array(list),
            ]),
            Limits::CEILING,
        )
        .unwrap_or_default();
        Digest(context_digest("access/catalog/v1", &bytes).0)
    }
}

/// `dCBOR(["schemas", namespace])`: the `schema-definition` Acceptances of a namespace
/// (OP-141 m.35 (d)).
#[must_use]
pub fn schemas_key(namespace: &str) -> Vec<u8> {
    dcbor::encode(
        &Value::Array(alloc::vec![Value::text("schemas"), Value::text(namespace)]),
        Limits::CEILING,
    )
    .unwrap_or_default()
}

#[cfg(test)]
pub(crate) mod tests;
