//! Canonical CBOR form of the data model (`conformance/cddl/kernel.cddl`, OP-106).
//!
//! Decoding is strict: unknown fields, unsorted or repeated set elements and values outside
//! the CDDL are rejected (OP-108 m.4). Arrays that are sets are sorted by the bytes of their
//! canonical encoding.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use suiss_crypto::dcbor::{self, Limits, Value};

use crate::digest::Digest;
use crate::model::{
    ActionRef, ActionSet, AuthoritySet, Binding, Bound, BudgetDimension, BudgetTerm, BudgetWindow,
    CanonicalAuthority, Conjunct, ConstraintSet, Consumption, DelegationTerms, EqValue, Id,
    Independence, ProofKind, PurposeRef, RequirementTerm, ResourceRef, ResourceSelector,
    Structural, SubjectSelector, WhileCondition, Window,
};

/// Why a CBOR value is not a value of the model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ModelError {
    /// Not canonical CBOR.
    #[error("not canonical CBOR: {0}")]
    Cbor(#[from] dcbor::DecodeError),
    /// Wrong CBOR type or shape.
    #[error("wrong shape")]
    Shape,
    /// A required field is missing.
    #[error("missing field")]
    Missing,
    /// A field the model does not define (OP-108 m.4).
    #[error("unknown field")]
    Unknown,
    /// Set elements are unsorted or repeated.
    #[error("set not canonical")]
    SetOrder,
    /// A value outside its CDDL range.
    #[error("value out of range")]
    Range,
}

/// A model type with a canonical CBOR form.
pub trait Canonical: Sized {
    /// The CBOR value.
    fn to_value(&self) -> Value;

    /// Reads a CBOR value.
    ///
    /// # Errors
    /// The value is not a value of this type.
    fn from_value(v: &Value) -> Result<Self, ModelError>;

    /// Canonical bytes.
    ///
    /// # Errors
    /// The value is outside the structural limits.
    fn to_bytes(&self) -> Result<Vec<u8>, dcbor::EncodeError> {
        dcbor::encode(&self.to_value(), Limits::CEILING)
    }

    /// Reads canonical bytes.
    ///
    /// # Errors
    /// Non-canonical bytes or a value outside the model.
    fn from_bytes(bytes: &[u8]) -> Result<Self, ModelError> {
        Self::from_value(&dcbor::decode(bytes, Limits::CEILING)?)
    }
}

pub(crate) struct Fields<'a> {
    entries: Vec<(&'a str, &'a Value, bool)>,
}

impl<'a> Fields<'a> {
    pub(crate) fn of(v: &'a Value) -> Result<Self, ModelError> {
        let Value::Map(entries) = v else {
            return Err(ModelError::Shape);
        };
        let mut out = Vec::with_capacity(entries.len());
        for (k, val) in entries {
            let Value::Text(k) = k else {
                return Err(ModelError::Shape);
            };
            out.push((k.as_str(), val, false));
        }
        Ok(Self { entries: out })
    }

    pub(crate) fn opt(&mut self, key: &str) -> Option<&'a Value> {
        self.entries
            .iter_mut()
            .find(|(k, _, _)| *k == key)
            .map(|e| {
                e.2 = true;
                e.1
            })
    }

    pub(crate) fn req(&mut self, key: &str) -> Result<&'a Value, ModelError> {
        self.opt(key).ok_or(ModelError::Missing)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn drain<T>(
        &mut self,
        read: impl Fn(&str, &Value) -> Result<T, ModelError>,
    ) -> Result<Vec<T>, ModelError> {
        self.entries
            .iter_mut()
            .map(|(k, v, used)| {
                *used = true;
                read(k, v)
            })
            .collect()
    }

    pub(crate) fn done(self) -> Result<(), ModelError> {
        if self.entries.iter().all(|e| e.2) {
            Ok(())
        } else {
            Err(ModelError::Unknown)
        }
    }
}

pub(crate) fn map(entries: impl IntoIterator<Item = (&'static str, Option<Value>)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .filter_map(|(k, v)| v.map(|v| (Value::text(k), v)))
            .collect(),
    )
}

fn single(v: &Value) -> Result<(&str, &Value), ModelError> {
    match v {
        Value::Map(entries) => match entries.as_slice() {
            [(Value::Text(k), inner)] => Ok((k.as_str(), inner)),
            _ => Err(ModelError::Shape),
        },
        _ => Err(ModelError::Shape),
    }
}

fn tagged(key: &'static str, v: Value) -> Value {
    map([(key, Some(v))])
}

pub(crate) fn set_value(items: impl IntoIterator<Item = Value>) -> Value {
    let mut encoded: Vec<(Vec<u8>, Value)> = items
        .into_iter()
        .map(|v| (dcbor::encode(&v, Limits::CEILING).unwrap_or_default(), v))
        .collect();
    encoded.sort_by(|a, b| a.0.cmp(&b.0));
    encoded.dedup_by(|a, b| a.0 == b.0);
    Value::Array(encoded.into_iter().map(|(_, v)| v).collect())
}

pub(crate) fn set_items(v: &Value, non_empty: bool) -> Result<&[Value], ModelError> {
    let Value::Array(items) = v else {
        return Err(ModelError::Shape);
    };
    if non_empty && items.is_empty() {
        return Err(ModelError::Range);
    }
    let mut previous: Option<Vec<u8>> = None;
    for item in items {
        let bytes = dcbor::encode(item, Limits::CEILING).map_err(|_| ModelError::Range)?;
        if previous.as_ref().is_some_and(|p| *p >= bytes) {
            return Err(ModelError::SetOrder);
        }
        previous = Some(bytes);
    }
    Ok(items)
}

pub(crate) fn set_of<T: Ord>(
    v: &Value,
    non_empty: bool,
    f: impl Fn(&Value) -> Result<T, ModelError>,
) -> Result<BTreeSet<T>, ModelError> {
    set_items(v, non_empty)?.iter().map(f).collect()
}

pub(crate) fn uint(v: &Value) -> Result<u64, ModelError> {
    match v {
        Value::Unsigned(u) => Ok(*u),
        _ => Err(ModelError::Shape),
    }
}

pub(crate) fn int(v: &Value) -> Result<i64, ModelError> {
    match v {
        Value::Unsigned(_) | Value::Negative(_) => v.as_i64().ok_or(ModelError::Range),
        _ => Err(ModelError::Shape),
    }
}

pub(crate) fn text(v: &Value) -> Result<&str, ModelError> {
    match v {
        Value::Text(t) => Ok(t),
        _ => Err(ModelError::Shape),
    }
}

pub(crate) fn boolean(v: &Value) -> Result<bool, ModelError> {
    match v {
        Value::Bool(b) => Ok(*b),
        _ => Err(ModelError::Shape),
    }
}

fn lower_start(s: &str) -> bool {
    s.chars().next().is_some_and(|c| c.is_ascii_lowercase())
}

fn ident_with(s: &str, max: usize, extra: &[char]) -> bool {
    lower_start(s)
        && s.len() <= max
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || extra.contains(&c))
}

pub(crate) fn ident(v: &Value) -> Result<String, ModelError> {
    let s = text(v)?;
    if ident_with(s, 63, &[]) {
        Ok(String::from(s))
    } else {
        Err(ModelError::Range)
    }
}

fn namespace(v: &Value) -> Result<String, ModelError> {
    let s = text(v)?;
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() <= 8 && parts.iter().all(|p| ident_with(p, 63, &['-'])) {
        Ok(String::from(s))
    } else {
        Err(ModelError::Range)
    }
}

pub(crate) fn unit(v: &Value) -> Result<String, ModelError> {
    let s = text(v)?;
    if ident_with(s, 16, &[]) {
        Ok(String::from(s))
    } else {
        Err(ModelError::Range)
    }
}

fn segments(v: &Value, non_empty: bool) -> Result<Vec<String>, ModelError> {
    let Value::Array(items) = v else {
        return Err(ModelError::Shape);
    };
    if non_empty && items.is_empty() {
        return Err(ModelError::Range);
    }
    items
        .iter()
        .map(|i| {
            let s = text(i)?;
            if (1..=128).contains(&s.len()) {
                Ok(String::from(s))
            } else {
                Err(ModelError::Range)
            }
        })
        .collect()
}

fn text_values(items: &[String]) -> Value {
    Value::Array(items.iter().map(|s| Value::text(s)).collect())
}

impl Canonical for Digest {
    fn to_value(&self) -> Value {
        Digest::to_value(self)
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        Digest::from_value(v).ok_or(ModelError::Shape)
    }
}

impl Canonical for Id {
    fn to_value(&self) -> Value {
        Value::Bytes(self.0.to_vec())
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        match v {
            Value::Bytes(b) => <[u8; 16]>::try_from(b.as_slice())
                .map(Id)
                .map_err(|_| ModelError::Range),
            _ => Err(ModelError::Shape),
        }
    }
}

impl Canonical for Window {
    fn to_value(&self) -> Value {
        Value::Array(alloc::vec![
            Value::Unsigned(self.from),
            Value::Unsigned(self.until)
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        match v {
            Value::Array(items) => match items.as_slice() {
                [a, b] => {
                    let w = Window {
                        from: uint(a)?,
                        until: uint(b)?,
                    };
                    if w.from <= w.until {
                        Ok(w)
                    } else {
                        Err(ModelError::Range)
                    }
                }
                _ => Err(ModelError::Shape),
            },
            _ => Err(ModelError::Shape),
        }
    }
}

impl Canonical for ActionRef {
    fn to_value(&self) -> Value {
        map([
            ("namespace", Some(Value::text(&self.namespace))),
            ("name", Some(Value::text(&self.name))),
            ("major", Some(Value::Unsigned(self.major))),
            ("schema", Some(self.schema.to_value())),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let a = ActionRef {
            namespace: namespace(f.req("namespace")?)?,
            name: ident(f.req("name")?)?,
            major: uint(f.req("major")?)?,
            schema: Canonical::from_value(f.req("schema")?)?,
        };
        f.done()?;
        Ok(a)
    }
}

impl Canonical for ResourceRef {
    fn to_value(&self) -> Value {
        map([
            ("namespace", Some(Value::text(&self.namespace))),
            ("path", Some(text_values(&self.path))),
            ("incarnation", Some(Value::Unsigned(self.incarnation))),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let r = ResourceRef {
            namespace: namespace(f.req("namespace")?)?,
            path: segments(f.req("path")?, true)?,
            incarnation: uint(f.req("incarnation")?)?,
        };
        f.done()?;
        Ok(r)
    }
}

impl Canonical for PurposeRef {
    fn to_value(&self) -> Value {
        match self {
            Self::Code(c) => tagged("code", Value::text(c)),
            Self::Work(d) => tagged("work", d.to_value()),
            Self::Aim(d) => tagged("aim", d.to_value()),
        }
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        match single(v)? {
            ("code", c) => Ok(Self::Code(ident(c)?)),
            ("work", d) => Ok(Self::Work(Canonical::from_value(d)?)),
            ("aim", d) => Ok(Self::Aim(Canonical::from_value(d)?)),
            _ => Err(ModelError::Unknown),
        }
    }
}

impl Canonical for EqValue {
    fn to_value(&self) -> Value {
        match self {
            Self::Text(t) => Value::text(t),
            Self::Bytes(b) => Value::Bytes(b.clone()),
            Self::Int(i) => Value::int(*i),
            Self::Bool(b) => Value::Bool(*b),
        }
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        match v {
            Value::Text(t) => Ok(Self::Text(t.clone())),
            Value::Bytes(b) => Ok(Self::Bytes(b.clone())),
            Value::Unsigned(_) | Value::Negative(_) => Ok(Self::Int(int(v)?)),
            Value::Bool(b) => Ok(Self::Bool(*b)),
            _ => Err(ModelError::Shape),
        }
    }
}

impl Canonical for ResourceSelector {
    fn to_value(&self) -> Value {
        match self {
            Self::Exact(r) => tagged("exact", r.to_value()),
            Self::Structural(s) => map([
                ("namespace", Some(Value::text(&s.namespace))),
                (
                    "prefix",
                    (!s.prefix.is_empty()).then(|| text_values(&s.prefix)),
                ),
                ("type", s.kind.as_deref().map(Value::text)),
                (
                    "where",
                    (!s.attrs.is_empty()).then(|| {
                        Value::Map(
                            s.attrs
                                .iter()
                                .map(|(k, v)| (Value::text(k), v.to_value()))
                                .collect(),
                        )
                    }),
                ),
            ]),
        }
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        if let Ok(("exact", r)) = single(v) {
            return Ok(Self::Exact(Canonical::from_value(r)?));
        }
        let mut f = Fields::of(v)?;
        let namespace = namespace(f.req("namespace")?)?;
        let prefix = f
            .opt("prefix")
            .map(|p| segments(p, true))
            .transpose()?
            .unwrap_or_default();
        let kind = f.opt("type").map(ident).transpose()?;
        let attrs = match f.opt("where") {
            None => BTreeMap::new(),
            Some(w) => {
                let mut wf = Fields::of(w)?;
                if wf.entries.is_empty() {
                    return Err(ModelError::Range);
                }
                let mut out = BTreeMap::new();
                for (k, val, used) in &mut wf.entries {
                    *used = true;
                    out.insert(ident(&Value::text(k))?, EqValue::from_value(val)?);
                }
                out
            }
        };
        f.done()?;
        Ok(Self::Structural(Structural {
            namespace,
            prefix,
            kind,
            attrs,
        }))
    }
}

impl Canonical for Conjunct {
    fn to_value(&self) -> Value {
        map([
            ("claim_class", Some(Value::text(&self.claim_class))),
            ("value", self.value.as_ref().map(Canonical::to_value)),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let c = Conjunct {
            claim_class: ident(f.req("claim_class")?)?,
            value: f.opt("value").map(EqValue::from_value).transpose()?,
        };
        f.done()?;
        Ok(c)
    }
}

impl Canonical for SubjectSelector {
    fn to_value(&self) -> Value {
        match self {
            Self::Party(id) => tagged("party", id.to_value()),
            Self::Pred(c) => tagged("pred", set_value(c.iter().map(Canonical::to_value))),
            Self::Public => Value::text("public"),
            Self::Foreign { domain, class } => tagged(
                "foreign",
                map([
                    ("domain", Some(domain.to_value())),
                    ("authority_class", Some(Value::text(class))),
                ]),
            ),
        }
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        if matches!(v, Value::Text(t) if t == "public") {
            return Ok(Self::Public);
        }
        match single(v)? {
            ("party", id) => Ok(Self::Party(Canonical::from_value(id)?)),
            ("pred", c) => Ok(Self::Pred(set_of(c, true, Conjunct::from_value)?)),
            ("foreign", inner) => {
                let mut f = Fields::of(inner)?;
                let s = Self::Foreign {
                    domain: Canonical::from_value(f.req("domain")?)?,
                    class: ident(f.req("authority_class")?)?,
                };
                f.done()?;
                Ok(s)
            }
            _ => Err(ModelError::Unknown),
        }
    }
}

impl Canonical for Bound {
    fn to_value(&self) -> Value {
        match self {
            Self::Enum(s) => tagged("enum", set_value(s.iter().map(|x| Value::text(x)))),
            Self::Eq(e) => tagged("eq", e.to_value()),
            Self::Range { min, max, unit } => tagged(
                "range",
                map([
                    ("min", min.map(Value::int)),
                    ("max", max.map(Value::int)),
                    ("unit", Some(Value::text(unit))),
                ]),
            ),
            Self::CountMax(n) => tagged("count_max", Value::Unsigned(*n)),
            Self::Interval(w) => tagged("interval", w.to_value()),
            Self::Resource(r) => tagged("resource", r.to_value()),
            Self::Subject(s) => tagged("subject", s.to_value()),
            Self::Purpose(p) => tagged("purpose", set_value(p.iter().map(Canonical::to_value))),
            Self::Flag(b) => tagged("flag", Value::Bool(*b)),
        }
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let (k, inner) = single(v)?;
        Ok(match k {
            "enum" => Self::Enum(set_of(inner, true, |x| text(x).map(String::from))?),
            "eq" => Self::Eq(EqValue::from_value(inner)?),
            "range" => {
                let mut f = Fields::of(inner)?;
                let b = Self::Range {
                    min: f.opt("min").map(int).transpose()?,
                    max: f.opt("max").map(int).transpose()?,
                    unit: unit(f.req("unit")?)?,
                };
                f.done()?;
                b
            }
            "count_max" => Self::CountMax(uint(inner)?),
            "interval" => Self::Interval(Window::from_value(inner)?),
            "resource" => Self::Resource(ResourceSelector::from_value(inner)?),
            "subject" => Self::Subject(SubjectSelector::from_value(inner)?),
            "purpose" => Self::Purpose(set_of(inner, true, PurposeRef::from_value)?),
            "flag" => Self::Flag(boolean(inner)?),
            _ => return Err(ModelError::Unknown),
        })
    }
}

impl Canonical for ActionSet {
    fn to_value(&self) -> Value {
        map([
            (
                "exact",
                (!self.exact.is_empty())
                    .then(|| set_value(self.exact.iter().map(Canonical::to_value))),
            ),
            (
                "prefix",
                (!self.prefix.is_empty()).then(|| {
                    set_value(self.prefix.iter().map(|(ns, cat)| {
                        map([
                            ("namespace", Some(Value::text(ns))),
                            ("catalog", Some(cat.to_value())),
                        ])
                    }))
                }),
            ),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let exact = f
            .opt("exact")
            .map(|e| set_of(e, true, ActionRef::from_value))
            .transpose()?
            .unwrap_or_default();
        let prefix = f
            .opt("prefix")
            .map(|p| {
                set_of(p, true, |x| {
                    let mut pf = Fields::of(x)?;
                    let item = (
                        namespace(pf.req("namespace")?)?,
                        Canonical::from_value(pf.req("catalog")?)?,
                    );
                    pf.done()?;
                    Ok(item)
                })
            })
            .transpose()?
            .unwrap_or_default();
        f.done()?;
        Ok(ActionSet { exact, prefix })
    }
}

fn param_map<T>(
    v: &Value,
    read: impl Fn(&Value) -> Result<T, ModelError>,
) -> Result<BTreeMap<String, T>, ModelError> {
    let mut f = Fields::of(v)?;
    if f.is_empty() {
        return Err(ModelError::Range);
    }
    Ok(f.drain(|k, val| Ok((ident(&Value::text(k))?, read(val)?)))?
        .into_iter()
        .collect())
}

pub(crate) fn opt_param_map<T>(
    v: Option<&Value>,
    read: impl Fn(&Value) -> Result<T, ModelError>,
) -> Result<BTreeMap<String, T>, ModelError> {
    v.map(|v| param_map(v, read))
        .transpose()
        .map(Option::unwrap_or_default)
}

pub(crate) fn map_value<T>(m: &BTreeMap<String, T>, write: impl Fn(&T) -> Value) -> Option<Value> {
    (!m.is_empty()).then(|| Value::Map(m.iter().map(|(k, v)| (Value::text(k), write(v))).collect()))
}

impl Canonical for AuthoritySet {
    fn to_value(&self) -> Value {
        map([
            ("actions", Some(self.actions.to_value())),
            ("resource", Some(self.resource.to_value())),
            ("params", map_value(&self.params, Canonical::to_value)),
            (
                "recipient",
                self.recipient.as_ref().map(Canonical::to_value),
            ),
            (
                "purpose",
                self.purpose
                    .as_ref()
                    .map(|p| set_value(p.iter().map(Canonical::to_value))),
            ),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let a = AuthoritySet {
            actions: ActionSet::from_value(f.req("actions")?)?,
            resource: ResourceSelector::from_value(f.req("resource")?)?,
            params: opt_param_map(f.opt("params"), Bound::from_value)?,
            recipient: f
                .opt("recipient")
                .map(SubjectSelector::from_value)
                .transpose()?,
            purpose: f
                .opt("purpose")
                .map(|p| set_of(p, true, PurposeRef::from_value))
                .transpose()?,
        };
        f.done()?;
        Ok(a)
    }
}

impl Canonical for WhileCondition {
    fn to_value(&self) -> Value {
        match self {
            Self::InstanceAlive(id) => tagged("instance_alive", id.to_value()),
            Self::ClaimHeld {
                class,
                subject,
                acceptance,
            } => tagged(
                "claim_held",
                map([
                    ("class", Some(Value::text(class))),
                    ("subject", Some(subject.to_value())),
                    ("acceptance", Some(acceptance.to_value())),
                ]),
            ),
        }
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        match single(v)? {
            ("instance_alive", id) => Ok(Self::InstanceAlive(Canonical::from_value(id)?)),
            ("claim_held", inner) => {
                let mut f = Fields::of(inner)?;
                let c = Self::ClaimHeld {
                    class: ident(f.req("class")?)?,
                    subject: SubjectSelector::from_value(f.req("subject")?)?,
                    acceptance: Canonical::from_value(f.req("acceptance")?)?,
                };
                f.done()?;
                Ok(c)
            }
            _ => Err(ModelError::Unknown),
        }
    }
}

impl Canonical for BudgetTerm {
    fn to_value(&self) -> Value {
        map([
            (
                "dimension",
                Some(match &self.dimension {
                    BudgetDimension::Count => Value::text("count"),
                    BudgetDimension::Amount(u) => tagged("amount", Value::text(u)),
                }),
            ),
            ("capacity", Some(Value::Unsigned(self.capacity))),
            (
                "window",
                Some(match self.window {
                    BudgetWindow::Total => Value::text("total"),
                    BudgetWindow::RollingSeconds(s) => tagged("rolling_s", Value::Unsigned(s)),
                }),
            ),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let dimension = match f.req("dimension")? {
            Value::Text(t) if t == "count" => BudgetDimension::Count,
            other => match single(other)? {
                ("amount", u) => BudgetDimension::Amount(unit(u)?),
                _ => return Err(ModelError::Unknown),
            },
        };
        let capacity = uint(f.req("capacity")?)?;
        let window = match f.req("window")? {
            Value::Text(t) if t == "total" => BudgetWindow::Total,
            other => match single(other)? {
                ("rolling_s", s) => BudgetWindow::RollingSeconds(uint(s)?),
                _ => return Err(ModelError::Unknown),
            },
        };
        f.done()?;
        Ok(BudgetTerm {
            dimension,
            capacity,
            window,
        })
    }
}

impl Canonical for ConstraintSet {
    fn to_value(&self) -> Value {
        map([
            ("validity", Some(self.validity.to_value())),
            (
                "while",
                (!self.conditions.is_empty())
                    .then(|| set_value(self.conditions.iter().map(Canonical::to_value))),
            ),
            (
                "budget",
                (!self.budget.is_empty())
                    .then(|| set_value(self.budget.iter().map(Canonical::to_value))),
            ),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let c = ConstraintSet {
            validity: Window::from_value(f.req("validity")?)?,
            conditions: f
                .opt("while")
                .map(|w| set_of(w, true, WhileCondition::from_value))
                .transpose()?
                .unwrap_or_default(),
            budget: f
                .opt("budget")
                .map(|b| set_of(b, true, BudgetTerm::from_value))
                .transpose()?
                .unwrap_or_default(),
        };
        f.done()?;
        Ok(c)
    }
}

impl Canonical for DelegationTerms {
    fn to_value(&self) -> Value {
        map([
            (
                "depth",
                (self.depth > 0).then_some(Value::Unsigned(self.depth)),
            ),
            (
                "downstream_holder_class",
                self.downstream_holder_class
                    .as_ref()
                    .map(Canonical::to_value),
            ),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let depth = match f.opt("depth") {
            None => 0,
            Some(d) => match uint(d)? {
                0 => return Err(ModelError::Range),
                n => n,
            },
        };
        let d = DelegationTerms {
            depth,
            downstream_holder_class: f
                .opt("downstream_holder_class")
                .map(SubjectSelector::from_value)
                .transpose()?,
        };
        f.done()?;
        Ok(d)
    }
}

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

const PROOF_KINDS: [(&str, ProofKind); 4] = [
    ("claim", ProofKind::Claim),
    ("contribution", ProofKind::Contribution),
    ("authentication", ProofKind::Authentication),
    ("foreign_authority", ProofKind::ForeignAuthority),
];
const BINDINGS: [(&str, Binding); 4] = [
    ("none", Binding::None),
    ("actor_instance", Binding::ActorInstance),
    ("intent_digest", Binding::IntentDigest),
    ("resource", Binding::Resource),
];
const CONSUMPTIONS: [(&str, Consumption); 2] = [
    ("reusable", Consumption::Reusable),
    ("single_use", Consumption::SingleUse),
];
const DISTINCT: [(&str, Independence); 3] = [
    ("party", Independence::DistinctParty),
    ("instance", Independence::DistinctInstance),
    ("issuer", Independence::DistinctIssuer),
];

impl Canonical for RequirementTerm {
    fn to_value(&self) -> Value {
        map([
            ("proof_kind", Some(word_of(self.proof_kind, &PROOF_KINDS))),
            ("class", Some(Value::text(&self.class))),
            (
                "count",
                (self.count != 1).then_some(Value::Unsigned(self.count)),
            ),
            (
                "binding",
                (self.binding != Binding::None).then(|| word_of(self.binding, &BINDINGS)),
            ),
            ("freshness_ms", self.freshness_ms.map(Value::Unsigned)),
            (
                "independence",
                (self.independence != Independence::None)
                    .then(|| tagged("distinct", word_of(self.independence, &DISTINCT))),
            ),
            (
                "consumption",
                (self.consumption != Consumption::Reusable)
                    .then(|| word_of(self.consumption, &CONSUMPTIONS)),
            ),
            ("source", self.source.as_ref().map(Canonical::to_value)),
            (
                "assurance",
                map_value(&self.assurance, |n| Value::Unsigned(*n)),
            ),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let independence = match f.opt("independence") {
            None => Independence::None,
            Some(Value::Text(t)) if t == "none" => return Err(ModelError::Range),
            Some(x) => match single(x)? {
                ("distinct", d) => word(d, &DISTINCT)?,
                _ => return Err(ModelError::Unknown),
            },
        };
        let t = RequirementTerm {
            proof_kind: word(f.req("proof_kind")?, &PROOF_KINDS)?,
            class: ident(f.req("class")?)?,
            count: match f.opt("count").map(uint).transpose()? {
                None => 1,
                Some(0 | 1) => return Err(ModelError::Range),
                Some(n) => n,
            },
            binding: match f.opt("binding").map(|b| word(b, &BINDINGS)).transpose()? {
                Some(Binding::None) => return Err(ModelError::Range),
                Some(b) => b,
                None => Binding::None,
            },
            freshness_ms: f.opt("freshness_ms").map(uint).transpose()?,
            independence,
            consumption: match f
                .opt("consumption")
                .map(|c| word(c, &CONSUMPTIONS))
                .transpose()?
            {
                Some(Consumption::Reusable) => return Err(ModelError::Range),
                Some(c) => c,
                None => Consumption::Reusable,
            },
            source: f
                .opt("source")
                .map(SubjectSelector::from_value)
                .transpose()?,
            assurance: opt_param_map(f.opt("assurance"), uint)?,
        };
        f.done()?;
        Ok(t)
    }
}

impl Canonical for CanonicalAuthority {
    fn to_value(&self) -> Value {
        map([
            ("authority", Some(self.authority.to_value())),
            ("constraints", Some(self.constraints.to_value())),
            ("delegation", Some(self.delegation.to_value())),
            (
                "requirements",
                Some(set_value(self.requirements.iter().map(Canonical::to_value))),
            ),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let c = CanonicalAuthority {
            authority: AuthoritySet::from_value(f.req("authority")?)?,
            constraints: ConstraintSet::from_value(f.req("constraints")?)?,
            delegation: DelegationTerms::from_value(f.req("delegation")?)?,
            requirements: set_of(f.req("requirements")?, false, RequirementTerm::from_value)?,
        };
        f.done()?;
        Ok(c)
    }
}

#[cfg(test)]
mod tests;
