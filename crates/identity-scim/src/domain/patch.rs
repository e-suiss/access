//! The PATCH engine (RFC 7644 §3.5.2, errata 7122, 8097; §10.6.2, IDP-23, Ek B 4808): `add`
//! follows its seven rules, `remove` and `replace` answer `noTarget` when their path selects
//! nothing they may change, and the request is atomic: the operations run on a copy and the
//! stored resource changes only when every one succeeded. Adding a value already there changes
//! nothing, so `meta.lastModified` stays.

use access_parse::scim::protocol::{self, AttrPath, CompareOp, Expr, PatchPath};
use serde_json::{Map, Value};

use super::filter::{self, Resolved, Use};
use super::resource::{self, Source};
use super::schema::{self, Attr, Kind, Mutability, Type};
use super::tolerance::{Profile, Rule};
use super::{ScimError, ScimType};

/// The PATCH request message schema.
pub const PATCH_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

/// Most operations in one request.
pub const MAX_OPERATIONS: usize = 1000;

/// An operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// `add`.
    Add,
    /// `remove`.
    Remove,
    /// `replace`.
    Replace,
}

/// One PATCH operation.
#[derive(Clone, Debug, PartialEq)]
pub struct Operation {
    /// The operation.
    pub op: Op,
    /// Its path.
    pub path: Option<PatchPath>,
    /// Its value.
    pub value: Option<Value>,
}

fn syntax(detail: &'static str) -> ScimError {
    ScimError::bad(ScimType::InvalidSyntax, detail)
}

fn path_error(detail: &'static str) -> ScimError {
    ScimError::bad(ScimType::InvalidPath, detail)
}

fn no_target() -> ScimError {
    ScimError::bad(ScimType::NoTarget, "The path selects nothing to change")
}

fn mutability() -> ScimError {
    ScimError::bad(
        ScimType::Mutability,
        "The path names an attribute the client may not change",
    )
}

/// Reads a `PatchOp` message.
///
/// # Errors
/// [`ScimError`] `invalidSyntax` or `invalidPath`.
pub fn parse(body: &Value, profile: &Profile) -> Result<Vec<Operation>, ScimError> {
    let o = body
        .as_object()
        .ok_or_else(|| syntax("The body is not an object"))?;
    let schemas_ok = o
        .get("schemas")
        .and_then(Value::as_array)
        .is_some_and(|a| a.iter().any(|s| s.as_str() == Some(PATCH_SCHEMA)));
    if !schemas_ok && !profile.has(Rule::MissingSchemas) {
        return Err(syntax("The body is not a PatchOp message"));
    }
    let ops = o
        .get("Operations")
        .or_else(|| o.get("operations"))
        .and_then(Value::as_array)
        .ok_or_else(|| syntax("The body has no Operations"))?;
    if ops.is_empty() || ops.len() > MAX_OPERATIONS {
        return Err(syntax("Operations is empty or too long"));
    }
    ops.iter()
        .map(|x| {
            let x = x
                .as_object()
                .ok_or_else(|| syntax("An operation is not an object"))?;
            let name = x
                .get("op")
                .and_then(Value::as_str)
                .ok_or_else(|| syntax("An operation has no op"))?;
            let loose = profile.has(Rule::PatchOpCaseInsensitive);
            let is = |w: &str| name == w || (loose && name.eq_ignore_ascii_case(w));
            let op = if is("add") {
                Op::Add
            } else if is("remove") {
                Op::Remove
            } else if is("replace") {
                Op::Replace
            } else {
                return Err(syntax("Unknown op"));
            };
            let path = match x.get("path") {
                None | Some(Value::Null) => None,
                Some(Value::String(p)) if p.is_empty() => None,
                Some(Value::String(p)) => {
                    Some(protocol::parse_path(p).map_err(|_| path_error("The path is invalid"))?)
                }
                Some(_) => return Err(path_error("The path is not a string")),
            };
            Ok(Operation {
                op,
                path,
                value: x.get("value").cloned(),
            })
        })
        .collect()
}

/// What a path selects.
#[derive(Clone, Debug)]
enum Target {
    /// A whole extension object.
    Extension(&'static str),
    /// An attribute, a sub-attribute, or some values of a multi-valued attribute.
    Attr {
        resolved: Resolved,
        filter: Option<Expr>,
        sub: Option<&'static Attr>,
    },
}

fn target(kind: Kind, path: &PatchPath, profile: &Profile) -> Result<Target, ScimError> {
    let loose = profile.has(Rule::PatchPathCaseInsensitive);
    let (attr_path, filter, after): (&AttrPath, Option<&Expr>, Option<&String>) = match path {
        PatchPath::Attr(p) => (p, None, None),
        PatchPath::Value { path, filter, sub } => (path, Some(filter), sub.as_ref()),
    };
    if filter.is_none()
        && attr_path.sub.is_none()
        && let Some(urn) = &attr_path.urn
    {
        let whole = format!("{urn}:{}", attr_path.name);
        if let Some(ext) = kind
            .extensions()
            .iter()
            .find(|e| e.id == whole || (loose && e.id.eq_ignore_ascii_case(&whole)))
        {
            return Ok(Target::Extension(ext.id));
        }
    }
    let resolved = filter::resolve(kind, attr_path, loose)
        .ok_or_else(|| path_error("The path names an attribute the schema does not have"))?;
    let sub = match (filter, after) {
        (Some(_), Some(s)) => Some(
            schema::sub_attr(resolved.attr, s)
                .ok_or_else(|| path_error("Unknown sub-attribute"))?,
        ),
        _ => None,
    };
    if let Some(f) = filter {
        if !resolved.attr.multi || resolved.attr.ty != Type::Complex {
            return Err(path_error(
                "A value path names a multi-valued complex attribute",
            ));
        }
        filter::check(
            kind,
            &Expr::ValuePath {
                path: attr_path.clone(),
                filter: Box::new(f.clone()),
            },
            Use::Patch,
            profile,
        )
        .map_err(|_| path_error("The value filter is invalid"))?;
    }
    let writes = |a: &Attr| matches!(a.mutability, Mutability::ReadWrite | Mutability::Immutable);
    if !writes(resolved.attr) && resolved.attr.mutability != Mutability::WriteOnly {
        return Err(mutability());
    }
    if resolved.attr.mutability == Mutability::WriteOnly {
        return Err(ScimError::bad(
            ScimType::InvalidValue,
            "A password is never written through SCIM",
        ));
    }
    let leaf = sub.or(resolved.sub);
    if leaf.is_some_and(|s| s.mutability == Mutability::ReadOnly) {
        return Err(mutability());
    }
    Ok(Target::Attr {
        resolved,
        filter: filter.cloned(),
        sub,
    })
}

fn container<'a>(
    res: &'a mut Map<String, Value>,
    ext: Option<&str>,
) -> Result<&'a mut Map<String, Value>, ScimError> {
    let Some(e) = ext else {
        return Ok(res);
    };
    let entry = res
        .entry(String::from(e))
        .or_insert_with(|| Value::Object(Map::new()));
    if !entry.is_object() {
        *entry = Value::Object(Map::new());
    }
    entry.as_object_mut().ok_or(ScimError::UNAVAILABLE)
}

fn identity(attr: &Attr, v: &Value) -> Value {
    if attr.name == "members" {
        v.get("value").cloned().unwrap_or(Value::Null)
    } else {
        v.clone()
    }
}

fn add_values(attr: &Attr, slot: &mut Map<String, Value>, new: Value) {
    let new_items = match new {
        Value::Array(a) => a,
        other => vec![other],
    };
    let entry = slot
        .entry(String::from(attr.name))
        .or_insert_with(|| Value::Array(Vec::new()));
    if !entry.is_array() {
        *entry = Value::Array(Vec::new());
    }
    if let Value::Array(items) = entry {
        for n in new_items {
            let id = identity(attr, &n);
            if !items.iter().any(|x| identity(attr, x) == id) {
                if n.get("primary") == Some(&Value::Bool(true)) {
                    for x in items.iter_mut() {
                        if let Some(o) = x.as_object_mut() {
                            o.remove("primary");
                        }
                    }
                }
                items.push(n);
            }
        }
    }
}

fn merge(slot: &mut Map<String, Value>, name: &str, new: Value) {
    let entry = slot
        .entry(String::from(name))
        .or_insert_with(|| Value::Object(Map::new()));
    match (entry, new) {
        (Value::Object(have), Value::Object(n)) => {
            for (k, v) in n {
                have.insert(k, v);
            }
        }
        (e, n) => *e = n,
    }
}

fn normalized(
    attr: &'static Attr,
    v: &Value,
    profile: &Profile,
) -> Result<Option<Value>, ScimError> {
    resource::value(attr, v, profile, Source::Patch)
}

fn sub_value(sub: &'static Attr, v: &Value, profile: &Profile) -> Result<Option<Value>, ScimError> {
    resource::value(sub, v, profile, Source::Patch)
}

fn require_value(v: Option<&Value>) -> Result<&Value, ScimError> {
    v.ok_or_else(|| ScimError::bad(ScimType::InvalidValue, "The operation has no value"))
}

fn seed(filter: &Expr) -> Option<Map<String, Value>> {
    match filter {
        Expr::Compare {
            path,
            op: CompareOp::Eq,
            value: access_parse::scim::Value::Text(t),
        } if path.urn.is_none() && path.sub.is_none() => {
            let mut m = Map::new();
            m.insert(path.name.clone(), Value::from(t.as_str()));
            Some(m)
        }
        Expr::And(a, b) => {
            let mut m = seed(a)?;
            m.extend(seed(b)?);
            Some(m)
        }
        _ => None,
    }
}

fn whole_object(
    kind: Kind,
    res: &mut Map<String, Value>,
    op: Op,
    v: &Value,
    profile: &Profile,
) -> Result<(), ScimError> {
    let o = v.as_object().ok_or_else(|| {
        ScimError::bad(ScimType::InvalidValue, "A path-less value is not an object")
    })?;
    for (k, x) in o {
        if k.eq_ignore_ascii_case("schemas") {
            continue;
        }
        let path = match protocol::attr_path(k) {
            Ok(p) => PatchPath::Attr(p),
            Err(_) if profile.has(Rule::IgnoreUnknownAttributes) => continue,
            Err(_) => return Err(path_error("A value names an invalid attribute")),
        };
        match target(kind, &path, profile) {
            Ok(t) => one(res, op, &t, Some(x), profile)?,
            Err(e)
                if e.scim_type == Some(ScimType::InvalidPath)
                    && profile.has(Rule::IgnoreUnknownAttributes) => {}
            Err(e) if e.scim_type == Some(ScimType::Mutability) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn extension_op(
    kind: Kind,
    res: &mut Map<String, Value>,
    op: Op,
    ext: &'static str,
    value: Option<&Value>,
    profile: &Profile,
) -> Result<(), ScimError> {
    if op == Op::Remove {
        if res.remove(ext).is_none() {
            return Err(no_target());
        }
        return Ok(());
    }
    let v = require_value(value)?;
    if op == Op::Replace {
        res.remove(ext);
    }
    let o = v.as_object().ok_or_else(|| {
        ScimError::bad(
            ScimType::InvalidValue,
            "An extension value is not an object",
        )
    })?;
    for (k, x) in o {
        let path = PatchPath::Attr(AttrPath {
            urn: Some(String::from(ext)),
            name: k.clone(),
            sub: None,
        });
        match target(kind, &path, profile) {
            Ok(t) => one(res, Op::Add, &t, Some(x), profile)?,
            Err(e)
                if profile.has(Rule::IgnoreUnknownAttributes)
                    && e.scim_type == Some(ScimType::InvalidPath) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "the three operations over the three target shapes, read side by side"
)]
fn one(
    res: &mut Map<String, Value>,
    op: Op,
    t: &Target,
    value: Option<&Value>,
    profile: &Profile,
) -> Result<(), ScimError> {
    let Target::Attr {
        resolved,
        filter,
        sub,
    } = t
    else {
        return Err(path_error("An extension is changed as a whole elsewhere"));
    };
    let attr = resolved.attr;
    let slot = container(res, resolved.extension)?;
    match (filter, resolved.sub) {
        (None, None) => match op {
            Op::Remove => {
                if attr.required {
                    return Err(ScimError::bad(
                        ScimType::InvalidValue,
                        "A required attribute cannot be removed",
                    ));
                }
                let by_value = profile.has(Rule::PatchRemoveMemberByValue)
                    && attr.name == "members"
                    && value.is_some();
                if by_value {
                    let gone: Vec<Value> = match value {
                        Some(Value::Array(a)) => a.iter().map(|x| identity(attr, x)).collect(),
                        Some(other) => vec![identity(attr, other)],
                        None => Vec::new(),
                    };
                    if let Some(Value::Array(items)) = slot.get_mut(attr.name) {
                        items.retain(|x| !gone.contains(&identity(attr, x)));
                    }
                } else {
                    slot.remove(attr.name);
                }
                Ok(())
            }
            Op::Add | Op::Replace => {
                let v = require_value(value)?;
                let Some(n) = normalized(attr, v, profile)? else {
                    if profile.has(Rule::EmptyValueClears) && !attr.required {
                        slot.remove(attr.name);
                        return Ok(());
                    }
                    return Err(ScimError::bad(ScimType::InvalidValue, "The value is empty"));
                };
                match (op, attr.multi, attr.ty) {
                    (Op::Add, true, _) => add_values(attr, slot, n),
                    (_, false, Type::Complex) => merge(slot, attr.name, n),
                    _ => {
                        slot.insert(String::from(attr.name), n);
                    }
                }
                Ok(())
            }
        },
        (None, Some(leaf)) => {
            if attr.multi {
                return Err(path_error(
                    "A sub-attribute of a multi-valued attribute needs a value filter",
                ));
            }
            match op {
                Op::Remove => {
                    if let Some(Value::Object(o)) = slot.get_mut(attr.name) {
                        o.remove(leaf.name);
                        if o.is_empty() {
                            slot.remove(attr.name);
                        }
                    }
                    Ok(())
                }
                Op::Add | Op::Replace => {
                    let v = require_value(value)?;
                    let entry = slot
                        .entry(String::from(attr.name))
                        .or_insert_with(|| Value::Object(Map::new()));
                    if let Value::Object(o) = entry {
                        match sub_value(leaf, v, profile)? {
                            Some(n) => {
                                o.insert(String::from(leaf.name), n);
                            }
                            None => {
                                o.remove(leaf.name);
                            }
                        }
                    }
                    Ok(())
                }
            }
        }
        (Some(f), _) => {
            let Some(Value::Array(items)) = slot.get_mut(attr.name) else {
                return match op {
                    Op::Remove => Ok(()),
                    Op::Replace => Err(no_target()),
                    Op::Add => {
                        let (Some(leaf), Some(mut m)) = (sub, seed(f)) else {
                            return Err(no_target());
                        };
                        let v = require_value(value)?;
                        if let Some(n) = sub_value(leaf, v, profile)? {
                            m.insert(String::from(leaf.name), n);
                        }
                        let new = normalized(attr, &Value::Array(vec![Value::Object(m)]), profile)?;
                        if let Some(n) = new {
                            add_values(attr, slot, n);
                        }
                        Ok(())
                    }
                };
            };
            let hits: Vec<usize> = items
                .iter()
                .enumerate()
                .filter(|(_, x)| filter::element_matches(attr, f, x))
                .map(|(i, _)| i)
                .collect();
            match op {
                Op::Remove => {
                    if let Some(leaf) = sub {
                        if leaf.mutability == Mutability::Immutable {
                            return Err(mutability());
                        }
                        for i in &hits {
                            if let Some(Value::Object(o)) = items.get_mut(*i) {
                                o.remove(leaf.name);
                            }
                        }
                        items.retain(|x| x.as_object().is_none_or(|o| !o.is_empty()));
                    } else {
                        let mut i = 0_usize;
                        items.retain(|_| {
                            let keep = !hits.contains(&i);
                            i = i.saturating_add(1);
                            keep
                        });
                    }
                }
                Op::Add | Op::Replace => {
                    let v = require_value(value)?;
                    if hits.is_empty() {
                        if op == Op::Replace {
                            return Err(no_target());
                        }
                        let (Some(leaf), Some(mut m)) = (sub, seed(f)) else {
                            return Err(no_target());
                        };
                        if let Some(n) = sub_value(leaf, v, profile)? {
                            m.insert(String::from(leaf.name), n);
                        }
                        if let Some(Value::Array(mut n)) =
                            normalized(attr, &Value::Array(vec![Value::Object(m)]), profile)?
                        {
                            items.append(&mut n);
                        }
                        return Ok(());
                    }
                    if let Some(leaf) = sub {
                        if leaf.mutability == Mutability::Immutable {
                            return Err(mutability());
                        }
                        let n = sub_value(leaf, v, profile)?;
                        for i in hits {
                            if let Some(Value::Object(o)) = items.get_mut(i) {
                                match &n {
                                    Some(n) => {
                                        o.insert(String::from(leaf.name), n.clone());
                                    }
                                    None => {
                                        o.remove(leaf.name);
                                    }
                                }
                            }
                        }
                    } else {
                        let Some(Value::Array(mut n)) =
                            normalized(attr, &Value::Array(vec![v.clone()]), profile)?
                        else {
                            return Err(ScimError::bad(
                                ScimType::InvalidValue,
                                "The value is empty",
                            ));
                        };
                        let Some(new) = n.pop() else {
                            return Err(ScimError::bad(
                                ScimType::InvalidValue,
                                "The value is empty",
                            ));
                        };
                        for i in hits {
                            if let Some(x) = items.get_mut(i) {
                                if op == Op::Replace {
                                    if identity(attr, x) != identity(attr, &new)
                                        && attr.name == "members"
                                    {
                                        return Err(mutability());
                                    }
                                    *x = new.clone();
                                } else if let (Some(o), Some(n)) =
                                    (x.as_object_mut(), new.as_object())
                                {
                                    for (k, v) in n {
                                        o.insert(k.clone(), v.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if items.is_empty() {
                slot.remove(attr.name);
            }
            Ok(())
        }
    }
}

/// Applies `ops` to `resource` of `kind`, all or none.
///
/// # Errors
/// [`ScimError`]; the resource is unchanged.
pub fn apply(
    kind: Kind,
    resource: &Value,
    ops: &[Operation],
    profile: &Profile,
) -> Result<Value, ScimError> {
    let mut res = resource
        .as_object()
        .cloned()
        .ok_or(ScimError::UNAVAILABLE)?;
    for o in ops {
        match &o.path {
            None => match o.op {
                Op::Remove => return Err(no_target()),
                op => whole_object(
                    kind,
                    &mut res,
                    op,
                    require_value(o.value.as_ref())?,
                    profile,
                )?,
            },
            Some(p) => match target(kind, p, profile)? {
                Target::Extension(ext) => {
                    extension_op(kind, &mut res, o.op, ext, o.value.as_ref(), profile)?;
                }
                t @ Target::Attr { .. } => one(&mut res, o.op, &t, o.value.as_ref(), profile)?,
            },
        }
    }
    resource::required(kind, &res)?;
    resource::reschema(kind, &mut res);
    Ok(Value::Object(res))
}

#[cfg(test)]
mod tests;
