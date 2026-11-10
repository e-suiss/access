//! SCIM filters over the server's schemas (RFC 7644 §3.4.2.2, CR-10, CR-40, Ek B 4809, 4810):
//! every path must name an attribute the resource type has and the client may read; a
//! `password` or any other never-returned attribute is refused, not ignored, so a filter cannot
//! probe it. In a list query `co`, `sw` and `ew` are served only on indexed attributes.

use std::cmp::Ordering;

use access_parse::scim::Value as Literal;
use access_parse::scim::protocol::{self, AttrPath, CompareOp, Expr};
use serde_json::Value;

use super::resource::datetime_ms;
use super::schema::{self, Attr, Kind, Returned, Type};
use super::tolerance::{Profile, Rule};
use super::{ScimError, ScimType};

fn refused(detail: &'static str) -> ScimError {
    ScimError::bad(ScimType::InvalidFilter, detail)
}

/// Where a filter is used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Use {
    /// A list query: substring operators need an index.
    List,
    /// A PATCH value path over one resource.
    Patch,
}

/// A path resolved against the schema.
#[derive(Clone, Copy, Debug)]
pub struct Resolved {
    /// The extension holding it.
    pub extension: Option<&'static str>,
    /// The attribute.
    pub attr: &'static Attr,
    /// Its sub-attribute.
    pub sub: Option<&'static Attr>,
}

fn urn_ok(written: Option<&str>, found: Option<&'static str>, kind: Kind, loose: bool) -> bool {
    let Some(w) = written else {
        return true;
    };
    let canonical = found.unwrap_or(kind.core().id);
    w == canonical || (loose && w.eq_ignore_ascii_case(canonical))
}

/// Resolves `path` of `kind`; `loose` matches a schema URN without regard to case.
///
/// # Errors
/// `None` when the schema has no such attribute.
#[must_use]
pub fn resolve(kind: Kind, path: &AttrPath, loose: bool) -> Option<Resolved> {
    let located = schema::locate(kind, path.urn.as_deref(), &path.name)?;
    if !urn_ok(path.urn.as_deref(), located.extension, kind, loose) {
        return None;
    }
    let sub = match &path.sub {
        Some(s) => Some(schema::sub_attr(located.attr, s)?),
        None => None,
    };
    Some(Resolved {
        extension: located.extension,
        attr: located.attr,
        sub,
    })
}

fn readable(attr: &Attr) -> bool {
    attr.returned != Returned::Never
}

fn check_compare(
    target: &Attr,
    indexed: bool,
    op: CompareOp,
    value: &Literal,
    usage: Use,
) -> Result<(), ScimError> {
    if !readable(target) {
        return Err(refused("The filter names an attribute it may not"));
    }
    if op.substring() && usage == Use::List && !indexed {
        return Err(refused(
            "co, sw and ew are served on indexed attributes only",
        ));
    }
    let ok = match (target.ty, value) {
        (_, Literal::Null) => matches!(op, CompareOp::Eq | CompareOp::Ne),
        (Type::Boolean, Literal::Bool(_)) => matches!(op, CompareOp::Eq | CompareOp::Ne),
        (Type::Integer | Type::Decimal, Literal::Number(_)) => !op.substring(),
        (Type::String | Type::Reference | Type::Complex, Literal::Text(_)) => true,
        (Type::DateTime, Literal::Text(t)) => !op.substring() && datetime_ms(t).is_some(),
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(refused("The filter compares a value of another type"))
    }
}

fn check_inner(attr: &Attr, e: &Expr, usage: Use) -> Result<(), ScimError> {
    let sub = |p: &AttrPath| -> Result<&'static Attr, ScimError> {
        if p.urn.is_some() || p.sub.is_some() {
            return Err(refused("A value filter names a sub-attribute only"));
        }
        schema::sub_attr(attr, &p.name).ok_or_else(|| refused("Unknown sub-attribute"))
    };
    match e {
        Expr::Present(p) => {
            let s = sub(p)?;
            if readable(s) {
                Ok(())
            } else {
                Err(refused("The filter names an attribute it may not"))
            }
        }
        Expr::Compare { path, op, value } => {
            let s = sub(path)?;
            check_compare(s, attr.indexed || s.indexed, *op, value, usage)
        }
        Expr::Not(x) => check_inner(attr, x, usage),
        Expr::And(a, b) | Expr::Or(a, b) => {
            check_inner(attr, a, usage)?;
            check_inner(attr, b, usage)
        }
        Expr::ValuePath { .. } => Err(refused("Value paths do not nest")),
    }
}

/// Checks `e` against `kind`'s schema for `usage`.
///
/// # Errors
/// [`ScimError`] `invalidFilter`.
pub fn check(kind: Kind, e: &Expr, usage: Use, profile: &Profile) -> Result<(), ScimError> {
    let loose = profile.has(Rule::FilterAttributeCaseInsensitive);
    let found = |p: &AttrPath| resolve(kind, p, loose).ok_or_else(|| refused("Unknown attribute"));
    match e {
        Expr::Present(p) => {
            let r = found(p)?;
            if readable(r.attr) && r.sub.is_none_or(readable) {
                Ok(())
            } else {
                Err(refused("The filter names an attribute it may not"))
            }
        }
        Expr::Compare { path, op, value } => {
            let r = found(path)?;
            if !readable(r.attr) {
                return Err(refused("The filter names an attribute it may not"));
            }
            let target = r.sub.unwrap_or(r.attr);
            let indexed = r.attr.indexed && r.sub.is_none();
            check_compare(target, indexed, *op, value, usage)
        }
        Expr::Not(x) => check(kind, x, usage, profile),
        Expr::And(a, b) | Expr::Or(a, b) => {
            check(kind, a, usage, profile)?;
            check(kind, b, usage, profile)
        }
        Expr::ValuePath { path, filter } => {
            let r = found(path)?;
            if !r.attr.multi || r.attr.ty != Type::Complex || !readable(r.attr) {
                return Err(refused(
                    "A value path names a multi-valued complex attribute",
                ));
            }
            check_inner(r.attr, filter, usage)
        }
    }
}

/// Parses and checks a list filter.
///
/// # Errors
/// [`ScimError`] `invalidFilter`.
pub fn parse(kind: Kind, text: &str, profile: &Profile) -> Result<Expr, ScimError> {
    let e = protocol::parse(text)?;
    check(kind, &e, Use::List, profile)?;
    Ok(e)
}

fn cmp_text(a: &str, b: &str, exact: bool) -> Ordering {
    if exact {
        a.cmp(b)
    } else {
        a.to_lowercase().cmp(&b.to_lowercase())
    }
}

fn compare_one(attr: &Attr, have: &Value, op: CompareOp, want: &Literal) -> bool {
    let ord = match (want, have) {
        (Literal::Null, _) => return op == CompareOp::Ne,
        (Literal::Bool(w), Value::Bool(h)) => return (h == w) == (op == CompareOp::Eq),
        (Literal::Number(w), Value::Number(h)) => {
            let (Ok(w), Some(h)) = (w.parse::<f64>(), h.as_f64()) else {
                return false;
            };
            match h.partial_cmp(&w) {
                Some(o) => o,
                None => return false,
            }
        }
        (Literal::Text(w), Value::String(h)) if attr.ty == Type::DateTime => {
            match (datetime_ms(h), datetime_ms(w)) {
                (Some(h), Some(w)) => h.cmp(&w),
                _ => return false,
            }
        }
        (Literal::Text(w), Value::String(h)) => {
            let (hh, ww) = if attr.case_exact {
                (h.clone(), w.clone())
            } else {
                (h.to_lowercase(), w.to_lowercase())
            };
            match op {
                CompareOp::Co => return hh.contains(&ww),
                CompareOp::Sw => return hh.starts_with(&ww),
                CompareOp::Ew => return hh.ends_with(&ww),
                _ => cmp_text(h, w, attr.case_exact),
            }
        }
        _ => return false,
    };
    match op {
        CompareOp::Eq => ord == Ordering::Equal,
        CompareOp::Ne => ord != Ordering::Equal,
        CompareOp::Gt => ord == Ordering::Greater,
        CompareOp::Ge => ord != Ordering::Less,
        CompareOp::Lt => ord == Ordering::Less,
        CompareOp::Le => ord != Ordering::Greater,
        CompareOp::Co | CompareOp::Sw | CompareOp::Ew => false,
    }
}

fn values<'a>(v: Option<&'a Value>, sub: Option<&Attr>, multi: bool) -> Vec<&'a Value> {
    let Some(v) = v else {
        return Vec::new();
    };
    let items: Vec<&Value> = match v {
        Value::Array(a) if multi => a.iter().collect(),
        other => vec![other],
    };
    items
        .into_iter()
        .filter_map(|x| match sub {
            Some(s) => x.get(s.name),
            None if x.is_object() => x.get("value"),
            None => Some(x),
        })
        .collect()
}

fn present(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
        _ => true,
    }
}

fn holder<'a>(resource: &'a Value, r: &Resolved) -> Option<&'a Value> {
    match r.extension {
        Some(ext) => resource.get(ext)?.get(r.attr.name),
        None => resource.get(r.attr.name),
    }
}

fn eval_inner(attr: &Attr, e: &Expr, element: &Value) -> bool {
    match e {
        Expr::Present(p) => schema::sub_attr(attr, &p.name)
            .and_then(|s| element.get(s.name))
            .is_some_and(present),
        Expr::Compare { path, op, value } => {
            let Some(s) = schema::sub_attr(attr, &path.name) else {
                return false;
            };
            match element.get(s.name) {
                Some(h) => compare_one(s, h, *op, value),
                None => match value {
                    Literal::Null => *op == CompareOp::Eq,
                    _ => *op == CompareOp::Ne,
                },
            }
        }
        Expr::Not(x) => !eval_inner(attr, x, element),
        Expr::And(a, b) => eval_inner(attr, a, element) && eval_inner(attr, b, element),
        Expr::Or(a, b) => eval_inner(attr, a, element) || eval_inner(attr, b, element),
        Expr::ValuePath { .. } => false,
    }
}

/// Whether one value of the multi-valued complex `attr` matches the value filter `e`.
#[must_use]
pub fn element_matches(attr: &Attr, e: &Expr, element: &Value) -> bool {
    eval_inner(attr, e, element)
}

/// Whether `resource` of `kind` matches the checked filter `e`.
#[must_use]
pub fn eval(kind: Kind, e: &Expr, resource: &Value) -> bool {
    match e {
        Expr::Present(p) => resolve(kind, p, true).is_some_and(|r| {
            values(holder(resource, &r), r.sub, r.attr.multi)
                .into_iter()
                .any(present)
        }),
        Expr::Compare { path, op, value } => {
            let Some(r) = resolve(kind, path, true) else {
                return false;
            };
            let target = r.sub.unwrap_or(r.attr);
            let found = values(holder(resource, &r), r.sub, r.attr.multi);
            if found.is_empty() {
                return match value {
                    Literal::Null => *op == CompareOp::Eq,
                    _ => *op == CompareOp::Ne,
                };
            }
            if *op == CompareOp::Ne {
                return found.iter().all(|h| compare_one(target, h, *op, value));
            }
            found.iter().any(|h| compare_one(target, h, *op, value))
        }
        Expr::Not(x) => !eval(kind, x, resource),
        Expr::And(a, b) => eval(kind, a, resource) && eval(kind, b, resource),
        Expr::Or(a, b) => eval(kind, a, resource) || eval(kind, b, resource),
        Expr::ValuePath { path, filter } => resolve(kind, path, true).is_some_and(|r| {
            holder(resource, &r)
                .and_then(Value::as_array)
                .is_some_and(|items| items.iter().any(|x| eval_inner(r.attr, filter, x)))
        }),
    }
}

/// The value an equality filter on `name` asks for, when the whole filter is that one
/// comparison: the server answers it from an index.
#[must_use]
pub fn equality<'a>(e: &'a Expr, name: &str) -> Option<&'a str> {
    match e {
        Expr::Compare {
            path,
            op: CompareOp::Eq,
            value: Literal::Text(t),
        } if path.sub.is_none() && path.name.eq_ignore_ascii_case(name) => Some(t),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
