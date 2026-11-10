//! A created or replaced resource, checked against its schemas and brought to the stored form
//! (RFC 7643 §2, RFC 7644 §3.3, §3.5.1): attribute names in the schema's spelling, extension
//! attributes under their URN, read-only values dropped, `id` and `meta` left to the server. A
//! password is never taken: the SCIM client is not a credential path (TN-61, MD-14).

use serde_json::{Map, Value};

use super::schema::{self, Attr, Kind, Mutability, Type};
use super::tolerance::{Profile, Rule};
use super::{ScimError, ScimType};

/// Longest string value, in bytes.
pub const MAX_STRING: usize = 2048;

/// Most values of one multi-valued attribute.
pub const MAX_VALUES: usize = 10_000;

/// Whether a value comes from a PATCH operation or a whole resource.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// `POST` or `PUT`.
    Resource,
    /// A PATCH operation's value.
    Patch,
}

fn invalid(detail: &'static str) -> ScimError {
    ScimError::bad(ScimType::InvalidValue, detail)
}

/// Unix milliseconds of an RFC 3339 date-time (`xsd:dateTime` as SCIM writes it).
#[must_use]
pub fn datetime_ms(s: &str) -> Option<i64> {
    if s.len() > 40 {
        return None;
    }
    let t = time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()?;
    i64::try_from(t.unix_timestamp_nanos().checked_div(1_000_000)?).ok()
}

/// RFC 3339 text of Unix milliseconds, in UTC.
#[must_use]
pub fn rfc3339(ms: i64) -> String {
    i128::from(ms)
        .checked_mul(1_000_000)
        .and_then(|ns| time::OffsetDateTime::from_unix_timestamp_nanos(ns).ok())
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}

fn boolean(v: &Value, attr: &Attr, profile: &Profile, source: Source) -> Result<bool, ScimError> {
    if let Some(b) = v.as_bool() {
        return Ok(b);
    }
    let text_ok = match source {
        Source::Patch => profile.has(Rule::PatchBoolAsString),
        Source::Resource => profile.has(Rule::ActiveAsString) && attr.name == "active",
    };
    match v.as_str() {
        Some(t) if text_ok && t.eq_ignore_ascii_case("true") => Ok(true),
        Some(t) if text_ok && t.eq_ignore_ascii_case("false") => Ok(false),
        _ => Err(invalid("A boolean attribute has another type")),
    }
}

pub(crate) fn simple(
    attr: &Attr,
    v: &Value,
    profile: &Profile,
    source: Source,
) -> Result<Option<Value>, ScimError> {
    if v.is_null() {
        return Ok(None);
    }
    Ok(Some(match attr.ty {
        Type::String | Type::Reference => {
            let s = v
                .as_str()
                .ok_or_else(|| invalid("A string attribute has another type"))?;
            if s.len() > MAX_STRING || s.chars().any(char::is_control) {
                return Err(invalid("A string attribute is too long or has controls"));
            }
            if s.is_empty() && profile.has(Rule::EmptyValueClears) {
                return Ok(None);
            }
            if !attr.canonical.is_empty() && attr.name != "type" {
                let c = attr
                    .canonical
                    .iter()
                    .find(|c| c.eq_ignore_ascii_case(s))
                    .ok_or_else(|| invalid("A value is not one of the canonical values"))?;
                return Ok(Some(Value::from(*c)));
            }
            Value::from(s)
        }
        Type::DateTime => {
            let s = v
                .as_str()
                .filter(|s| datetime_ms(s).is_some())
                .ok_or_else(|| invalid("A dateTime attribute is not RFC 3339"))?;
            Value::from(s)
        }
        Type::Boolean => Value::Bool(boolean(v, attr, profile, source)?),
        Type::Integer => {
            if v.as_i64().is_none() {
                return Err(invalid("An integer attribute has another type"));
            }
            v.clone()
        }
        Type::Decimal => {
            if !v.is_number() {
                return Err(invalid("A decimal attribute has another type"));
            }
            v.clone()
        }
        Type::Complex => return Err(invalid("A complex attribute has another type")),
    }))
}

fn unknown(profile: &Profile) -> Result<(), ScimError> {
    if profile.has(Rule::IgnoreUnknownAttributes) {
        Ok(())
    } else {
        Err(ScimError::bad(
            ScimType::InvalidSyntax,
            "The body names an attribute the schema does not have",
        ))
    }
}

fn complex_value(
    attr: &'static Attr,
    v: &Value,
    profile: &Profile,
    source: Source,
) -> Result<Option<Value>, ScimError> {
    if v.is_null() {
        return Ok(None);
    }
    let o = v
        .as_object()
        .ok_or_else(|| invalid("A complex attribute has another type"))?;
    let mut out = Map::new();
    for (k, x) in o {
        let Some(sub) = schema::sub_attr(attr, k) else {
            unknown(profile)?;
            continue;
        };
        if sub.mutability == Mutability::ReadOnly {
            continue;
        }
        if let Some(n) = simple(sub, x, profile, source)? {
            out.insert(String::from(sub.name), n);
        }
    }
    Ok((!out.is_empty()).then_some(Value::Object(out)))
}

/// One value of `attr` as stored; `None` when it clears the attribute.
///
/// # Errors
/// [`ScimError`] `invalidValue` or `invalidSyntax`.
pub fn value(
    attr: &'static Attr,
    v: &Value,
    profile: &Profile,
    source: Source,
) -> Result<Option<Value>, ScimError> {
    if attr.multi {
        let items: Vec<&Value> = match v {
            Value::Null => return Ok(None),
            Value::Array(a) => a.iter().collect(),
            other if source == Source::Patch => vec![other],
            _ => return Err(invalid("A multi-valued attribute is not a list")),
        };
        if items.len() > MAX_VALUES {
            return Err(invalid("Too many values"));
        }
        let mut out: Vec<Value> = Vec::new();
        for x in items {
            let one = if attr.ty == Type::Complex {
                complex_value(attr, x, profile, source)?
            } else {
                simple(attr, x, profile, source)?
            };
            if let Some(one) = one
                && !out.contains(&one)
            {
                out.push(one);
            }
        }
        let primaries = out
            .iter()
            .filter(|x| x.get("primary") == Some(&Value::Bool(true)))
            .count();
        if primaries > 1 {
            return Err(invalid("More than one value is primary"));
        }
        return Ok((!out.is_empty()).then_some(Value::Array(out)));
    }
    let v = match v {
        Value::Array(a) if a.len() == 1 && profile.has(Rule::PatchSingleValueArray) => {
            a.first().unwrap_or(&Value::Null)
        }
        Value::Array(a) if a.is_empty() && profile.has(Rule::EmptyValueClears) => {
            return Ok(None);
        }
        Value::Array(_) => return Err(invalid("A single-valued attribute is a list")),
        other => other,
    };
    if attr.ty == Type::Complex {
        complex_value(attr, v, profile, source)
    } else {
        simple(attr, v, profile, source)
    }
}

fn password(attr: &Attr) -> Result<(), ScimError> {
    if attr.mutability == Mutability::WriteOnly {
        return Err(invalid("A password is never written through SCIM"));
    }
    Ok(())
}

fn flatten(kind: Kind, body: &mut Map<String, Value>, profile: &Profile) {
    if !profile.has(Rule::EnterpriseExtensionFlattened) {
        return;
    }
    for ext in kind.extensions() {
        let prefix = format!("{}:", ext.id);
        let flat: Vec<String> = body
            .keys()
            .filter(|k| {
                k.len() > prefix.len()
                    && k.get(..prefix.len())
                        .is_some_and(|p| p.eq_ignore_ascii_case(&prefix))
            })
            .cloned()
            .collect();
        for k in flat {
            if let Some(v) = body.remove(&k) {
                let name = k.get(prefix.len()..).unwrap_or_default().to_owned();
                let entry = body
                    .entry(String::from(ext.id))
                    .or_insert_with(|| Value::Object(Map::new()));
                if let Some(o) = entry.as_object_mut() {
                    o.insert(name, v);
                }
            }
        }
    }
}

/// The stored form of a created or replaced resource of `kind`: no `id`, no `meta`.
///
/// # Errors
/// [`ScimError`]: `invalidSyntax` for a body outside the schemas, `invalidValue` for a value,
/// `sensitive` for a password.
pub fn canonical(kind: Kind, body: &Value, profile: &Profile) -> Result<Value, ScimError> {
    let mut body = body
        .as_object()
        .cloned()
        .ok_or_else(|| ScimError::bad(ScimType::InvalidSyntax, "The body is not an object"))?;
    let core = kind.core().id;
    let listed: Vec<String> = match body.remove("schemas") {
        Some(Value::Array(a)) => a
            .iter()
            .map(|s| s.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| ScimError::bad(ScimType::InvalidSyntax, "schemas is not a list"))?,
        None if profile.has(Rule::MissingSchemas) => vec![String::from(core)],
        _ => {
            return Err(ScimError::bad(
                ScimType::InvalidSyntax,
                "The body names no schemas",
            ));
        }
    };
    if !listed.iter().any(|s| s.eq_ignore_ascii_case(core)) {
        return Err(ScimError::bad(
            ScimType::InvalidSyntax,
            "The body does not name the resource type's schema",
        ));
    }
    for s in &listed {
        if !s.eq_ignore_ascii_case(core) && schema::extension(kind, s).is_none() {
            unknown(profile)?;
        }
    }
    flatten(kind, &mut body, profile);
    let mut out = Map::new();
    let mut schemas = vec![Value::from(core)];
    for (k, v) in &body {
        if let Some(ext) = schema::extension(kind, k) {
            let o = v
                .as_object()
                .ok_or_else(|| invalid("An extension is not an object"))?;
            let mut inner = Map::new();
            for (ek, ev) in o {
                let Some(attr) = ext.attrs.iter().find(|a| a.name.eq_ignore_ascii_case(ek)) else {
                    unknown(profile)?;
                    continue;
                };
                password(attr)?;
                if attr.mutability == Mutability::ReadOnly {
                    continue;
                }
                if let Some(n) = value(attr, ev, profile, Source::Resource)? {
                    inner.insert(String::from(attr.name), n);
                }
            }
            if !inner.is_empty() {
                schemas.push(Value::from(ext.id));
                out.insert(String::from(ext.id), Value::Object(inner));
            }
            continue;
        }
        let Some(located) = schema::locate(kind, None, k) else {
            unknown(profile)?;
            continue;
        };
        let attr = located.attr;
        password(attr)?;
        if attr.mutability == Mutability::ReadOnly {
            continue;
        }
        if let Some(n) = value(attr, v, profile, Source::Resource)? {
            out.insert(String::from(attr.name), n);
        }
    }
    required(kind, &out)?;
    out.insert(String::from("schemas"), Value::Array(schemas));
    Ok(Value::Object(out))
}

/// Checks that `resource` carries every required attribute of `kind`.
///
/// # Errors
/// [`ScimError`] `invalidValue`.
pub fn required(kind: Kind, resource: &Map<String, Value>) -> Result<(), ScimError> {
    for attr in kind.core().attrs {
        if attr.required
            && attr.mutability != Mutability::ReadOnly
            && !resource.contains_key(attr.name)
        {
            return Err(invalid("A required attribute is missing"));
        }
    }
    Ok(())
}

/// The `schemas` list `resource` should carry: its core schema and each extension it holds.
pub fn reschema(kind: Kind, resource: &mut Map<String, Value>) {
    let mut schemas = vec![Value::from(kind.core().id)];
    for ext in kind.extensions() {
        let held = resource
            .get(ext.id)
            .and_then(Value::as_object)
            .is_some_and(|o| !o.is_empty());
        if held {
            schemas.push(Value::from(ext.id));
        } else {
            resource.remove(ext.id);
        }
    }
    resource.insert(String::from("schemas"), Value::Array(schemas));
}

#[cfg(test)]
mod tests;
