//! Attribute projection (RFC 7644 §3.4.2.5, §3.9; §10.6.2, Ek B 4815): `always` attributes come
//! first and cannot be excluded, then the `default` layer unless `attributes` narrows it, and
//! `never` attributes are dropped whatever the request says; `request` attributes appear only
//! when named.

use serde_json::{Map, Value};

use super::filter;
use super::schema::{self, Attr, Kind, Returned};
use super::{ScimError, ScimType};
use access_parse::scim::protocol;

/// A parsed `attributes` or `excludedAttributes` list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Selection {
    /// `(extension, attribute, sub-attribute)` names in the schema's spelling.
    names: Vec<(Option<&'static str>, &'static str, Option<&'static str>)>,
}

impl Selection {
    /// Whether nothing is named.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    fn names_attr(&self, ext: Option<&str>, attr: &str) -> bool {
        self.names.iter().any(|(e, a, _)| *e == ext && *a == attr)
    }

    fn names_whole(&self, ext: Option<&str>, attr: &str) -> bool {
        self.names
            .iter()
            .any(|(e, a, s)| *e == ext && *a == attr && s.is_none())
    }

    fn names_sub(&self, ext: Option<&str>, attr: &str, sub: &str) -> bool {
        self.names
            .iter()
            .any(|(e, a, s)| *e == ext && *a == attr && (s.is_none() || *s == Some(sub)))
    }
}

/// Parses a comma-separated attribute list of `kind`.
///
/// # Errors
/// [`ScimError`] `invalidValue` for a name the schema does not have.
pub fn selection(kind: Kind, list: Option<&str>) -> Result<Selection, ScimError> {
    let mut names = Vec::new();
    let Some(list) = list else {
        return Ok(Selection { names });
    };
    if list.len() > 4096 {
        return Err(ScimError::bad(
            ScimType::InvalidValue,
            "The attribute list is too long",
        ));
    }
    for raw in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let p = protocol::attr_path(raw)
            .map_err(|_| ScimError::bad(ScimType::InvalidValue, "An attribute name is invalid"))?;
        let Some(r) = filter::resolve(kind, &p, true) else {
            return Err(ScimError::bad(
                ScimType::InvalidValue,
                "An attribute name is not in the schema",
            ));
        };
        names.push((r.extension, r.attr.name, r.sub.map(|s| s.name)));
    }
    Ok(Selection { names })
}

fn keep(attr: &Attr, ext: Option<&str>, attributes: &Selection, excluded: &Selection) -> bool {
    match attr.returned {
        Returned::Always => true,
        Returned::Never => false,
        Returned::Request => attributes.names_attr(ext, attr.name),
        Returned::Default if !attributes.is_empty() => attributes.names_attr(ext, attr.name),
        Returned::Default => !excluded.names_whole(ext, attr.name),
    }
}

fn project_value(
    attr: &Attr,
    ext: Option<&str>,
    v: &Value,
    attributes: &Selection,
    excluded: &Selection,
) -> Option<Value> {
    if attr.sub.is_empty() {
        return Some(v.clone());
    }
    let narrow = |o: &Map<String, Value>| -> Map<String, Value> {
        o.iter()
            .filter(|(k, _)| {
                let Some(sub) = schema::sub_attr(attr, k) else {
                    return false;
                };
                if sub.returned == Returned::Never {
                    return false;
                }
                if !attributes.is_empty() && !attributes.names_whole(ext, attr.name) {
                    return attributes.names_sub(ext, attr.name, sub.name)
                        || sub.returned == Returned::Always;
                }
                !excluded
                    .names
                    .iter()
                    .any(|(e, a, s)| *e == ext && *a == attr.name && *s == Some(sub.name))
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    };
    match v {
        Value::Object(o) => {
            let n = narrow(o);
            (!n.is_empty()).then_some(Value::Object(n))
        }
        Value::Array(items) => {
            let n: Vec<Value> = items
                .iter()
                .filter_map(Value::as_object)
                .map(narrow)
                .filter(|m| !m.is_empty())
                .map(Value::Object)
                .collect();
            (!n.is_empty()).then_some(Value::Array(n))
        }
        other => Some(other.clone()),
    }
}

/// The representation of the stored `resource` of `kind` the request asks for.
#[must_use]
pub fn project(
    kind: Kind,
    resource: &Value,
    attributes: &Selection,
    excluded: &Selection,
) -> Value {
    let mut out = Map::new();
    let Some(o) = resource.as_object() else {
        return Value::Object(out);
    };
    if let Some(s) = o.get("schemas") {
        out.insert(String::from("schemas"), s.clone());
    }
    for attr in schema::COMMON.iter().chain(kind.core().attrs) {
        if let Some(v) = o.get(attr.name)
            && keep(attr, None, attributes, excluded)
            && let Some(p) = project_value(attr, None, v, attributes, excluded)
        {
            out.insert(String::from(attr.name), p);
        }
    }
    for ext in kind.extensions() {
        let Some(inner) = o.get(ext.id).and_then(Value::as_object) else {
            continue;
        };
        let mut n = Map::new();
        for attr in ext.attrs {
            if let Some(v) = inner.get(attr.name)
                && keep(attr, Some(ext.id), attributes, excluded)
                && let Some(p) = project_value(attr, Some(ext.id), v, attributes, excluded)
            {
                n.insert(String::from(attr.name), p);
            }
        }
        if !n.is_empty() {
            out.insert(String::from(ext.id), Value::Object(n));
        }
    }
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use serde_json::json;

    use super::*;

    fn user() -> Value {
        json!({
            "schemas": [schema::USER],
            "id": "u1",
            "userName": "bjensen",
            "title": "Guide",
            "name": { "givenName": "Barbara", "familyName": "Jensen" },
            "meta": { "resourceType": "User", "version": "W/\"1\"" },
        })
    }

    // IDP-23, Ek B 4815
    #[test]
    fn always_first_then_default_and_never_never() {
        let none = Selection::default();
        let all = project(Kind::User, &user(), &none, &none);
        assert_eq!(all["title"], "Guide");
        assert_eq!(all["id"], "u1");
        let only = selection(Kind::User, Some("name.givenName")).unwrap();
        let p = project(Kind::User, &user(), &only, &none);
        assert_eq!(p["id"], "u1");
        assert!(p.get("title").is_none());
        assert_eq!(p["name"], json!({ "givenName": "Barbara" }));
        let ex = selection(Kind::User, Some("title,id")).unwrap();
        let p = project(Kind::User, &user(), &none, &ex);
        assert!(p.get("title").is_none());
        assert_eq!(p["id"], "u1");
        let mut with_pw = user();
        with_pw["password"] = json!("x");
        let pw = selection(Kind::User, Some("password")).unwrap();
        assert!(
            project(Kind::User, &with_pw, &pw, &none)
                .get("password")
                .is_none()
        );
        assert!(selection(Kind::User, Some("colour")).is_err());
    }
}
