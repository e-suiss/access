//! Shared helpers of the contract tests: where the committed documents live, how they are
//! compared and rewritten, and a small JSON Schema checker for the examples.

#![allow(dead_code, reason = "each contract test uses a part of the helpers")]

use std::path::PathBuf;

use serde_json::Value;

pub(crate) fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../sdks/openapi")
}

pub(crate) fn pretty(v: &impl serde::Serialize) -> String {
    let mut s = serde_json::to_string_pretty(v).unwrap();
    s.push('\n');
    s
}

pub(crate) fn check_file(path: &PathBuf, expected: &str) {
    if std::env::var_os("ACCESS_UPDATE_CONTRACTS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, expected).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(path).unwrap_or_default();
    let same = committed == expected
        || serde_json::from_str::<serde_json::Value>(&committed).ok()
            == serde_json::from_str::<serde_json::Value>(expected).ok();
    assert!(
        same,
        "{} is stale; run ACCESS_UPDATE_CONTRACTS=1 just login-contract",
        path.display()
    );
}

pub(crate) fn resolve<'a>(doc: &'a Value, schema: &'a Value) -> &'a Value {
    match schema.get("$ref").and_then(Value::as_str) {
        Some(r) => {
            let name = r.trim_start_matches("#/components/schemas/");
            resolve(doc, &doc["components"]["schemas"][name])
        }
        None => schema,
    }
}

pub(crate) fn errors(doc: &Value, schema: &Value, value: &Value, at: &str) -> Vec<String> {
    let schema = resolve(doc, schema);
    let mut out = Vec::new();
    if let Some(c) = schema.get("const")
        && c != value
    {
        out.push(format!("{at}: expected {c}"));
    }
    if let Some(e) = schema.get("enum").and_then(Value::as_array)
        && !e.contains(value)
    {
        out.push(format!("{at}: {value} not in enum"));
    }
    if let Some(alts) = schema.get("oneOf").and_then(Value::as_array) {
        let ok = alts
            .iter()
            .filter(|a| errors(doc, a, value, at).is_empty())
            .count();
        if ok != 1 {
            out.push(format!("{at}: {ok} oneOf branches match"));
        }
    }
    let ty = schema.get("type").and_then(Value::as_str);
    let type_ok = match ty {
        Some("object") => value.is_object(),
        Some("string") => value.is_string(),
        Some("integer") => value.is_u64() || value.is_i64(),
        Some("boolean") => value.is_boolean(),
        Some("array") => value.is_array(),
        _ => true,
    };
    if !type_ok {
        out.push(format!("{at}: not {}", ty.unwrap_or_default()));
        return out;
    }
    if let Some(items) = schema.get("items")
        && let Some(list) = value.as_array()
    {
        for (i, v) in list.iter().enumerate() {
            out.extend(errors(doc, items, v, &format!("{at}[{i}]")));
        }
    }
    if let Some(obj) = value.as_object() {
        for req in schema
            .get("required")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if !obj.contains_key(req.as_str().unwrap()) {
                out.push(format!("{at}: missing {req}"));
            }
        }
        let props = schema.get("properties").and_then(Value::as_object);
        for (k, v) in obj {
            if let Some(names) = schema.get("propertyNames") {
                out.extend(errors(doc, names, &Value::String(k.clone()), at));
            }
            match (
                props.and_then(|p| p.get(k)),
                schema.get("additionalProperties"),
            ) {
                (Some(s), _) => out.extend(errors(doc, s, v, &format!("{at}.{k}"))),
                (None, Some(Value::Bool(false))) => out.push(format!("{at}: unexpected {k}")),
                (None, Some(extra)) if extra.is_object() => {
                    out.extend(errors(doc, extra, v, &format!("{at}.{k}")));
                }
                _ => {}
            }
        }
    }
    out
}

pub(crate) fn validate(doc: &Value, schema: &Value, value: &Value, name: &str) {
    let errs = errors(doc, schema, value, name);
    assert!(errs.is_empty(), "{errs:#?}");
}
