//! A JSON Schema (draft 2020-12) validator for the keywords the event contracts use.

use serde_json::Value as Json;

#[path = "../../../kernel/tests/contracts/regex.rs"]
#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::panic,
    reason = "the Kernel's contract test helper, shared as is"
)]
mod regex;

use regex::Regex;

pub struct Schema<'a> {
    root: &'a Json,
}

impl<'a> Schema<'a> {
    pub const fn new(root: &'a Json) -> Self {
        Self { root }
    }

    fn resolve(&self, s: &'a Json) -> &'a Json {
        match s.get("$ref").and_then(Json::as_str) {
            Some(r) => {
                let name = r.strip_prefix("#/$defs/").unwrap();
                self.resolve(&self.root["$defs"][name])
            }
            None => s,
        }
    }

    pub fn errors(&self, value: &Json) -> Vec<String> {
        let mut out = Vec::new();
        self.check(self.root, value, "$", &mut out);
        out
    }

    fn valid(&self, schema: &'a Json, value: &Json) -> bool {
        let mut out = Vec::new();
        self.check(schema, value, "", &mut out);
        out.is_empty()
    }

    #[allow(clippy::too_many_lines, reason = "one keyword per branch")]
    fn check(&self, schema: &'a Json, value: &Json, at: &str, out: &mut Vec<String>) {
        let s = self.resolve(schema);
        if let Some(c) = s.get("const")
            && c != value
        {
            out.push(format!("{at}: not {c}"));
        }
        if let Some(list) = s.get("enum").and_then(Json::as_array)
            && !list.contains(value)
        {
            out.push(format!("{at}: {value} not in enum"));
        }
        if let Some(alts) = s.get("oneOf").and_then(Json::as_array) {
            let n = alts.iter().filter(|a| self.valid(a, value)).count();
            if n != 1 {
                out.push(format!("{at}: {n} oneOf branches match"));
            }
        }
        let type_ok = match s.get("type").and_then(Json::as_str) {
            Some("object") => value.is_object(),
            Some("string") => value.is_string(),
            Some("integer") => value.is_i64() || value.is_u64(),
            Some("boolean") => value.is_boolean(),
            Some("array") => value.is_array(),
            _ => true,
        };
        if !type_ok {
            out.push(format!("{at}: wrong type"));
            return;
        }
        if let Some(n) = value.as_i64()
            && s.get("minimum")
                .and_then(Json::as_i64)
                .is_some_and(|m| n < m)
        {
            out.push(format!("{at}: below minimum"));
        }
        if let Some(text) = value.as_str() {
            let len = text.chars().count() as u64;
            if s.get("minLength")
                .and_then(Json::as_u64)
                .is_some_and(|m| len < m)
            {
                out.push(format!("{at}: too short"));
            }
            if s.get("maxLength")
                .and_then(Json::as_u64)
                .is_some_and(|m| len > m)
            {
                out.push(format!("{at}: too long"));
            }
            if let Some(p) = s.get("pattern").and_then(Json::as_str)
                && !Regex::new(p, false).is_match(text)
            {
                out.push(format!("{at}: {text} does not match {p}"));
            }
        }
        if let Some(list) = value.as_array() {
            if s.get("minItems")
                .and_then(Json::as_u64)
                .is_some_and(|m| (list.len() as u64) < m)
            {
                out.push(format!("{at}: too few items"));
            }
            if let Some(items) = s.get("items") {
                for (i, v) in list.iter().enumerate() {
                    self.check(items, v, &format!("{at}[{i}]"), out);
                }
            }
        }
        if let Some(obj) = value.as_object() {
            let n = obj.len() as u64;
            if s.get("minProperties")
                .and_then(Json::as_u64)
                .is_some_and(|m| n < m)
                || s.get("maxProperties")
                    .and_then(Json::as_u64)
                    .is_some_and(|m| n > m)
            {
                out.push(format!("{at}: wrong member count"));
            }
            for req in s
                .get("required")
                .and_then(Json::as_array)
                .into_iter()
                .flatten()
            {
                if !obj.contains_key(req.as_str().unwrap()) {
                    out.push(format!("{at}: missing {req}"));
                }
            }
            let props = s.get("properties").and_then(Json::as_object);
            for (k, v) in obj {
                if let Some(names) = s.get("propertyNames") {
                    self.check(
                        names,
                        &Json::String(k.clone()),
                        &format!("{at}.{k} (name)"),
                        out,
                    );
                }
                match (props.and_then(|p| p.get(k)), s.get("additionalProperties")) {
                    (Some(p), _) => self.check(p, v, &format!("{at}.{k}"), out),
                    (None, Some(Json::Bool(false))) => out.push(format!("{at}: unexpected {k}")),
                    (None, Some(extra)) if extra.is_object() => {
                        self.check(extra, v, &format!("{at}.{k}"), out);
                    }
                    _ => {}
                }
            }
        }
    }
}
