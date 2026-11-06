//! A JSON Schema (draft 2020-12) validator for the keywords the contracts use, and the mapping
//! of a valid JSON value to its CBOR form that the `x-cbor` annotations name.

use serde_json::Value as Json;
use suiss_crypto::dcbor::Value;

use super::regex::Regex;

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
            out.push(format!("{at}: not one of {list:?}"));
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
        if let Some(n) = value.as_i64().or_else(|| value.as_u64().map(|_| i64::MAX)) {
            if s.get("minimum")
                .and_then(Json::as_i64)
                .is_some_and(|m| n < m)
            {
                out.push(format!("{at}: below minimum"));
            }
            if s.get("maximum")
                .and_then(Json::as_i64)
                .is_some_and(|m| n > m)
            {
                out.push(format!("{at}: above maximum"));
            }
        }
        if let Some(text) = value.as_str() {
            let len = text.chars().count();
            if s.get("minLength")
                .and_then(Json::as_u64)
                .is_some_and(|m| (len as u64) < m)
            {
                out.push(format!("{at}: too short"));
            }
            if s.get("maxLength")
                .and_then(Json::as_u64)
                .is_some_and(|m| (len as u64) > m)
            {
                out.push(format!("{at}: too long"));
            }
            if let Some(p) = s.get("pattern").and_then(Json::as_str)
                && !Regex::new(p, false).is_match(text)
            {
                out.push(format!("{at}: does not match {p}"));
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
            if s.get("minProperties")
                .and_then(Json::as_u64)
                .is_some_and(|min| (obj.len() as u64) < min)
            {
                out.push(format!("{at}: too few members"));
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

    fn valid(&self, schema: &'a Json, value: &Json) -> bool {
        let mut out = Vec::new();
        self.check(schema, value, "", &mut out);
        out.is_empty()
    }

    pub fn to_cbor(&self, value: &Json) -> Value {
        self.convert(self.root, value)
    }

    fn convert(&self, schema: &'a Json, value: &Json) -> Value {
        let s = self.resolve(schema);
        if let Some(alts) = s.get("oneOf").and_then(Json::as_array) {
            let branch = alts.iter().find(|a| self.valid(a, value)).unwrap();
            return self.convert(branch, value);
        }
        match s.get("x-cbor").and_then(Json::as_str) {
            Some("bytes") => return Value::Bytes(b64url(value.as_str().unwrap())),
            Some("digest") => {
                return Value::Array(vec![
                    Value::int(-16),
                    Value::Bytes(b64url(value.as_str().unwrap())),
                ]);
            }
            Some("window") => {
                return Value::Array(vec![
                    Value::Unsigned(value["from"].as_u64().unwrap()),
                    Value::Unsigned(value["until"].as_u64().unwrap()),
                ]);
            }
            Some("bytes-member") => return Value::Bytes(b64url(value["bytes"].as_str().unwrap())),
            _ => {}
        }
        match value {
            Json::Bool(b) => Value::Bool(*b),
            Json::Number(n) => n
                .as_u64()
                .map_or_else(|| Value::int(n.as_i64().unwrap()), Value::Unsigned),
            Json::String(t) => Value::Text(t.clone()),
            Json::Array(items) => {
                let item_schema = s.get("items").unwrap_or(&Json::Null);
                Value::Array(items.iter().map(|v| self.convert(item_schema, v)).collect())
            }
            Json::Object(obj) => {
                let props = s.get("properties").and_then(Json::as_object);
                let extra = s.get("additionalProperties").unwrap_or(&Json::Null);
                let mut entries: Vec<(Value, Value)> = obj
                    .iter()
                    .map(|(k, v)| {
                        let sub = props.and_then(|p| p.get(k)).unwrap_or(extra);
                        (Value::text(k), self.convert(sub, v))
                    })
                    .collect();
                entries
                    .sort_by_key(|(k, _)| suiss_crypto::dcbor::encode(k, super::LIMITS).unwrap());
                Value::Map(entries)
            }
            Json::Null => panic!("null has no CBOR form here"),
        }
    }
}

fn b64url(text: &str) -> Vec<u8> {
    access_kernel::json::b64url_decode(text).unwrap()
}
