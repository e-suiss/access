//! An intent as a product writes it for the ADP (L1-ADP-8, §9.13): the JSON `context.intent`
//! of an evaluation, read into the Kernel's envelope so the client can sign its digest and
//! compute its render, and the holding basis beside it.

use std::collections::BTreeMap;

use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope, ParamValue};
use access_kernel::json::b64url_decode;
use access_kernel::meta::HoldingRef;
use access_kernel::model::{ActionRef, EqValue, Id, PurposeRef, ResourceRef, Window};
use serde_json::Value;

use crate::ClientError;

fn bad(what: &str) -> ClientError {
    ClientError::File(String::from("intent"), format!("{what} is not valid"))
}

fn text(v: &Value, name: &str) -> Result<String, ClientError> {
    v.get(name)
        .and_then(Value::as_str)
        .map(String::from)
        .ok_or_else(|| bad(name))
}

fn uint(v: &Value, name: &str) -> Result<u64, ClientError> {
    v.get(name).and_then(Value::as_u64).ok_or_else(|| bad(name))
}

fn fixed<const N: usize>(v: &Value, name: &str) -> Result<[u8; N], ClientError> {
    v.as_str()
        .and_then(|s| b64url_decode(s).ok())
        .and_then(|b| <[u8; N]>::try_from(b).ok())
        .ok_or_else(|| bad(name))
}

/// A base64url 32-byte digest.
///
/// # Errors
/// [`ClientError::File`].
pub fn digest(v: &Value, name: &str) -> Result<Digest, ClientError> {
    fixed(v, name).map(Digest)
}

/// A base64url 16-byte id.
///
/// # Errors
/// [`ClientError::File`].
pub fn id(v: &Value, name: &str) -> Result<Id, ClientError> {
    fixed(v, name).map(Id)
}

fn window(v: &Value) -> Result<Window, ClientError> {
    Ok(Window {
        from: uint(v, "from")?,
        until: uint(v, "until")?,
    })
}

fn action(v: &Value) -> Result<ActionRef, ClientError> {
    Ok(ActionRef {
        namespace: text(v, "namespace")?,
        name: text(v, "name")?,
        major: uint(v, "major")?,
        schema: digest(v.get("schema").ok_or_else(|| bad("schema"))?, "schema")?,
    })
}

fn resource(v: &Value) -> Result<ResourceRef, ClientError> {
    let path = v
        .get("path")
        .and_then(Value::as_array)
        .ok_or_else(|| bad("path"))?
        .iter()
        .map(|p| p.as_str().map(String::from).ok_or_else(|| bad("path")))
        .collect::<Result<_, _>>()?;
    Ok(ResourceRef {
        namespace: text(v, "namespace")?,
        path,
        incarnation: v.get("incarnation").and_then(Value::as_u64).unwrap_or(0),
    })
}

fn eq(v: &Value) -> Result<EqValue, ClientError> {
    Ok(match v {
        Value::String(s) => EqValue::Text(s.clone()),
        Value::Number(n) => EqValue::Int(n.as_i64().ok_or_else(|| bad("eq"))?),
        Value::Bool(b) => EqValue::Bool(*b),
        Value::Object(_) => EqValue::Bytes(
            v.get("bytes")
                .and_then(Value::as_str)
                .and_then(|s| b64url_decode(s).ok())
                .ok_or_else(|| bad("eq"))?,
        ),
        _ => return Err(bad("eq")),
    })
}

fn purpose(v: &Value) -> Result<PurposeRef, ClientError> {
    let (tag, inner) = single(v, "purpose")?;
    Ok(match tag {
        "code" => PurposeRef::Code(
            inner
                .as_str()
                .map(String::from)
                .ok_or_else(|| bad("purpose"))?,
        ),
        "work" => PurposeRef::Work(digest(inner, "purpose")?),
        "aim" => PurposeRef::Aim(digest(inner, "purpose")?),
        _ => return Err(bad("purpose")),
    })
}

fn single<'a>(v: &'a Value, what: &str) -> Result<(&'a str, &'a Value), ClientError> {
    match v.as_object() {
        Some(m) if m.len() == 1 => m
            .iter()
            .next()
            .map(|(k, v)| (k.as_str(), v))
            .ok_or_else(|| bad(what)),
        _ => Err(bad(what)),
    }
}

fn param(v: &Value) -> Result<ParamValue, ClientError> {
    let (tag, inner) = single(v, "param")?;
    Ok(match tag {
        "enum" => ParamValue::Enum(
            inner
                .as_str()
                .map(String::from)
                .ok_or_else(|| bad("param"))?,
        ),
        "eq" => ParamValue::Eq(eq(inner)?),
        "amount" => ParamValue::Amount {
            value: inner
                .get("value")
                .and_then(Value::as_i64)
                .ok_or_else(|| bad("amount"))?,
            unit: text(inner, "unit")?,
        },
        "count" => ParamValue::Count(inner.as_u64().ok_or_else(|| bad("count"))?),
        "interval" => ParamValue::Interval(window(inner)?),
        "resource" => ParamValue::Resource(resource(inner)?),
        "subject" => ParamValue::Subject(id(inner, "subject")?),
        "purpose" => ParamValue::Purpose(purpose(inner)?),
        "flag" => ParamValue::Flag(inner.as_bool().ok_or_else(|| bad("flag"))?),
        _ => return Err(bad("param")),
    })
}

fn named<T>(
    v: Option<&Value>,
    each: impl Fn(&Value) -> Result<T, ClientError>,
    what: &str,
) -> Result<BTreeMap<String, T>, ClientError> {
    match v {
        None => Ok(BTreeMap::new()),
        Some(Value::Object(m)) => m.iter().map(|(k, v)| Ok((k.clone(), each(v)?))).collect(),
        Some(_) => Err(bad(what)),
    }
}

/// The intent envelope of the ADP JSON `intent` object.
///
/// # Errors
/// [`ClientError::File`] naming the member that is not valid.
pub fn parse(v: &Value) -> Result<IntentEnvelope, ClientError> {
    let resources = v
        .get("resources")
        .and_then(Value::as_array)
        .filter(|r| !r.is_empty())
        .ok_or_else(|| bad("resources"))?
        .iter()
        .map(resource)
        .collect::<Result<Vec<_>, _>>()?;
    let context = match v.get("context") {
        None => ContextRefs::default(),
        Some(c) => ContextRefs {
            plan: None,
            work: c.get("work").map(|d| digest(d, "work")).transpose()?,
            commitment: c
                .get("commitment")
                .map(|d| digest(d, "commitment"))
                .transpose()?,
            step: c.get("step").map(|d| digest(d, "step")).transpose()?,
            upstream_exercise: c
                .get("upstream_exercise")
                .map(|d| digest(d, "upstream_exercise"))
                .transpose()?,
        },
    };
    Ok(IntentEnvelope {
        provenance: BTreeMap::new(),
        action: action(v.get("action").ok_or_else(|| bad("action"))?)?,
        resources,
        params: named(v.get("params"), param, "params")?,
        opaque: named(v.get("opaque"), |d| digest(d, "opaque"), "opaque")?,
        recipient: v.get("recipient").map(|r| id(r, "recipient")).transpose()?,
        purpose: v.get("purpose").map(purpose).transpose()?,
        context,
        validity: window(v.get("validity").ok_or_else(|| bad("validity"))?)?,
    })
}

/// A holding basis of `grant` by `holder` since `since`.
#[must_use]
pub fn holding(grant: Id, holder: Id, since: u64) -> HoldingRef {
    HoldingRef {
        grant,
        holder,
        since,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

    use access_kernel::json::b64url_encode;
    use serde_json::json;

    use super::*;

    // L1-ADP-8
    #[test]
    fn the_adp_intent_reads_into_the_envelope() {
        let v = json!({
            "action": { "namespace": "work", "name": "commit", "major": 1, "schema": b64url_encode(&[1; 32]) },
            "resources": [{ "namespace": "work", "path": ["sample"] }],
            "params": {
                "ledger": { "eq": "main" },
                "declaration": { "eq": { "bytes": b64url_encode(&[2; 32]) } },
                "amount": { "amount": { "value": -5, "unit": "eur" } },
                "n": { "count": 3 },
                "when": { "interval": { "from": 1, "until": 2 } },
                "who": { "subject": b64url_encode(&[3; 16]) },
                "why": { "purpose": { "code": "audit" } },
                "ok": { "flag": true },
                "kind": { "enum": "a" },
            },
            "recipient": b64url_encode(&[4; 16]),
            "validity": { "from": 10, "until": 20 },
        });
        let e = parse(&v).unwrap();
        assert_eq!(e.action.name, "commit");
        assert_eq!(e.resources[0].path, ["sample"]);
        assert_eq!(e.params.len(), 9);
        assert_eq!(
            e.params["ledger"],
            ParamValue::Eq(EqValue::Text("main".into()))
        );
        assert_eq!(
            e.params["declaration"],
            ParamValue::Eq(EqValue::Bytes(vec![2; 32]))
        );
        assert_eq!(
            e.params["amount"],
            ParamValue::Amount {
                value: -5,
                unit: "eur".into()
            }
        );
        assert_eq!(e.recipient, Some(Id([4; 16])));
        assert_eq!(
            e.validity,
            Window {
                from: 10,
                until: 20
            }
        );
        let mut no_resource = v.clone();
        no_resource["resources"] = json!([]);
        assert!(
            parse(&no_resource)
                .unwrap_err()
                .to_string()
                .contains("resources")
        );
        let mut short = v;
        short["action"]["schema"] = json!("AQID");
        assert!(parse(&short).unwrap_err().to_string().contains("schema"));
    }
}
