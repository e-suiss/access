//! The render of an intent for an Approval Surface or S1 (§9.13.3 `render`, §9.14.5 WYSIWYS,
//! XI-8): what the approver is shown, built from the accepted Action Schema's render definition
//! and the intent alone, so the decision point and every conformant surface compute the same
//! `render_digest`. The render is presentation data: it names no authority and is no
//! instruction (A-7). A render that differs from the decision point's is "The request changed
//! after you approved…" and collects no approval (§9.14.2).

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::context_digest;

use crate::digest::Digest;
use crate::intent::{IntentEnvelope, ParamValue, intent_digest};
use crate::model::{EqValue, PurposeRef, ResourceRef};
use crate::schema::{ActionSchema, EffectClass};

/// Digest context of a render.
pub const CONTEXT: &str = "access/render/v1";

/// The locale a surface renders in when the realm names none; localisations are Stage 8 and
/// change the tag, never the fields.
pub const DEFAULT_LOCALE: &str = "en";

/// Field name of the action.
pub const ACTION: &str = "action";
/// Field name of the primary resource.
pub const RESOURCE: &str = "resource";
/// Field name of the recipient.
pub const RECIPIENT: &str = "recipient";
/// Field name of the validity window.
pub const VALIDITY: &str = "validity";

/// One line the approver sees.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    /// The field: a schema parameter's name, or one of the fixed names.
    pub name: String,
    /// Its canonical text.
    pub text: String,
    /// Whether it is a material field of the effect class (§9.14.5).
    pub material: bool,
}

/// The render of one intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Render {
    /// The Action Schema's digest, which the render definition is part of (XI-8).
    pub schema: Digest,
    /// The intent digest.
    pub intent: Digest,
    /// Locale tag.
    pub locale: String,
    /// The schema's render template, when it has one.
    pub template: Option<String>,
    /// The fields, in display order: action, resource, parameters by name, recipient, validity.
    pub fields: Vec<Field>,
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn resource_text(r: &ResourceRef) -> String {
    let mut out = r.namespace.clone();
    for p in &r.path {
        out.push('/');
        out.push_str(p);
    }
    if r.incarnation != 0 {
        out.push('@');
        out.push_str(&u64_text(r.incarnation));
    }
    out
}

fn u64_text(n: u64) -> String {
    use core::fmt::Write as _;
    let mut out = String::new();
    let _ = write!(out, "{n}");
    out
}

fn i64_text(n: i64) -> String {
    if n < 0 {
        let mut out = String::from("-");
        out.push_str(&u64_text(n.unsigned_abs()));
        out
    } else {
        u64_text(n.unsigned_abs())
    }
}

fn eq_text(v: &EqValue) -> String {
    match v {
        EqValue::Text(t) => t.clone(),
        EqValue::Bytes(b) => hex(b),
        EqValue::Int(i) => i64_text(*i),
        EqValue::Bool(b) => String::from(if *b { "true" } else { "false" }),
    }
}

fn purpose_text(p: &PurposeRef) -> String {
    match p {
        PurposeRef::Code(c) => c.clone(),
        PurposeRef::Work(d) | PurposeRef::Aim(d) => hex(&d.0),
    }
}

/// The canonical text of a parameter value.
#[must_use]
pub fn param_text(v: &ParamValue) -> String {
    match v {
        ParamValue::Enum(e) => e.clone(),
        ParamValue::Eq(e) => eq_text(e),
        ParamValue::Amount { value, unit } => {
            let mut out = i64_text(*value);
            out.push(' ');
            out.push_str(unit);
            out
        }
        ParamValue::Count(c) => u64_text(*c),
        ParamValue::Interval(w) => window_text(w.from, w.until),
        ParamValue::Resource(r) => resource_text(r),
        ParamValue::Subject(id) => hex(&id.0),
        ParamValue::Purpose(p) => purpose_text(p),
        ParamValue::Flag(b) => String::from(if *b { "true" } else { "false" }),
    }
}

fn window_text(from: u64, until: u64) -> String {
    let mut out = u64_text(from);
    out.push_str("..");
    out.push_str(&u64_text(until));
    out
}

/// Whether a parameter of `schema` is material: every authority-relevant parameter of an
/// irreversible or reversible action; none of an action without effect (§9.13.3
/// `effect_class`, §9.14.5).
#[must_use]
pub fn material(schema: Option<&ActionSchema>) -> bool {
    schema.is_none_or(|s| s.effect != EffectClass::None)
}

/// The render of `intent` under `schema` in `locale`.
///
/// # Errors
/// The intent cannot be encoded.
pub fn of(
    schema: Option<&ActionSchema>,
    intent: &IntentEnvelope,
    locale: &str,
) -> Result<Render, dcbor::EncodeError> {
    let params_material = material(schema);
    let mut fields = Vec::with_capacity(intent.params.len().saturating_add(4));
    let mut action = intent.action.namespace.clone();
    action.push('/');
    action.push_str(&intent.action.name);
    action.push('@');
    action.push_str(&u64_text(intent.action.major));
    fields.push(Field {
        name: String::from(ACTION),
        text: action,
        material: true,
    });
    if let Some(r) = intent.resources.first() {
        fields.push(Field {
            name: String::from(RESOURCE),
            text: resource_text(r),
            material: true,
        });
    }
    for (name, value) in &intent.params {
        fields.push(Field {
            name: name.clone(),
            text: param_text(value),
            material: params_material,
        });
    }
    if let Some(r) = &intent.recipient {
        fields.push(Field {
            name: String::from(RECIPIENT),
            text: hex(&r.0),
            material: true,
        });
    }
    fields.push(Field {
        name: String::from(VALIDITY),
        text: window_text(intent.validity.from, intent.validity.until),
        material: false,
    });
    Ok(Render {
        schema: intent.action.schema,
        intent: intent_digest(intent)?,
        locale: String::from(locale),
        template: schema.and_then(|s| s.render.clone()),
        fields,
    })
}

/// The material fields of a render, sorted without repeats: the AAS `material_fields`.
#[must_use]
pub fn material_fields(r: &Render) -> BTreeSet<String> {
    r.fields
        .iter()
        .filter(|f| f.material)
        .map(|f| f.name.clone())
        .collect()
}

fn value(r: &Render) -> Value {
    let mut entries = alloc::vec![
        (Value::text("schema"), r.schema.to_value()),
        (Value::text("intent"), r.intent.to_value()),
        (Value::text("locale"), Value::text(&r.locale)),
        (
            Value::text("fields"),
            Value::Array(
                r.fields
                    .iter()
                    .map(|f| {
                        Value::Array(alloc::vec![
                            Value::text(&f.name),
                            Value::text(&f.text),
                            Value::Bool(f.material),
                        ])
                    })
                    .collect(),
            ),
        ),
    ];
    if let Some(t) = &r.template {
        entries.push((Value::text("template"), Value::text(t)));
    }
    Value::Map(entries)
}

/// `render_digest`: the digest of the render under `access/render/v1`.
///
/// # Errors
/// The render cannot be encoded.
pub fn digest(r: &Render) -> Result<Digest, dcbor::EncodeError> {
    let bytes = dcbor::encode(&value(r), Limits::CEILING)?;
    Ok(Digest(context_digest(CONTEXT, &bytes).0))
}

#[cfg(test)]
mod tests;
