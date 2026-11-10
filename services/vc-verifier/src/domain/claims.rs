//! The Claims a verified presentation becomes (Ek B 4831; §10.7.2, IDP-21, AP-7, PI-3): issued
//! by the verifier's operator Party, bound to and signed by the verifier Instance, about the
//! subject Party the request named. A PID becomes an `identity_binding_person` whose evidence is
//! the digest of what was verified, with `loa_eidas` only where [`super::trust::loa_eidas`]
//! gives it; a boolean or integer claim becomes a `vc_<name>` attribute Claim. Text values never
//! leave the verifier: they enter only the evidence digest. A Claim counts only where an
//! Acceptance names the verifier as issuer (IDI-9).

use std::collections::BTreeMap;

use access_kernel::claim::Statement;
use access_kernel::claim::body::{BindingKind, Body, Class, IdentityBinding, body_digest};
use access_kernel::digest::Digest;
use access_kernel::json::Json;
use access_kernel::model::{EqValue, Id, Window};
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::context_digest;

use super::dcql::{Path, Step, path_json};

/// The context label of a person binding's evidence digest.
pub const EVIDENCE_CONTEXT: &str = "access/vc-verifier/person-evidence/v1";
/// The longest a verifier Claim holds: a year, and never past the credential's own end.
pub const VALIDITY_MS: u64 = 365 * 24 * 3_600_000;
/// The prefix of an attribute Claim class.
pub const ATTRIBUTE_PREFIX: &str = "vc_";

/// Who reports: the verifier Instance and its operator Party.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reporter {
    /// The operator Party: the Claims' issuer.
    pub operator: Id,
    /// The verifier Instance whose key signs.
    pub instance: Id,
}

/// What was verified, in the shape the Claims need.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    /// The domain the request was for.
    pub domain: Digest,
    /// The subject Party the request named.
    pub subject: Id,
    /// The credential issuer (`iss`, or the leaf certificate's digest for an mdoc).
    pub issuer: String,
    /// `vct` or `docType`.
    pub credential_type: String,
    /// Whether the credential is the EU PID.
    pub pid: bool,
    /// `loa_eidas`, when the trust rule gives it.
    pub loa_eidas: Option<u64>,
    /// The values at the asked paths.
    pub values: Vec<(Path, Json)>,
    /// When the credential stops holding, milliseconds.
    pub until: u64,
}

/// A Claim ready to sign: the statement and, for a class with a body, its canonical bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// The statement.
    pub statement: Statement,
    /// The body.
    pub body: Option<Vec<u8>>,
}

fn path_text(p: &Path) -> String {
    path_json(p).to_string()
}

fn value_digest(v: &Json) -> [u8; 32] {
    suiss_crypto::digest::sha256(json_text(v).as_bytes())
}

fn json_text(v: &Json) -> String {
    match v {
        Json::Null => String::from("null"),
        Json::Bool(b) => b.to_string(),
        Json::Int(i) => i.to_string(),
        Json::Str(s) => serde_json::Value::from(s.as_str()).to_string(),
        Json::Array(items) => format!(
            "[{}]",
            items.iter().map(json_text).collect::<Vec<_>>().join(",")
        ),
        Json::Object(m) => format!(
            "{{{}}}",
            m.iter()
                .map(|(k, v)| format!("{}:{}", serde_json::Value::from(k.as_str()), json_text(v)))
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

/// The evidence digest of a person binding: issuer, type and every asked path with its value's
/// digest, in path order.
#[must_use]
pub fn evidence(v: &Verified) -> Digest {
    let mut entries: Vec<(String, [u8; 32])> = v
        .values
        .iter()
        .map(|(p, j)| (path_text(p), value_digest(j)))
        .collect();
    entries.sort();
    let value = Value::Array(vec![
        Value::text(&v.issuer),
        Value::text(&v.credential_type),
        Value::Array(
            entries
                .into_iter()
                .map(|(p, d)| Value::Array(vec![Value::text(&p), Value::Bytes(d.to_vec())]))
                .collect(),
        ),
    ]);
    let bytes = dcbor::encode(&value, Limits::CEILING).unwrap_or_default();
    Digest(context_digest(EVIDENCE_CONTEXT, &bytes).0)
}

/// The attribute class of an asked path: `vc_` and its last member name in lower case, other
/// characters as `_`, at most 63 characters.
#[must_use]
pub fn attribute_class(p: &Path) -> Option<String> {
    let name = p.iter().rev().find_map(|s| match s {
        Step::Key(k) => Some(k.as_str()),
        _ => None,
    })?;
    let mut class = String::from(ATTRIBUTE_PREFIX);
    for c in name.chars() {
        class.push(if c.is_ascii_alphanumeric() {
            c.to_ascii_lowercase()
        } else {
            '_'
        });
    }
    class.truncate(63);
    Some(class)
}

fn statement(
    v: &Verified,
    by: Reporter,
    class: String,
    value: Option<EqValue>,
    at: u64,
) -> Statement {
    let mut assurance = BTreeMap::new();
    if let Some(l) = v.loa_eidas {
        assurance.insert(String::from("loa_eidas"), l);
    }
    Statement {
        domain: v.domain,
        issuer: by.operator,
        subject: v.subject,
        class,
        value,
        issued_at: at,
        validity: Window {
            from: at,
            until: at.saturating_add(VALIDITY_MS).min(v.until),
        },
        assurance,
        bound_intent: None,
        bound_instance: Some(by.instance),
        bound_resource: None,
        supersedes: None,
    }
}

/// The Claims of one verified credential.
#[must_use]
pub fn reports(v: &Verified, by: Reporter, at: u64) -> Vec<Report> {
    let mut out = Vec::new();
    if v.pid {
        let body = Body::IdentityBinding(IdentityBinding {
            evidence: evidence(v),
            workload: None,
        });
        let class = Class::IdentityBinding(BindingKind::Person);
        let value = body.to_value();
        if let (Ok(digest), Ok(bytes)) = (
            body_digest(class, &value),
            dcbor::encode(&value, Limits::CEILING),
        ) {
            out.push(Report {
                statement: statement(
                    v,
                    by,
                    class.name(),
                    Some(EqValue::Bytes(digest.to_vec())),
                    at,
                ),
                body: Some(bytes),
            });
        }
    }
    let attr = Verified {
        loa_eidas: None,
        ..v.clone()
    };
    for (p, j) in &v.values {
        let value = match j {
            Json::Bool(b) => EqValue::Bool(*b),
            Json::Int(i) => EqValue::Int(*i),
            _ => continue,
        };
        if let Some(class) = attribute_class(p) {
            out.push(Report {
                statement: statement(&attr, by, class, Some(value), at),
                body: None,
            });
        }
    }
    out
}
