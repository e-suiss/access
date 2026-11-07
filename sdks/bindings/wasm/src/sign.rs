//! What a browser needs to sign an AIS with a browser key (OP-151 m.3 (e), X11): the
//! statement in canonical CBOR, the `COSE_Sign1` protected header, `Sig_structure` and envelope,
//! the device key's `COSE_Key` and thumbprint, and the decoded statement and intent a signature
//! screen shows. The private key never enters the Kernel; the browser signs the `Sig_structure`.
//! No CBOR is written in TypeScript (OP-8).

use core::fmt::Write as _;

use access_kernel::ais::{CONTENT_TYPE, Statement};
use access_kernel::codec::Canonical;
use access_kernel::combinator::{Capacity, Mode};
use access_kernel::digest::Digest;
use access_kernel::intent::IntentEnvelope;
use access_kernel::json::b64url_encode;
use access_kernel::meta::{ExerciseBasis, basis_value, exercise_basis};
use access_kernel::model::{Id, PurposeRef};
use access_kernel::render::param_text;
use access_kernel::verify::cose::PublicKey;
use access_kernel::verify::key_scope::thumbprint;
use suiss_crypto::cose::{self, to_be_signed};
use suiss_crypto::dcbor::{self, Limits, Value};
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

/// A refusal's stable name.
type Refused = &'static str;

fn js(name: Refused) -> JsError {
    JsError::new(name)
}

fn bytes32(b: &[u8]) -> Result<[u8; 32], Refused> {
    <[u8; 32]>::try_from(b).map_err(|_| "input")
}

fn id16(b: &[u8]) -> Result<Id, Refused> {
    <[u8; 16]>::try_from(b).map(Id).map_err(|_| "input")
}

fn mode_of(mode: &str) -> Result<Mode, Refused> {
    match mode {
        "commit" => Ok(Mode::Commit),
        "continue" => Ok(Mode::Continue),
        "check" => Ok(Mode::Check),
        _ => Err("input"),
    }
}

const fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Commit => "commit",
        Mode::Continue => "continue",
        Mode::Check => "check",
    }
}

/// The canonical statement (§9.5 AIS): `capacity_for` empty means `own`; `basis` is the
/// canonical CBOR of an Exercise basis; `exercise` empty means none.
///
/// # Errors
/// `input`.
#[expect(
    clippy::too_many_arguments,
    reason = "the statement's fields, as the CDDL lists them"
)]
pub(crate) fn statement(
    domain: &[u8],
    nonce: &[u8],
    intent: &[u8],
    mode: &str,
    pep: &str,
    capacity_for: &[u8],
    basis: &[u8],
    iat: u64,
    exercise: &[u8],
) -> Result<Vec<u8>, Refused> {
    let capacity = if capacity_for.is_empty() {
        Capacity::Own
    } else {
        Capacity::For(id16(capacity_for)?)
    };
    let basis = dcbor::decode(basis, Limits::CEILING).map_err(|_| "input")?;
    let s = Statement {
        domain: Digest(bytes32(domain)?),
        nonce: nonce.to_vec(),
        intent: Digest(bytes32(intent)?),
        mode: mode_of(mode)?,
        pep: pep.to_owned(),
        capacity,
        basis: exercise_basis(&basis).map_err(|_| "input")?,
        iat,
        exercise: if exercise.is_empty() {
            None
        } else {
            Some(Digest(bytes32(exercise)?))
        },
    };
    let out = s.to_bytes().map_err(|_| "input")?;
    Statement::from_bytes(&out).map_err(|_| "input")?;
    Ok(out)
}

/// The canonical CBOR of the basis "the public holding of Grant `grant`" or "the Anchor
/// `anchor`".
///
/// # Errors
/// `input`.
pub(crate) fn basis(kind: &str, id: &[u8]) -> Result<Vec<u8>, Refused> {
    let id = id16(id)?;
    let b = match kind {
        "public" => ExerciseBasis::Public(id),
        "anchor" => ExerciseBasis::Anchor(id),
        _ => return Err("input"),
    };
    dcbor::encode(&basis_value(&b), Limits::CEILING).map_err(|_| "input")
}

/// The protected header of an AIS by the key `kid` with COSE algorithm `alg` (−9 ESP256 or
/// −19 Ed25519).
///
/// # Errors
/// `input`.
pub(crate) fn protected(alg: i64, kid: &[u8]) -> Result<Vec<u8>, Refused> {
    if !matches!(alg, -9 | -19) {
        return Err("algorithm not allowed");
    }
    dcbor::encode(
        &Value::Map(vec![
            (Value::Unsigned(cose::ALG), Value::int(alg)),
            (
                Value::Unsigned(cose::CONTENT_TYPE),
                Value::text(CONTENT_TYPE),
            ),
            (
                Value::Unsigned(cose::KID),
                Value::Bytes(bytes32(kid)?.to_vec()),
            ),
        ]),
        Limits::CEILING,
    )
    .map_err(|_| "input")
}

/// The tagged `COSE_Sign1` of `protected`, `payload` and a 64-byte `signature`.
///
/// # Errors
/// `input`.
pub(crate) fn sign1(
    protected: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> Result<Vec<u8>, Refused> {
    if signature.len() != 64 {
        return Err("input");
    }
    let v = Value::Tag(
        18,
        Box::new(Value::Array(vec![
            Value::Bytes(protected.to_vec()),
            Value::Map(Vec::new()),
            Value::Bytes(payload.to_vec()),
            Value::Bytes(signature.to_vec()),
        ])),
    );
    let out = dcbor::encode(&v, Limits::CEILING).map_err(|_| "input")?;
    cose::parse_sign1(&out).map_err(|_| "input")?;
    Ok(out)
}

fn p256(x: &[u8], y: &[u8]) -> Result<PublicKey, Refused> {
    let (x, y) = (bytes32(x)?, bytes32(y)?);
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(4);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    let key = PublicKey::P256(sec1);
    key.check().map_err(|_| "input")?;
    Ok(key)
}

/// The `COSE_Key` of a P-256 public key (RFC 9052 §7, without `alg`): how a device presents
/// its key to the device Instance flow (OP-149 m.6).
///
/// # Errors
/// `input` for coordinates that are not a P-256 point.
pub(crate) fn cose_key_p256(x: &[u8], y: &[u8]) -> Result<Vec<u8>, Refused> {
    p256(x, y)?;
    dcbor::encode(
        &Value::Map(vec![
            (Value::Unsigned(1), Value::Unsigned(2)),
            (Value::int(-1), Value::Unsigned(1)),
            (Value::int(-2), Value::Bytes(x.to_vec())),
            (Value::int(-3), Value::Bytes(y.to_vec())),
        ]),
        Limits::CEILING,
    )
    .map_err(|_| "input")
}

/// The RFC 7638 thumbprint of a P-256 public key: the `kid` of its AIS (CR-24).
///
/// # Errors
/// `input`.
pub(crate) fn thumbprint_p256(x: &[u8], y: &[u8]) -> Result<Vec<u8>, Refused> {
    Ok(thumbprint(&p256(x, y)?).to_vec())
}

/// JSON string literal.
fn q(s: &str) -> String {
    let mut out = String::with_capacity(s.len().saturating_add(2));
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 || matches!(c, '\u{2028}' | '\u{2029}') => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn b(bytes: &[u8]) -> String {
    q(&b64url_encode(bytes))
}

/// The statement in `bytes` as the Kernel decodes it, as JSON: what a signature screen shows
/// (X11). Integers are strings (OP-8).
///
/// # Errors
/// `input`.
pub(crate) fn describe_statement(bytes: &[u8]) -> Result<String, Refused> {
    let s = Statement::from_bytes(bytes).map_err(|_| "input")?;
    let capacity = match s.capacity {
        Capacity::Own => q("own"),
        Capacity::For(p) => format!("{{\"for\":{}}}", b(&p.0)),
    };
    let basis = match &s.basis {
        ExerciseBasis::Anchor(a) => format!("{{\"anchor\":{}}}", b(&a.0)),
        ExerciseBasis::Public(g) => format!("{{\"public\":{}}}", b(&g.0)),
        ExerciseBasis::Holding(h) => format!(
            "{{\"holding\":{{\"grant\":{},\"holder\":{},\"since\":{}}}}}",
            b(&h.grant.0),
            b(&h.holder.0),
            q(&h.since.to_string())
        ),
    };
    Ok(format!(
        "{{\"domain\":{},\"nonce\":{},\"intent\":{},\"mode\":{},\"pep\":{},\"capacity\":{capacity},\"basis\":{basis},\"iat\":{},\"exercise\":{}}}",
        b(&s.domain.0),
        b(&s.nonce),
        b(&s.intent.0),
        q(mode_name(s.mode)),
        q(&s.pep),
        q(&s.iat.to_string()),
        s.exercise.map_or_else(|| String::from("null"), |e| b(&e.0)),
    ))
}

/// The intent envelope in `bytes` as the Kernel decodes it, as JSON, with its digest: the
/// action, resources, typed parameters as text, opaque parameter names, recipient, purpose and
/// validity a signature screen shows (X11).
///
/// # Errors
/// `input`.
pub(crate) fn describe_intent(bytes: &[u8]) -> Result<String, Refused> {
    let e = IntentEnvelope::from_bytes(bytes).map_err(|_| "input")?;
    let digest = access_kernel::intent::intent_digest(&e).map_err(|_| "input")?;
    let resources: Vec<String> = e
        .resources
        .iter()
        .map(|r| {
            let path: Vec<String> = r.path.iter().map(|p| q(p)).collect();
            format!(
                "{{\"namespace\":{},\"path\":[{}],\"incarnation\":{}}}",
                q(&r.namespace),
                path.join(","),
                q(&r.incarnation.to_string())
            )
        })
        .collect();
    let params: Vec<String> = e
        .params
        .iter()
        .map(|(k, v)| format!("{}:{}", q(k), q(&param_text(v))))
        .collect();
    let opaque: Vec<String> = e.opaque.keys().map(|k| q(k)).collect();
    let purpose = match &e.purpose {
        None => String::from("null"),
        Some(PurposeRef::Code(c)) => format!("{{\"code\":{}}}", q(c)),
        Some(PurposeRef::Work(d)) => format!("{{\"work\":{}}}", b(&d.0)),
        Some(PurposeRef::Aim(d)) => format!("{{\"aim\":{}}}", b(&d.0)),
    };
    Ok(format!(
        "{{\"digest\":{},\"action\":{{\"namespace\":{},\"name\":{},\"major\":{}}},\"resources\":[{}],\"params\":{{{}}},\"opaque\":[{}],\"recipient\":{},\"purpose\":{purpose},\"validity\":{{\"from\":{},\"until\":{}}}}}",
        b(&digest.0),
        q(&e.action.namespace),
        q(&e.action.name),
        q(&e.action.major.to_string()),
        resources.join(","),
        params.join(","),
        opaque.join(","),
        e.recipient
            .map_or_else(|| String::from("null"), |r| b(&r.0)),
        q(&e.validity.from.to_string()),
        q(&e.validity.until.to_string()),
    ))
}

/// See [`statement`].
///
/// # Errors
/// `input`.
#[wasm_bindgen(js_name = aisStatement)]
#[expect(
    clippy::too_many_arguments,
    reason = "the statement's fields, as the CDDL lists them"
)]
pub fn ais_statement(
    domain: &[u8],
    nonce: &[u8],
    intent: &[u8],
    mode: &str,
    pep: &str,
    capacity_for: &[u8],
    basis_cbor: &[u8],
    iat: u64,
    exercise: &[u8],
) -> Result<Vec<u8>, JsError> {
    statement(
        domain,
        nonce,
        intent,
        mode,
        pep,
        capacity_for,
        basis_cbor,
        iat,
        exercise,
    )
    .map_err(js)
}

/// See [`basis`].
///
/// # Errors
/// `input`.
#[wasm_bindgen(js_name = exerciseBasis)]
pub fn exercise_basis_cbor(kind: &str, id: &[u8]) -> Result<Vec<u8>, JsError> {
    basis(kind, id).map_err(js)
}

/// See [`protected`].
///
/// # Errors
/// `input` or `algorithm not allowed`.
#[wasm_bindgen(js_name = aisProtected)]
pub fn ais_protected(alg: i32, kid: &[u8]) -> Result<Vec<u8>, JsError> {
    protected(i64::from(alg), kid).map_err(js)
}

/// The `Sig_structure` (RFC 9052 §4.4) the browser signs.
#[wasm_bindgen(js_name = coseToBeSigned)]
#[must_use]
pub fn cose_to_be_signed(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    to_be_signed(protected, payload)
}

/// See [`sign1`].
///
/// # Errors
/// `input`.
#[wasm_bindgen(js_name = coseSign1)]
pub fn cose_sign1(protected: &[u8], payload: &[u8], signature: &[u8]) -> Result<Vec<u8>, JsError> {
    sign1(protected, payload, signature).map_err(js)
}

/// See [`cose_key_p256`].
///
/// # Errors
/// `input`.
#[wasm_bindgen(js_name = coseKeyP256)]
pub fn cose_key_p256_js(x: &[u8], y: &[u8]) -> Result<Vec<u8>, JsError> {
    cose_key_p256(x, y).map_err(js)
}

/// See [`thumbprint_p256`].
///
/// # Errors
/// `input`.
#[wasm_bindgen(js_name = thumbprintP256)]
pub fn thumbprint_p256_js(x: &[u8], y: &[u8]) -> Result<Vec<u8>, JsError> {
    thumbprint_p256(x, y).map_err(js)
}

/// See [`describe_statement`].
///
/// # Errors
/// `input`.
#[wasm_bindgen(js_name = describeStatement)]
pub fn describe_statement_js(bytes: &[u8]) -> Result<String, JsError> {
    describe_statement(bytes).map_err(js)
}

/// See [`describe_intent`].
///
/// # Errors
/// `input`.
#[wasm_bindgen(js_name = describeIntent)]
pub fn describe_intent_js(bytes: &[u8]) -> Result<String, JsError> {
    describe_intent(bytes).map_err(js)
}

#[cfg(test)]
mod tests;
