//! Offboarding's commit (OP-157 m.3 (v), m.6 (a), §8.17.9.6, E6, X20, TN-75): the caller's
//! signed Exercises, in order, with one explicit choice for every channel the preview names.
//!
//! The body is `{choices, operations}`:
//! - `choices` names every channel: `grants` (each direct Grant `keep` or `revoke`), `instances`
//!   (each Instance `terminate`), `holdings` (each rule-shaped holding `retain`, `exclude` or
//!   `restrict`), `self_anchor` (`retire` or `transfer`) and `reentry` (`allowed` or `blocked`).
//!   A channel member without a choice, or a choice the preview does not offer, is `422
//!   offboarding-disposition-missing`; nothing has a default.
//! - `operations` are the caller's own meta-action commits, each with its own AIS: a
//!   `grant_revoke` per revoked Grant, a `grant_amend` per excluded or restricted holding, an
//!   `instance_terminate` per Instance and, last, the departure: `party_depart` for `retire`, or
//!   the self-anchor's `anchor_transfer` for `transfer`. They must carry out the choices exactly.
//!
//! The envelope's AIS signs the commit digest, which names the Party, the choices and every
//! operation's AIS, so the envelope attributes the set and each Exercise attributes its own
//! change. There is no bulk Exercise and no atomicity (TN-125): the operations run in order and
//! the first that does not commit stops the rest. The Party reads as offboarded only once the
//! departure committed and was recorded.

use std::collections::{BTreeMap, BTreeSet};

use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::meta::Payload;
use access_kernel::model::Id;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value, json};
use suiss_crypto::dcbor::{self, Limits, Value as Cbor};
use suiss_crypto::digest::context_digest;

use super::handlers::{object, slug};
use crate::api::app::{Caller, Committed, Ctx};
use crate::api::domain::caller::{AIS_FIELD, WriteCaller, ais_kid, verify_ais};
use crate::api::ports::{
    Departure, Env, MetaTarget, MetaWrite, ResourceKind, ResourceQuery, Surfaces as _, Written,
};
use crate::problem::{Code, codes};

/// Context of an offboarding commit digest, the intent the envelope's AIS signs.
pub const CONTEXT: &str = "access/offboarding/v1";

/// Most operations in one offboarding commit.
pub const MAX_OPERATIONS: usize = 100;

/// The domain an operation is decoded with before the realm's own replaces it.
const DOMAIN_PLACEHOLDER: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// The choice for each channel (§8.17.9.6), every member named.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Choices {
    /// Each direct Grant: `keep` or `revoke`.
    pub grants: BTreeMap<String, String>,
    /// Each Instance: `terminate`.
    pub instances: BTreeMap<String, String>,
    /// Each rule-shaped holding: `retain`, `exclude` or `restrict`.
    pub holdings: BTreeMap<String, String>,
    /// `retire` or `transfer`.
    pub self_anchor: String,
    /// `allowed` or `blocked`.
    pub reentry: String,
}

fn missing() -> &'static Code {
    &codes::realm::OFFBOARDING_DISPOSITION_MISSING
}

fn channel(v: Option<&Value>) -> Result<BTreeMap<String, String>, &'static Code> {
    let Some(Value::Object(m)) = v else {
        return Err(missing());
    };
    m.iter()
        .map(|(k, v)| match v {
            Value::String(c) => Ok((k.clone(), c.clone())),
            _ => Err(missing()),
        })
        .collect()
}

fn offered(preview: &Value, ch: &str) -> Vec<String> {
    preview["channels"][ch]["choices"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// Each member of a listed channel with the choices the preview offers for it.
fn members(preview: &Value, ch: &str, id: &str) -> BTreeMap<String, Vec<String>> {
    preview["channels"][ch]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|m| {
                    let key = m.get(id)?.as_str()?.to_owned();
                    let choices = m
                        .get("choices")?
                        .as_array()?
                        .iter()
                        .filter_map(Value::as_str)
                        .map(String::from)
                        .collect();
                    Some((key, choices))
                })
                .collect()
        })
        .unwrap_or_default()
}

impl Choices {
    /// The choices `v` names, checked against `preview`: every channel member named once with
    /// a choice the preview offers it, and nothing else (E6, OP-157 m.3 (v)).
    ///
    /// # Errors
    /// `offboarding-disposition-missing`.
    pub fn parse(v: Option<&Value>, preview: &Value) -> Result<Self, &'static Code> {
        let Some(Value::Object(m)) = v else {
            return Err(missing());
        };
        if m.keys().any(|k| {
            !matches!(
                k.as_str(),
                "grants" | "instances" | "holdings" | "self_anchor" | "reentry"
            )
        }) {
            return Err(&codes::realm::INVALID_BODY);
        }
        let text = |k: &str| match m.get(k) {
            Some(Value::String(s)) => Ok(s.clone()),
            _ => Err(missing()),
        };
        let c = Self {
            grants: channel(m.get("grants"))?,
            instances: channel(m.get("instances"))?,
            holdings: channel(m.get("holdings"))?,
            self_anchor: text("self_anchor")?,
            reentry: text("reentry")?,
        };
        for (chosen, ch, id) in [
            (&c.grants, "grants", "grant"),
            (&c.instances, "instances", "instance"),
            (&c.holdings, "holdings", "grant"),
        ] {
            let listed = members(preview, ch, id);
            if listed.len() != chosen.len() {
                return Err(missing());
            }
            for (key, offer) in &listed {
                if !chosen.get(key).is_some_and(|c| offer.contains(c)) {
                    return Err(missing());
                }
            }
        }
        for (chosen, ch) in [(&c.self_anchor, "self_anchor"), (&c.reentry, "reentry")] {
            if !offered(preview, ch).contains(chosen) {
                return Err(missing());
            }
        }
        Ok(c)
    }

    fn cbor(&self) -> Cbor {
        let map = |m: &BTreeMap<String, String>| {
            Cbor::Map(
                m.iter()
                    .map(|(k, v)| (Cbor::text(k), Cbor::text(v)))
                    .collect(),
            )
        };
        Cbor::Map(vec![
            (Cbor::text("grants"), map(&self.grants)),
            (Cbor::text("instances"), map(&self.instances)),
            (Cbor::text("holdings"), map(&self.holdings)),
            (Cbor::text("self_anchor"), Cbor::text(&self.self_anchor)),
            (Cbor::text("reentry"), Cbor::text(&self.reentry)),
        ])
    }

    /// The choices as canonical JSON, the record a departure keeps.
    #[must_use]
    pub fn json(&self) -> String {
        json!({
            "grants": self.grants,
            "instances": self.instances,
            "holdings": self.holdings,
            "self_anchor": self.self_anchor,
            "reentry": self.reentry,
        })
        .to_string()
    }
}

/// One operation as submitted: its own AIS and its decoded meta-action commit.
#[derive(Clone, Debug)]
struct Operation {
    operation: String,
    key: String,
    ais: Vec<u8>,
    request: access_authority_core::domain::Request,
}

fn operation(v: Value) -> Result<Operation, &'static Code> {
    let Value::Object(mut op) = v else {
        return Err(&codes::realm::INVALID_JOB);
    };
    let operation = match op.remove("operation") {
        Some(Value::String(o)) if o.len() <= 64 => o,
        _ => return Err(&codes::realm::INVALID_JOB),
    };
    let key = match op.remove("key") {
        Some(Value::String(k)) if k.len() <= 160 => k,
        _ => return Err(&codes::realm::INVALID_JOB),
    };
    let Some(Value::Object(mut body)) = op.remove("body") else {
        return Err(&codes::realm::INVALID_JOB);
    };
    if !op.is_empty() {
        return Err(&codes::realm::INVALID_JOB);
    }
    let ais = body
        .remove(AIS_FIELD)
        .and_then(|a| a.as_str().and_then(|a| b64url_decode(a).ok()))
        .filter(|a| !a.is_empty())
        .ok_or(&codes::AIS_REQUIRED)?;
    body.insert(String::from("mode"), Value::from("commit"));
    body.insert(String::from("domain"), Value::from(DOMAIN_PLACEHOLDER));
    let raw = serde_json::to_vec(&json!({ "context": body })).map_err(|_| &codes::INTERNAL)?;
    let request = crate::adp::domain::decode_context(&raw, 1 << 20)
        .map_err(|_| &codes::realm::INVALID_JOB)?
        .request;
    let payload = request
        .payload
        .as_ref()
        .ok_or(&codes::realm::JOB_OPERATION_NOT_ALLOWED)?;
    let digest = payload.digest().map_err(|_| &codes::realm::INVALID_JOB)?;
    if request.intent.action != access_kernel::meta::core_action(payload.action())
        || request
            .intent
            .opaque
            .get(access_kernel::meta::PAYLOAD_PARAM)
            != Some(&digest)
    {
        return Err(&codes::realm::JOB_OPERATION_NOT_ALLOWED);
    }
    Ok(Operation {
        operation,
        key,
        ais,
        request,
    })
}

fn parse(raw: &[u8]) -> Result<(Map<String, Value>, Vec<Operation>), &'static Code> {
    let mut body = object(raw)?;
    body.remove(AIS_FIELD);
    let Some(Value::Array(ops)) = body.remove("operations") else {
        return Err(&codes::realm::INVALID_JOB);
    };
    if ops.is_empty() || ops.len() > MAX_OPERATIONS {
        return Err(&codes::realm::INVALID_JOB);
    }
    let ops = ops
        .into_iter()
        .map(operation)
        .collect::<Result<Vec<_>, _>>()?;
    Ok((body, ops))
}

fn b64(id: &Id) -> String {
    b64url_encode(&id.0)
}

/// Checks that `ops` carry out `c` exactly for `party` with self-anchor `anchor`: one Exercise
/// per revoked Grant, excluded or restricted holding and Instance, in any order, and the
/// departure last (OP-157 m.3 (v)).
fn carries_out(
    c: &Choices,
    ops: &[Operation],
    (party, anchor): (&str, Option<&str>),
) -> Result<(), &'static Code> {
    let refuse = &codes::realm::JOB_OPERATION_NOT_ALLOWED;
    let (last, rest) = ops.split_last().ok_or_else(missing)?;
    let departs = match (c.self_anchor.as_str(), &last.request.payload) {
        ("retire", Some(Payload::PartyDepart { party: p, .. })) => {
            last.operation == "departParty" && b64(p) == party && last.key == party
        }
        ("transfer", Some(Payload::AnchorTransfer { anchor: a, .. })) => {
            last.operation == "transferAnchor"
                && anchor == Some(b64(a).as_str())
                && last.key == party
        }
        _ => false,
    };
    if !departs {
        return Err(missing());
    }
    let mut revoked = BTreeSet::new();
    let mut amended = BTreeSet::new();
    let mut ended = BTreeSet::new();
    for o in rest {
        let (seen, id, op) = match &o.request.payload {
            Some(Payload::GrantRevoke { grant }) => (&mut revoked, b64(grant), "revokeGrant"),
            Some(Payload::GrantAmend { grant, .. }) => (&mut amended, b64(grant), "amendGrant"),
            Some(Payload::InstanceTerminate { instance }) => {
                (&mut ended, b64(instance), "terminateInstance")
            }
            _ => return Err(refuse),
        };
        if o.operation != op || o.key != id || !seen.insert(id) {
            return Err(refuse);
        }
    }
    let chosen = |m: &BTreeMap<String, String>, pick: &[&str]| -> BTreeSet<String> {
        m.iter()
            .filter(|(_, v)| pick.contains(&v.as_str()))
            .map(|(k, _)| k.clone())
            .collect()
    };
    for (want, got) in [
        (chosen(&c.grants, &["revoke"]), &revoked),
        (chosen(&c.holdings, &["exclude", "restrict"]), &amended),
        (chosen(&c.instances, &["terminate"]), &ended),
    ] {
        if got.iter().any(|g| !want.contains(g)) {
            return Err(refuse);
        }
        if want != *got {
            return Err(missing());
        }
    }
    Ok(())
}

/// The commit digest: `context_digest("access/offboarding/v1", dCBOR([party, choices,
/// [[operation, key, H(ais)], …]]))`.
fn digest(party: &str, c: &Choices, ops: &[Operation]) -> Result<[u8; 32], &'static Code> {
    let items = ops
        .iter()
        .map(|o| {
            Cbor::Array(vec![
                Cbor::text(&o.operation),
                Cbor::text(&o.key),
                Cbor::Bytes(
                    context_digest("access/offboarding-item/v1", &o.ais)
                        .0
                        .to_vec(),
                ),
            ])
        })
        .collect();
    let v = Cbor::Array(vec![Cbor::text(party), c.cbor(), Cbor::Array(items)]);
    let bytes = dcbor::encode(&v, Limits::CEILING).map_err(|_| &codes::INTERNAL)?;
    Ok(context_digest(CONTEXT, &bytes).0)
}

async fn preview<E: Env>(ctx: &Ctx<E>, party: &str) -> Result<Value, &'static Code> {
    ctx.api
        .env()
        .realm()
        .read(ResourceQuery {
            slug: slug(ctx),
            kind: ResourceKind::OffboardingPreviews,
            key: Some(party.to_owned()),
            after: None,
            limit: 1,
        })
        .await
        .map_err(|_| &codes::UNAVAILABLE)?
        .and_then(|l| l.items.into_iter().next())
        .map(|i| i.body)
        .ok_or(&codes::NOT_FOUND)
}

/// The choices and operations of `body`, checked against the Party's preview now.
async fn checked<E: Env>(
    ctx: &Ctx<E>,
    party: &str,
    raw: &[u8],
) -> Result<(Choices, Vec<Operation>), &'static Code> {
    let (mut body, ops) = parse(raw)?;
    let choices = body.remove("choices");
    if !body.is_empty() {
        return Err(&codes::realm::INVALID_BODY);
    }
    let p = preview(ctx, party).await?;
    // §8.17.9.6
    if p["departed_position"].is_string() {
        return Err(&codes::realm::CONFLICT);
    }
    let c = Choices::parse(choices.as_ref(), &p)?;
    carries_out(
        &c,
        &ops,
        (party, p["channels"]["self_anchor"]["anchor"].as_str()),
    )?;
    Ok((c, ops))
}

/// `POST …/intents` for `commitOffboarding`: the digest the envelope's AIS signs (TN-110).
///
/// # Errors
/// A problem as the commit would answer it.
pub(super) async fn draft<E: Env>(
    ctx: &Ctx<E>,
    operation: &'static str,
    mut request: Map<String, Value>,
) -> Result<Response, &'static Code> {
    let Some(Value::String(party)) = request.remove("key") else {
        return Err(&codes::realm::INVALID_BODY);
    };
    let Some(Value::Object(body)) = request.remove("body") else {
        return Err(&codes::realm::INVALID_BODY);
    };
    let raw = serde_json::to_vec(&body).map_err(|_| &codes::INTERNAL)?;
    let (c, ops) = checked(ctx, &party, &raw).await?;
    let d = digest(&party, &c, &ops)?;
    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "operation": operation,
            "key": party,
            "body": body,
            "domain": b64url_encode(&ctx.domain.0),
            "intent_digest": b64url_encode(&d),
        })),
    )
        .into_response())
}

/// The caller of one operation: its AIS by the envelope's own key, verified at `now_ms`.
async fn operation_caller<E: Env>(
    ctx: &Ctx<E>,
    o: &Operation,
    actor: [u8; 32],
    now_ms: u64,
) -> Result<WriteCaller, &'static Code> {
    let kid = ais_kid(&o.ais).map_err(|_| &codes::AIS_INVALID)?;
    if kid != actor {
        return Err(&codes::AIS_REJECTED);
    }
    let key = ctx
        .api
        .env()
        .surfaces()
        .instance_key(ctx.domain, kid, now_ms)
        .await
        .map_err(|_| &codes::UNAVAILABLE)?
        .ok_or(&codes::AIS_REJECTED)?;
    verify_ais(o.ais.clone(), kid, &key, &ctx.domain, now_ms).map_err(|_| &codes::AIS_REJECTED)
}

/// `POST …/offboarding/{party}/commit` (OP-157 m.3 (v), m.6 (a)).
///
/// # Errors
/// `422 offboarding-disposition-missing` for a channel without its choice or Exercise; the
/// problem of the first operation that does not commit.
pub(super) async fn commit<E: Env>(
    ctx: &Ctx<E>,
    party: String,
    raw: &[u8],
) -> Result<Response, &'static Code> {
    let Caller::Write(envelope) = &ctx.caller else {
        return Err(&codes::AIS_REQUIRED);
    };
    let (c, ops) = checked(ctx, &party, raw).await?;
    // TN-110
    if envelope.statement.intent.0 != digest(&party, &c, &ops)? {
        return Err(&codes::realm::JOB_INTENT_MISMATCH);
    }
    let party_id = b64url_decode(&party)
        .ok()
        .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
        .ok_or(&codes::NOT_FOUND)?;
    let now_ms = ctx
        .api
        .env()
        .clock()
        .now_ms()
        .map_err(|_| &codes::UNAVAILABLE)?;
    let mut exercises = Vec::with_capacity(ops.len());
    let mut departure = None;
    let count = ops.len();
    for (i, o) in ops.into_iter().enumerate() {
        let caller = operation_caller(ctx, &o, envelope.kid, now_ms).await?;
        let mut request = o.request;
        request.domain = ctx.domain;
        let target = (i.saturating_add(1) == count).then(|| {
            MetaTarget::Offboarding(Departure {
                party: party_id,
                choices: c.json(),
                reentry_blocked: c.reentry == "blocked",
                actor: envelope.kid,
            })
        });
        let written = ctx
            .api
            .env()
            .realm()
            .exercise(
                MetaWrite {
                    slug: slug(ctx),
                    target,
                    request,
                },
                caller,
            )
            .await
            .map_err(|_| &codes::UNAVAILABLE)?;
        match written {
            Written::Committed {
                exercise_id,
                position,
                ..
            } => {
                exercises.push(json!({
                    "operation": o.operation,
                    "key": o.key,
                    "exercise_id": b64url_encode(&exercise_id.0),
                    "position": position.to_string(),
                }));
                departure = Some(Committed {
                    exercise_id,
                    position,
                });
            }
            Written::NotAllowed | Written::Accepted { .. } => {
                return Err(&codes::EXERCISE_NOT_ALLOWED);
            }
            Written::Rejected(code) => return Err(code),
        }
    }
    let departure = departure.ok_or(&codes::INTERNAL)?;
    let mut out = departure.json();
    if let Value::Object(o) = &mut out {
        o.insert(String::from("exercises"), Value::Array(exercises));
        if let Ok(p) = preview(ctx, &party).await {
            o.insert(String::from("resource"), p);
        }
    }
    Ok((StatusCode::OK, axum::Json(out)).into_response())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    fn preview() -> Value {
        json!({
            "channels": {
                "grants": [
                    { "grant": "g1", "choices": ["keep", "revoke"] },
                    { "grant": "g2", "choices": ["keep", "revoke"] },
                ],
                "instances": [{ "instance": "i1", "choices": ["terminate"] }],
                "holdings": [{ "grant": "h1", "choices": ["retain", "exclude", "restrict"] }],
                "self_anchor": { "anchor": "a1", "choices": ["retire", "transfer"] },
                "reentry": { "choices": ["allowed", "blocked"] },
            }
        })
    }

    fn full() -> Value {
        json!({
            "grants": { "g1": "keep", "g2": "revoke" },
            "instances": { "i1": "terminate" },
            "holdings": { "h1": "retain" },
            "self_anchor": "retire",
            "reentry": "blocked",
        })
    }

    // §8.17.9.6, E6, OP-157 m.3 (v), Ek B 5649
    #[test]
    fn every_channel_needs_its_own_explicit_choice() {
        let p = preview();
        let c = Choices::parse(Some(&full()), &p).unwrap();
        assert_eq!(c.reentry, "blocked");
        let missing = &codes::realm::OFFBOARDING_DISPOSITION_MISSING;
        assert_eq!(Choices::parse(None, &p), Err(missing));
        for (path, drop) in [("grants", "g2"), ("instances", "i1"), ("holdings", "h1")] {
            let mut v = full();
            v[path].as_object_mut().unwrap().remove(drop);
            assert_eq!(Choices::parse(Some(&v), &p), Err(missing), "{path}");
        }
        for k in ["self_anchor", "reentry", "grants"] {
            let mut v = full();
            v.as_object_mut().unwrap().remove(k);
            assert_eq!(Choices::parse(Some(&v), &p), Err(missing), "{k}");
        }
        let mut v = full();
        v["grants"]["g1"] = json!("default");
        assert_eq!(Choices::parse(Some(&v), &p), Err(missing));
        let mut v = full();
        v["holdings"]["h1"] = json!("revoke");
        assert_eq!(Choices::parse(Some(&v), &p), Err(missing));
        let mut v = full();
        v["grants"]["g9"] = json!("keep");
        assert_eq!(Choices::parse(Some(&v), &p), Err(missing), "not previewed");
        let mut v = full();
        v["self_anchor"] = json!("keep");
        assert_eq!(Choices::parse(Some(&v), &p), Err(missing));
        assert_ne!(
            digest("p", &c, &[]).unwrap(),
            digest(
                "p",
                &Choices {
                    reentry: String::from("allowed"),
                    ..c.clone()
                },
                &[]
            )
            .unwrap(),
            "the envelope signs every choice"
        );
    }
}
