//! An approval on the hosted Approval Surface without a browser (OP-149 m.29 (b), m.9, §9.14.1
//! A, §9.14.5 WYSIWYS): the test user signs in with the software passkey and the session is
//! bound to the device key's Instance (OP-149 m.32); as the requesting
//! product, the client commits the intent with the PEP certificate and gets `REQUIRE_ACTION`,
//! then pushes the typed authority request with the contribution its device Instance signed
//! (`POST /v1/approve/requests`), opens the flow (`POST /v1/approve/flows`), checks the render
//! the decision point kept against its own, answers the challenge H(AAS) with the passkey
//! (`POST /v1/approve/flows/{flow}`), commits the intent again with the contribution as proof
//! and verifies the receipt the ALLOW carries (§9.8). Given a request a product already built,
//! the client only approves it.

use access_internal_api::instances::IDENTITY_PEP;
use access_kernel::ais::Statement;
use access_kernel::codec::Canonical as _;
use access_kernel::combinator::{Capacity, Mode};
use access_kernel::contribution::contribute_intent;
use access_kernel::digest::Digest;
use access_kernel::intent::{IntentEnvelope, intent_digest};
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::meta::{ExerciseBasis, HoldingRef};
use access_kernel::model::{Id, Window};
use access_kernel::receipt;
use access_kernel::render;
use access_kernel::verify::PureBackend;
use access_kernel::verify::cose::{KeySet, parse_sign1};
use access_kernel::verify::key_scope::{DomainMetadata, verify_metadata};
use serde_json::{Value, json};
use suiss_crypto::signer::Signer;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::ClientError;
use crate::adp::{self, Exercise, holding_json, pep_name};
use crate::dpop::{now_ms, random_text};
use crate::http::{Http, Response};
use crate::login::{Credential, Jar, attach_device, post_json, sign_in};
use crate::passkey::Passkey;

/// The contribute class of an approval (§9.14.1).
pub const APPROVE_CLASS: &str = "approve";

/// How long the pushed request waits on the surface, ms.
const REQUEST_TTL_MS: u64 = 60 * 60 * 1_000;

/// How long the contribution's intent stays valid, ms.
const CONTRIBUTION_TTL_MS: u64 = 10 * 60 * 1_000;

/// How far back a validity starts, ms: the clocks of this client and the server may differ.
const SKEW_MS: u64 = 60 * 1_000;

/// What an approval needs.
pub struct Approve<'a> {
    /// The realm issuer the test user signs in at.
    pub issuer: &'a str,
    /// The deployment's API base.
    pub api_base: &'a str,
    /// A redirect URI a client of the realm registered.
    pub redirect_uri: &'a str,
    /// The test user's login identifier.
    pub identifier: &'a str,
    /// The test user's software passkey.
    pub passkey: &'a Passkey<'a>,
    /// The test user's device Instance key.
    pub device: &'a dyn Signer,
    /// The PEP certificate's leaf, DER.
    pub pep_leaf_der: &'a [u8],
    /// The governing domain.
    pub domain: Digest,
    /// The test user's Party.
    pub party: Id,
    /// The test user's device Instance, named in the request when known.
    pub instance: Option<Id>,
    /// The intent, as the product writes it for the ADP.
    pub intent: &'a Value,
    /// The Party's holding of the Grant over the action.
    pub basis: HoldingRef,
    /// The Party's holding of the Grant over `access/contribute`.
    pub contribution: HoldingRef,
    /// The reason shown with the request.
    pub reason: &'a str,
    /// A pushed request a product built already; the client then approves without exercising.
    pub request: Option<&'a Value>,
}

fn unexpected(step: &'static str, r: &Response) -> ClientError {
    ClientError::Unexpected {
        step,
        status: r.status,
        body: r.text(),
    }
}

/// RFC 3339 text of a Unix millisecond time.
fn rfc3339(ms: u64) -> Result<String, ClientError> {
    i128::from(ms)
        .checked_mul(1_000_000)
        .and_then(|ns| OffsetDateTime::from_unix_timestamp_nanos(ns).ok())
        .and_then(|t| t.format(&Rfc3339).ok())
        .ok_or(ClientError::Encode)
}

fn digest_of(v: &Value, what: &'static str) -> Result<Digest, ClientError> {
    v.as_str()
        .and_then(|s| b64url_decode(s).ok())
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .map(Digest)
        .ok_or_else(|| ClientError::File(String::from(what), String::from("not a digest")))
}

/// The typed authority request (OP-149 m.9, `authority-request.cddl`) a product pushes for a
/// `REQUIRE_ACTION` it got: who asks, what for, why, and the decision it answers.
fn authority_request(a: &Approve<'_>, nonce: &[u8], intent: Digest, now: u64) -> Value {
    let mut requester = json!({ "party": b64url_encode(&a.party.0) });
    if let (Some(i), Some(r)) = (a.instance, requester.as_object_mut()) {
        r.insert(String::from("instance"), b64url_encode(&i.0).into());
    }
    let first = a.intent.get("resources").and_then(|r| r.get(0)).cloned();
    json!({
        "requester": requester,
        "action": a.intent.get("action").cloned().unwrap_or(Value::Null),
        "resource": first.unwrap_or(Value::Null),
        "params": a.intent.get("params").cloned().unwrap_or_else(|| json!({})),
        "capacity": "own",
        "reason": a.reason,
        "require_action": {
            "domain": b64url_encode(&a.domain.0),
            "nonce": b64url_encode(nonce),
            "intent": b64url_encode(&intent.0),
        },
        "expires_at": now.saturating_add(REQUEST_TTL_MS),
    })
}

/// The contribution the device pre-signs for the push (§9.14.1 A step 4, L0-META-30): an
/// `approve` of `target` under the Party's holding over `access/contribute`.
fn contribution(a: &Approve<'_>, target: Digest, now: u64) -> Result<Value, ClientError> {
    let nonce = access_crypto::random::bytes::<16>()
        .map_err(|_| ClientError::Key(String::from("random source")))?;
    let validity = Window {
        from: now.saturating_sub(SKEW_MS),
        until: now.saturating_add(CONTRIBUTION_TTL_MS),
    };
    let intent = contribute_intent(target, APPROVE_CLASS, validity).ok_or(ClientError::Encode)?;
    let statement = Statement {
        domain: a.domain,
        nonce: nonce.to_vec(),
        intent: intent_digest(&intent).map_err(|_| ClientError::Encode)?,
        mode: Mode::Commit,
        pep: String::from(IDENTITY_PEP),
        capacity: Capacity::Own,
        basis: ExerciseBasis::Holding(a.contribution),
        iat: now,
        exercise: None,
    };
    let holding = holding_json(&a.contribution);
    Ok(json!({
        "nonce": b64url_encode(&nonce),
        "class": APPROVE_CLASS,
        "basis": holding.get("holding").cloned().unwrap_or(Value::Null),
        "valid_from": rfc3339(validity.from)?,
        "valid_until": rfc3339(validity.until)?,
        "ais": b64url_encode(&adp::ais(a.device, &statement)?),
    }))
}

/// Whether the render the surface shows is the one this client computes from the intent
/// (§9.14.5 WYSIWYS): the same fields, texts and material marks, in order.
fn same_render(shown: &Value, mine: &render::Render) -> bool {
    let Some(fields) = shown.get("fields").and_then(Value::as_array) else {
        return false;
    };
    fields.len() == mine.fields.len()
        && fields.iter().zip(&mine.fields).all(|(f, m)| {
            f.get("name").and_then(Value::as_str) == Some(m.name.as_str())
                && f.get("text").and_then(Value::as_str) == Some(m.text.as_str())
                && f.get("material").and_then(Value::as_bool) == Some(m.material)
        })
}

/// Verifies `sign1` with its key `excerpt` against the domain's metadata as the ADP publishes
/// it (§9.8, CR-58 m.5, §9.15.1), for this PEP and intent.
async fn verified_receipt(
    http: &Http,
    a: &Approve<'_>,
    intent: Digest,
    sign1: &[u8],
    excerpt: &[u8],
) -> Result<Value, ClientError> {
    let domain = format!("sha-256:{}", b64url_encode(&a.domain.0));
    let r = http
        .request(
            "GET",
            &format!("{}/.well-known/access-domain-metadata/{domain}", a.api_base),
            &[],
            None,
        )
        .await?;
    if r.status != 200 {
        return Err(unexpected("domain metadata", &r));
    }
    let failed = |what: &str| ClientError::Verify(String::from(what));
    let claimed = parse_sign1(&r.body)
        .ok()
        .and_then(|s| s.payload)
        .and_then(|p| DomainMetadata::from_bytes(&p).ok())
        .ok_or_else(|| failed("metadata does not decode"))?;
    let mut trusted = KeySet::default();
    for b in claimed.binding.values() {
        trusted
            .insert(b.kid, b.key.clone())
            .map_err(|_| failed("metadata binding key"))?;
        trusted.allowed.insert(b.alg);
    }
    let metadata = verify_metadata(&PureBackend, &r.body, &trusted)
        .map_err(|e| failed(&format!("metadata: {e:?}")))?;
    let receipt = receipt::verify(
        &PureBackend,
        &metadata,
        sign1,
        excerpt,
        &receipt::Expected {
            domain: &a.domain,
            audience: &pep_name(a.pep_leaf_der),
            intent: &intent,
            now: now_ms(),
        },
    )
    .map_err(|e| failed(&format!("receipt: {e:?}")))?;
    Ok(json!({
        "verified": true,
        "exercise": b64url_encode(&receipt.exercise.0),
        "record": receipt.record,
        "audience": receipt.audience,
        "iat": receipt.iat,
        "cose_sign1": b64url_encode(sign1),
        "key_excerpt": b64url_encode(excerpt),
    }))
}

/// `GET /access/v1/exercises/{id}?domain=` (OP-149 m.21 (b)): the receipt the decision point
/// kept, once signed.
async fn kept_receipt(
    http: &Http,
    a: &Approve<'_>,
    exercise: &str,
) -> Result<Option<(Vec<u8>, Vec<u8>)>, ClientError> {
    let domain = format!("sha-256:{}", b64url_encode(&a.domain.0));
    let r = http
        .request(
            "GET",
            &format!(
                "{}/access/v1/exercises/{exercise}?domain={domain}",
                a.api_base
            ),
            &[],
            None,
        )
        .await?;
    if r.status != 200 {
        return Err(unexpected("exercise", &r));
    }
    let v = r.json();
    let part = |k: &str| {
        v.get("receipt")
            .and_then(|r| r.get(k))
            .and_then(Value::as_str)
            .and_then(|s| b64url_decode(s).ok())
    };
    Ok(part("cose_sign1").zip(part("key_excerpt")))
}

const NULL: Value = Value::Null;

/// The member `path` of `v`, `Null` when absent.
fn at<'a>(v: &'a Value, path: &[&str]) -> &'a Value {
    path.iter().fold(v, |v, k| v.get(k).unwrap_or(&NULL))
}

fn text_at(v: &Value, path: &[&str]) -> Option<String> {
    at(v, path).as_str().map(String::from)
}

/// This client's own `REQUIRE_ACTION` as the product's PEP: its nonce, and whether the decision
/// also left an `authentication` term unmet, the step-up the approval's Claim meets (§8.17.5.4,
/// OP-149 m.33 (c)).
struct Opening {
    nonce: [u8; 16],
    step_up: bool,
}

/// Whether the `REQUIRE_ACTION` explanation leaves an `authentication` Claim term unmet
/// (explanation.cddl `unmet-term`): Work's `next: step_up`.
fn asks_step_up(decision: &Value) -> bool {
    at(decision, &["context", "unmet"])
        .as_array()
        .is_some_and(|unmet| {
            unmet.iter().any(|u| {
                *at(u, &["term", "proof_kind"]) == "claim"
                    && *at(u, &["term", "class"]) == "authentication"
            })
        })
}

/// The `REQUIRE_ACTION` the approval answers (§9.14.1 step 1): the request a product built, or
/// this client's own commit of the intent as the product's PEP.
async fn opened(
    http: &Http,
    a: &Approve<'_>,
    intent: &IntentEnvelope,
    digest: Digest,
    now: u64,
) -> Result<(Value, Option<Opening>), ClientError> {
    if let Some(given) = a.request {
        let ra = at(given, &["require_action"]);
        if digest_of(at(ra, &["intent"]), "request")? != digest
            || digest_of(at(ra, &["domain"]), "request")? != a.domain
        {
            return Err(ClientError::File(
                String::from("request"),
                String::from("require_action names another intent or domain"),
            ));
        }
        return Ok((given.clone(), None));
    }
    let nonce = access_crypto::random::bytes::<16>()
        .map_err(|_| ClientError::Key(String::from("random source")))?;
    let asked = adp::commit(http, &exercise(a, intent, &nonce, Vec::new())).await?;
    if adp::outcome(&asked) != Some("require_action") {
        return Err(ClientError::Unexpected {
            step: "exercise",
            status: 200,
            body: asked.to_string(),
        });
    }
    let opening = Opening {
        nonce,
        step_up: asks_step_up(&asked),
    };
    Ok((authority_request(a, &nonce, digest, now), Some(opening)))
}

/// `POST /v1/approve/requests` (OP-149 m.9): the request with the contribution the device
/// signed; returns the `request_uri`.
async fn push(
    http: &Http,
    a: &Approve<'_>,
    request: Value,
    digest: Digest,
    now: u64,
) -> Result<String, ClientError> {
    let mut coordinator = Jar::default();
    let pushed = post_json(
        http,
        &format!("{}/v1/approve/requests", a.issuer),
        &mut coordinator,
        Some(json!({ "request": request, "contribution": contribution(a, digest, now)? })),
    )
    .await?;
    if pushed.status != 201 {
        return Err(unexpected("push", &pushed));
    }
    text_at(&pushed.json(), &["request_uri"]).ok_or_else(|| unexpected("push", &pushed))
}

/// What a started flow gives the approver: its id and the challenge H(AAS).
struct Started {
    flow: String,
    challenge: Vec<u8>,
}

/// `POST /v1/approve/flows` (§9.14.1 A step 2), with the render the decision point kept checked
/// against this intent's (§9.14.5 WYSIWYS).
async fn start(
    http: &Http,
    a: &Approve<'_>,
    jar: &mut Jar,
    request_uri: &str,
    state: &str,
    mine: &render::Render,
) -> Result<Started, ClientError> {
    let started = post_json(
        http,
        &format!("{}/v1/approve/flows", a.issuer),
        jar,
        Some(json!({ "request": request_uri, "redirect_uri": a.redirect_uri, "state": state })),
    )
    .await?;
    if started.status != 201 {
        return Err(unexpected("approval flow", &started));
    }
    let s = started.json();
    if !same_render(at(&s, &["render"]), mine) {
        return Err(ClientError::Unexpected {
            step: "render",
            status: started.status,
            body: at(&s, &["render"]).to_string(),
        });
    }
    let challenge = at(&s, &["options", "challenge"])
        .as_str()
        .and_then(|c| b64url_decode(c).ok())
        .ok_or_else(|| unexpected("approval flow", &started))?;
    let flow = text_at(&s, &["flow"]).ok_or_else(|| unexpected("approval flow", &started))?;
    Ok(Started { flow, challenge })
}

/// `POST /v1/approve/flows/{flow}` (§9.14.1 A steps 3 and 4): one assertion over H(AAS);
/// returns the answer with `exercise` and `render_digest`.
async fn finish(
    http: &Http,
    a: &Approve<'_>,
    jar: &mut Jar,
    started: &Started,
    state: &str,
) -> Result<Value, ClientError> {
    let finished = post_json(
        http,
        &format!("{}/v1/approve/flows/{}", a.issuer, started.flow),
        jar,
        Some(json!({
            "credential": a.passkey.assert(&started.challenge)?,
            "redirect_uri": a.redirect_uri,
            "state": state,
        })),
    )
    .await?;
    if finished.status != 200 {
        return Err(unexpected("approval", &finished));
    }
    Ok(finished.json())
}

/// §9.14.1 step 5: the product commits again with the contribution as its proof, and the
/// approver's `authentication` Claim too when the opening asked for a step-up (OP-149 m.33 (c)),
/// and the ALLOW's receipt is verified; returns the Exercise and the verified receipt.
async fn allowed_receipt(
    http: &Http,
    a: &Approve<'_>,
    intent: &IntentEnvelope,
    digest: Digest,
    opening: &Opening,
    contribution: &Value,
    claim: &Value,
) -> Result<(String, Value), ClientError> {
    let mut proofs = vec![json!({ "contribution": contribution })];
    if opening.step_up {
        proofs.push(json!({ "claim_ref": claim }));
    }
    let allowed = adp::commit(http, &exercise(a, intent, &opening.nonce, proofs)).await?;
    if at(&allowed, &["decision"]) != &Value::Bool(true) {
        return Err(ClientError::Unexpected {
            step: "exercise (approved)",
            status: 200,
            body: allowed.to_string(),
        });
    }
    let exercise_id = text_at(&allowed, &["context", "exercise"]).ok_or(ClientError::Encode)?;
    let part = |k: &str| {
        at(&allowed, &["context", "receipt", k])
            .as_str()
            .and_then(|s| b64url_decode(s).ok())
    };
    let signed = match kept_receipt(http, a, &exercise_id).await? {
        Some(pair) => pair,
        None => part("sign1")
            .zip(part("excerpt"))
            .ok_or_else(|| ClientError::Verify(String::from("no signed receipt")))?,
    };
    let receipt = verified_receipt(http, a, digest, &signed.0, &signed.1).await?;
    Ok((exercise_id, receipt))
}

/// Runs the approval and returns `{instance, exercise, contribution, claim, step_up,
/// render_digest, receipt}`: the device Instance the approval session was bound to, the allowed
/// Exercise with its verified receipt when this client exercised the intent, the contribution
/// Exercise, the approver's `authentication` Claim and the render digest either way, and whether
/// the opening asked for a step-up that the Claim met (OP-149 m.33 (c)).
///
/// # Errors
/// [`ClientError`]; a decision the surface or the ADP refuses with is
/// [`ClientError::Unexpected`] with what Access said (`approval-request-changed`,
/// `assertion-rejected`, …).
pub async fn approve(http: &Http, a: &Approve<'_>) -> Result<Value, ClientError> {
    let intent = crate::intent::parse(a.intent)?;
    let digest = intent_digest(&intent).map_err(|_| ClientError::Encode)?;
    let now = now_ms();
    // the approver signs in with the passkey (AAL2) and keeps the session
    let mut jar = sign_in(http, a.issuer, a.identifier, Credential::Passkey(a.passkey)).await?;
    // OP-149 m.32: the approval session carries the device's existing Instance
    let instance = attach_device(http, a.issuer, &mut jar, a.device).await?;
    let (request, opening) = opened(http, a, &intent, digest, now).await?;
    let request_uri = push(http, a, request, digest, now).await?;
    let state = random_text::<8>()?;
    let mine =
        render::of(None, &intent, render::DEFAULT_LOCALE).map_err(|_| ClientError::Encode)?;
    let started = start(http, a, &mut jar, &request_uri, &state, &mine).await?;
    // §8.17.5.4, §13.7.3: the one passkey assertion over H(AAS) is the approval and, bound to
    // the approver's Instance, the step-up of the same actor
    let finished = finish(http, a, &mut jar, &started, &state).await?;
    let render_digest = at(&finished, &["render_digest"]).clone();
    let my_digest = render::digest(&mine).map_err(|_| ClientError::Encode)?;
    let contribution = at(&finished, &["exercise"]).clone();
    let claim = at(&finished, &["claim"]).clone();
    let mut out = json!({
        "instance": instance,
        "contribution": contribution,
        "claim": claim,
        "step_up": opening.as_ref().is_some_and(|o| o.step_up),
        "render_digest": render_digest,
        "render_digest_verified": render_digest == b64url_encode(&my_digest.0),
    });
    if let Some(opening) = opening {
        let (exercise_id, receipt) =
            allowed_receipt(http, a, &intent, digest, &opening, &contribution, &claim).await?;
        if let Some(o) = out.as_object_mut() {
            o.insert(String::from("exercise"), Value::from(exercise_id));
            o.insert(String::from("receipt"), receipt);
        }
    }
    Ok(out)
}

fn exercise<'a>(
    a: &'a Approve<'a>,
    intent: &'a IntentEnvelope,
    nonce: &'a [u8],
    proofs: Vec<Value>,
) -> Exercise<'a> {
    Exercise {
        api_base: a.api_base,
        domain: a.domain,
        party: a.party,
        nonce,
        intent,
        intent_json: a.intent,
        basis: a.basis,
        proofs,
        pep_leaf_der: a.pep_leaf_der,
        device: a.device,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

    use std::collections::BTreeMap;

    use access_kernel::intent::{ContextRefs, IntentEnvelope, ParamValue};
    use access_kernel::model::{ActionRef, EqValue, ResourceRef};

    use super::*;

    // §9.14.5 WYSIWYS, OP-149 m.9: the request names the REQUIRE_ACTION it answers and the
    // render check accepts the decision point's fields only as this intent renders them
    #[test]
    fn requests_and_renders_follow_the_intent() {
        let intent = IntentEnvelope {
            action: ActionRef {
                namespace: "work".into(),
                name: "commit".into(),
                major: 1,
                schema: Digest([1; 32]),
            },
            resources: vec![ResourceRef {
                namespace: "work".into(),
                path: vec!["sample".into()],
                incarnation: 0,
            }],
            params: BTreeMap::from([(
                String::from("ledger"),
                ParamValue::Eq(EqValue::Text("main".into())),
            )]),
            opaque: BTreeMap::new(),
            recipient: None,
            purpose: None,
            context: ContextRefs::default(),
            validity: Window { from: 1, until: 2 },
        };
        let mine = render::of(None, &intent, render::DEFAULT_LOCALE).unwrap();
        let shown = json!({ "fields": [
            { "name": "action", "text": "work/commit@1", "material": true },
            { "name": "resource", "text": "work/sample", "material": true },
            { "name": "ledger", "text": "main", "material": true },
            { "name": "validity", "text": "1..2", "material": false },
        ]});
        assert!(same_render(&shown, &mine));
        let mut changed = shown.clone();
        changed["fields"][2]["text"] = json!("other");
        assert!(!same_render(&changed, &mine));
        assert!(!same_render(&json!({ "fields": [] }), &mine));
        assert_eq!(
            rfc3339(1_700_000_000_123).unwrap(),
            "2023-11-14T22:13:20.123Z"
        );
    }

    // OP-149 m.33 (c), §8.17.5.4: an unmet authentication Claim term in the REQUIRE_ACTION is
    // the step-up the approval also meets; an approval term alone is not
    #[test]
    fn a_step_up_is_an_unmet_authentication_term() {
        let approval = json!({ "term": { "proof_kind": "contribution", "class": "approve", "binding": "intent_digest" }, "missing": 1, "position": "anchor", "satisfiable_by_actor": true });
        let authentication = json!({ "term": { "proof_kind": "claim", "class": "authentication", "binding": "actor_instance", "freshness_ms": 900_000, "assurance": { "aal": 2, "phishing_resistant": 1 } }, "missing": 1, "position": "anchor", "satisfiable_by_actor": true });
        let decision = |unmet: Vec<Value>| json!({ "decision": false, "context": { "outcome": "require_action", "unmet": unmet } });
        assert!(!asks_step_up(&decision(vec![approval.clone()])));
        assert!(asks_step_up(&decision(vec![approval, authentication])));
        assert!(!asks_step_up(
            &json!({ "decision": true, "context": { "outcome": "allow" } })
        ));
    }
}
