//! One support access episode without a browser (MD-9, TN-137, §8.16, OP-157 m.3 (f), m.6
//! (i)): the support operator signs in with its password and asks the person for view access
//! for one case (`POST /v1/support/requests`); the person signs in with the software passkey,
//! attaches the device, reads the drafted `grant.issue` (`GET /v1/support/requests`), signs
//! exactly that with the device key and gives it (`POST /v1/support/requests/{id}/give`); then
//! the operator's own Instance views the person's account `For` them under the given Grant and
//! the case, through the PEP certificate. The access stays given: the person's own page lists
//! it, its use is in the person's Activity under the operator's name, and the person revokes it.

use access_kernel::ais::Statement;
use access_kernel::codec::Canonical as _;
use access_kernel::combinator::{Capacity, Mode};
use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope, intent_digest};
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::meta::{ExerciseBasis, Payload};
use access_kernel::model::{Id, PurposeRef, ResourceRef, ResourceSelector, Window};
use serde_json::{Value, json};
use suiss_crypto::signer::Signer;

use crate::ClientError;
use crate::adp::{self, Exercise};
use crate::dpop::now_ms;
use crate::http::{Http, Response};
use crate::intent::holding;
use crate::login::{Credential, Jar, attach_device, post_json, sign_in};
use crate::passkey::Passkey;

/// What the operator asks for: a view of the account (OP-157 m.3 (c)).
pub const SCOPE: &str = "read";

/// For how long, minutes (TN-137, PD).
pub const MINUTES: u32 = 30;

/// How long the operator's intent stays valid, ms.
const INTENT_TTL_MS: u64 = 10 * 60 * 1_000;

/// How far back a validity starts, ms: the clocks of this client and the server may differ.
const SKEW_MS: u64 = 60 * 1_000;

/// What an episode needs.
pub struct Episode<'a> {
    /// The realm issuer both sign in at.
    pub issuer: &'a str,
    /// The deployment's API base.
    pub api_base: &'a str,
    /// The PEP certificate's leaf, DER.
    pub pep_leaf_der: &'a [u8],
    /// The governing domain.
    pub domain: Digest,
    /// The operator's login identifier.
    pub operator: &'a str,
    /// The operator's password.
    pub operator_password: &'a str,
    /// The operator's device Instance key.
    pub operator_device: &'a dyn Signer,
    /// The operator's Party.
    pub operator_party: Id,
    /// The person's login identifier.
    pub person: &'a str,
    /// The person's account (`usr_…`).
    pub person_subject: &'a str,
    /// The person's Party.
    pub person_party: Id,
    /// The person's software passkey.
    pub person_passkey: &'a Passkey<'a>,
    /// The person's device Instance key.
    pub person_device: &'a dyn Signer,
    /// The case system's registered name.
    pub case_system: &'a str,
    /// The person's open case.
    pub case: &'a str,
}

fn unexpected(step: &'static str, r: &Response) -> ClientError {
    ClientError::Unexpected {
        step,
        status: r.status,
        body: r.text(),
    }
}

fn text<'v>(v: &'v Value, path: &[&str]) -> Option<&'v str> {
    path.iter().try_fold(v, |v, k| v.get(k))?.as_str()
}

fn bytes(v: &Value, path: &[&str], step: &'static str) -> Result<Vec<u8>, ClientError> {
    text(v, path)
        .and_then(|s| b64url_decode(s).ok())
        .ok_or_else(|| ClientError::Unexpected {
            step,
            status: 200,
            body: v.to_string(),
        })
}

fn id16(v: &Value, path: &[&str], step: &'static str) -> Result<Id, ClientError> {
    <[u8; 16]>::try_from(bytes(v, path, step)?)
        .map(Id)
        .map_err(|_| ClientError::Encode)
}

/// `GET url` with the jar's cookies.
async fn get(http: &Http, url: &str, jar: &mut Jar) -> Result<Response, ClientError> {
    let cookies = jar.header();
    let headers: Vec<(&str, &str)> = if cookies.is_empty() {
        Vec::new()
    } else {
        vec![("Cookie", cookies.as_str())]
    };
    let r = http.request("GET", url, &headers, None).await?;
    jar.take(&r);
    Ok(r)
}

/// The person's device signs the `give` Access drafted, exactly as drafted (TN-137 (1)).
fn signed_give(e: &Episode<'_>, give: &Value) -> Result<Value, ClientError> {
    let step = "support give";
    let intent = IntentEnvelope::from_bytes(&bytes(give, &["intent"], step)?)
        .map_err(|_| ClientError::Encode)?;
    let anchor = id16(give, &["basis", "anchor"], step)?;
    let nonce = access_crypto::random::bytes::<16>()
        .map_err(|_| ClientError::Key(String::from("random source")))?;
    let statement = Statement {
        domain: e.domain,
        nonce: nonce.to_vec(),
        intent: intent_digest(&intent).map_err(|_| ClientError::Encode)?,
        mode: Mode::Commit,
        pep: String::from(text(give, &["pep"]).ok_or(ClientError::Encode)?),
        capacity: Capacity::Own,
        basis: ExerciseBasis::Anchor(anchor),
        iat: now_ms(),
        exercise: None,
    };
    Ok(json!({
        "nonce": b64url_encode(&nonce),
        "intent": give["intent"],
        "payload": give["payload"],
        "basis": { "anchor": b64url_encode(&anchor.0) },
        "ais": b64url_encode(&adp::ais(e.person_device, &statement)?),
    }))
}

/// The operator's view of the person's account settings under the given Grant (TN-137 (4)):
/// the action, resource and case the drafted Grant names; the intent and its ADP JSON.
fn view_intent(give: &Value) -> Result<(IntentEnvelope, Value), ClientError> {
    let payload = Payload::from_bytes(&bytes(give, &["payload"], "support give")?)
        .map_err(|_| ClientError::Encode)?;
    let Payload::GrantIssue(content) = payload else {
        return Err(ClientError::Encode);
    };
    let a = &content.authority.authority;
    let action = a
        .actions
        .exact
        .iter()
        .next()
        .ok_or(ClientError::Encode)?
        .clone();
    let ResourceSelector::Structural(s) = &a.resource else {
        return Err(ClientError::Encode);
    };
    let case = a
        .purpose
        .as_ref()
        .and_then(|p| {
            p.iter().find_map(|x| match x {
                PurposeRef::Case(d) => Some(*d),
                _ => None,
            })
        })
        .ok_or(ClientError::Encode)?;
    let mut path = s.prefix.clone();
    path.push(String::from("settings"));
    let now = now_ms();
    let validity = Window {
        from: now.saturating_sub(SKEW_MS),
        until: now.saturating_add(INTENT_TTL_MS),
    };
    let intent = IntentEnvelope {
        provenance: std::collections::BTreeMap::new(),
        action: action.clone(),
        resources: vec![ResourceRef {
            namespace: s.namespace.clone(),
            path: path.clone(),
            incarnation: 0,
        }],
        params: std::collections::BTreeMap::new(),
        opaque: std::collections::BTreeMap::new(),
        recipient: None,
        purpose: Some(PurposeRef::Case(case)),
        context: ContextRefs::default(),
        validity,
    };
    let json = json!({
        "action": {
            "namespace": action.namespace,
            "name": action.name,
            "major": action.major,
            "schema": b64url_encode(&action.schema.0),
        },
        "resources": [{ "namespace": s.namespace, "path": path }],
        "purpose": { "case": b64url_encode(&case.0) },
        "validity": { "from": validity.from, "until": validity.until },
    });
    Ok((intent, json))
}

/// Runs the episode and returns `{request, grant, since, exercise}`: the request's id, the given
/// Grant and where its holding opened, and the operator's allowed view.
///
/// # Errors
/// [`ClientError`]; a step Access refuses is [`ClientError::Unexpected`] with what it said
/// (`support-operator-required`, `support-case-required`, `support-not-given`, …).
#[expect(
    clippy::too_many_lines,
    reason = "one episode: ask, give, view, in the order they happen"
)]
pub async fn episode(http: &Http, e: &Episode<'_>) -> Result<Value, ClientError> {
    let mut operator = sign_in(
        http,
        e.issuer,
        e.operator,
        Credential::Password(e.operator_password, None),
    )
    .await?;
    let asked = post_json(
        http,
        &format!("{}/v1/support/requests", e.issuer),
        &mut operator,
        Some(json!({
            "subject": e.person_subject,
            "case_system": e.case_system,
            "case": e.case,
            "scope": SCOPE,
            "minutes": MINUTES,
        })),
    )
    .await?;
    if asked.status != 201 {
        return Err(unexpected("support request", &asked));
    }
    let request = String::from(
        text(&asked.json(), &["id"]).ok_or_else(|| unexpected("support request", &asked))?,
    );
    let mut person = sign_in(
        http,
        e.issuer,
        e.person,
        Credential::Passkey(e.person_passkey),
    )
    .await?;
    attach_device(http, e.issuer, &mut person, e.person_device).await?;
    let listed = get(
        http,
        &format!("{}/v1/support/requests", e.issuer),
        &mut person,
    )
    .await?;
    if listed.status != 200 {
        return Err(unexpected("support requests", &listed));
    }
    let rows = listed.json();
    let give = rows
        .get("requests")
        .and_then(Value::as_array)
        .and_then(|r| {
            r.iter()
                .find(|r| text(r, &["id"]) == Some(request.as_str()))
        })
        .and_then(|r| r.get("give"))
        .cloned()
        .ok_or_else(|| unexpected("support requests", &listed))?;
    let given = post_json(
        http,
        &format!("{}/v1/support/requests/{request}/give", e.issuer),
        &mut person,
        Some(signed_give(e, &give)?),
    )
    .await?;
    if given.status != 201 {
        return Err(unexpected("support give", &given));
    }
    let g = given.json();
    let grant = id16(&g, &["basis", "holding", "grant"], "support give")?;
    let since = g
        .get("basis")
        .and_then(|b| b.get("holding"))
        .and_then(|h| h.get("since"))
        .and_then(Value::as_u64)
        .ok_or_else(|| unexpected("support give", &given))?;
    let (intent, intent_json) = view_intent(&give)?;
    let nonce = access_crypto::random::bytes::<16>()
        .map_err(|_| ClientError::Key(String::from("random source")))?;
    let viewed = adp::commit(
        http,
        &Exercise {
            api_base: e.api_base,
            domain: e.domain,
            party: e.operator_party,
            nonce: &nonce,
            intent: &intent,
            intent_json: &intent_json,
            basis: holding(grant, e.operator_party, since),
            capacity: Capacity::For(e.person_party),
            proofs: Vec::new(),
            pep_leaf_der: e.pep_leaf_der,
            device: e.operator_device,
        },
    )
    .await?;
    if adp::outcome(&viewed) != Some("allow") {
        return Err(ClientError::Unexpected {
            step: "support view",
            status: 200,
            body: viewed.to_string(),
        });
    }
    Ok(json!({
        "request": request,
        "grant": b64url_encode(&grant.0),
        "since": since,
        "exercise": viewed.get("context").and_then(|c| c.get("exercise")).cloned().unwrap_or(Value::Null),
    }))
}
