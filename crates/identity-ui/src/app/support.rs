//! Support access on the Frontend API (MD-9, TN-137, XI-7, SI-21, OP-157 m.3 (f), (g)). An
//! operator asks; the person is invited and answers on their own page; only the person's own
//! device signs the `grant.issue` that gives access, exactly as the request drafted it. Every
//! write is an Exercise committed with the identity plane as PEP, and the identity plane records,
//! audits and announces what became of it. There is no way for an operator to open the person's
//! page or to act as the person.

use access_identity_account::adapters::system::{SystemClock, SystemEntropy};
use access_identity_account::app::artifacts::{self, Format, Refused};
use access_identity_account::app::support::{
    self as model, Draft, INVITATION_MS, Names, REQUEST_PREFIX, Scope, hex,
};
use access_identity_account::domain::login::Problem;
use access_identity_oauth::ports::RealmEntry;
use access_internal_api::idp::{IdpAction, Submission, Verdict};
use access_internal_api::support::SupportAuthority;
use access_kernel::codec::Canonical as _;
use access_kernel::combinator::Capacity;
use access_kernel::digest::Digest;
use access_kernel::intent::{IntentEnvelope, ParamValue};
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::meta::{self, ExerciseBasis, HoldingRef, Payload, kind};
use access_kernel::model::{EqValue, Id, PurposeRef, ResourceRef, Window};
use access_store::audit::AuditEvent;
use access_store::identity::TenantTx;
use access_store::idp;
use access_store::support_access::{
    Answer, End, NewSupportArtifact, NewSupportRequest, SupportRequestRow,
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::me::{governing, unavailable};
use super::signup::STEP_UP_MAX_AGE_MS;
use super::{Browser, Hosted, Reply};
use crate::domain::frontend::rfc3339;
use crate::ports::{Clock, Kits, Messages, RealmKit};

/// Most requests one list shows.
const PAGE: i64 = 50;

/// Largest support artifact the route takes before the realm's own limit, bytes (PD).
pub const MAX_ARTIFACT_BYTES: usize = 10 * 1024 * 1024;

/// The context an artifact's redacted text is sealed under.
const SEAL_CONTEXT: &[u8] = b"access/support-artifact/v1";

/// The resource segment of a person's support artifacts.
const ARTIFACTS: &str = "artifacts";

const fn problem(status: u16, code: &'static str, title: &'static str) -> Problem {
    Problem {
        status,
        code,
        title,
        retry_after_s: None,
    }
}

const INVALID: Problem = problem(400, "invalid-request", "The request is not valid");
const NO_PARTY: Problem = problem(409, "support-party", "Add this device first");
const NO_ORG: Problem = problem(
    403,
    "support-operator-required",
    "Only a member of a support organization can ask for support access",
);
const UNKNOWN: Problem = problem(
    404,
    "support-request-unknown",
    "There is no open support request with this id for you",
);
const BLOCKED: Problem = problem(
    409,
    "support-blocked",
    "This person turned on Block support access",
);
const CASE_SYSTEM: Problem = problem(
    404,
    "case-system-unknown",
    "No live support case system by that name",
);
const CASE_REQUIRED: Problem = problem(
    409,
    "support-case-required",
    "The case system's cases don't count in this realm yet",
);
const NOT_GIVEN: Problem = problem(
    403,
    "support-not-given",
    "Access recorded no support access for this",
);
const FORMAT: Problem = problem(
    415,
    "artifact-format-refused",
    "Only HAR, JSON and text log files can be shared; images and videos can't be cleaned of secrets",
);
const TOO_LARGE: Problem = problem(413, "artifact-too-large", "The file is too large");
const CLOSED: Problem = problem(
    409,
    "support-artifacts-closed",
    "This realm doesn't take support files",
);
const ARTIFACT_UNKNOWN: Problem = problem(404, "support-artifact-unknown", "There is no such file");
const ARTIFACT_DENIED: Problem = problem(
    403,
    "support-artifact-denied",
    "Reading this file needs its own support access",
);

/// An Exercise a device signed, as a route carries it.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signed {
    /// The Exercise nonce, base64url.
    pub nonce: String,
    /// The intent's canonical bytes, base64url.
    pub intent: String,
    /// The meta payload's canonical bytes, base64url, for a core meta-action.
    #[serde(default)]
    pub payload: Option<String>,
    /// The basis.
    pub basis: SignedBasis,
    /// The device Instance's AIS, base64url.
    pub ais: String,
}

/// A declared basis.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SignedBasis {
    /// An Anchor's root, base64url.
    Anchor(String),
    /// A holding.
    Holding {
        /// The Grant, base64url.
        grant: String,
        /// Its holder, base64url.
        holder: String,
        /// Where its episode opened.
        since: u64,
    },
}

/// `POST /v1/support/requests`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ask {
    /// The person's account id.
    pub subject: String,
    /// The case system's registered name.
    pub case_system: String,
    /// The case as the case system shows it.
    pub case: String,
    /// `read`, `profile` or `artifacts`.
    pub scope: String,
    /// For how many minutes.
    pub minutes: u32,
}

/// `PUT /v1/me/support-block`.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Block {
    /// On or off.
    pub blocked: bool,
}

/// `POST /v1/support/artifacts`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upload {
    /// The support request the artifact is for: its case.
    pub request: String,
    /// The artifact's media type.
    pub content_type: String,
    /// The artifact's text.
    pub content: String,
    /// The person's `idp.account.artifact_upload` Exercise.
    pub exercise: Signed,
}

struct Parsed {
    nonce: Vec<u8>,
    intent: IntentEnvelope,
    payload: Option<Payload>,
    basis: ExerciseBasis,
    ais: Vec<u8>,
}

fn b64<const N: usize>(text: &str) -> Option<[u8; N]> {
    b64url_decode(text)
        .ok()
        .and_then(|b| <[u8; N]>::try_from(b).ok())
}

fn parse(s: &Signed) -> Option<Parsed> {
    let nonce = b64url_decode(&s.nonce)
        .ok()
        .filter(|n| (16..=64).contains(&n.len()))?;
    let intent = b64url_decode(&s.intent)
        .ok()
        .filter(|b| b.len() <= 16 * 1024)
        .and_then(|b| IntentEnvelope::from_bytes(&b).ok())?;
    let payload = match &s.payload {
        None => None,
        Some(p) => Some(
            b64url_decode(p)
                .ok()
                .filter(|b| b.len() <= 32 * 1024)
                .and_then(|b| Payload::from_bytes(&b).ok())?,
        ),
    };
    let ais = b64url_decode(&s.ais)
        .ok()
        .filter(|a| (1..=8192).contains(&a.len()))?;
    let basis = match &s.basis {
        SignedBasis::Anchor(a) => ExerciseBasis::Anchor(Id(b64(a)?)),
        SignedBasis::Holding {
            grant,
            holder,
            since,
        } => ExerciseBasis::Holding(HoldingRef {
            grant: Id(b64(grant)?),
            holder: Id(b64(holder)?),
            since: *since,
        }),
    };
    Some(Parsed {
        nonce,
        intent,
        payload,
        basis,
        ais,
    })
}

/// Whether a request's case label is one the case system could show: no free text (TN-73).
fn case_label(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && s.len() <= 64
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '#' | '-'))
}

/// Where a request stands.
fn state(row: &SupportRequestRow, now: u64) -> &'static str {
    match (&row.answer, row.end) {
        (_, Some((End::Revoked, _))) => "revoked",
        (_, Some((End::Ended, _))) => "ended",
        (Some((Answer::Declined, _)), _) => "declined",
        (Some((Answer::Granted { until_ms, .. }, _)), None) if now >= *until_ms => "ended",
        (Some((Answer::Granted { .. }, _)), None) => "active",
        (None, _) if now >= row.expires_ms => "expired",
        (None, _) => "waiting",
    }
}

/// The resources of a person's support artifacts.
fn artifacts_resource(person: &Id, artifact: Option<&[u8; 16]>) -> ResourceRef {
    let mut path = vec![hex(&person.0), String::from(ARTIFACTS)];
    path.extend(artifact.map(|a| hex(a)));
    ResourceRef {
        namespace: String::from(model::RESOURCES),
        path,
        incarnation: 0,
    }
}

/// Whether `intent` is `action` on `resource` for the one case `case`, naming it in `params.case`
/// as the action's schema declares (OP-157 m.6 (e)).
fn case_intent(
    intent: &IntentEnvelope,
    action: IdpAction,
    resource: &ResourceRef,
    case: &Digest,
) -> bool {
    intent.action == action.action_ref()
        && intent.resources == [resource.clone()]
        && intent.purpose == Some(PurposeRef::Case(*case))
        && intent.params.len() == 1
        && intent.params.get("case") == Some(&ParamValue::Eq(EqValue::Text(hex(&case.0))))
        && intent.recipient.is_none()
}

impl<K, C, M> Hosted<K, C, M>
where
    K: Kits,
    C: Clock + Sync,
    M: Messages,
{
    async fn begin(&self, kit: &RealmKit) -> Result<TenantTx, Reply> {
        TenantTx::begin(&self.db, kit.tenant, kit.realm)
            .await
            .map_err(|_| unavailable())
    }

    async fn party(&self, kit: &RealmKit, subject: [u8; 16]) -> Result<[u8; 16], Reply> {
        let mut t = self.begin(kit).await?;
        let p = idp::subject_party(&mut t, &subject)
            .await
            .map_err(|_| unavailable())?;
        t.commit().await.map_err(|_| unavailable())?;
        p.ok_or_else(|| Reply::problem(NO_PARTY))
    }

    async fn commit_signed<A: SupportAuthority>(
        authority: &A,
        pep: &str,
        (domain, actor, capacity): (Digest, [u8; 16], Capacity),
        p: Parsed,
    ) -> Result<access_internal_api::idp::Committed, Reply> {
        let verdict = authority
            .commit(Submission {
                domain,
                nonce: p.nonce,
                intent: p.intent,
                payload: p.payload.map(Box::new),
                basis: p.basis,
                capacity,
                ais: p.ais,
                contributions: Vec::new(),
                pep: String::from(pep),
                actor: Some(Id(actor)),
            })
            .await;
        match verdict {
            Ok(Verdict::Committed(c)) => Ok(c),
            Ok(Verdict::NotAllowed { .. } | Verdict::Refused { .. }) => {
                Err(Reply::problem(NOT_GIVEN))
            }
            Err(_) => Err(unavailable()),
        }
    }

    fn row_json(kit: &RealmKit, row: &SupportRequestRow, names: &Names, now: u64) -> Value {
        let scope = Scope::parse(&row.scope);
        let mut v = json!({
            "id": kit.ids.encode(REQUEST_PREFIX, row.id).ok(),
            "state": state(row, now),
            "operator": names.operator,
            "organization": names.organization,
            "case_system": row.case_system,
            "case": row.case_label,
            "scope": row.scope,
            "what": scope.map(Scope::what),
            "minutes": row.minutes,
            "read_only": scope != Some(Scope::Profile),
            "created_at": rfc3339(row.created_ms),
            "expires_at": rfc3339(row.expires_ms),
        });
        if let (
            Some((
                Answer::Granted {
                    grant,
                    until_ms,
                    position,
                    template,
                    ..
                },
                at,
            )),
            Value::Object(o),
        ) = (&row.answer, &mut v)
        {
            o.insert(String::from("template"), Value::from(template.as_str()));
            o.insert(String::from("given_at"), Value::from(rfc3339(*at)));
            o.insert(String::from("until"), Value::from(rfc3339(*until_ms)));
            o.insert(
                String::from("basis"),
                json!({ "holding": {
                    "grant": b64url_encode(grant),
                    "holder": b64url_encode(&row.operator_party),
                    "since": position,
                } }),
            );
        }
        if let (Some((_, at)), Value::Object(o)) = (row.end, &mut v) {
            o.insert(String::from("ended_at"), Value::from(rfc3339(at)));
        }
        v
    }

    /// `POST /v1/support/requests` (OP-157 m.3 (f), TN-137 (1)): a support operator asks for
    /// access to one person's account for one case. Access sends the person an invitation that
    /// opens their own page; nothing is granted and the operator never opens that page (XI-7).
    pub async fn ask_support(&self, entry: &RealmEntry, b: &Browser<'_>, body: &Ask) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let operator = match self.fresh(&kit, b, None).await {
            Ok((s, _)) => s,
            Err(r) => return r,
        };
        let Some(scope) = Scope::parse(&body.scope).filter(|s| s.fits(body.minutes)) else {
            return Reply::problem(INVALID);
        };
        if !case_label(&body.case) {
            return Reply::problem(INVALID);
        }
        let Ok(subject) = kit
            .ids
            .decode(access_identity_account::app::SUBJECT_PREFIX, &body.subject)
        else {
            return Reply::problem(INVALID);
        };
        if subject == operator {
            return Reply::problem(INVALID);
        }
        let operator_party = match self.party(&kit, operator).await {
            Ok(p) => p,
            Err(r) => return r,
        };
        let Ok(case_ref) = access_kernel::digest::case_ref(&body.case_system, &body.case) else {
            return Reply::problem(INVALID);
        };
        let issuer = kit.issuer.clone();
        let done = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            let now = t.server_time().await?;
            let Some(system) = t
                .case_systems()
                .await?
                .into_iter()
                .find(|c| c.name == body.case_system && c.live)
            else {
                return Ok(Err(Reply::problem(CASE_SYSTEM)));
            };
            let Some(subject_party) = idp::subject_party(&mut t, &subject).await? else {
                return Ok(Err(Reply::problem(INVALID)));
            };
            if t.support_blocked(subject).await? {
                return Ok(Err(Reply::problem(BLOCKED)));
            }
            let in_org = t.org_by_party(operator_party).await?.is_some()
                || t.orgs_of(operator).await?.iter().any(|(o, _)| !o.ended);
            if !in_org {
                return Ok(Err(Reply::problem(NO_ORG)));
            }
            let id = t
                .insert_support_request(&NewSupportRequest {
                    operator,
                    operator_party,
                    subject,
                    subject_party,
                    case_system: &system.name,
                    case_label: &body.case,
                    case_ref: case_ref.0,
                    scope: scope.name(),
                    minutes: body.minutes,
                    created_ms: now,
                    expires_ms: now.saturating_add(INVITATION_MS),
                })
                .await?;
            let Some(row) = t.support_request(id).await? else {
                return Ok(Err(unavailable()));
            };
            let names = model::names(&mut t, &*kit.kek, &row, &kit.name)
                .await
                .map_err(|_| access_store::StoreError::Corrupt)?;
            model::requested(
                &mut t,
                (&*kit.kek, &kit.ids),
                (&SystemEntropy, &SystemClock),
                &row,
                (&names, &issuer),
            )
            .await
            .map_err(|_| access_store::StoreError::Corrupt)?;
            t.commit().await?;
            Ok::<_, access_store::StoreError>(Ok((row, names, now)))
        };
        match done.await {
            Ok(Ok((row, names, now))) => Reply::json(201, Self::row_json(&kit, &row, &names, now)),
            Ok(Err(r)) => r,
            Err(_) => unavailable(),
        }
    }

    /// `GET /v1/support/requests`: the requests made to the session's person, each still open one
    /// with the exact `grant.issue` it asks for, ready to sign on the person's own device; and
    /// the requests the session's operator made, with where each stands and, once given, the
    /// holding it acts on (OP-157 m.3 (f)).
    pub async fn support_requests<A: SupportAuthority>(
        &self,
        authority: &A,
        pep: &str,
        entry: &RealmEntry,
        b: &Browser<'_>,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let subject = match self.fresh(&kit, b, None).await {
            Ok((s, _)) => s,
            Err(r) => return r,
        };
        let read = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            let now = t.server_time().await?;
            let party = idp::subject_party(&mut t, &subject).await?;
            let blocked = t.support_blocked(subject).await?;
            let to_me = t.support_requests(subject, false, now, PAGE).await?;
            let by_me = t.support_requests(subject, true, now, PAGE).await?;
            let systems = t.case_systems().await?;
            let mut named = Vec::with_capacity(to_me.len().saturating_add(by_me.len()));
            for row in to_me.iter().chain(by_me.iter()) {
                let n = model::names(&mut t, &*kit.kek, row, &kit.name)
                    .await
                    .map_err(|_| access_store::StoreError::Corrupt)?;
                named.push(n);
            }
            t.commit().await?;
            Ok::<_, access_store::StoreError>((now, party, blocked, to_me, by_me, systems, named))
        };
        let Ok((now, party, blocked, to_me, by_me, systems, labels)) = read.await else {
            return unavailable();
        };
        let domain = match governing(&self.db, &kit).await {
            Ok(d) => d,
            Err(r) => return r,
        };
        let mut names = labels.into_iter();
        let mut incoming = Vec::with_capacity(to_me.len());
        for row in &to_me {
            let Some(n) = names.next() else { break };
            let mut v = Self::row_json(&kit, row, &n, now);
            if state(row, now) == "waiting"
                && !blocked
                && let (Some(person), Some(system)) = (
                    party,
                    systems.iter().find(|s| s.name == row.case_system && s.live),
                )
            {
                match self
                    .draft(authority, (domain, pep), (person, system.issuer), row, now)
                    .await
                {
                    Ok(Some(give)) => {
                        if let Value::Object(o) = &mut v {
                            o.insert(String::from("give"), give);
                        }
                    }
                    Ok(None) => {}
                    Err(r) => return r,
                }
            }
            incoming.push(v);
        }
        let sent: Vec<Value> = by_me
            .iter()
            .zip(names)
            .map(|(row, n)| Self::row_json(&kit, row, &n, now))
            .collect();
        Reply::json(
            200,
            json!({ "requests": incoming, "sent": sent, "blocked": blocked }),
        )
    }

    /// The `grant.issue` request `row` asks the person for, as their device signs it: payload,
    /// intent and basis; `None` while the case system's Claims count for nothing here.
    async fn draft<A: SupportAuthority>(
        &self,
        authority: &A,
        (domain, pep): (Digest, &str),
        (person, issuer): ([u8; 16], [u8; 16]),
        row: &SupportRequestRow,
        now: u64,
    ) -> Result<Option<Value>, Reply> {
        let Some(scope) = Scope::parse(&row.scope) else {
            return Ok(None);
        };
        let facts = authority
            .facts(domain, Id(person), Id(issuer))
            .await
            .map_err(|_| unavailable())?;
        let (Some(anchor), Some(acceptance)) = (facts.anchor, facts.acceptance) else {
            return Ok(None);
        };
        let validity = Window {
            from: now,
            until: now.saturating_add(u64::from(row.minutes).saturating_mul(60_000)),
        };
        let draft = Draft {
            person: Id(person),
            anchor,
            operator: Id(row.operator_party),
            case: Digest(row.case_ref),
            acceptance,
            scope,
            validity,
        };
        let payload = Payload::GrantIssue(draft.grant());
        let window = Window {
            from: now.saturating_sub(60_000),
            until: now.saturating_add(10 * 60_000),
        };
        let Some(intent) =
            access_internal_api::instances::self_signed_intent(&payload, Id(person), window)
        else {
            return Err(unavailable());
        };
        let (Ok(p), Ok(i)) = (payload.to_bytes(), intent.to_bytes()) else {
            return Err(unavailable());
        };
        Ok(Some(json!({
            "template": scope.template(row.minutes).0,
            "payload": b64url_encode(&p),
            "intent": b64url_encode(&i),
            "basis": { "anchor": b64url_encode(&anchor.0) },
            "pep": pep,
            "until": rfc3339(validity.until),
        })))
    }

    /// The person's `grant.revoke` of `grant`, as their device signs it: payload, intent and
    /// basis.
    async fn revoke_draft<A: SupportAuthority>(
        authority: &A,
        (domain, pep): (Digest, &str),
        person: [u8; 16],
        grant: [u8; 16],
        now: u64,
    ) -> Result<Option<Value>, Reply> {
        let facts = authority
            .facts(domain, Id(person), Id(person))
            .await
            .map_err(|_| unavailable())?;
        let Some(anchor) = facts.anchor else {
            return Ok(None);
        };
        let payload = Payload::GrantRevoke { grant: Id(grant) };
        let window = Window {
            from: now.saturating_sub(60_000),
            until: now.saturating_add(10 * 60_000),
        };
        let Some(intent) =
            access_internal_api::instances::self_signed_intent(&payload, Id(person), window)
        else {
            return Err(unavailable());
        };
        let (Ok(p), Ok(i)) = (payload.to_bytes(), intent.to_bytes()) else {
            return Err(unavailable());
        };
        Ok(Some(json!({
            "payload": b64url_encode(&p),
            "intent": b64url_encode(&i),
            "basis": { "anchor": b64url_encode(&anchor.0) },
            "pep": pep,
        })))
    }

    async fn own_open(
        &self,
        kit: &RealmKit,
        subject: [u8; 16],
        request: &str,
    ) -> Result<(SupportRequestRow, u64), Reply> {
        let Ok(id) = kit.ids.decode(REQUEST_PREFIX, request) else {
            return Err(Reply::problem(UNKNOWN));
        };
        let mut t = self.begin(kit).await?;
        let now = t.server_time().await.map_err(|_| unavailable())?;
        let row = t.support_request(id).await.map_err(|_| unavailable())?;
        t.commit().await.map_err(|_| unavailable())?;
        match row {
            Some(r) if r.subject == subject && state(&r, now) == "waiting" => Ok((r, now)),
            _ => Err(Reply::problem(UNKNOWN)),
        }
    }

    /// `POST /v1/support/requests/{request}/decline`: nothing is granted.
    pub async fn decline_support(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        request: &str,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let subject = match self.fresh(&kit, b, None).await {
            Ok((s, _)) => s,
            Err(r) => return r,
        };
        let (row, now) = match self.own_open(&kit, subject, request).await {
            Ok(r) => r,
            Err(r) => return r,
        };
        let done = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            let first = t
                .answer_support_request(row.id, &Answer::Declined, now)
                .await?;
            t.commit().await?;
            Ok::<_, access_store::StoreError>(first)
        };
        match done.await {
            Ok(true) => Reply::json(200, json!({ "state": "declined" })),
            Ok(false) => Reply::problem(UNKNOWN),
            Err(_) => unavailable(),
        }
    }

    /// `POST /v1/support/requests/{request}/give` (TN-137 (1), §8.16): the person's own device's
    /// `grant.issue` of exactly the Grant the request drafted, for no longer than it asked. It is
    /// committed with the person's own assertion, then recorded, audited and announced to the
    /// person (SI-21, §8.16 #6, #7).
    #[expect(clippy::too_many_lines, reason = "one give, checked step by step")]
    pub async fn give_support<A: SupportAuthority>(
        &self,
        authority: &A,
        pep: &str,
        entry: &RealmEntry,
        b: &Browser<'_>,
        request: &str,
        body: &Signed,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let subject = match self.fresh(&kit, b, None).await {
            Ok((s, _)) => s,
            Err(r) => return r,
        };
        let (row, now) = match self.own_open(&kit, subject, request).await {
            Ok(r) => r,
            Err(r) => return r,
        };
        let Some(parsed) = parse(body) else {
            return Reply::problem(INVALID);
        };
        let Some(Payload::GrantIssue(content)) = parsed.payload.clone() else {
            return Reply::problem(INVALID);
        };
        let Some(scope) = Scope::parse(&row.scope) else {
            return Reply::problem(INVALID);
        };
        let domain = match governing(&self.db, &kit).await {
            Ok(d) => d,
            Err(r) => return r,
        };
        let issuer = match self.issuer_of(&kit, &row.case_system).await {
            Ok(i) => i,
            Err(r) => return r,
        };
        let Ok(facts) = authority
            .facts(domain, Id(row.subject_party), Id(issuer))
            .await
        else {
            return unavailable();
        };
        let (Some(anchor), Some(acceptance)) = (facts.anchor, facts.acceptance) else {
            return Reply::problem(CASE_REQUIRED);
        };
        let draft = Draft {
            person: Id(row.subject_party),
            anchor,
            operator: Id(row.operator_party),
            case: Digest(row.case_ref),
            acceptance,
            scope,
            validity: content.authority.constraints.validity,
        };
        // §8.16, XI-7
        if !draft.signed_as(&content, row.minutes, now)
            || parsed.basis != ExerciseBasis::Anchor(anchor)
        {
            return Reply::problem(INVALID);
        }
        let until = content.authority.constraints.validity.until;
        let minutes = u32::try_from(
            until
                .saturating_sub(content.authority.constraints.validity.from)
                .div_ceil(60_000),
        )
        .unwrap_or(u32::MAX);
        let committed = match Self::commit_signed(
            authority,
            pep,
            (domain, row.subject_party, Capacity::Own),
            parsed,
        )
        .await
        {
            Ok(c) => c,
            Err(r) => return r,
        };
        let grant = meta::object_id(&committed.exercise, kind::GRANT, 0);
        let answer = Answer::Granted {
            grant: grant.0,
            exercise: committed.exercise.0,
            until_ms: until,
            position: committed.position,
            template: String::from(scope.template(minutes).0),
        };
        let done = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            let names = model::names(&mut t, &*kit.kek, &row, &kit.name)
                .await
                .map_err(|_| access_store::StoreError::Corrupt)?;
            model::granted(
                &mut t,
                (&*kit.kek, &kit.ids),
                (&SystemEntropy, &SystemClock),
                &row,
                (&answer, now),
                &names,
            )
            .await
            .map_err(|_| access_store::StoreError::Corrupt)?;
            let row = t.support_request(row.id).await?;
            t.commit().await?;
            Ok::<_, access_store::StoreError>((row, names))
        };
        match done.await {
            Ok((Some(row), names)) => Reply::json(201, Self::row_json(&kit, &row, &names, now)),
            _ => unavailable(),
        }
    }

    async fn issuer_of(&self, kit: &RealmKit, system: &str) -> Result<[u8; 16], Reply> {
        let mut t = self.begin(kit).await?;
        let found = t.case_systems().await.map_err(|_| unavailable())?;
        t.commit().await.map_err(|_| unavailable())?;
        found
            .into_iter()
            .find(|c| c.name == system && c.live)
            .map(|c| c.issuer)
            .ok_or_else(|| Reply::problem(CASE_SYSTEM))
    }

    /// `GET /v1/me/support-access` (U57, SI-21, OP-157 m.3 (f)): the support access the person
    /// gave, active and ended, with the operator, their organization, the case, the scope and
    /// the end: what the Activity rows of a support Grant are attributed with.
    pub async fn support_access<A: SupportAuthority>(
        &self,
        authority: &A,
        pep: &str,
        entry: &RealmEntry,
        b: &Browser<'_>,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let subject = match self.fresh(&kit, b, None).await {
            Ok((s, _)) => s,
            Err(r) => return r,
        };
        let read = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            let now = t.server_time().await?;
            let since = now.saturating_sub(30 * 86_400_000);
            let rows = t.support_requests(subject, false, since, PAGE).await?;
            let blocked = t.support_blocked(subject).await?;
            let mut out = Vec::new();
            for row in rows {
                let Some((Answer::Granted { grant, .. }, _)) = &row.answer else {
                    continue;
                };
                let n = model::names(&mut t, &*kit.kek, &row, &kit.name)
                    .await
                    .map_err(|_| access_store::StoreError::Corrupt)?;
                let active = state(&row, now) == "active";
                out.push((
                    Self::row_json(&kit, &row, &n, now),
                    active.then_some((row.subject_party, *grant)),
                ));
            }
            t.commit().await?;
            Ok::<_, access_store::StoreError>((out, blocked, now))
        };
        let Ok((rows, blocked, now)) = read.await else {
            return unavailable();
        };
        let mut access = Vec::with_capacity(rows.len());
        let mut domain = None;
        for (mut v, revocable) in rows {
            if let Some((person, grant)) = revocable {
                let d = match domain {
                    Some(d) => d,
                    None => match governing(&self.db, &kit).await {
                        Ok(d) => *domain.insert(d),
                        Err(r) => return r,
                    },
                };
                match Self::revoke_draft(authority, (d, pep), person, grant, now).await {
                    Ok(Some(r)) => {
                        if let Value::Object(o) = &mut v {
                            o.insert(String::from("revoke"), r);
                        }
                    }
                    Ok(None) => {}
                    Err(r) => return r,
                }
            }
            access.push(v);
        }
        Reply::json(200, json!({ "access": access, "blocked": blocked }))
    }

    /// `POST /v1/me/support-access/{grant}/revoke` (§8.16 #11): the person's own `grant.revoke`
    /// of a support Grant they gave; only that Grant and its cascade end, the person's own
    /// sessions are untouched. "You revoked support access" is recorded and announced.
    pub async fn revoke_support<A: SupportAuthority>(
        &self,
        authority: &A,
        pep: &str,
        entry: &RealmEntry,
        b: &Browser<'_>,
        grant: &str,
        body: &Signed,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let subject = match self.fresh(&kit, b, None).await {
            Ok((s, _)) => s,
            Err(r) => return r,
        };
        let Some(grant) = b64::<16>(grant) else {
            return Reply::problem(UNKNOWN);
        };
        let Some(parsed) = parse(body) else {
            return Reply::problem(INVALID);
        };
        if parsed.payload != Some(Payload::GrantRevoke { grant: Id(grant) }) {
            return Reply::problem(INVALID);
        }
        let row = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            let r = t.support_request_by_grant(grant).await?;
            t.commit().await?;
            Ok::<_, access_store::StoreError>(r)
        };
        let row = match row.await {
            Ok(Some(r)) if r.subject == subject && r.end.is_none() => r,
            Ok(_) => return Reply::problem(UNKNOWN),
            Err(_) => return unavailable(),
        };
        let domain = match governing(&self.db, &kit).await {
            Ok(d) => d,
            Err(r) => return r,
        };
        if let Err(r) = Self::commit_signed(
            authority,
            pep,
            (domain, row.subject_party, Capacity::Own),
            parsed,
        )
        .await
        {
            return r;
        }
        let done = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            let now = t.server_time().await?;
            model::ended(
                &mut t,
                (&*kit.kek, &kit.ids),
                (&SystemEntropy, &SystemClock),
                &row,
                (End::Revoked, now),
                &kit.name,
            )
            .await
            .map_err(|_| access_store::StoreError::Corrupt)?;
            t.commit().await?;
            Ok::<_, access_store::StoreError>(now)
        };
        match done.await {
            Ok(now) => Reply::json(200, json!({ "state": "revoked", "ended_at": rfc3339(now) })),
            Err(_) => unavailable(),
        }
    }

    /// `PUT /v1/me/support-block` (§8.16 #8, OP-157 m.3 (c)): turned on, no support request
    /// reaches the person; turning it off again needs a sign-in in the last 5 minutes.
    pub async fn put_support_block(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        body: Block,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let fresh = if body.blocked {
            None
        } else {
            Some(STEP_UP_MAX_AGE_MS)
        };
        let subject = match self.fresh(&kit, b, fresh).await {
            Ok((s, _)) => s,
            Err(r) => return r,
        };
        let done = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            let now = t.server_time().await?;
            if t.support_blocked(subject).await? != body.blocked {
                t.set_support_block(subject, body.blocked, now).await?;
            }
            t.commit().await?;
            Ok::<_, access_store::StoreError>(())
        };
        match done.await {
            Ok(()) => Reply::json(200, json!({ "blocked": body.blocked })),
            Err(_) => unavailable(),
        }
    }

    /// `POST /v1/support/artifacts` (§8.16 #12, TN-74, OP-157 m.3 (g)): the person's HAR, JSON or
    /// text log for one of their support requests, under their own
    /// `idp.account.artifact_upload` Exercise. Images and videos are refused; tokens, cookies
    /// and `Authorization` values are redacted before anything is kept, and only the redacted
    /// text is sealed under the artifact's own key.
    pub async fn upload_artifact<A: SupportAuthority>(
        &self,
        authority: &A,
        pep: &str,
        entry: &RealmEntry,
        b: &Browser<'_>,
        body: &Upload,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let subject = match self.fresh(&kit, b, None).await {
            Ok((s, _)) => s,
            Err(r) => return r,
        };
        // TN-74, OP-157 m.3 (g)
        let Ok(format) = artifacts::format_of(&body.content_type) else {
            return Reply::problem(FORMAT);
        };
        let Ok(id) = kit.ids.decode(REQUEST_PREFIX, &body.request) else {
            return Reply::problem(UNKNOWN);
        };
        let read = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            let now = t.server_time().await?;
            let policy = t.support_artifact_policy().await?;
            let row = t.support_request(id).await?;
            t.commit().await?;
            Ok::<_, access_store::StoreError>((now, policy, row))
        };
        let Ok((now, policy, row)) = read.await else {
            return unavailable();
        };
        let Some(policy) = policy else {
            return Reply::problem(CLOSED);
        };
        let Some(row) = row.filter(|r| r.subject == subject) else {
            return Reply::problem(UNKNOWN);
        };
        if body.content.len() > MAX_ARTIFACT_BYTES
            || body.content.len() > usize::try_from(policy.max_bytes).unwrap_or(0)
        {
            return Reply::problem(TOO_LARGE);
        }
        let redacted = match artifacts::redact(format, &body.content) {
            Ok(r) => r,
            Err(Refused::Format) => return Reply::problem(FORMAT),
            Err(Refused::Malformed) => return Reply::problem(INVALID),
        };
        let Some(parsed) = parse(&body.exercise) else {
            return Reply::problem(INVALID);
        };
        let person = Id(row.subject_party);
        let case = Digest(row.case_ref);
        if parsed.payload.is_some()
            || !case_intent(
                &parsed.intent,
                IdpAction::AccountArtifactUpload,
                &artifacts_resource(&person, None),
                &case,
            )
        {
            return Reply::problem(INVALID);
        }
        let domain = match governing(&self.db, &kit).await {
            Ok(d) => d,
            Err(r) => return r,
        };
        let committed = match Self::commit_signed(
            authority,
            pep,
            (domain, row.subject_party, Capacity::Own),
            parsed,
        )
        .await
        {
            Ok(c) => c,
            Err(r) => return r,
        };
        self.keep_artifact(
            &kit,
            (&row, format),
            &redacted,
            (committed.exercise, now),
            policy.retention_days,
            b,
        )
        .await
    }

    async fn keep_artifact(
        &self,
        kit: &RealmKit,
        (row, format): (&SupportRequestRow, Format),
        redacted: &artifacts::Redacted,
        (exercise, now): (Digest, u64),
        retention_days: u32,
        b: &Browser<'_>,
    ) -> Reply {
        let digest32 = suiss_crypto::digest::sha256(redacted.text.as_bytes());
        let mut context = SEAL_CONTEXT.to_vec();
        context.extend_from_slice(&row.subject);
        context.extend_from_slice(&row.case_ref);
        context.extend_from_slice(&digest32);
        let Ok(dek) = suiss_crypto::envelope::Dek::generate() else {
            return unavailable();
        };
        let Ok(wrapped) = kit.kek.wrap(&dek) else {
            return unavailable();
        };
        let Ok(sealed) = suiss_crypto::envelope::seal_body(dek, &context, redacted.text.as_bytes())
        else {
            return unavailable();
        };
        let actor = kit
            .ids
            .encode(access_identity_account::app::SUBJECT_PREFIX, row.subject)
            .unwrap_or_default();
        let size = u32::try_from(redacted.text.len()).unwrap_or(u32::MAX);
        let done = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            let id = t
                .insert_support_artifact(&NewSupportArtifact {
                    subject: row.subject,
                    subject_party: row.subject_party,
                    case_ref: row.case_ref,
                    format: format.name(),
                    size_bytes: size,
                    redactions: redacted.count,
                    digest: digest32,
                    upload_exercise: exercise.0,
                    kek_id: kit.kek.id(),
                    wrapped_dek: &wrapped,
                    nonce: sealed.nonce,
                    ciphertext: &sealed.ciphertext,
                    created_ms: now,
                    retain_until_ms: now
                        .saturating_add(u64::from(retention_days).saturating_mul(86_400_000)),
                })
                .await?;
            t.audit(&AuditEvent {
                event_type: "support.artifact_uploaded",
                actor: &actor,
                target: &b64url_encode(&id),
                correlation: b.correlation,
            })
            .await?;
            t.commit().await?;
            Ok::<_, access_store::StoreError>(id)
        };
        match done.await {
            Ok(id) => Reply::json(
                201,
                json!({
                    "id": b64url_encode(&id),
                    "format": format.name(),
                    "size": size,
                    "redactions": redacted.count,
                    "digest": b64url_encode(&digest32),
                }),
            ),
            Err(_) => unavailable(),
        }
    }

    /// `GET /v1/support/artifacts/{artifact}` (§8.16 #12, TN-74, OP-157 m.3 (g)): the redacted
    /// text, only to an operator whose own `idp.account.artifact_read` Exercise `For` the person,
    /// on the separate artifact Grant the person gave for that case, was allowed and recorded.
    #[expect(clippy::too_many_lines, reason = "one read, checked step by step")]
    pub async fn read_artifact<A: SupportAuthority>(
        &self,
        authority: &A,
        pep: &str,
        entry: &RealmEntry,
        b: &Browser<'_>,
        artifact: &str,
        exercise: Option<&Signed>,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let reader = match self.fresh(&kit, b, None).await {
            Ok((s, _)) => s,
            Err(r) => return r,
        };
        let Some(id) = b64::<16>(artifact) else {
            return Reply::problem(ARTIFACT_UNKNOWN);
        };
        let row = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            let r = t.support_artifact(id).await?;
            t.commit().await?;
            Ok::<_, access_store::StoreError>(r)
        };
        let row = match row.await {
            Ok(Some(r)) if r.sealed.is_some() => r,
            Ok(_) => return Reply::problem(ARTIFACT_UNKNOWN),
            Err(_) => return unavailable(),
        };
        let Some(parsed) = exercise.and_then(parse) else {
            return Reply::problem(ARTIFACT_DENIED);
        };
        let person = Id(row.subject_party);
        if parsed.payload.is_some()
            || !case_intent(
                &parsed.intent,
                IdpAction::AccountArtifactRead,
                &artifacts_resource(&person, Some(&row.id)),
                &Digest(row.case_ref),
            )
        {
            return Reply::problem(ARTIFACT_DENIED);
        }
        let reader_party = match self.party(&kit, reader).await {
            Ok(p) => p,
            Err(r) => return r,
        };
        let domain = match governing(&self.db, &kit).await {
            Ok(d) => d,
            Err(r) => return r,
        };
        if Self::commit_signed(
            authority,
            pep,
            (domain, reader_party, Capacity::For(person)),
            parsed,
        )
        .await
        .is_err()
        {
            return Reply::problem(ARTIFACT_DENIED);
        }
        let Some((wrapped, nonce, ciphertext)) = row.sealed.clone() else {
            return Reply::problem(ARTIFACT_UNKNOWN);
        };
        let mut context = SEAL_CONTEXT.to_vec();
        context.extend_from_slice(&row.subject);
        context.extend_from_slice(&row.case_ref);
        context.extend_from_slice(&row.digest);
        let Ok(dek) = kit.kek.unwrap(&wrapped) else {
            return unavailable();
        };
        let Ok(text) = suiss_crypto::envelope::open_body(
            &dek,
            &context,
            &suiss_crypto::envelope::Sealed { nonce, ciphertext },
        ) else {
            return unavailable();
        };
        let Ok(text) = String::from_utf8(text.to_vec()) else {
            return unavailable();
        };
        let actor = kit
            .ids
            .encode(access_identity_account::app::SUBJECT_PREFIX, reader)
            .unwrap_or_default();
        let audited = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            t.audit(&AuditEvent {
                event_type: "support.artifact_read",
                actor: &actor,
                target: &b64url_encode(&row.id),
                correlation: b.correlation,
            })
            .await?;
            t.commit().await
        };
        if audited.await.is_err() {
            return unavailable();
        }
        let media = Format::parse(&row.format).map_or("text/plain", Format::media_type);
        Reply::json(
            200,
            json!({
                "id": b64url_encode(&row.id),
                "format": row.format,
                "media_type": media,
                "redactions": row.redactions,
                "digest": b64url_encode(&row.digest),
                "content": text,
            }),
        )
    }
}
