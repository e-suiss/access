//! One's cloud key permissions on the Frontend API (OP-156 m.3 (w), (g), E59, OP-78): the
//! person's device Instance grants one with its own `one.cloud_key/grant` Exercise, committed
//! with the identity plane as PEP; the record names purpose, classes, window, the TEE
//! measurement and job key digests and the Mandate, never a key or data. The person sees every
//! permission and ends one with a tap; the end of the window, of the Mandate or its narrowing
//! ends it too, and every ended permission tells the TEE to destroy its copies.

use access_identity_account::domain::login::Problem;
use access_identity_oauth::ports::RealmEntry;
use access_internal_api::idp::Verdict;
use access_internal_api::one::{CloudKeyAuthority, CloudKeyExercise, WORK_NAMESPACE};
use access_kernel::codec::Canonical as _;
use access_kernel::combinator::Capacity;
use access_kernel::intent::IntentEnvelope;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::meta::{ExerciseBasis, HoldingRef};
use access_kernel::model::Id;
use access_store::audit::AuditEvent;
use access_store::cloud_keys::NewCloudKey;
use access_store::identity::TenantTx;
use access_store::idp;
use serde::Deserialize;
use serde_json::{Value, json};

use super::me::{governing, unavailable};
use super::signup::STEP_UP_MAX_AGE_MS;
use super::{Body, Browser, Hosted, Reply};
use crate::domain::cloud_key::{State, Terms, TermsError, grant_terms, revoked_permission, state};
use crate::domain::frontend::rfc3339;
use crate::ports::{Clock, Kits, Messages, RealmKit};

/// The opaque id prefix of a permission.
pub const PERMISSION_PREFIX: &str = "ckp";

/// Most permissions one list shows.
const PAGE: i64 = 50;

/// A device Instance's signed Exercise, as the route carries it.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedExercise {
    /// The Exercise nonce, base64url.
    pub nonce: String,
    /// The intent's canonical bytes, base64url.
    pub intent: String,
    /// The `holding` basis.
    pub basis: Holding,
    /// The device Instance's AIS, base64url.
    pub ais: String,
}

/// A `holding` basis: the Grant, its holder and the position its episode opened at.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Holding {
    /// The Grant, base64url.
    pub grant: String,
    /// The holder, base64url.
    pub holder: String,
    /// The position.
    pub since: u64,
}

const fn problem(status: u16, code: &'static str, title: &'static str) -> Problem {
    Problem {
        status,
        code,
        title,
        retry_after_s: None,
    }
}

const INVALID: Problem = problem(400, "invalid-request", "The request is not valid");
const NO_PARTY: Problem = problem(409, "cloud-key-party", "Add this device first");
const MANDATE: Problem = problem(
    409,
    "cloud-key-mandate",
    "The rule for acting while you're away doesn't cover this work",
);
const NOT_ALLOWED: Problem = problem(403, "cloud-key-denied", "This permission isn't allowed");
const UNKNOWN: Problem = problem(404, "cloud-key-unknown", "There is no such permission");

fn terms_problem(e: TermsError) -> Reply {
    Reply::problem(match e {
        TermsError::Action => problem(400, "cloud-key-action", "This is not the right action"),
        TermsError::Terms => problem(400, "cloud-key-terms", "The permission is incomplete"),
        TermsError::Class => problem(
            400,
            "cloud-key-class",
            "Only data that only you can open can be named",
        ),
        TermsError::Window => problem(400, "cloud-key-window", "A permission lasts at most a day"),
    })
}

fn b64<const N: usize>(text: &str) -> Option<[u8; N]> {
    b64url_decode(text)
        .ok()
        .and_then(|b| <[u8; N]>::try_from(b).ok())
}

struct Parsed {
    nonce: Vec<u8>,
    intent: IntentEnvelope,
    basis: ExerciseBasis,
    ais: Vec<u8>,
}

fn parse(s: &SignedExercise) -> Option<Parsed> {
    let nonce = b64url_decode(&s.nonce)
        .ok()
        .filter(|n| (16..=64).contains(&n.len()))?;
    let intent = b64url_decode(&s.intent)
        .ok()
        .filter(|b| b.len() <= 16 * 1024)
        .and_then(|b| IntentEnvelope::from_bytes(&b).ok())?;
    let ais = b64url_decode(&s.ais)
        .ok()
        .filter(|a| (1..=8192).contains(&a.len()))?;
    let basis = ExerciseBasis::Holding(HoldingRef {
        grant: Id(b64(&s.basis.grant)?),
        holder: Id(b64(&s.basis.holder)?),
        since: s.basis.since,
    });
    Some(Parsed {
        nonce,
        intent,
        basis,
        ais,
    })
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{x:02x}"));
        s
    })
}

fn row_json(kit: &RealmKit, id: [u8; 16], g: &NewCloudKey, s: State) -> Value {
    json!({
        "id": kit.ids.encode(PERMISSION_PREFIX, id).ok(),
        "purpose": g.purpose,
        "classes": g.classes,
        "valid_from": rfc3339(u64::try_from(g.valid_from).unwrap_or(0)),
        "valid_until": rfc3339(u64::try_from(g.valid_until).unwrap_or(0)),
        "tee_measurement": b64url_encode(&g.tee_measurement),
        "job_key": b64url_encode(&g.job_key),
        "mandate": b64url_encode(&g.mandate),
        "exercise": b64url_encode(&g.exercise),
        "state": s.name(),
        "destroy": s.destroy(),
    })
}

impl<K, C, M> Hosted<K, C, M>
where
    K: Kits,
    C: Clock + Sync,
    M: Messages,
{
    async fn party_of(&self, kit: &RealmKit, subject: [u8; 16]) -> Result<[u8; 16], Reply> {
        let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm)
            .await
            .map_err(|_| unavailable())?;
        let p = idp::subject_party(&mut t, &subject)
            .await
            .map_err(|_| unavailable())?;
        t.commit().await.map_err(|_| unavailable())?;
        p.ok_or_else(|| Reply::problem(NO_PARTY))
    }

    /// Commits the device Instance's Exercise `p` of the session's Party in `domain`.
    async fn exercise<A: CloudKeyAuthority>(
        authority: &A,
        pep: &str,
        (domain, party): (access_kernel::digest::Digest, [u8; 16]),
        p: Parsed,
    ) -> Result<access_kernel::digest::Digest, Reply> {
        let verdict = authority
            .commit(CloudKeyExercise {
                domain,
                nonce: p.nonce,
                intent: p.intent,
                basis: p.basis,
                capacity: Capacity::Own,
                ais: p.ais,
                pep: String::from(pep),
                actor: Id(party),
            })
            .await;
        match verdict {
            Ok(Verdict::Committed(c)) => Ok(c.exercise),
            Ok(Verdict::NotAllowed { .. } | Verdict::Refused { .. }) => {
                Err(Reply::problem(NOT_ALLOWED))
            }
            Err(_) => Err(unavailable()),
        }
    }

    /// `POST /v1/me/cloud-key-permissions` (E59 (2)): after a sign-in in the last 5 minutes, the
    /// device Instance's `one.cloud_key/grant` Exercise, for at most 24 hours and never past the
    /// Mandate that covers the work; the record holds no key or data.
    pub async fn grant_cloud_key<A: CloudKeyAuthority>(
        &self,
        authority: &A,
        pep: &str,
        entry: &RealmEntry,
        b: &Browser<'_>,
        body: &SignedExercise,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let subject = match self.fresh(&kit, b, Some(STEP_UP_MAX_AGE_MS)).await {
            Ok((s, _)) => s,
            Err(r) => return r,
        };
        let Some(parsed) = parse(body) else {
            return Reply::problem(INVALID);
        };
        let (party, domain, now) = match self.scope(&kit, subject).await {
            Ok(s) => s,
            Err(r) => return r,
        };
        let terms: Terms = match grant_terms(&parsed.intent, now) {
            Ok(t) => t,
            Err(e) => return terms_problem(e),
        };
        // E59 (2), E46
        match authority
            .mandate(domain, Id(terms.mandate), (WORK_NAMESPACE, &terms.purpose))
            .await
        {
            Ok(access_internal_api::one::MandateStanding::Covers(until))
                if terms.until <= until => {}
            Ok(_) => return Reply::problem(MANDATE),
            Err(_) => return unavailable(),
        }
        let exercise = match Self::exercise(authority, pep, (domain, party), parsed).await {
            Ok(e) => e,
            Err(r) => return r,
        };
        let row = NewCloudKey {
            subject,
            party,
            domain: domain.0,
            exercise: exercise.0,
            purpose: terms.purpose,
            classes: terms.classes,
            valid_from: i64::try_from(terms.from).unwrap_or(i64::MAX),
            valid_until: i64::try_from(terms.until).unwrap_or(i64::MAX),
            tee_measurement: terms.tee_measurement,
            job_key: terms.job_key,
            mandate: terms.mandate,
        };
        let actor = kit.ids.encode("usr", subject).unwrap_or_default();
        let kept = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            let id = t.insert_cloud_key(&row).await?;
            if let Some(id) = id {
                t.audit(&AuditEvent {
                    event_type: "cloud_key.granted",
                    actor: &actor,
                    target: &hex(&id),
                    correlation: b.correlation,
                })
                .await?;
            }
            t.commit().await?;
            Ok::<_, access_store::StoreError>(id)
        };
        match kept.await {
            Ok(Some(id)) => Reply::json(201, row_json(&kit, id, &row, State::Live)),
            Ok(None) => Reply::problem(INVALID),
            Err(_) => unavailable(),
        }
    }

    /// The session subject's Party, the governing domain and trusted now.
    async fn scope(
        &self,
        kit: &RealmKit,
        subject: [u8; 16],
    ) -> Result<([u8; 16], access_kernel::digest::Digest, u64), Reply> {
        let party = self.party_of(kit, subject).await?;
        let domain = governing(&self.db, kit).await?;
        let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm)
            .await
            .map_err(|_| unavailable())?;
        let now = t.server_time().await.map_err(|_| unavailable())?;
        t.commit().await.map_err(|_| unavailable())?;
        Ok((party, domain, now))
    }

    /// `GET /v1/me/cloud-key-permissions` (E59 (3)): every permission whose window has not
    /// long ended, with where it stands and whether the TEE must destroy its copies.
    pub async fn cloud_keys<A: CloudKeyAuthority>(
        &self,
        authority: &A,
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
            let since = i64::try_from(now.saturating_sub(7 * 86_400_000)).unwrap_or(0);
            let rows = t.cloud_keys(subject, since, PAGE).await?;
            t.commit().await?;
            Ok::<_, access_store::StoreError>((rows, now))
        };
        let Ok((rows, now)) = read.await else {
            return unavailable();
        };
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let until = u64::try_from(r.grant.valid_until).unwrap_or(0);
            let mandate = if r.ended.is_some() || now >= until {
                access_internal_api::one::MandateStanding::Ended
            } else {
                match authority
                    .mandate(
                        access_kernel::digest::Digest(r.grant.domain),
                        Id(r.grant.mandate),
                        (WORK_NAMESPACE, &r.grant.purpose),
                    )
                    .await
                {
                    Ok(m) => m,
                    Err(_) => return unavailable(),
                }
            };
            let s = state(r.ended.is_some(), until, mandate, now);
            out.push(row_json(&kit, r.id, &r.grant, s));
        }
        Reply::json(200, json!({ "permissions": out }))
    }

    /// `POST /v1/me/cloud-key-permissions/{permission}/revoke` (E59 (3)): one tap ends it. The
    /// device may send its `one.cloud_key/revoke` Exercise with it; ending never waits on one.
    pub async fn revoke_cloud_key<A: CloudKeyAuthority>(
        &self,
        authority: &A,
        pep: &str,
        entry: &RealmEntry,
        b: &Browser<'_>,
        permission: &str,
        body: Option<&SignedExercise>,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let subject = match self.fresh(&kit, b, None).await {
            Ok((s, _)) => s,
            Err(r) => return r,
        };
        let Ok(id) = kit.ids.decode(PERMISSION_PREFIX, permission) else {
            return Reply::problem(UNKNOWN);
        };
        let exercise = match body {
            None => None,
            Some(s) => {
                let Some(parsed) = parse(s) else {
                    return Reply::problem(INVALID);
                };
                match revoked_permission(&parsed.intent) {
                    Ok(p) if p == id => {}
                    Ok(_) => return Reply::problem(INVALID),
                    Err(e) => return terms_problem(e),
                }
                let (party, domain, _) = match self.scope(&kit, subject).await {
                    Ok(s) => s,
                    Err(r) => return r,
                };
                match Self::exercise(authority, pep, (domain, party), parsed).await {
                    Ok(e) => Some(e.0),
                    Err(r) => return r,
                }
            }
        };
        let actor = kit.ids.encode("usr", subject).unwrap_or_default();
        let done = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            let now = t.server_time().await?;
            let ended = t
                .end_cloud_key(
                    subject,
                    id,
                    exercise,
                    i64::try_from(now).unwrap_or(i64::MAX),
                )
                .await?;
            if ended {
                t.audit(&AuditEvent {
                    event_type: "cloud_key.revoked",
                    actor: &actor,
                    target: &hex(&id),
                    correlation: b.correlation,
                })
                .await?;
            }
            t.commit().await?;
            Ok::<_, access_store::StoreError>(ended)
        };
        match done.await {
            Ok(true) => Reply::new(204, Body::Empty),
            Ok(false) => Reply::problem(UNKNOWN),
            Err(_) => unavailable(),
        }
    }
}
