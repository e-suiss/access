//! Agent use cases of the identity plane (OP-154 m.3 (c), (e), (f), (g), AG-19, AG-20, AG-41):
//! what a committed `idp.agent.*` Exercise writes besides its decision, the realm issuer's
//! agent Claims, the sponsor rule and the registry read.

use access_crypto::opaque_id::IdKey;
use access_identity_account::adapters::pg::PgTx;
use access_identity_account::app::SUBJECT_PREFIX;
use access_identity_account::app::claims::emit as emit_claim;
use access_identity_account::domain::claims::agent_claim;
use access_identity_events::app::emit;
use access_identity_events::domain::catalog::IdentityEvent;
use access_internal_api::idp::ACTOR_BINDING;
use access_kernel::claim::body::Class;
use access_kernel::digest::Digest;
use access_kernel::json::b64url_encode;
use access_kernel::meta::ActorKind;
use access_kernel::model::{EqValue, Id};
use access_store::agents::{AgentRow, NewAgent, SponsorRow, TemplateRow};
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::idp;
use serde_json::{Value as Json, json};
use suiss_crypto::dcbor::{self, Limits, Value};

use super::Admin;
use super::rest::rfc3339;
use crate::AdminError;
use crate::domain::Invalid;
use crate::domain::agent::{AgentChange, AgentRegister, Sponsor};
use crate::ports::{AgentRegistration, Decider, Governance, Instances, RealmKeys};

/// Statuses of an agent.
pub const ACTIVE: &str = "active";
/// An agent without an active human sponsor (AG-41, OP-154 m.3 (e)).
pub const SUSPENDED: &str = "suspended";
/// A retired agent; nothing is deleted (OP-73).
pub const RETIRED: &str = "retired";

/// The realm issuer's Acceptance of the agent classes for predicate input (OP-154 m.3 (c),
/// (e)): an agent Grant's `sponsored_by` requirement is met only by the realm issuer's Claim.
#[must_use]
pub fn agent_claims(issuer: Id) -> Value {
    acceptance(
        issuer,
        access_kernel::claim::PREDICATE_INPUT,
        &[Class::OperatedBy, Class::SponsoredBy, Class::AgentKind],
    )
}

/// The realm issuer's Acceptance of `operated_by` for subject selection (OP-154 m.3 (g), C15):
/// an agent Grant's downstream holder class selects the agents of the same operator.
#[must_use]
pub fn agent_selection(issuer: Id) -> Value {
    acceptance(
        issuer,
        access_kernel::claim::SUBJECT_SELECTION,
        &[Class::OperatedBy],
    )
}

fn acceptance(issuer: Id, use_: &str, classes: &[Class]) -> Value {
    use access_kernel::codec::Canonical as _;
    let mut names: Vec<(Vec<u8>, Value)> = classes
        .iter()
        .map(|c| {
            let v = Value::text(&c.name());
            (dcbor::encode(&v, Limits::CEILING).unwrap_or_default(), v)
        })
        .collect();
    names.sort_by(|a, b| a.0.cmp(&b.0));
    Value::Map(vec![
        (Value::text("issuer"), issuer.to_value()),
        (Value::text("use"), Value::text(use_)),
        (
            Value::text("classes"),
            Value::Array(names.into_iter().map(|(_, v)| v).collect()),
        ),
        (
            Value::text("subject"),
            access_kernel::model::SubjectSelector::Public.to_value(),
        ),
        (
            Value::text("validity"),
            Value::Array(vec![Value::Unsigned(0), Value::Unsigned(u64::MAX)]),
        ),
    ])
}

/// The state an agent change must find (OP-154 m.3 (c), (e)).
///
/// # Errors
/// [`Invalid`] as [`AdminError`].
pub(crate) async fn current(t: &mut TenantTx, a: &AgentChange) -> Result<(), AdminError> {
    match a {
        AgentChange::Register(r) => {
            if t.agent(r.party).await?.is_some() {
                return Err(Invalid::Agent.into());
            }
            for s in &r.sponsors {
                sponsor_party(t, *s).await?;
            }
        }
        AgentChange::Update(u) => {
            live(t, u.agent).await?;
        }
        AgentChange::Retire(agent) => {
            live(t, *agent).await?;
        }
        AgentChange::SponsorAssign(s) => {
            live(t, s.agent).await?;
            sponsor_party(t, s.subject).await?;
            if open_sponsors(t, s.agent).await?.contains(&s.subject) {
                return Err(AdminError::Conflict);
            }
        }
        AgentChange::SponsorRemove(s) => {
            live(t, s.agent).await?;
            if !open_sponsors(t, s.agent).await?.contains(&s.subject) {
                return Err(Invalid::NoAccount.into());
            }
        }
        AgentChange::TemplateDefine(_) => {}
    }
    Ok(())
}

async fn live(t: &mut TenantTx, agent: [u8; 16]) -> Result<AgentRow, AdminError> {
    t.agent(agent)
        .await?
        .filter(|a| a.status != RETIRED)
        .ok_or_else(|| Invalid::NoAgent.into())
}

/// A sponsor is a person: a subject of the realm bound to a Party (AG-41).
async fn sponsor_party(t: &mut TenantTx, subject: [u8; 16]) -> Result<[u8; 16], AdminError> {
    let account = access_store::idp::realm::account(t, subject)
        .await?
        .ok_or(Invalid::NoAccount)?;
    if !access_identity_account::domain::status::AccountStatus::parse(&account.status)
        .is_some_and(access_identity_account::domain::status::AccountStatus::can_authenticate)
    {
        return Err(Invalid::AccountState.into());
    }
    idp::subject_party(t, &subject)
        .await?
        .ok_or_else(|| Invalid::NoAccount.into())
}

async fn open_sponsors(t: &mut TenantTx, agent: [u8; 16]) -> Result<Vec<[u8; 16]>, AdminError> {
    Ok(t.sponsorships(agent)
        .await?
        .into_iter()
        .filter(|s| s.ended_ms.is_none())
        .map(|s| s.subject)
        .collect())
}

fn event_id() -> Result<[u8; 32], AdminError> {
    access_crypto::random::bytes::<32>().map_err(|_| AdminError::Encode)
}

/// Queues the realm issuer's `sponsored_by` Claim of `agent` naming `sponsor_party`, or its
/// retraction (OP-154 m.3 (e)): one line per sponsor.
async fn sponsored_by(
    t: &mut PgTx,
    agent: [u8; 16],
    (subject, sponsor_party): ([u8; 16], [u8; 16]),
    at: u64,
    retract: bool,
) -> Result<(), AdminError> {
    let order = agent_claim(
        agent,
        Class::SponsoredBy,
        (EqValue::Bytes(sponsor_party.to_vec()), &subject),
        at,
        retract,
    );
    emit_claim(t, &order).await.map_err(claim_error)
}

fn claim_error(e: access_identity_account::AccountError) -> AdminError {
    match e {
        access_identity_account::AccountError::Store(s) => AdminError::Store(s),
        _ => AdminError::Encode,
    }
}

/// What a committed `idp.agent.*` Exercise writes (OP-154 m.3 (c), (e), (g)): the record, the
/// realm issuer's Claims about the agent, the sponsorship episodes, and the webhooks
/// `agent.sponsor_assigned` and `agent.suspended` (SI-21). Nothing is deleted (OP-73).
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn committed(
    t: &mut PgTx,
    realm: RealmId,
    a: &AgentChange,
    exercise: &Digest,
    at: u64,
) -> Result<(), AdminError> {
    match a {
        AgentChange::Register(r) => register(t, realm, r, exercise, at).await,
        AgentChange::Update(u) => {
            if t.0
                .update_agent(u.agent, &u.display_name, u.description.as_deref())
                .await?
            {
                Ok(())
            } else {
                Err(AdminError::Conflict)
            }
        }
        AgentChange::SponsorAssign(s) => assign(t, realm, *s, exercise, at).await,
        AgentChange::SponsorRemove(s) => {
            leave(
                t,
                realm,
                (s.agent, s.subject),
                ("remove", Some(exercise)),
                at,
            )
            .await
        }
        AgentChange::Retire(agent) => retire(t, *agent, exercise, at).await,
        AgentChange::TemplateDefine(tpl) => {
            let content =
                dcbor::encode(&tpl.to_value(), Limits::CEILING).map_err(|_| AdminError::Encode)?;
            let version =
                t.0.agent_template(tpl.name.as_str())
                    .await?
                    .map_or(1, |r| r.version.saturating_add(1));
            t.0.insert_agent_template(&TemplateRow {
                name: String::from(tpl.name.as_str()),
                version,
                content,
                defined: exercise.0,
            })
            .await?;
            Ok(())
        }
    }
}

async fn register(
    t: &mut PgTx,
    realm: RealmId,
    r: &AgentRegister,
    exercise: &Digest,
    at: u64,
) -> Result<(), AdminError> {
    t.0.insert_agent(&NewAgent {
        party: r.party,
        operator: r.operator,
        kind: r.kind.name(),
        display_name: &r.display_name,
        description: r.description.as_deref(),
        exercise: &exercise.0,
    })
    .await?;
    // OP-154 m.3 (c), AG-20
    let operated = agent_claim(
        r.party,
        Class::OperatedBy,
        (EqValue::Bytes(r.operator.to_vec()), &[]),
        at,
        false,
    );
    emit_claim(t, &operated).await.map_err(claim_error)?;
    let kind = agent_claim(
        r.party,
        Class::AgentKind,
        (EqValue::Text(String::from(r.kind.name())), &[]),
        at,
        false,
    );
    emit_claim(t, &kind).await.map_err(claim_error)?;
    for s in &r.sponsors {
        assign(
            t,
            realm,
            Sponsor {
                agent: r.party,
                subject: *s,
            },
            exercise,
            at,
        )
        .await?;
    }
    Ok(())
}

async fn assign(
    t: &mut PgTx,
    realm: RealmId,
    s: Sponsor,
    exercise: &Digest,
    at: u64,
) -> Result<(), AdminError> {
    let party = sponsor_party(&mut t.0, s.subject).await?;
    t.0.open_sponsorship(s.agent, s.subject, &exercise.0)
        .await?;
    sponsored_by(t, s.agent, (s.subject, party), at, false).await?;
    // AG-41, OP-154 m.3 (e)
    t.0.set_agent_status(s.agent, ACTIVE).await?;
    // SI-21
    let event =
        IdentityEvent::agent_sponsor_assigned(event_id()?, realm.as_bytes(), &s.agent, &party, at);
    emit(&mut t.0, &event).await?;
    Ok(())
}

/// Ends the sponsorship of `agent` by `subject`; when it was the last one, the realm issuer
/// withdraws `sponsored_by` and the agent is suspended (OP-154 m.3 (e), AG-41). Suspension needs
/// no signer and no system key.
async fn leave(
    t: &mut PgTx,
    realm: RealmId,
    (agent, subject): ([u8; 16], [u8; 16]),
    (by, exercise): (&str, Option<&Digest>),
    at: u64,
) -> Result<(), AdminError> {
    if !t
        .0
        .end_sponsorship(agent, subject, by, exercise.map(|e| &e.0))
        .await?
    {
        return Err(Invalid::NoAccount.into());
    }
    let party = idp::subject_party(&mut t.0, &subject)
        .await?
        .ok_or_else(|| AdminError::Refused(String::from(ACTOR_BINDING)))?;
    sponsored_by(t, agent, (subject, party), at, true).await?;
    if open_sponsors(&mut t.0, agent).await?.is_empty()
        && t.0.set_agent_status(agent, SUSPENDED).await?
    {
        // SI-21
        let event = IdentityEvent::agent_suspended(event_id()?, realm.as_bytes(), &agent, at);
        emit(&mut t.0, &event).await?;
    }
    Ok(())
}

async fn retire(
    t: &mut PgTx,
    agent: [u8; 16],
    exercise: &Digest,
    at: u64,
) -> Result<(), AdminError> {
    let row = live(&mut t.0, agent).await?;
    for s in open_sponsors(&mut t.0, agent).await? {
        t.0.end_sponsorship(agent, s, "retire", Some(&exercise.0))
            .await?;
        if let Some(party) = idp::subject_party(&mut t.0, &s).await? {
            sponsored_by(t, agent, (s, party), at, true).await?;
        }
    }
    let operated = agent_claim(
        agent,
        Class::OperatedBy,
        (EqValue::Bytes(row.operator.to_vec()), &[]),
        at,
        true,
    );
    emit_claim(t, &operated).await.map_err(claim_error)?;
    if t.0.set_agent_status(agent, RETIRED).await? {
        Ok(())
    } else {
        Err(AdminError::Conflict)
    }
}

/// A person left: an account suspended, deleted or deprovisioned ends each sponsorship it held
/// (OP-154 m.3 (e), AG-41, X13), and each agent left without a sponsor is suspended.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn sponsor_left(
    t: &mut PgTx,
    realm: RealmId,
    subject: [u8; 16],
    at: u64,
) -> Result<(), AdminError> {
    for agent in t.0.sponsored_by(subject).await? {
        leave(t, realm, (agent, subject), ("account", None), at).await?;
    }
    Ok(())
}

fn sponsor_json(ids: &IdKey, s: &SponsorRow) -> Result<Json, AdminError> {
    Ok(json!({
        "account_id": ids.encode(SUBJECT_PREFIX, s.subject)?,
        "assigned_at": rfc3339(s.assigned_ms),
        "assigned_exercise": b64url_encode(&s.assigned),
        "ended_at": s.ended_ms.map(rfc3339),
        "ended_by": s.ended_by,
        "ended_exercise": s.ended.map(|e| b64url_encode(&e)),
    }))
}

/// The registry view of one agent (OP-154 m.3 (e), AG-41, Ek B 4382, 4475): kind, operator,
/// sponsors, status and the sponsorship changes (SI-21); with `instances`, its live Instances
/// (the audit and revocation unit, AG-21). Connected accounts are empty until the token vault
/// serves them; nothing here is a token.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn view(
    t: &mut TenantTx,
    ids: &IdKey,
    a: &AgentRow,
    instances: Option<&[Id]>,
) -> Result<Json, AdminError> {
    let episodes = t.sponsorships(a.party).await?;
    let sponsors = episodes
        .iter()
        .filter(|s| s.ended_ms.is_none())
        .map(|s| ids.encode(SUBJECT_PREFIX, s.subject))
        .collect::<Result<Vec<_>, _>>()?;
    let mut out = json!({
        "agent": b64url_encode(&a.party),
        "display_name": a.display_name,
        "description": a.description,
        "agent_kind": a.kind,
        "operator": b64url_encode(&a.operator),
        "sponsors": sponsors,
        "status": a.status,
        "status_at": rfc3339(a.status_ms),
        "connections": [],
        "last_run_at": null,
        "created_at": rfc3339(a.created_ms),
        "registered_exercise": b64url_encode(&a.registered),
    });
    if let Some(o) = out.as_object_mut() {
        // SI-21, Ek B 4514
        let changes = episodes
            .iter()
            .map(|s| sponsor_json(ids, s))
            .collect::<Result<Vec<_>, _>>()?;
        o.insert(String::from("sponsorships"), Json::Array(changes));
        if let Some(list) = instances {
            // AG-21, Ek B 4510
            o.insert(
                String::from("instances"),
                Json::Array(
                    list.iter()
                        .map(|i| Json::String(b64url_encode(&i.0)))
                        .collect(),
                ),
            );
        }
    }
    Ok(out)
}

impl<D: Decider, G: Governance + Instances, K: RealmKeys> Admin<'_, D, G, K> {
    /// Records an agent's Party from the `party_register` its operator's client signed with a
    /// one-time key (OP-154 m.3 (c), L0-META-7): `actor_kind = agent`, rooted solely in the
    /// operator Party, an organization or a person of the realm's domain. The key is dropped
    /// and never an Instance; the agent's Instances are its runtime keys'.
    ///
    /// # Errors
    /// [`AdminError`]; a refusal by the domain is [`AdminError::Refused`].
    pub async fn register_agent(
        &self,
        (tenant, realm): (TenantId, RealmId),
        (party, operator): (Id, Id),
        key: access_kernel::verify::cose::PublicKey,
        register: access_internal_api::instances::SelfSigned,
    ) -> Result<bool, AdminError> {
        let mut t = TenantTx::begin(self.app, tenant, realm).await?;
        let g = idp::governance(&mut t).await?.ok_or(AdminError::NoRealm)?;
        t.commit().await?;
        let domain = Digest(*g.domain.as_bytes());
        let kind = self
            .governance
            .party(domain, operator)
            .await
            .map_err(|e| AdminError::Unavailable(e.0))?;
        // OP-154 m.3 (c), E23
        if !kind.is_some_and(|k| {
            matches!(k.actor_kind, ActorKind::Organization | ActorKind::Human) && !k.ended
        }) {
            return Err(Invalid::Agent.into());
        }
        let verdict = self
            .governance
            .register_agent(AgentRegistration {
                tenant: *tenant.as_bytes(),
                domain,
                party,
                operator,
                key,
                register,
                pep: String::from(self.pep),
            })
            .await
            .map_err(|e| AdminError::Unavailable(e.0))?;
        match verdict {
            crate::ports::OrgRegistered::Registered { replayed } => Ok(replayed),
            crate::ports::OrgRegistered::Refused { code } => Err(AdminError::Refused(code)),
        }
    }

    /// An agent is registered only for a live agent Party of the realm's domain whose root the
    /// operator is (OP-154 m.3 (c)).
    pub(crate) async fn agent_registrable(
        &self,
        domain: Digest,
        r: &AgentRegister,
    ) -> Result<(), AdminError> {
        let kind = self
            .governance
            .party(domain, Id(r.party))
            .await
            .map_err(|e| AdminError::Unavailable(e.0))?;
        if kind.is_some_and(|k| k.actor_kind == ActorKind::Agent && !k.ended) {
            Ok(())
        } else {
            Err(Invalid::Agent.into())
        }
    }

    /// The live Instances of the agent `agent` (AG-21): what `revoke-all` ends.
    ///
    /// # Errors
    /// [`AdminError`].
    pub async fn agent_instances(
        &self,
        (tenant, realm): (TenantId, RealmId),
        agent: [u8; 16],
    ) -> Result<Option<Vec<Id>>, AdminError> {
        let mut t = TenantTx::begin(self.app, tenant, realm).await?;
        let g = idp::governance(&mut t).await?.ok_or(AdminError::NoRealm)?;
        let row = t.agent(agent).await?;
        t.commit().await?;
        if row.is_none() {
            return Ok(None);
        }
        let list = self
            .governance
            .instances(Digest(*g.domain.as_bytes()), Id(agent))
            .await
            .map_err(|e| AdminError::Unavailable(e.0))?;
        Ok(Some(list))
    }
}
