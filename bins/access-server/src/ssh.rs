//! The realm's SSH certificate authority in access-server (OP-156 m.3 (o), IDP-32).
//!
//! The identity signer holds each realm's `ssh-ca` keys. Before every read or issuance the
//! realm's newest `idp.ssh.*` CA change is carried out on the signer, under the realm's lock,
//! and every key's phase recorded: `ca.pub` names the keys servers trust, the KRL every key
//! that no longer signs and every certificate whose projection's basis ended. A certificate is
//! a `projection.issue` of the holder's `ssh.login` Grant: the draft is drawn from the Grant,
//! the holder signs it with an Instance key of the Party its access token's account is bound
//! to (§13.4 G54), the authority plane decides it, and only an ALLOW is encoded, held within
//! the Grant, signed and recorded.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use access_http::problem::codes::realm as r;
use access_http::ssh::{SshFront, SshReply};
use access_identity_admin::ports::{Decider, Instances};
use access_identity_events::domain::catalog::{CertificateHolder, IdentityEvent};
use access_identity_oauth::app::oauth::RealmHolder;
use access_identity_oauth::domain::authority::{ais_kid, parse_exercise};
use access_identity_oauth::ports::RealmEntry;
use access_identity_signer::protocol::{Realm, Request, Response};
use access_identity_signer::ssh::{KeyInfo, Phase, SshRequest, SshResponse, Step};
use access_identity_ssh::SshError;
use access_identity_ssh::app::{IssueError, certify};
use access_identity_ssh::domain::key::Ed25519Public;
use access_identity_ssh::domain::krl::Krl;
use access_identity_ssh::domain::projection::{self, Ask, Holder};
use access_identity_ssh::domain::schema;
use access_identity_ssh::ports::{CaKey, CaRefusal, Random, Unavailable};
use access_internal_api::idp::{Submission, Verdict};
use access_internal_api::instances::{IDENTITY_PEP, self_signed_intent};
use access_internal_api::ssh::{SshGrants, Standing};
use access_kernel::codec::Canonical as _;
use access_kernel::combinator::{Capacity, Outcome};
use access_kernel::digest::Digest;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::meta::{ActorKind, ExerciseBasis, Payload};
use access_kernel::model::{Id, ResourceSelector, Window};
use access_kernel::validity::{ProfileClass, ProfileVariant};
use access_store::Pool;
use access_store::audit::AuditEvent;
use access_store::identity::TenantTx;
use access_store::ssh::NewCertificate;
use serde_json::{Value, json};

/// How long a new key is published before it signs: servers pull `ca.pub` at least daily.
pub(crate) const PUBLISH_MS: u64 = 24 * 3_600_000;

/// How long a retired key stays trusted: the longest certificate it signed, and a margin.
pub(crate) const RETIRE_MS: u64 = 13 * 3_600_000;

/// How long a draft's intent stays valid.
const DRAFT_MS: u64 = 10 * 60_000;

/// Most live certificates one KRL considers.
const KRL_SCAN: u32 = 10_000;

/// The identity signer's `ssh-ca` keys of one realm.
pub(crate) struct SignerCa<'a>(pub(crate) &'a Path);

async fn signer_call(socket: &Path, r: SshRequest) -> Result<SshResponse, String> {
    match access_identity_signer::adapters::call(socket, &Request::Ssh(r)).await {
        Ok(Response::Ssh(s)) => Ok(s),
        Ok(Response::Error(code)) => Err(code),
        _ => Err(String::from("signer-unavailable")),
    }
}

async fn signer_keys(socket: &Path, realm: Realm) -> Result<Vec<KeyInfo>, ()> {
    match signer_call(socket, SshRequest::Keys(realm)).await {
        Ok(SshResponse::Keys(k)) => Ok(k),
        _ => Err(()),
    }
}

impl CaKey for SignerCa<'_> {
    async fn active(&self, realm: [u8; 16]) -> Result<Option<Ed25519Public>, Unavailable> {
        let keys = signer_keys(self.0, Realm(realm))
            .await
            .map_err(|()| Unavailable)?;
        Ok(keys
            .iter()
            .find(|k| k.phase == Phase::Active)
            .map(|k| Ed25519Public(k.key)))
    }

    async fn sign(
        &self,
        realm: [u8; 16],
        key: Ed25519Public,
        data: Vec<u8>,
    ) -> Result<[u8; 64], CaRefusal> {
        match signer_call(
            self.0,
            SshRequest::Sign {
                realm: Realm(realm),
                key: key.0,
                data,
            },
        )
        .await
        {
            Ok(SshResponse::Signed(s)) => Ok(s),
            Err(code) if code == access_identity_signer::ssh::SshKeyError::Changed.code() => {
                Err(CaRefusal::Changed)
            }
            Err(code) if code == access_identity_signer::ssh::SshKeyError::NoKey.code() => {
                Err(CaRefusal::Off)
            }
            _ => Err(CaRefusal::Unavailable),
        }
    }
}

/// The operating system's randomness.
pub(crate) struct OsRandom;

impl Random for OsRandom {
    fn fill(&self, out: &mut [u8]) -> Result<(), Unavailable> {
        for chunk in out.chunks_mut(32) {
            let b: [u8; 32] = access_crypto::random::bytes().map_err(|_| Unavailable)?;
            chunk.copy_from_slice(b.get(..chunk.len()).ok_or(Unavailable)?);
        }
        Ok(())
    }
}

/// The realm's CA as it stands after reconciliation.
struct Standings {
    /// Whether the newest change leaves the CA on.
    on: bool,
    /// The signer's keys.
    keys: Vec<KeyInfo>,
    /// CA keys that no longer sign anything valid.
    revoked: BTreeSet<Ed25519Public>,
}

const fn phase_name(p: Phase) -> &'static str {
    match p {
        Phase::Published => "published",
        Phase::Active => "active",
        Phase::Retiring => "retiring",
    }
}

/// The certificate authority over the application pool, the identity signer's socket and the
/// authority plane in this process.
pub(crate) struct SshCa<P> {
    app: Pool,
    signer: PathBuf,
    plane: P,
}

fn unavailable<T: core::fmt::Display>(e: T) -> SshReply {
    tracing::warn!(error = %e, "ssh certificate authority unavailable");
    SshReply::Unavailable
}

fn refusal(e: SshError) -> SshReply {
    SshReply::Refused(match e {
        SshError::Lifetime => &r::SSH_LIFETIME,
        SshError::NoPrincipal
        | SshError::Constraint
        | SshError::Extension
        | SshError::NotGranted => &r::SSH_NOT_GRANTED,
        _ => &r::INVALID_SSH_REQUEST,
    })
}

fn covers_group(selector: &ResourceSelector, group: &str) -> bool {
    let wanted = schema::host_group(group);
    match selector {
        ResourceSelector::Exact(r) => *r == wanted,
        ResourceSelector::Structural(s) => {
            s.namespace == wanted.namespace
                && s.kind.is_none()
                && s.attrs.is_empty()
                && wanted.path.starts_with(&s.prefix)
        }
    }
}

fn holding_json(basis: &ExerciseBasis) -> Value {
    match basis {
        ExerciseBasis::Holding(h) => json!({
            "holding": {
                "grant": b64url_encode(&h.grant.0),
                "holder": b64url_encode(&h.holder.0),
                "since": h.since,
            }
        }),
        _ => Value::Null,
    }
}

impl<P> SshCa<P>
where
    P: SshGrants + Decider + Instances + Send + Sync + 'static,
{
    pub(crate) const fn new(app: Pool, signer: PathBuf, plane: P) -> Self {
        Self { app, signer, plane }
    }

    /// Carries out the realm's newest CA change and any rotation step now due, and records
    /// every key's phase.
    async fn reconcile(&self, t: &mut TenantTx, realm: Realm, now: u64) -> Result<Standings, ()> {
        t.lock_ssh_ca().await.map_err(|_| ())?;
        let change = t.ssh_ca_change().await.map_err(|_| ())?;
        let applied = t.ssh_ca_applied().await.map_err(|_| ())?;
        let Some(change) = change else {
            return Ok(Standings {
                on: false,
                keys: Vec::new(),
                revoked: BTreeSet::new(),
            });
        };
        let on = change.change != "disable";
        let mut keys = signer_keys(&self.signer, realm).await?;
        let mut step = None;
        if change.version > applied {
            step = Some(match change.change.as_str() {
                "enable" => None,
                "disable" => Some(Step::Close),
                "rotate" => Some(Step::Add),
                _ => Some(Step::Emergency),
            });
        } else if on {
            let due = |p: Phase, after: u64| {
                keys.iter()
                    .any(|k| k.phase == p && k.since.saturating_add(after) <= now)
            };
            if due(Phase::Retiring, RETIRE_MS) {
                step = Some(Some(Step::Remove));
            } else if due(Phase::Published, PUBLISH_MS) {
                step = Some(Some(Step::Switch));
            }
        }
        if let Some(step) = step {
            let answer = match step {
                None => signer_call(&self.signer, SshRequest::Open(realm)).await,
                Some(step) => signer_call(&self.signer, SshRequest::Rotate { realm, step }).await,
            };
            keys = match answer {
                Ok(SshResponse::Keys(k)) => k,
                Err(code) if code == access_identity_signer::ssh::SshKeyError::Order.code() => {
                    signer_keys(&self.signer, realm).await?
                }
                _ => return Err(()),
            };
            let revoke = matches!(change.change.as_str(), "disable" | "emergency");
            self.record(t, &keys, change.version, revoke, now).await?;
        }
        let revoked = t
            .ssh_ca_keys()
            .await
            .map_err(|_| ())?
            .into_iter()
            .filter(|k| k.phase == "revoked")
            .map(|k| Ed25519Public(k.public_key))
            .collect();
        Ok(Standings { on, keys, revoked })
    }

    async fn record(
        &self,
        t: &mut TenantTx,
        keys: &[KeyInfo],
        change: u64,
        revoke: bool,
        now: u64,
    ) -> Result<(), ()> {
        let rows: BTreeMap<[u8; 32], String> = t
            .ssh_ca_keys()
            .await
            .map_err(|_| ())?
            .into_iter()
            .map(|k| (k.public_key, k.phase))
            .collect();
        for k in keys {
            let phase = phase_name(k.phase);
            if rows.get(&k.key).map(String::as_str) != Some(phase) {
                t.put_ssh_ca_key(&k.key, phase, k.since, change)
                    .await
                    .map_err(|_| ())?;
            }
        }
        for (key, phase) in &rows {
            let gone = !keys.iter().any(|k| k.key == *key);
            if gone && matches!(phase.as_str(), "published" | "active" | "retiring") {
                let next = if revoke { "revoked" } else { "removed" };
                t.put_ssh_ca_key(key, next, now, change)
                    .await
                    .map_err(|_| ())?;
            }
        }
        Ok(())
    }

    async fn begin(&self, realm: &RealmEntry) -> Result<(TenantTx, u64), ()> {
        let now = access_store::authority::server_time(&self.app)
            .await
            .map_err(|_| ())?;
        let t = TenantTx::begin(&self.app, realm.tenant, realm.realm)
            .await
            .map_err(|_| ())?;
        Ok((t, now))
    }

    /// Who holds a certificate of `holder` asked for by the account bound to `caller`, by the
    /// Party's actor kind in the domain: the caller itself, or a live agent Party, which acts
    /// for the caller; `None` for anyone else.
    async fn holder_of(
        &self,
        domain: Digest,
        caller: Id,
        holder: Id,
    ) -> Result<Option<Holder>, String> {
        let kind = Instances::party(&self.plane, domain, holder)
            .await
            .map_err(|e| e.0)?;
        Ok(match kind {
            Some(k) if k.ended => None,
            Some(k) if k.actor_kind == ActorKind::Agent => Some(Holder::Agent),
            Some(_) if holder == caller => Some(Holder::Person),
            _ => None,
        })
    }

    async fn live_group(t: &mut TenantTx, group: &str) -> Result<bool, ()> {
        Ok(t.ssh_host_groups()
            .await
            .map_err(|_| ())?
            .iter()
            .any(|g| g.name == group && g.live))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one draft, its checks in the order they are made"
    )]
    async fn draft(
        &self,
        realm: &RealmEntry,
        holder: &RealmHolder,
        body: &Value,
    ) -> Result<SshReply, String> {
        let Some(m) = body.as_object() else {
            return Ok(SshReply::Refused(&r::INVALID_SSH_REQUEST));
        };
        if m.keys().any(|k| {
            !matches!(
                k.as_str(),
                "host_group" | "public_key" | "principals" | "lifetime_s" | "agent"
            )
        }) {
            return Ok(SshReply::Refused(&r::INVALID_SSH_REQUEST));
        }
        let group = m.get("host_group").and_then(Value::as_str);
        let key = m
            .get("public_key")
            .and_then(Value::as_str)
            .and_then(|k| b64url_decode(k).ok())
            .and_then(|k| <[u8; 32]>::try_from(k).ok());
        let principals = match m.get("principals") {
            None => Some(None),
            Some(Value::Array(a)) => a
                .iter()
                .map(|p| p.as_str().map(String::from))
                .collect::<Option<BTreeSet<_>>>()
                .map(Some),
            Some(_) => None,
        };
        let lifetime = match m.get("lifetime_s") {
            None => Some(None),
            Some(v) => v.as_u64().map(|s| Some(s.saturating_mul(1000))),
        };
        let agent = match m.get("agent") {
            None => Some(None),
            Some(a) => a
                .as_str()
                .and_then(|a| b64url_decode(a).ok())
                .and_then(|a| <[u8; 16]>::try_from(a).ok())
                .map(|a| Some(Id(a))),
        };
        let (Some(group), Some(key), Some(principals), Some(lifetime), Some(agent)) =
            (group, key, principals, lifetime, agent)
        else {
            return Ok(SshReply::Refused(&r::INVALID_SSH_REQUEST));
        };
        let (mut t, now) = self.begin(realm).await.map_err(|()| "begin")?;
        let Some(g) = access_store::idp::governance(&mut t)
            .await
            .map_err(|e| e.to_string())?
        else {
            return Ok(SshReply::Refused(&r::SSH_NOT_GRANTED));
        };
        let domain = Digest(*g.domain.as_bytes());
        let Some(party) = access_store::idp::subject_party(&mut t, &holder.subject)
            .await
            .map_err(|e| e.to_string())?
        else {
            return Ok(SshReply::Refused(&r::SSH_NOT_GRANTED));
        };
        let caller = Id(party);
        let party = agent.unwrap_or(caller);
        let Some(kind) = self.holder_of(domain, caller, party).await? else {
            return Ok(SshReply::Refused(&r::SSH_NOT_GRANTED));
        };
        if !Self::live_group(&mut t, group)
            .await
            .map_err(|()| "groups")?
        {
            return Ok(SshReply::Refused(&r::SSH_NOT_GRANTED));
        }
        let on = self
            .reconcile(&mut t, Realm(*realm.realm.as_bytes()), now)
            .await
            .map_err(|()| "reconcile")?
            .on;
        t.commit().await.map_err(|e| e.to_string())?;
        if !on {
            return Ok(SshReply::Refused(&r::SSH_CA_OFF));
        }
        let holdings = self
            .plane
            .holdings(domain, party, schema::login_ref())
            .await
            .map_err(|e| e.0)?;
        let ask = Ask {
            host_group: String::from(group),
            key: Ed25519Public(key),
            principals,
            lifetime_ms: lifetime,
        };
        let mut last = SshError::NotGranted;
        for h in holdings {
            if !covers_group(&h.authority.authority.resource, group) {
                continue;
            }
            let bounds = match projection::draft(&h.authority, kind, &ask, now) {
                Ok(b) => b,
                Err(e) => {
                    last = e;
                    continue;
                }
            };
            let payload = Payload::ProjectionIssue {
                bounds,
                audience: BTreeSet::from([realm.issuer.endpoint(&format!("/ssh/{group}"))]),
                class: ProfileClass::Online,
                variant: ProfileVariant::OnlineStrict,
                max_staleness_ms: None,
                offline_slice: None,
            };
            let validity = Window {
                from: now.saturating_sub(projection::BACKDATE_MS),
                until: now.saturating_add(DRAFT_MS),
            };
            let intent = self_signed_intent(&payload, party, validity).ok_or("intent")?;
            let nonce = access_crypto::random::bytes::<16>().map_err(|_| "random")?;
            let basis = ExerciseBasis::Holding(h.holding);
            return Ok(SshReply::Ok(json!({
                "draft": {
                    "domain": b64url_encode(&domain.0),
                    "nonce": b64url_encode(&nonce),
                    "intent": b64url_encode(&intent.to_bytes().map_err(|_| "intent")?),
                    "payload": b64url_encode(&payload.to_bytes().map_err(|_| "payload")?),
                    "basis": holding_json(&basis),
                    "capacity": if party == caller {
                        json!("own")
                    } else {
                        json!({ "for": b64url_encode(&caller.0) })
                    },
                    "pep": IDENTITY_PEP,
                    "holder": kind.name(),
                }
            })));
        }
        Ok(refusal(last))
    }

    #[allow(
        clippy::too_many_lines,
        clippy::many_single_char_names,
        reason = "one issuance, its checks in the order they are made"
    )]
    async fn issue(
        &self,
        realm: &RealmEntry,
        holder: &RealmHolder,
        exercise: &str,
    ) -> Result<SshReply, String> {
        let Ok(e) = parse_exercise(exercise) else {
            return Ok(SshReply::Refused(&r::INVALID_SSH_REQUEST));
        };
        if ais_kid(&e.ais).is_none() {
            return Ok(SshReply::Refused(&r::INVALID_SSH_REQUEST));
        }
        let ExerciseBasis::Holding(basis) = e.basis else {
            return Ok(SshReply::Refused(&r::INVALID_SSH_REQUEST));
        };
        let Payload::ProjectionIssue { bounds, .. } = &e.payload else {
            return Ok(SshReply::Refused(&r::INVALID_SSH_REQUEST));
        };
        let (mut t, now) = self.begin(realm).await.map_err(|()| "begin")?;
        let Some(g) = access_store::idp::governance(&mut t)
            .await
            .map_err(|err| err.to_string())?
        else {
            return Ok(SshReply::Refused(&r::SSH_NOT_GRANTED));
        };
        let domain = Digest(*g.domain.as_bytes());
        let party = access_store::idp::subject_party(&mut t, &holder.subject)
            .await
            .map_err(|err| err.to_string())?
            .map(Id);
        let Some(caller) = party.filter(|_| e.domain == domain) else {
            return Ok(SshReply::Refused(&r::INVALID_SSH_REQUEST));
        };
        let Some(kind) = self.holder_of(domain, caller, basis.holder).await? else {
            return Ok(SshReply::Refused(&r::SSH_NOT_GRANTED));
        };
        // AG-24
        let capacity = if basis.holder == caller {
            Capacity::Own
        } else {
            Capacity::For(caller)
        };
        if e.capacity != capacity {
            return Ok(SshReply::Refused(&r::INVALID_SSH_REQUEST));
        }
        // OP-156 m.3 (o)
        let (group, key) = match projection::precheck(bounds, kind, now) {
            Ok(v) => v,
            Err(err) => return Ok(refusal(err)),
        };
        if !Self::live_group(&mut t, &group)
            .await
            .map_err(|()| "groups")?
        {
            return Ok(SshReply::Refused(&r::SSH_NOT_GRANTED));
        }
        let on = self
            .reconcile(&mut t, Realm(*realm.realm.as_bytes()), now)
            .await
            .map_err(|()| "reconcile")?
            .on;
        t.commit().await.map_err(|err| err.to_string())?;
        if !on {
            return Ok(SshReply::Refused(&r::SSH_CA_OFF));
        }
        let grant = self
            .plane
            .holdings(domain, basis.holder, schema::login_ref())
            .await
            .map_err(|err| err.0)?
            .into_iter()
            .find(|h| h.holding == basis);
        let Some(grant) = grant else {
            return Ok(SshReply::Refused(&r::SSH_NOT_GRANTED));
        };
        // IDP-32, G2
        if let Err(err) = projection::derive(
            &grant.authority,
            bounds,
            kind,
            "-",
            bounds.constraints.validity.until,
        ) {
            return Ok(refusal(err));
        }
        let verdict = Box::pin(self.plane.decide(Submission {
            domain,
            nonce: e.nonce.clone(),
            intent: e.intent.clone(),
            payload: Some(Box::new(e.payload.clone())),
            basis: e.basis,
            capacity,
            ais: e.ais.clone(),
            contributions: Vec::new(),
            pep: String::from(IDENTITY_PEP),
            actor: Some(basis.holder),
        }))
        .await
        .map_err(|err| err.0)?;
        let committed = match verdict {
            Verdict::Committed(c) if !c.replayed => c,
            Verdict::Committed(_) | Verdict::Refused { .. } => {
                return Ok(SshReply::Refused(&r::INVALID_SSH_REQUEST));
            }
            Verdict::NotAllowed { decision, .. } => {
                return Ok(SshReply::NotAllowed(
                    if decision.outcome == Outcome::RequireAction {
                        "require_action"
                    } else {
                        "deny"
                    },
                ));
            }
        };
        let key_id = b64url_encode(&committed.exercise.0);
        // IDP-32, G2
        let p = match projection::derive(
            &grant.authority,
            bounds,
            kind,
            &key_id,
            bounds.constraints.validity.until,
        ) {
            Ok(p) => p,
            Err(err) => return Ok(refusal(err)),
        };
        if p.public_key != key || p.host_group != group {
            return Ok(SshReply::Refused(&r::INVALID_SSH_REQUEST));
        }
        let issued = match Box::pin(certify(
            &SignerCa(&self.signer),
            &OsRandom,
            *realm.realm.as_bytes(),
            &p,
        ))
        .await
        {
            Ok(i) => i,
            Err(IssueError::Off) => return Ok(SshReply::Refused(&r::SSH_CA_OFF)),
            Err(IssueError::Refused(err)) => return Ok(refusal(err)),
            Err(IssueError::Unavailable) => return Err(String::from("certify")),
        };
        let f = &issued.fields;
        let principals: Vec<String> = f.principals.iter().cloned().collect();
        let intent = e.intent.to_bytes().map_err(|_| "intent")?;
        let mut t = TenantTx::begin(&self.app, realm.tenant, realm.realm)
            .await
            .map_err(|err| err.to_string())?;
        t.insert_ssh_certificate(&NewCertificate {
            ca_key: f.ca.0,
            serial: f.serial,
            key_id: &key_id,
            domain: domain.0,
            exercise: committed.exercise.0,
            position: committed.position,
            intent: &intent,
            holder: kind.name(),
            party: basis.holder.0,
            host_group: &group,
            principals: &principals,
            public_key: f.key.0,
            valid_after: f.valid_after,
            valid_before: f.valid_before,
            issued_ms: now,
        })
        .await
        .map_err(|err| err.to_string())?;
        // OP-41
        t.audit(&AuditEvent {
            event_type: "ssh.certificate_issued",
            actor: "ssh-ca",
            target: &key_id,
            correlation: "-",
        })
        .await
        .map_err(|err| err.to_string())?;
        let id = access_crypto::random::bytes::<32>().map_err(|_| "random")?;
        let event = IdentityEvent::ssh_certificate_issued(
            id,
            realm.realm.as_bytes(),
            (
                &basis.holder.0,
                match kind {
                    Holder::Person => CertificateHolder::Person,
                    Holder::Agent => CertificateHolder::Agent,
                },
                &key_id,
                &group,
            ),
            f.valid_before,
            now,
        );
        access_identity_events::app::emit(&mut t, &event)
            .await
            .map_err(|err| err.to_string())?;
        t.commit().await.map_err(|err| err.to_string())?;
        Ok(SshReply::Ok(json!({
            "certificate": issued.certificate.line(&key_id),
            "key_id": key_id,
            "serial": f.serial.to_string(),
            "principals": principals,
            "host_group": group,
            "holder": kind.name(),
            "valid_after": f.valid_after,
            "valid_before": f.valid_before,
            "ca_key": f.ca.line(""),
            "projection": b64url_encode(
                &suiss_crypto::dcbor::encode(&p.to_value(), suiss_crypto::dcbor::Limits::CEILING)
                    .map_err(|_| "projection")?
            ),
        })))
    }

    async fn ca_lines(&self, realm: &RealmEntry) -> Result<Option<String>, String> {
        let (mut t, now) = self.begin(realm).await.map_err(|()| "begin")?;
        let s = self
            .reconcile(&mut t, Realm(*realm.realm.as_bytes()), now)
            .await
            .map_err(|()| "reconcile")?;
        t.commit().await.map_err(|e| e.to_string())?;
        if !s.on || s.keys.is_empty() {
            return Ok(None);
        }
        let comment = format!("access-ca@{}", realm.slug);
        Ok(Some(s.keys.iter().fold(String::new(), |mut out, k| {
            out.push_str(&Ed25519Public(k.key).line(&comment));
            out.push('\n');
            out
        })))
    }

    async fn krl_bytes(&self, realm: &RealmEntry) -> Result<Vec<u8>, String> {
        let (mut t, now) = self.begin(realm).await.map_err(|()| "begin")?;
        let s = self
            .reconcile(&mut t, Realm(*realm.realm.as_bytes()), now)
            .await
            .map_err(|()| "reconcile")?;
        t.commit().await.map_err(|e| e.to_string())?;
        let now_s = now / 1000;
        let mut t = TenantTx::begin(&self.app, realm.tenant, realm.realm)
            .await
            .map_err(|e| e.to_string())?;
        let certificates = t
            .ssh_certificates(now_s, KRL_SCAN)
            .await
            .map_err(|e| e.to_string())?;
        t.commit().await.map_err(|e| e.to_string())?;
        let mut serials: BTreeMap<Ed25519Public, BTreeSet<u64>> = BTreeMap::new();
        let mut ended = Vec::new();
        for c in &certificates {
            let ca = Ed25519Public(c.ca_key);
            if c.revoked.is_some() {
                serials.entry(ca).or_default().insert(c.serial);
                continue;
            }
            if s.revoked.contains(&ca) {
                continue;
            }
            // INV-5, IDP-32
            let standing = self
                .plane
                .standing(Digest(c.domain), Digest(c.exercise))
                .await
                .map_err(|e| e.0)?;
            if standing != Standing::Stands {
                ended.push((c.ca_key, c.serial));
                serials.entry(ca).or_default().insert(c.serial);
            }
        }
        let mut t = TenantTx::begin(&self.app, realm.tenant, realm.realm)
            .await
            .map_err(|e| e.to_string())?;
        for (ca, serial) in ended {
            t.revoke_ssh_certificate(&ca, serial, "basis-ended", now)
                .await
                .map_err(|e| e.to_string())?;
        }
        let version = t.ssh_krl_version().await.map_err(|e| e.to_string())?;
        t.commit().await.map_err(|e| e.to_string())?;
        Krl {
            version,
            generated: now_s,
            serials,
            keys: s.revoked,
        }
        .encode()
        .map_err(|e| e.to_string())
    }
}

impl<P> SshFront for SshCa<P>
where
    P: SshGrants + Decider + Instances + Send + Sync + 'static,
{
    async fn ca_pub(&self, realm: &RealmEntry) -> Result<Option<String>, ()> {
        Box::pin(self.ca_lines(realm)).await.map_err(|e| {
            tracing::warn!(error = %e, "ssh ca.pub unavailable");
        })
    }

    async fn krl(&self, realm: &RealmEntry) -> Result<Vec<u8>, ()> {
        Box::pin(self.krl_bytes(realm)).await.map_err(|e| {
            tracing::warn!(error = %e, "ssh krl unavailable");
        })
    }

    async fn certificate(&self, realm: &RealmEntry, holder: RealmHolder, body: Value) -> SshReply {
        let done = match body.get("exercise").and_then(Value::as_str) {
            Some(x) if body.as_object().is_some_and(|m| m.len() == 1) => {
                Box::pin(self.issue(realm, &holder, x)).await
            }
            Some(_) => Ok(SshReply::Refused(&r::INVALID_SSH_REQUEST)),
            None => Box::pin(self.draft(realm, &holder, &body)).await,
        };
        done.unwrap_or_else(unavailable)
    }
}
