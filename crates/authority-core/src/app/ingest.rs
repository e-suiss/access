//! Claim Ingest on the domain's leader (CMP-8, §9.13): a submission is verified by its carrier,
//! given its disposition under the live Acceptances, drawn from its issuer's quota and recorded
//! as a `claim` record through the sequencer. Nothing else changes; ingest is not acceptance
//! (INV-2, PI-22).

use access_authority_ingest::domain::{self as carrier, Frame, Mapped, Refusal};
use access_authority_sequencer::SequencerError;
use access_authority_sequencer::domain::Outcome as Committed;
use access_authority_sequencer::ports::DomainLog;
use access_internal_api::claims::{Carrier, ClaimSubmission, ClaimVerdict, Quarantine};
use access_kernel::claim::body::{self, Body, Class};
use access_kernel::claim::{self, ClaimState, Disposition, Statement};
use access_kernel::codec::Canonical;
use access_kernel::meta::{self, ContentState, kind};
use access_kernel::model::{EqValue, Id};
use suiss_crypto::dcbor::Value;

use crate::CoreError;
use crate::app::events::Derived;
use crate::app::{Authority, MAX_RETRIES, NewClaim, Resolved};
use crate::domain::Snapshot;
use crate::ports::{Binding, Reader, Salts};

/// What an ingest recorded, for the indexes kept beside the log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ingested {
    /// The answer.
    pub verdict: ClaimVerdict,
    /// The Claim's issuer.
    pub issuer: Id,
    /// Its class.
    pub class: String,
    /// When its issuer's quota was used up: the window's start and length in milliseconds
    /// (G44, §16.7).
    pub quota: Option<(u64, u64)>,
    /// The holder Instances an admitted compromise declaration ended (§9.9.3 k.6): their live
    /// projection families are revoked at the record once it is in.
    pub ended: Vec<Id>,
    /// The end of the Claim's validity, milliseconds; 0 for a refused submission.
    pub until: u64,
    /// The resource lifecycle fact of a `resource_lifecycle` Claim, to be kept in the
    /// incarnation registry once admitted (OP-156 m.3 (k)).
    pub lifecycle: Option<crate::app::resources::Lifecycle>,
    /// The Claim's subject.
    pub subject: Id,
    /// Its `value`.
    pub value: Option<EqValue>,
}

impl Ingested {
    /// A submission that does not verify: rejected with its reason, nothing recorded.
    fn refused(r: Refusal) -> Self {
        Self {
            verdict: ClaimVerdict::Rejected {
                code: String::from(r.0),
            },
            issuer: Id([0; 16]),
            class: String::new(),
            quota: None,
            ended: Vec::new(),
            until: 0,
            lifecycle: None,
            subject: Id([0; 16]),
            value: None,
        }
    }
}

/// A verified submission: what it says, who signed it and its body.
struct Verified {
    statement: Statement,
    instance: Option<Id>,
    body: Option<(Vec<u8>, Option<Body>)>,
    external: bool,
    /// Signed by a dropped realm key after its issuer cutoff: held (§13.7.7, SEC9).
    cut_off: bool,
}

type Checked = Result<Verified, Refusal>;

fn code(e: claim::ClaimError) -> Refusal {
    Refusal(e.code())
}

/// The classes whose use in actor-binding needs the subject's designation of their issuer
/// (§9.13.1, P21).
const DESIGNATED: [&str; 2] = ["authentication", "authenticator_binding"];

/// The prefix shared by every issuer's Acceptance index.
fn acceptances_prefix() -> Vec<u8> {
    let mut key = meta::key(kind::ACCEPTANCES, &Id([0; 16]));
    key.truncate(key.len().saturating_sub(17));
    key
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// Ingests `sub` at trusted time `now` (CMP-8, §9.13 rules 1 to 7).
    ///
    /// # Errors
    /// [`CoreError`] when the submission gets no answer; a Claim that does not verify is an
    /// answer ([`ClaimVerdict::Rejected`]).
    #[expect(
        clippy::too_many_lines,
        reason = "one commit loop over the submission's verdict and the fields kept beside the log"
    )]
    pub async fn ingest(&mut self, sub: &ClaimSubmission, now: u64) -> Result<Ingested, CoreError> {
        if sub.domain != self.domain {
            return Err(CoreError::Protocol("domain"));
        }
        let mut snap = Snapshot::default();
        let v = match self.carried(&mut snap, sub, now).await? {
            Ok(v) => v,
            Err(r) => return Ok(Ingested::refused(r)),
        };
        let id = claim::claim_id(&sub.claim);
        let issuer = v.statement.issuer;
        let class = v.statement.class.clone();
        let until = v.statement.validity.until;
        let body = v.body.as_ref().map(|(b, _)| b.as_slice());
        // L2-CLM-4
        if let Some(done) = self.replayed(&mut snap, id, &v, body).await? {
            return Ok(done);
        }
        // OP-156 m.3 (k), INV-32, E14
        let lifecycle = match self.lifecycle_gate(&v.statement, body).await? {
            Ok(l) => l,
            Err(r) => return Ok(Ingested::refused(r)),
        };
        for _ in 0..MAX_RETRIES {
            let mut snap = Snapshot::default();
            let pos = self
                .leader
                .head()
                .pos
                .checked_add(1)
                .ok_or(CoreError::Protocol("position"))?;
            let (disposition, draw, quota) = self.dispose(&mut snap, &v, now).await?;
            let resolved = Resolved {
                claims: vec![NewClaim {
                    bytes: sub.claim.clone(),
                    id,
                    statement: v.statement.clone(),
                    instance: v.instance,
                    disposition,
                    pos,
                    draw,
                }],
                ..Resolved::default()
            };
            let (items, ended) = self.ingest_items(&resolved, &v, now).await?;
            match self.leader.commit(now, &items).await {
                Ok(done) => {
                    let (position, ended) = match done {
                        Committed::Appended(positions) => {
                            (positions.last().copied().unwrap_or(pos), ended)
                        }
                        Committed::Replayed(at) => (at, Vec::new()),
                    };
                    // §17.8.2, TI-18
                    access_telemetry::signals::INGEST_CLAIMS.incr([
                        if Quarantine::of(disposition).is_some() {
                            "quarantined"
                        } else {
                            "admitted"
                        },
                    ]);
                    let verdict = match Quarantine::of(disposition) {
                        None => ClaimVerdict::Admitted {
                            claim: id,
                            position,
                            replayed: false,
                        },
                        Some(reason) => ClaimVerdict::Quarantined {
                            claim: id,
                            position,
                            reason,
                        },
                    };
                    return Ok(Ingested {
                        verdict,
                        issuer,
                        class,
                        quota,
                        ended,
                        until,
                        lifecycle,
                        subject: v.statement.subject,
                        value: v.statement.value.clone(),
                    });
                }
                Err(e) if e.is_retry() => {
                    access_telemetry::signals::VALIDATION_RETRIES.incr(["ingest"]);
                }
                Err(SequencerError::NonceConflict) => return Err(CoreError::Nonce),
                Err(e) => return Err(e.into()),
            }
        }
        Err(CoreError::Rejected(
            access_kernel::combinator::Rejection::Fuel,
        ))
    }

    /// The answer for a Claim already recorded: admitted as a replay at its first position
    /// (L2-CLM-4); `None` for a new one.
    async fn replayed(
        &self,
        snap: &mut Snapshot,
        id: Id,
        v: &Verified,
        body: Option<&[u8]>,
    ) -> Result<Option<Ingested>, CoreError> {
        let Some(state) = self
            .get(snap, &meta::key(kind::CLAIM, &id))
            .await?
            .and_then(|s| ClaimState::from_value(&s).ok())
        else {
            return Ok(None);
        };
        Ok(Some(Ingested {
            verdict: ClaimVerdict::Admitted {
                claim: id,
                position: state.since,
                replayed: true,
            },
            issuer: v.statement.issuer,
            class: v.statement.class.clone(),
            quota: None,
            ended: Vec::new(),
            until: v.statement.validity.until,
            lifecycle: crate::app::resources::recorded(&v.statement, body),
            subject: v.statement.subject,
            value: v.statement.value.clone(),
        }))
    }

    /// The `claim` record of an ingest: without the raw carrier of an external one (§10.1.2
    /// rule 1), with the body kept by its digest (§9.13.1). With it the holders the Claim ends.
    async fn ingest_items(
        &mut self,
        resolved: &Resolved,
        v: &Verified,
        now: u64,
    ) -> Result<(Vec<access_authority_sequencer::domain::Item>, Vec<Id>), CoreError> {
        let (claims, ended) = self.claim_events(self.domain, resolved, now).await?;
        let derived = Derived {
            decision: Vec::new(),
            claims,
            ended: Vec::new(),
            ended_by_claims: ended.clone(),
        };
        let mut items = self.claim_items(resolved, &derived)?;
        if let Some(item) = items.first_mut() {
            if v.external {
                item.proofs.clear();
            }
            if let (Some((bytes, _)), Some(EqValue::Bytes(d))) = (&v.body, &v.statement.value)
                && let Ok(d) = <[u8; 32]>::try_from(d.as_slice())
            {
                item.proofs.push((d, bytes.clone()));
            }
        }
        Ok((items, ended))
    }

    /// The disposition of `s`, its quota draw and, when the quota is used up, the window
    /// (L2-CLM-3, §9.13.1, G44).
    async fn dispose(
        &self,
        snap: &mut Snapshot,
        v: &Verified,
        now: u64,
    ) -> Result<(Disposition, Option<(Vec<u8>, u64)>, Option<(u64, u64)>), CoreError> {
        // SEC9
        if v.cut_off {
            return Ok((Disposition::SourceNotAccepted, None, None));
        }
        let s = &v.statement;
        let gates = self.gates(snap, &s.issuer).await?;
        let mut disposition = claim::disposition(s, &gates, now);
        // P21
        if disposition == Disposition::Admit && !self.designated(snap, s, now).await? {
            disposition = Disposition::SourceNotAccepted;
        }
        if disposition != Disposition::Admit || carrier::narrowing(s) {
            return Ok((disposition, None, None));
        }
        let Some((limit, window)) = claim::quota_of(s, &gates, now) else {
            return Ok((disposition, None, None));
        };
        let key = claim::quota_key(&s.issuer, window, now);
        if self.counter(&key).await? >= limit {
            // G44
            return Ok((
                Disposition::Quota,
                None,
                Some((carrier::window_start(now, window), window)),
            ));
        }
        Ok((disposition, Some((key, limit)), None))
    }

    /// Verifies `sub` by its carrier.
    async fn carried(
        &self,
        snap: &mut Snapshot,
        sub: &ClaimSubmission,
        now: u64,
    ) -> Result<Checked, CoreError> {
        let body = sub.body.as_deref();
        let (statement, instance) = match sub.carrier {
            Carrier::Cose | Carrier::Webauthn => {
                let kid = match claim::kid(&sub.claim) {
                    Ok(k) => k,
                    Err(e) => return Ok(Err(code(e))),
                };
                let Some((instance, party, key)) = self.instance_of(snap, &kid).await? else {
                    return Ok(Err(Refusal("claim-signature")));
                };
                match claim::verify(&sub.claim, &key, &party, &self.domain) {
                    Ok(s) => (s, Some(instance)),
                    Err(e) => return Ok(Err(code(e))),
                }
            }
            Carrier::Unsigned(channel) => {
                match claim::unsigned(&sub.claim, &self.domain, &channel) {
                    Ok(u) => (u.statement, None),
                    Err(e) => return Ok(Err(code(e))),
                }
            }
            Carrier::Oidc | Carrier::Set => return self.external(snap, sub, now).await,
            _ => return Ok(Err(Refusal::CARRIER)),
        };
        let decoded = match body::check(&statement, body) {
            Ok(d) => d,
            Err(e) => return Ok(Err(Refusal(e.code()))),
        };
        if sub.carrier == Carrier::Webauthn
            && let Err(r) = carrier::check_webauthn(decoded.as_ref())
        {
            return Ok(Err(r));
        }
        // CI-2, TN-46
        if let Err(r) = carrier::check_risk(&statement) {
            return Ok(Err(r));
        }
        Ok(Ok(Verified {
            cut_off: false,
            statement,
            instance,
            body: body.map(|b| (b.to_vec(), decoded)),
            external: false,
        }))
    }

    /// An `oidc` or `set` carrier: verified under a pinned issuer's key set and mapped, its
    /// subject held by an identity binding (§9.13 issuer identification, §10.1.2).
    async fn external(
        &self,
        snap: &mut Snapshot,
        sub: &ClaimSubmission,
        now: u64,
    ) -> Result<Checked, CoreError> {
        let subject = match carrier::carrier_context(sub.body.as_deref()) {
            Ok(s) => s,
            Err(r) => return Ok(Err(r)),
        };
        let iss = match carrier::peek_iss(&sub.claim) {
            Ok(i) => i,
            Err(r) => return Ok(Err(r)),
        };
        let mut last = Refusal::ISSUER;
        for (issuer, pinned) in self.pinned(snap, &iss).await? {
            let frame = Frame {
                domain: self.domain,
                issuer,
                subject,
                pinned: &pinned,
                now,
                skew_ms: claim::SKEW_MS,
            };
            let mapped = if sub.carrier == Carrier::Oidc {
                carrier::map_oidc(&sub.claim, &frame)
            } else {
                carrier::map_set(&sub.claim, &frame)
            };
            let m: Mapped = match mapped {
                Ok(m) => m,
                Err(r) => {
                    last = r;
                    continue;
                }
            };
            if !self.bound(snap, &subject, &m.subject, now).await? {
                return Ok(Err(Refusal::SUBJECT));
            }
            // §13.7.7, SEC9
            let cutoff = match carrier::peek_kid(&sub.claim) {
                Some(kid) => self.reader.key_cutoff(&iss, &kid).await?,
                None => None,
            };
            let decoded = match body::check(&m.statement, m.body.as_deref()) {
                Ok(d) => d,
                Err(e) => return Ok(Err(Refusal(e.code()))),
            };
            return Ok(Ok(Verified {
                cut_off: carrier::past_cutoff(m.statement.issued_at, cutoff),
                statement: m.statement,
                instance: None,
                body: m.body.map(|b| (b, decoded)),
                external: true,
            }));
        }
        Ok(Err(last))
    }

    /// The live Acceptances whose pinned key set names `iss`, with their issuer Party.
    async fn pinned(
        &self,
        snap: &mut Snapshot,
        iss: &str,
    ) -> Result<Vec<(Id, claim::Pinned)>, CoreError> {
        let mut out = Vec::new();
        for (_, value, _) in self.scan(&acceptances_prefix()).await? {
            let Some(Value::Array(ids)) = value else {
                continue;
            };
            for v in ids {
                let Ok(a) = Id::from_value(&v) else {
                    continue;
                };
                let Some(content) = self
                    .get(snap, &meta::key(kind::ACCEPTANCE, &a))
                    .await?
                    .and_then(|v| ContentState::from_value(&v).ok())
                    .filter(|c| c.ended.is_none())
                else {
                    continue;
                };
                if let Ok(g) = claim::Gate::of(&content.content)
                    && let (Some(issuer), Some(p)) = (g.issuer, g.pinned)
                    && p.iss == iss
                    && !out.iter().any(|(i, q)| *i == issuer && *q == p)
                {
                    out.push((issuer, p));
                }
            }
        }
        Ok(out)
    }

    /// Whether an admitted, current `identity_binding_person` Claim about `party` holds the
    /// upstream subject `digest` (§10.1.1: the bond is only an explicit identity binding).
    async fn bound(
        &self,
        snap: &mut Snapshot,
        party: &Id,
        digest: &access_kernel::digest::Digest,
        now: u64,
    ) -> Result<bool, CoreError> {
        let class = Class::IdentityBinding(body::BindingKind::Person).name();
        let want = carrier::binding_value(digest);
        for (_, value, _) in self.scan(&claim::member_prefix(&class, party)).await? {
            let Some(id) = value.and_then(|v| Id::from_value(&v).ok()) else {
                continue;
            };
            let Some(state) = self
                .get(snap, &meta::key(kind::CLAIM, &id))
                .await?
                .and_then(|v| ClaimState::from_value(&v).ok())
                .filter(|s| current(s, now) && s.statement.value == want)
            else {
                continue;
            };
            let gates = self.gates(snap, &state.statement.issuer).await?;
            if gates.iter().any(|g| {
                claim::ADMITTING_USES
                    .iter()
                    .any(|u| g.admits_for(u, &state.statement, now))
            }) && self.in_line(snap, &id, &state.statement, now).await?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Whether the subject's current key-state designates the issuer for the class (§9.13.1
    /// rule 2, P21). A key-state counts only when its issuer is a controller a current accepted
    /// `controller_of` Claim about the subject names (OP-152 m.7 (d) E20). Without such a
    /// key-state the Acceptance alone decides; with one, every current key-state in its issuer
    /// line must name the issuer for the class, and a key-state whose body cannot be read
    /// designates nobody (fail closed).
    pub(crate) async fn designated(
        &self,
        snap: &mut Snapshot,
        s: &Statement,
        now: u64,
    ) -> Result<bool, CoreError> {
        if !DESIGNATED.contains(&s.class.as_str()) {
            return Ok(true);
        }
        let controllers = self.controllers(snap, &s.subject, now).await?;
        let class = Class::PartyKeyState.name();
        for (_, value, _) in self.scan(&claim::member_prefix(&class, &s.subject)).await? {
            let Some(id) = value.and_then(|v| Id::from_value(&v).ok()) else {
                continue;
            };
            let Some(state) = self
                .get(snap, &meta::key(kind::CLAIM, &id))
                .await?
                .and_then(|v| ClaimState::from_value(&v).ok())
                .filter(|k| current(k, now) && k.statement.subject == s.subject)
            else {
                continue;
            };
            // OP-152 m.7 (d) E20
            if !controllers.contains(&state.statement.issuer) {
                continue;
            }
            let gates = self.gates(snap, &state.statement.issuer).await?;
            let accepted = gates.iter().any(|g| {
                g.admits_for(claim::ACTOR_BINDING, &state.statement, now)
                    || g.admits(&state.statement, now)
            });
            if !accepted || !self.unsuperseded(snap, &id, &state.statement).await? {
                continue;
            }
            if !self.names(&state.statement, &s.class, &s.issuer).await? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// The Parties a current, accepted and unsuperseded `controller_of` Claim about `subject`
    /// names (§9.13.1, §10.1.5, OP-152 m.7 (d) E20): only their key-state is the subject's
    /// controller designation.
    async fn controllers(
        &self,
        snap: &mut Snapshot,
        subject: &Id,
        now: u64,
    ) -> Result<std::collections::BTreeSet<Id>, CoreError> {
        let class = Class::ControllerOf.name();
        let mut out = std::collections::BTreeSet::new();
        for (_, value, _) in self.scan(&claim::member_prefix(&class, subject)).await? {
            let Some(id) = value.and_then(|v| Id::from_value(&v).ok()) else {
                continue;
            };
            let Some(state) = self
                .get(snap, &meta::key(kind::CLAIM, &id))
                .await?
                .and_then(|v| ClaimState::from_value(&v).ok())
                .filter(|c| current(c, now) && c.statement.subject == *subject)
            else {
                continue;
            };
            let Some(EqValue::Bytes(b)) = &state.statement.value else {
                continue;
            };
            let Ok(controller) = <[u8; 16]>::try_from(b.as_slice()) else {
                continue;
            };
            let gates = self.gates(snap, &state.statement.issuer).await?;
            let accepted = gates.iter().any(|g| {
                g.admits_for(claim::ACTOR_BINDING, &state.statement, now)
                    || g.admits(&state.statement, now)
            });
            if accepted && self.unsuperseded(snap, &id, &state.statement).await? {
                out.insert(Id(controller));
            }
        }
        Ok(out)
    }

    /// Whether the key-state `k` designates `issuer` for `class`.
    async fn names(&self, k: &Statement, class: &str, issuer: &Id) -> Result<bool, CoreError> {
        let Some(EqValue::Bytes(d)) = &k.value else {
            return Ok(false);
        };
        let Ok(d) = <[u8; 32]>::try_from(d.as_slice()) else {
            return Ok(false);
        };
        let Some(bytes) = self.reader.proof(&d).await? else {
            return Ok(false);
        };
        Ok(match body::check(k, Some(&bytes)) {
            Ok(Some(Body::PartyKeyState(ks))) => ks
                .designated
                .get(class)
                .is_some_and(|set| set.contains(issuer)),
            _ => false,
        })
    }
}

const fn current(s: &ClaimState, now: u64) -> bool {
    s.ended.is_none() && s.statement.validity.from <= now && now <= s.statement.validity.until
}
