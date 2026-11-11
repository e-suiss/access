//! Realm rehome and residency (§5.16, §12.1.1 2a, E14, MD-5a, CMP-26, OP-30, OP-158 m.3 (o)):
//! `idp.realm.rehome` is reserved, CT3 and two-ended. One Exercise is committed in the realm's
//! governing domain and one in the domain it moves to; the realm moves only when both are
//! committed, in the transaction that records the second, and its placement then follows the
//! new domain's cell. One end alone leaves the realm where it is. A residency names a region
//! this cell is in; declaring another one is a cell move first.

use access_internal_api::idp::{Submission, Verdict};
use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_store::identity::TenantTx;
use access_store::idp::{self, Decision as Bind, Governing};
use access_store::placement::{self, End, Side, Subject};
use access_store::scope::DomainId;

use super::{Admin, Applied, Proposal};
use crate::AdminError;
use crate::domain::resilience::{DrClass, Rehome, Residency};
use crate::domain::{Change, Invalid};
use crate::ports::{Decider, Governance, Instances, RealmKeys};

/// The rehome target must be another domain of the realm's tenant in this cell (E14).
///
/// # Errors
/// [`Invalid::PlacementMismatch`] for a domain this cell does not hold for the tenant;
/// [`AdminError::Conflict`] for the realm's own governing domain.
pub(crate) async fn current(t: &mut TenantTx, g: &Governing, r: &Rehome) -> Result<(), AdminError> {
    let to = DomainId::from_bytes(r.domain);
    if to == g.domain {
        return Err(AdminError::Conflict);
    }
    if !placement::tenant_domain(t, &to).await? {
        return Err(Invalid::PlacementMismatch.into());
    }
    Ok(())
}

/// A residency names the region this cell declares, and a synchronous multi-region class only
/// on a cell that declares one (CMP-26, OP-30).
///
/// # Errors
/// [`Invalid::PlacementMismatch`].
pub(crate) async fn residency_current(t: &mut TenantTx, r: &Residency) -> Result<(), AdminError> {
    let Some(cell) = placement::cell_profile_in(t).await? else {
        return Err(Invalid::PlacementMismatch.into());
    };
    let class_fits = r.class == DrClass::Regional || cell.class == DrClass::MultiRegionSync.name();
    if cell.region.as_deref() != Some(r.region.as_str()) || !class_fits {
        return Err(Invalid::PlacementMismatch.into());
    }
    Ok(())
}

/// The statement an AIS carries, read without verifying it; the authority plane verifies it.
fn statement(ais: &[u8]) -> Result<access_kernel::ais::Statement, AdminError> {
    access_kernel::verify::cose::parse_sign1(ais)
        .ok()
        .and_then(|s| s.payload)
        .and_then(|p| access_kernel::ais::Statement::from_bytes(&p).ok())
        .ok_or_else(|| AdminError::Refused(String::from("ais-invalid")))
}

impl<D: Decider, G: Governance + Instances, K: RealmKeys> Admin<'_, D, G, K> {
    async fn decide_end(
        &self,
        p: &Proposal,
        (domain, nonce, intent): (Digest, &[u8], access_kernel::intent::IntentEnvelope),
        (basis, capacity, ais): (
            access_kernel::meta::ExerciseBasis,
            access_kernel::combinator::Capacity,
            Vec<u8>,
        ),
    ) -> Result<Result<access_internal_api::idp::Committed, Applied>, AdminError> {
        self.standing((p.tenant, p.realm), domain, &ais, None)
            .await?;
        let verdict = self
            .decider
            .decide(Submission {
                actor: None,
                domain,
                nonce: nonce.to_vec(),
                intent,
                payload: None,
                basis,
                capacity,
                ais,
                contributions: Vec::new(),
                pep: String::from(self.pep),
            })
            .await
            .map_err(|e| AdminError::Unavailable(e.0))?;
        match verdict {
            Verdict::Committed(c) if c.domain == domain && c.nonce == nonce => Ok(Ok(c)),
            Verdict::Committed(_) => Err(AdminError::Unbound),
            Verdict::NotAllowed { decision, .. }
                if access_internal_api::idp::catalog_upgrade_required(&decision) =>
            {
                Err(Invalid::CatalogUpgradeRequired.into())
            }
            Verdict::NotAllowed { decision, position } => {
                Ok(Err(Applied::NotAllowed { decision, position }))
            }
            Verdict::Refused { code, .. } if code == "unavailable" => {
                Err(AdminError::Unavailable(code))
            }
            Verdict::Refused { code, .. } => Err(AdminError::Refused(code)),
        }
    }

    /// Commits a rehome's from end with `ais` in the realm's governing domain and, with
    /// `target_ais`, its to end in the new domain; the realm moves when both are committed
    /// (E14, OP-158 m.3 (o)). A DENY of the from end is [`Applied::NotAllowed`]; with only the
    /// from end committed, the realm stays and the answer is [`Invalid::RehomeIncomplete`].
    ///
    /// # Errors
    /// [`AdminError`].
    pub async fn rehome(
        &self,
        proposal: &Proposal,
        ais: Vec<u8>,
        target_ais: Option<Vec<u8>>,
    ) -> Result<Applied, AdminError> {
        let Change::Rehome(move_to) = &proposal.change else {
            return Err(Invalid::Body.into());
        };
        let prepared = self.prepare(proposal).await?;
        let ends = Ends {
            from: prepared.domain,
            to: Digest(move_to.domain),
        };
        if let Err(denied) = self.old_end(proposal, &prepared, ends, ais).await? {
            return Ok(denied);
        }
        let target_ais = target_ais.ok_or(Invalid::RehomeIncomplete)?;
        let second = self.new_end(proposal, &prepared, ends, target_ais).await?;
        self.complete(proposal, ends, &second).await?;
        Ok(Applied::Written {
            exercise: second.exercise,
            position: second.position,
            secret: None,
        })
    }

    /// The from end: decided in the governing domain, bound there and recorded.
    async fn old_end(
        &self,
        proposal: &Proposal,
        prepared: &super::Prepared,
        ends: Ends,
        ais: Vec<u8>,
    ) -> Result<Result<(), Applied>, AdminError> {
        let first = match self
            .decide_end(
                proposal,
                (ends.from, &proposal.nonce, prepared.intent.clone()),
                (proposal.basis, proposal.capacity, ais),
            )
            .await?
        {
            Ok(c) if c.intent == prepared.digest => c,
            Ok(_) => return Err(AdminError::Unbound),
            Err(denied) => return Ok(Err(denied)),
        };
        let change = proposal.change.digest().map_err(|_| AdminError::Encode)?;
        let label = proposal.change.action().label();
        let (from, to) = ends.ids();
        let mut tx = TenantTx::begin(self.app, proposal.tenant, proposal.realm).await?;
        let bound = idp::bind(
            &mut tx,
            &Bind {
                domain: &from,
                position: first.position,
                nonce: &first.nonce,
                intent: first.intent.0,
                change: change.0,
                action: &label,
            },
        )
        .await?;
        if bound.is_some() {
            placement::record_end(
                &mut tx,
                &End {
                    side: Side::From,
                    from: &from,
                    to: &to,
                    position: first.position,
                    nonce: &first.nonce,
                    intent: first.intent.0,
                },
            )
            .await?;
        }
        tx.commit().await?;
        Ok(Ok(()))
    }

    /// The to end: decided in the new domain with the AIS signed for it.
    async fn new_end(
        &self,
        proposal: &Proposal,
        prepared: &super::Prepared,
        ends: Ends,
        target_ais: Vec<u8>,
    ) -> Result<access_internal_api::idp::Committed, AdminError> {
        let named = statement(&target_ais)?;
        if named.domain != ends.to || named.intent != prepared.digest {
            return Err(AdminError::Unbound);
        }
        match self
            .decide_end(
                proposal,
                (ends.to, &named.nonce, prepared.intent.clone()),
                (named.basis, named.capacity, target_ais),
            )
            .await?
        {
            Ok(c) if c.intent == prepared.digest => Ok(c),
            Ok(_) => Err(AdminError::Unbound),
            Err(denied) => {
                tracing::info!(
                    event = "rehome.incomplete",
                    decision = ?denied,
                    "the new governing domain did not commit its end; the realm stays (E14)"
                );
                Err(Invalid::RehomeIncomplete.into())
            }
        }
    }

    /// Records the to end and moves the realm when both ends are there (E14); its placement
    /// then follows the new domain's cell (TI-17).
    async fn complete(
        &self,
        proposal: &Proposal,
        ends: Ends,
        second: &access_internal_api::idp::Committed,
    ) -> Result<(), AdminError> {
        let (from, to) = ends.ids();
        let mut tx = TenantTx::begin(self.app, proposal.tenant, proposal.realm).await?;
        placement::record_end(
            &mut tx,
            &End {
                side: Side::To,
                from: &from,
                to: &to,
                position: second.position,
                nonce: &second.nonce,
                intent: second.intent.0,
            },
        )
        .await?;
        if placement::complete_rehome(&mut tx, &from, &to)
            .await?
            .is_none()
        {
            tx.rollback().await?;
            return Err(Invalid::RehomeIncomplete.into());
        }
        let at = access_store::authority::server_time(self.app).await?;
        // TI-17
        let cell = match placement::cell_of(self.app, &Subject::Domain(ends.to.0)).await? {
            Some(c) => Some((c.cell, c.dedicated)),
            None => placement::cell_profile_in(&mut tx)
                .await?
                .map(|c| (c.cell, c.dedicated_to.is_some())),
        };
        if let Some((cell, dedicated)) = cell {
            placement::place(
                &mut tx,
                &Subject::Realm(*proposal.realm.as_bytes()),
                (&cell, dedicated),
                at,
            )
            .await?;
        }
        let target = access_kernel::json::b64url_encode(&ends.to.0);
        let correlation = access_kernel::json::b64url_encode(&second.exercise.0);
        tx.audit(&access_store::audit::AuditEvent {
            event_type: "realm.rehomed",
            actor: super::DECIDED_BY,
            target: &target,
            correlation: &correlation,
        })
        .await?;
        tx.commit().await?;
        Ok(())
    }
}

/// The two governing domains of a rehome.
#[derive(Clone, Copy)]
struct Ends {
    from: Digest,
    to: Digest,
}

impl Ends {
    fn ids(self) -> (DomainId, DomainId) {
        (
            DomainId::from_bytes(self.from.0),
            DomainId::from_bytes(self.to.0),
        )
    }
}

fn placed(p: Option<&placement::Placed>) -> serde_json::Value {
    p.map_or(
        serde_json::Value::Null,
        |p| serde_json::json!({ "cell": p.cell, "dedicated": p.dedicated, "version": p.version }),
    )
}

/// `getPlacement`: the cell this realm, its governing domain and its tenant are placed in, this
/// cell's own profile and the realm's residency (TI-17, CMP-26, OP-158 m.3 (o)). An absent
/// placement reads as this cell: the cell that leads a domain serves it.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn placement_view(t: &mut TenantTx) -> Result<serde_json::Value, AdminError> {
    let g = idp::governance(t).await?.ok_or(AdminError::NoRealm)?;
    let realm = t.realm().ok_or(AdminError::NoRealm)?;
    let cell = placement::cell_profile_in(t).await?;
    let mut latest = Vec::new();
    for subject in [
        Subject::Tenant(*t.tenant().as_bytes()),
        Subject::Realm(*realm.as_bytes()),
        Subject::Domain(*g.domain.as_bytes()),
    ] {
        latest.push(placement::history(t, &subject).await?.pop());
    }
    let residency = placement::residency(t).await?;
    let open = placement::open_ends(t).await?;
    Ok(serde_json::json!({
        "cell": cell.as_ref().map(|c| c.cell.clone()),
        "region": cell.as_ref().and_then(|c| c.region.clone()),
        "dedicated_cell": cell.as_ref().is_some_and(|c| c.dedicated_to.is_some()),
        "tenant": placed(latest.first().and_then(Option::as_ref)),
        "realm": placed(latest.get(1).and_then(Option::as_ref)),
        "domain": placed(latest.get(2).and_then(Option::as_ref)),
        "governing_domain": access_kernel::json::b64url_encode(g.domain.as_bytes()),
        "residency": residency.map(|(region, class)| serde_json::json!({ "region": region, "class": class })),
        "pending_rehome": open.iter().map(|(side, _, to, pos)| serde_json::json!({
            "side": if *side == Side::From { "from" } else { "to" },
            "to": access_kernel::json::b64url_encode(to.as_bytes()),
            "position": pos.to_string(),
        })).collect::<Vec<_>>(),
        "routing_only": true,
    }))
}

/// `getDurability`: the cell's durability profile, the realm's DR class and RPO (HL-40, OP-29,
/// OP-158 m.3 (n), (p)). A synchronous cell declares RPO 0; an async DR profile its own RPO.
/// What the governing domain declares about witnesses and replicas is added by the server.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn durability_view(t: &mut TenantTx) -> Result<serde_json::Value, AdminError> {
    let g = idp::governance(t).await?.ok_or(AdminError::NoRealm)?;
    let cell = placement::cell_profile_in(t).await?;
    let residency = placement::residency(t).await?;
    let dr = access_store::cells::dr_profile(t).await?;
    let class = residency
        .as_ref()
        .map(|(_, c)| c.clone())
        .or_else(|| cell.as_ref().map(|c| c.class.clone()));
    Ok(serde_json::json!({
        "durability": cell.as_ref().map(|c| c.durability.clone()),
        "class": class,
        "region": residency.as_ref().map(|(r, _)| r.clone()).or_else(|| cell.as_ref().and_then(|c| c.region.clone())),
        "dr_profile": dr.map(|rpo_s| serde_json::json!({ "rpo_s": rpo_s })),
        "rpo_s": if cell.as_ref().is_some_and(|c| c.durability == "single-node") {
            serde_json::Value::Null
        } else {
            serde_json::json!(dr.unwrap_or(0))
        },
        "governing_domain": access_kernel::json::b64url_encode(g.domain.as_bytes()),
    }))
}
