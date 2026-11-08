//! Organization ownership transfer (TN-91, TN-92, OP-153 m.3 (p)): the organization Anchor's
//! `anchor_transfer`, CT3. An owner proposes it with the Exercise its own client signed; every
//! owner and the recipient are told; the recipient contributes; any owner or the recipient may
//! cancel until it commits; it is submitted only once the recipient contributed and at least
//! 24 hours passed since the proposal, and then the domain's own CT3 time-lock still holds it.
//! Ownership is root standing over the Anchor, never billing; a DNS ownership recovery exists
//! only when the Genesis root terms declare it.

use access_identity_account::adapters::system::{SystemClock, SystemEntropy};
use access_identity_account::notify::message::{Address, Body, Message, Notice};
use access_identity_account::notify::notifier::OutboxNotifier;
use access_identity_account::notify::ports::Notifier as _;
use access_internal_api::idp::Submission;
use access_kernel::meta::{ExerciseBasis, Payload, Root};
use access_kernel::model::Id;
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::org_authority::{NewTransfer, Transfer, TransferState};

use super::orgs::live_org;
use super::{Admin, Applied};
use crate::AdminError;
use crate::domain::Invalid;
use crate::ports::{Decider, Governance, Instances, RealmKeys};

/// Least time between a proposal and its submission: 24 hours (TN-91, OP-153 m.3 (p)).
pub const TRANSFER_DELAY_MS: u64 = 86_400_000;

/// The submission is not this organization's transfer to the recipient.
pub const NOT_THE_TRANSFER: &str = "not-the-transfer";

/// Only an owner proposes, and only its own client signs.
pub const OWNER_ONLY: &str = "owner-only";

/// The transfer waits for the recipient's contribution or its delay.
pub const TRANSFER_WAITING: &str = "transfer-waiting";

/// What a proposal recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proposed {
    /// The transfer.
    pub transfer: [u8; 16],
    /// The earliest it can be submitted, Unix ms.
    pub effective_ms: u64,
}

fn payload_digest(w: &Submission) -> Result<[u8; 32], AdminError> {
    w.payload
        .as_deref()
        .ok_or(AdminError::Encode)?
        .digest()
        .map(|d| d.0)
        .map_err(|_| AdminError::Encode)
}

impl<D: Decider, G: Governance + Instances, K: RealmKeys> Admin<'_, D, G, K> {
    async fn signer_is(&self, w: &Submission, party: [u8; 16]) -> Result<bool, AdminError> {
        Ok(self
            .decider
            .signer(w.domain, &w.ais)
            .await
            .map_err(|e| AdminError::Unavailable(e.0))?
            .is_some_and(|s| s.0 == party))
    }

    /// Proposes the transfer of organization `org` from owner `from` to member `to` with the
    /// `anchor_transfer` `w` the owner's client signed (TN-91): its new root is the recipient's
    /// Party alone, on the organization's own Anchor. Nothing is submitted yet; every owner and
    /// the recipient are told.
    ///
    /// # Errors
    /// [`AdminError`].
    pub async fn propose_transfer(
        &self,
        (tenant, realm): (TenantId, RealmId),
        org: [u8; 16],
        (from, to): ([u8; 16], [u8; 16]),
        w: &Submission,
    ) -> Result<Proposed, AdminError> {
        let mut t = TenantTx::begin(self.app, tenant, realm).await?;
        let found = live_org(&mut t, org).await?;
        let anchor = t.party_anchor(found.party).await?.ok_or(Invalid::NoOrg)?;
        let members = t.members(found.id).await?;
        if !members.iter().any(|m| m.subject == from && m.owner) {
            return Err(AdminError::Refused(String::from(OWNER_ONLY)));
        }
        if !members.iter().any(|m| m.subject == to && !m.owner) {
            return Err(Invalid::NoMember.into());
        }
        let from_party = access_store::idp::subject_party(&mut t, &from)
            .await?
            .ok_or(Invalid::NoMember)?;
        let to_party = access_store::idp::subject_party(&mut t, &to)
            .await?
            .ok_or(Invalid::NoMember)?;
        t.commit().await?;
        let names = matches!(
            w.payload.as_deref(),
            Some(Payload::AnchorTransfer { anchor: a, root: Root::Sole(r), .. })
                if a.0 == anchor && r.0 == to_party
        ) && w.basis == ExerciseBasis::Anchor(Id(anchor));
        if !names {
            return Err(AdminError::Refused(String::from(NOT_THE_TRANSFER)));
        }
        if !self.signer_is(w, from_party).await? {
            return Err(AdminError::Refused(String::from(OWNER_ONLY)));
        }
        let digest = payload_digest(w)?;
        let now = access_store::authority::server_time(self.app).await?;
        let effective_ms = now.saturating_add(TRANSFER_DELAY_MS);
        let mut t = TenantTx::begin(self.app, tenant, realm).await?;
        let transfer = t
            .insert_transfer(&NewTransfer {
                org: found.id,
                from,
                to,
                to_party,
                nonce: &w.nonce,
                payload_digest: &digest,
                effective_ms,
                dns_recovery: false,
            })
            .await
            .map_err(|_| AdminError::Conflict)?;
        let mut told: Vec<[u8; 16]> = members
            .iter()
            .filter(|m| m.owner)
            .map(|m| m.subject)
            .collect();
        told.push(to);
        self.tell(&mut t, realm, &told, now, effective_ms).await?;
        let at = now;
        super::orgs::organization_event(
            &mut t,
            self.ids,
            access_identity_events::domain::catalog::IdentityKind::OrganizationUpdated,
            found.id,
            at,
        )
        .await?;
        t.commit().await?;
        Ok(Proposed {
            transfer,
            effective_ms,
        })
    }

    /// Tells every one of `subjects` of the proposed transfer at its registered address
    /// (TN-91: all roots are notified).
    async fn tell(
        &self,
        t: &mut TenantTx,
        realm: RealmId,
        subjects: &[[u8; 16]],
        now: u64,
        until: u64,
    ) -> Result<(), AdminError> {
        let vault = self
            .keys
            .vault(realm)
            .ok_or_else(|| AdminError::Unavailable(String::from("vault")))?;
        let named = access_identity_account::app::Realm {
            tenant: t.tenant(),
            realm,
            kek: &*vault.kek,
            ids: self.ids,
        };
        let notifier = OutboxNotifier::new(&named, &SystemEntropy, &SystemClock);
        for subject in subjects {
            let Some((kind, stored)) = t.contact(*subject).await? else {
                continue;
            };
            let Some(value) = access_identity_account::app::vault::reveal_with_kek(
                t,
                &*vault.kek,
                *subject,
                &stored,
            )
            .await
            .map_err(|e| AdminError::Unavailable(e.to_string()))?
            else {
                continue;
            };
            let to = if kind == "phone" {
                Address::Phone(value)
            } else {
                Address::Email(value)
            };
            let valid_since_ms = super::mailbox_since(t, *subject, &to).await?;
            notifier
                .notify(
                    t,
                    &Message {
                        subject: *subject,
                        to,
                        locale: None,
                        valid_since_ms,
                        body: Body::Notice {
                            notice: Notice::OwnershipHandover,
                            at_ms: now,
                            until_ms: Some(until),
                        },
                    },
                )
                .await
                .map_err(|_| AdminError::Unavailable(String::from("relay")))?;
        }
        Ok(())
    }

    /// The transfer `id` of organization `org`, open.
    async fn open_transfer(
        &self,
        t: &mut TenantTx,
        org: [u8; 16],
        id: [u8; 16],
    ) -> Result<(access_store::orgs::OrgRow, Transfer), AdminError> {
        let found = live_org(t, org).await?;
        let tr = t
            .transfer(id)
            .await?
            .filter(|tr| tr.org == found.id)
            .filter(|tr| {
                matches!(
                    tr.state,
                    TransferState::Proposed | TransferState::Contributed
                )
            })
            .ok_or(Invalid::NoMember)?;
        Ok((found, tr))
    }

    /// Records the recipient's contribution (TN-91): only the recipient's own session gives it.
    ///
    /// # Errors
    /// [`AdminError`].
    pub async fn contribute_transfer(
        &self,
        (tenant, realm): (TenantId, RealmId),
        org: [u8; 16],
        id: [u8; 16],
        by: [u8; 16],
    ) -> Result<(), AdminError> {
        let mut t = TenantTx::begin(self.app, tenant, realm).await?;
        let (_, tr) = self.open_transfer(&mut t, org, id).await?;
        if tr.to != by {
            return Err(AdminError::Refused(String::from(NOT_THE_TRANSFER)));
        }
        if !t.contribute_transfer(id).await? {
            return Err(AdminError::Conflict);
        }
        t.commit().await?;
        Ok(())
    }

    /// Cancels an open transfer (TN-91): any owner or the recipient, until it commits.
    ///
    /// # Errors
    /// [`AdminError`].
    pub async fn cancel_transfer(
        &self,
        (tenant, realm): (TenantId, RealmId),
        org: [u8; 16],
        id: [u8; 16],
        by: [u8; 16],
    ) -> Result<(), AdminError> {
        let mut t = TenantTx::begin(self.app, tenant, realm).await?;
        let (found, tr) = self.open_transfer(&mut t, org, id).await?;
        let owner = t
            .members(found.id)
            .await?
            .iter()
            .any(|m| m.subject == by && m.owner);
        if !owner && tr.to != by {
            return Err(AdminError::Refused(String::from(OWNER_ONLY)));
        }
        if !t.cancel_transfer(id, by).await? {
            return Err(AdminError::Conflict);
        }
        t.commit().await?;
        Ok(())
    }

    /// Submits a contributed transfer past its delay with the same `anchor_transfer` (TN-91):
    /// the domain decides it, its CT3 time-lock included. A commit makes the recipient an owner
    /// and takes ownership from the proposer; a pending time-lock answers
    /// [`Applied::NotAllowed`] and nothing changes.
    ///
    /// # Errors
    /// [`AdminError`].
    pub async fn complete_transfer(
        &self,
        (tenant, realm): (TenantId, RealmId),
        org: [u8; 16],
        id: [u8; 16],
        w: Submission,
    ) -> Result<Applied, AdminError> {
        let mut t = TenantTx::begin(self.app, tenant, realm).await?;
        let (found, tr) = self.open_transfer(&mut t, org, id).await?;
        let from_party = access_store::idp::subject_party(&mut t, &tr.from)
            .await?
            .ok_or(Invalid::NoMember)?;
        let now = i64::try_from(t.server_time().await?).unwrap_or(i64::MAX);
        t.commit().await?;
        if tr.state != TransferState::Contributed || now < tr.effective_ms {
            return Err(AdminError::Refused(String::from(TRANSFER_WAITING)));
        }
        if w.nonce != tr.nonce || payload_digest(&w)? != tr.payload_digest {
            return Err(AdminError::Refused(String::from(NOT_THE_TRANSFER)));
        }
        if !self.signer_is(&w, from_party).await? {
            return Err(AdminError::Refused(String::from(OWNER_ONLY)));
        }
        let applied = Box::pin(self.meta((tenant, realm), w)).await?;
        if let Applied::Written { exercise, .. } | Applied::AlreadyWritten { exercise, .. } =
            &applied
        {
            let mut t = TenantTx::begin(self.app, tenant, realm).await?;
            if t.complete_transfer(id, &exercise.0).await? {
                t.promote_owner(found.id, tr.to).await?;
                t.drop_ownership(found.id, tr.from).await?;
                let at = t.server_time().await?;
                super::orgs::organization_event(
                    &mut t,
                    self.ids,
                    access_identity_events::domain::catalog::IdentityKind::OrganizationUpdated,
                    found.id,
                    at,
                )
                .await?;
            }
            t.commit().await?;
        }
        Ok(applied)
    }
}
