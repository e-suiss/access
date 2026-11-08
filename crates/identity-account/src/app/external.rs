//! Accounts and links of external identities (IDP-31, P-ID-9, TN-65, OP-153 m.3 (l), (m)).
//!
//! An external identity is found by its key only, never by an address (MD-5, TN-3). A first
//! sign-in with an unknown identity creates an account; the provider's address becomes its
//! login identifier only when the preset vouches for it and no other account holds it, and is
//! otherwise kept sealed and unconfirmed with the link. A matching address never links or
//! combines anything (nOAuth).

use access_store::Pool;
use access_store::audit::AuditEvent;
use access_store::federation::ProviderAddress;
use access_store::identity::TenantTx;

use crate::AccountError;
use crate::adapters::pg::PgTx;
use crate::app::vault::{self, Vault};
use crate::app::{Actor, Realm, events};
use crate::domain::identifier::{Identifier, IdentifierKind};
use crate::domain::status::AccountStatus;
use crate::ports::AccountTx;

/// What a provider said about an identity, already checked in the back end.
pub struct Asserted<'a> {
    /// The provider name.
    pub provider: &'a str,
    /// `identity_key(provider, subject)`.
    pub key: &'a [u8; 32],
    /// The address and whether the preset vouches for it.
    pub address: Option<(&'a str, bool)>,
    /// The display name, attacker-controlled text.
    pub name: Option<&'a str>,
}

/// The outcome of a sign-in with an external identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolved {
    /// The identity is linked to this account, now proven again.
    Existing([u8; 16]),
    /// A new account was created for it.
    Created([u8; 16]),
    /// The linked account cannot sign in (not active).
    Unusable,
}

/// The outcome of linking an external identity to a signed-in account (TN-65).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Linked {
    /// Linked; every session of the account ended (TN-65 (5)).
    Linked,
    /// Already linked to this account; its proof is renewed.
    Already,
    /// Linked to another account; nothing changed.
    Elsewhere,
}

/// The outcome of unlinking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unlinked {
    /// The link ended; its record stays (OP-73).
    Ended,
    /// No such live link of the account.
    Missing,
    /// It is the account's last way to sign in (TN-68); nothing changed.
    LastMethod,
}

/// The outcome of combining two accounts (OP-153 m.3 (m)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Combined {
    /// Combined: the snapshot was written first; the absorbed account is a tombstone.
    Done {
        /// The snapshot's digest, as the audit event names it.
        snapshot: [u8; 32],
    },
    /// No live ticket, the same account, or an authentication older than five minutes.
    Refused,
}

/// External identities of one realm.
pub struct Externals<'a> {
    /// The `access_app` pool.
    pub pool: &'a Pool,
    /// The realm.
    pub realm: &'a Realm<'a>,
    /// The realm's vault keys.
    pub vault: &'a Vault,
}

async fn audit(
    tx: &mut PgTx,
    event_type: &str,
    actor: &str,
    target: &str,
    correlation: &str,
) -> Result<(), AccountError> {
    tx.audit(&AuditEvent {
        event_type,
        actor,
        target,
        correlation,
    })
    .await
}

impl Externals<'_> {
    async fn begin(&self) -> Result<PgTx, AccountError> {
        Ok(PgTx(
            TenantTx::begin(self.pool, self.realm.tenant, self.realm.realm).await?,
            Some(self.vault.clone()),
        ))
    }

    async fn sealed(
        &self,
        tx: &mut PgTx,
        subject: [u8; 16],
        address: Option<(&str, bool)>,
    ) -> Result<Option<ProviderAddress>, AccountError> {
        let Some((value, vouched)) = address else {
            return Ok(None);
        };
        let s =
            vault::seal_identifier(&mut tx.0, self.vault, subject, IdentifierKind::Email, value)
                .await?;
        Ok(Some(ProviderAddress {
            nonce: s.nonce,
            ciphertext: s.ciphertext,
            index: s.index,
            vouched,
        }))
    }

    /// Signs in with `a` (OP-153 m.3 (l)): its linked account, or a new one; the answer does
    /// not depend on whether any account holds the provider's address (CR-40).
    ///
    /// # Errors
    /// [`AccountError`].
    pub async fn sign_in(
        &self,
        a: &Asserted<'_>,
        now_ms: u64,
        who: &Actor<'_>,
    ) -> Result<Resolved, AccountError> {
        let mut tx = self.begin().await?;
        if let Some(row) = tx.0.federated_by_key(a.key).await? {
            let status = tx
                .subject(row.subject, false)
                .await?
                .ok_or(AccountError::Corrupt)?
                .status;
            if status != AccountStatus::Active.name() {
                tx.commit().await?;
                return Ok(Resolved::Unusable);
            }
            tx.0.federated_verified(row.link, now_ms).await?;
            tx.commit().await?;
            return Ok(Resolved::Existing(row.subject));
        }
        let wrapped = crate::app::sealing::new_subject_key(self.realm)?;
        let subject = tx
            .insert_subject(AccountStatus::Active, self.realm.kek.id(), &wrapped)
            .await?;
        let external = self.realm.external(subject)?;
        audit(
            &mut tx,
            "account.created",
            who.actor,
            &external,
            who.correlation,
        )
        .await?;
        // OP-151 m.3 (i)
        events::created(&mut tx, self.realm, subject).await?;
        crate::app::accounts::status_claim(&mut tx, subject, AccountStatus::Active).await?;
        // IDP-31 (3), MD-5
        if let Some((value, true)) = a.address
            && let Ok(id) = Identifier::new(IdentifierKind::Email, value)
            && tx.add_identifier(subject, &id).await?
        {
            let index = self.vault.index_of(
                self.realm.tenant.as_bytes(),
                self.realm.realm.as_bytes(),
                value,
            )?;
            if let Some(identifier) = tx.0.identifier_id(subject, &index).await? {
                // TN-66
                tx.0.insert_mailbox(
                    identifier,
                    subject,
                    i64::try_from(now_ms).map_err(|_| AccountError::Corrupt)?,
                )
                .await?;
            }
        }
        if let Some(n) = a.name.map(str::trim).filter(|n| !n.is_empty()) {
            vault::set_profile(&mut tx.0, self.vault, subject, "name", n).await?;
        }
        let address = self.sealed(&mut tx, subject, a.address).await?;
        if !tx
            .0
            .link_federated(subject, a.provider, a.key, address.as_ref(), now_ms)
            .await?
        {
            return Err(AccountError::Corrupt);
        }
        audit(
            &mut tx,
            "account.registered",
            who.actor,
            &external,
            who.correlation,
        )
        .await?;
        tx.commit().await?;
        Ok(Resolved::Created(subject))
    }

    /// Links `a` to the signed-in `subject` after its fresh re-authentication and the proof of
    /// control the provider's assertion is (TN-65 (3), (5), (6)): every session of the account
    /// ends with the link.
    ///
    /// # Errors
    /// [`AccountError`].
    pub async fn link(
        &self,
        subject: [u8; 16],
        a: &Asserted<'_>,
        now_ms: u64,
        who: &Actor<'_>,
    ) -> Result<Linked, AccountError> {
        let mut tx = self.begin().await?;
        if let Some(row) = tx.0.federated_by_key(a.key).await? {
            let out = if row.subject == subject {
                tx.0.federated_verified(row.link, now_ms).await?;
                Linked::Already
            } else {
                Linked::Elsewhere
            };
            tx.commit().await?;
            return Ok(out);
        }
        let address = self.sealed(&mut tx, subject, a.address).await?;
        if !tx
            .0
            .link_federated(subject, a.provider, a.key, address.as_ref(), now_ms)
            .await?
        {
            return Err(AccountError::Corrupt);
        }
        // TN-65 (5)
        tx.end_sessions(subject).await?;
        let external = self.realm.external(subject)?;
        audit(
            &mut tx,
            "account.linked",
            who.actor,
            &external,
            who.correlation,
        )
        .await?;
        tx.commit().await?;
        Ok(Linked::Linked)
    }

    /// Ends `subject`'s link `link`; the record is kept (OP-73), and the account's last way to
    /// sign in stays (TN-68).
    ///
    /// # Errors
    /// [`AccountError`].
    pub async fn unlink(
        &self,
        subject: [u8; 16],
        link: [u8; 16],
        now_ms: u64,
        who: &Actor<'_>,
    ) -> Result<Unlinked, AccountError> {
        let mut tx = self.begin().await?;
        if !tx
            .0
            .federated_of(subject)
            .await?
            .iter()
            .any(|r| r.link == link)
        {
            tx.commit().await?;
            return Ok(Unlinked::Missing);
        }
        // TN-68
        if !tx.0.keeps_a_method(subject, link).await? {
            tx.commit().await?;
            return Ok(Unlinked::LastMethod);
        }
        if !tx
            .0
            .end_federated(subject, link, "unlinked", now_ms)
            .await?
        {
            return Err(AccountError::Corrupt);
        }
        let external = self.realm.external(subject)?;
        audit(
            &mut tx,
            "account.unlinked",
            who.actor,
            &external,
            who.correlation,
        )
        .await?;
        tx.commit().await?;
        Ok(Unlinked::Ended)
    }

    /// Issues the absorbed account's half of a combination to its own fresh session
    /// (`auth_ms`); the ticket's digest is kept, the ticket returned once.
    ///
    /// # Errors
    /// [`AccountError`].
    pub async fn offer(
        &self,
        subject: [u8; 16],
        auth_ms: u64,
        ticket_hash: &[u8; 32],
        now_ms: u64,
    ) -> Result<(), AccountError> {
        let mut tx = self.begin().await?;
        tx.0.insert_combine_ticket(
            ticket_hash,
            subject,
            auth_ms,
            now_ms,
            now_ms.saturating_add(crate::domain::combine::COMBINE_FRESHNESS_MS),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Combines the ticket's account into `survivor` (OP-153 m.3 (m), TN-67, INV-39): both
    /// authenticated within five minutes, irreversible. The snapshot and its audit event are
    /// written before anything moves; the absorbed account's identifiers and links move to the
    /// survivor and it becomes a tombstone. Nothing of the authority plane moves: no lineage,
    /// holding, Mandate, budget or Grant (TNI-11); the realm issuer's `identity_binding_person`
    /// Claim records the binding.
    ///
    /// # Errors
    /// [`AccountError`].
    #[expect(
        clippy::too_many_lines,
        reason = "the snapshot, then each move, in one transaction"
    )]
    pub async fn combine(
        &self,
        survivor: [u8; 16],
        survivor_auth_ms: u64,
        ticket_hash: &[u8; 32],
        now_ms: u64,
        who: &Actor<'_>,
    ) -> Result<Combined, AccountError> {
        let mut tx = self.begin().await?;
        let Some((absorbed, absorbed_auth_ms)) =
            tx.0.take_combine_ticket(ticket_hash, now_ms).await?
        else {
            tx.commit().await?;
            return Ok(Combined::Refused);
        };
        if !crate::domain::combine::combine_allowed(
            survivor,
            survivor_auth_ms,
            absorbed,
            absorbed_auth_ms,
            now_ms,
        ) {
            tx.commit().await?;
            return Ok(Combined::Refused);
        }
        let absorbed_row = tx
            .subject(absorbed, true)
            .await?
            .ok_or(AccountError::Corrupt)?;
        let survivor_row = tx
            .subject(survivor, true)
            .await?
            .ok_or(AccountError::Corrupt)?;
        if absorbed_row.status != AccountStatus::Active.name()
            || survivor_row.status != AccountStatus::Active.name()
        {
            tx.commit().await?;
            return Ok(Combined::Refused);
        }
        let (ids_a, links_a) = (
            tx.0.identifiers(absorbed).await?,
            tx.0.federated_of(absorbed).await?,
        );
        let (ids_s, links_s) = (
            tx.0.identifiers(survivor).await?,
            tx.0.federated_of(survivor).await?,
        );
        let view = |ids: &[access_store::accounts::IdentifierRow],
                    links: &[access_store::federation::FederatedRow],
                    subject: [u8; 16]| {
            serde_json::json!({
                "subject": self.realm.external(subject).unwrap_or_default(),
                "identifiers": ids.iter().filter(|i| i.live).map(|i| serde_json::json!({
                    "id": access_kernel::json::b64url_encode(&i.id), "kind": i.kind,
                })).collect::<Vec<_>>(),
                "links": links.iter().map(|l| serde_json::json!({
                    "id": access_kernel::json::b64url_encode(&l.link), "provider": l.provider,
                })).collect::<Vec<_>>(),
            })
        };
        let snapshot = serde_json::json!({
            "survivor": view(&ids_s, &links_s, survivor),
            "absorbed": view(&ids_a, &links_a, absorbed),
            "at_ms": now_ms,
        })
        .to_string();
        let digest = suiss_crypto::digest::sha256(snapshot.as_bytes());
        // TN-67
        if !tx
            .0
            .insert_combination(survivor, absorbed, &snapshot, &digest, now_ms)
            .await?
        {
            tx.commit().await?;
            return Ok(Combined::Refused);
        }
        let target = self.realm.external(survivor)?;
        audit(
            &mut tx,
            "account.combined",
            who.actor,
            &target,
            who.correlation,
        )
        .await?;
        for i in ids_a.iter().filter(|i| i.live) {
            let Some(value) = tx.reveal(absorbed, &i.stored).await? else {
                continue;
            };
            let index = self.vault.index_of(
                self.realm.tenant.as_bytes(),
                self.realm.realm.as_bytes(),
                &value,
            )?;
            tx.0.release_identifier(absorbed, &index, &vault::folded(&value))
                .await?;
            let kind = match i.kind.as_str() {
                "email" => IdentifierKind::Email,
                "phone" => IdentifierKind::Phone,
                "username" => IdentifierKind::Username,
                _ => return Err(AccountError::Corrupt),
            };
            if let Ok(id) = Identifier::new(kind, &value) {
                tx.add_identifier(survivor, &id).await?;
            }
        }
        for l in &links_a {
            tx.0.end_federated(absorbed, l.link, "combined", now_ms)
                .await?;
            tx.0.link_federated(survivor, &l.provider, &l.key, None, now_ms)
                .await?;
        }
        for (from, to) in [
            (AccountStatus::Active, AccountStatus::Deactivated),
            (AccountStatus::Deactivated, AccountStatus::Tombstone),
        ] {
            if !tx.set_status(absorbed, from, to).await? {
                return Err(AccountError::Corrupt);
            }
            crate::app::accounts::status_moved(&mut tx, self.realm, absorbed, (from, to), who)
                .await?;
        }
        let mut proof = digest.to_vec();
        proof.extend_from_slice(&absorbed);
        let at = tx.server_time().await?;
        crate::app::claims::emit(
            &mut tx,
            &crate::domain::claims::identity_binding(
                survivor,
                access_kernel::claim::body::BindingKind::Person,
                &proof,
                at,
            ),
        )
        .await?;
        tx.commit().await?;
        Ok(Combined::Done { snapshot: digest })
    }

    /// The live links of `subject`.
    ///
    /// # Errors
    /// [`AccountError`].
    pub async fn links(
        &self,
        subject: [u8; 16],
    ) -> Result<Vec<access_store::federation::FederatedRow>, AccountError> {
        let mut tx = self.begin().await?;
        let rows = tx.0.federated_of(subject).await?;
        tx.commit().await?;
        Ok(rows)
    }
}
