//! Social sign-in, linked sign-ins and combined accounts (OP-153 m.3 (l), (m); IDP-31, P-ID-9,
//! TN-65–TN-67, TN-87). Every read and write is scoped to the transaction's realm by row-level
//! security; nothing is deleted (OP-73).

use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::TenantTx;
use crate::idp::Bound;

fn scope(t: &TenantTx) -> Result<(Uuid, Uuid), StoreError> {
    let realm = t.realm().ok_or(StoreError::Range)?;
    Ok((
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*realm.as_bytes()),
    ))
}

fn i64_of(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Range)
}

fn u64_of(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn key32(v: Vec<u8>) -> Result<[u8; 32], StoreError> {
    <[u8; 32]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

/// A social preset as a realm enabled it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocialRow {
    /// The preset id.
    pub preset: String,
    /// The realm's client id; `None` names the shared development client.
    pub client_id: Option<String>,
    /// Its secret's reference.
    pub client_secret_ref: Option<String>,
    /// Whether it is offered.
    pub active: bool,
    /// The client id before the last change (TN-87).
    pub previous_client_id: Option<String>,
    /// When the client id last changed.
    pub client_changed_ms: Option<u64>,
    /// Position of the decision that last changed it.
    pub position: u64,
}

/// An external identity linked to an account (P-ID-9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FederatedRow {
    /// The link.
    pub link: [u8; 16],
    /// The account.
    pub subject: [u8; 16],
    /// The provider name.
    pub provider: String,
    /// `identity_key(provider, subject)`.
    pub key: [u8; 32],
    /// When it was linked.
    pub created_ms: u64,
    /// When control of it was last proven.
    pub verified_ms: u64,
}

/// The address a provider gave, sealed under the account's contact key (OP-153 m.3 (l)).
pub struct ProviderAddress {
    /// AEAD nonce.
    pub nonce: [u8; 12],
    /// Ciphertext and tag.
    pub ciphertext: Vec<u8>,
    /// The realm's blind index.
    pub index: [u8; 32],
    /// Whether the preset vouches for it.
    pub vouched: bool,
}

/// A social attempt taken from the redirect.
#[derive(Clone, PartialEq, Eq)]
pub struct AttemptRow {
    /// The provider name.
    pub provider: String,
    /// The signed-in subject a link attempt links to.
    pub link_to: Option<[u8; 16]>,
    /// The ID token's expected nonce.
    pub nonce: String,
    /// The PKCE verifier.
    pub verifier: String,
}

impl core::fmt::Debug for AttemptRow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AttemptRow")
            .field("provider", &self.provider)
            .finish_non_exhaustive()
    }
}

/// A new social attempt.
pub struct NewAttempt<'a> {
    /// `SHA-256` of the `state`.
    pub state_hash: &'a [u8; 32],
    /// The flow device digest.
    pub device_hash: &'a [u8; 32],
    /// The provider name.
    pub provider: &'a str,
    /// The subject a link attempt links to.
    pub link_to: Option<[u8; 16]>,
    /// The nonce.
    pub nonce: &'a str,
    /// The PKCE verifier.
    pub verifier: &'a str,
    /// Now.
    pub now_ms: u64,
    /// When it expires.
    pub expires_ms: u64,
}

impl TenantTx {
    /// Whether this transaction's realm is a sandbox (OP-151 m.3 (m)).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn realm_is_sandbox(&mut self) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        Ok(sqlx::query_scalar!(
            r#"SELECT EXISTS (SELECT 1 FROM access.sandbox_domains
                               WHERE tenant_id = $1 AND realm_id = $2) AS "found!""#,
            tenant,
            realm,
        )
        .fetch_one(&mut *self.tx)
        .await?)
    }

    /// The realm's social preset `preset`, active or disabled.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn social_provider(&mut self, preset: &str) -> Result<Option<SocialRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let r = sqlx::query!(
            "SELECT preset, client_id, client_secret_ref, status, previous_client_id,
                    client_changed_ms, decision_pos
               FROM access.idp_social_providers
              WHERE tenant_id = $1 AND realm_id = $2 AND preset = $3",
            tenant,
            realm,
            preset,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        r.map(|r| {
            Ok(SocialRow {
                preset: r.preset,
                client_id: r.client_id,
                client_secret_ref: r.client_secret_ref,
                active: r.status == "active",
                previous_client_id: r.previous_client_id,
                client_changed_ms: r.client_changed_ms.map(u64_of).transpose()?,
                position: u64_of(r.decision_pos)?,
            })
        })
        .transpose()
    }

    /// Every social preset the realm ever enabled, by preset id.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn social_providers(&mut self) -> Result<Vec<SocialRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            "SELECT preset, client_id, client_secret_ref, status, previous_client_id,
                    client_changed_ms, decision_pos
               FROM access.idp_social_providers
              WHERE tenant_id = $1 AND realm_id = $2 ORDER BY preset",
            tenant,
            realm,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(SocialRow {
                    preset: r.preset,
                    client_id: r.client_id,
                    client_secret_ref: r.client_secret_ref,
                    active: r.status == "active",
                    previous_client_id: r.previous_client_id,
                    client_changed_ms: r.client_changed_ms.map(u64_of).transpose()?,
                    position: u64_of(r.decision_pos)?,
                })
            })
            .collect()
    }

    /// Writes the realm's social preset under `bound` (`idp.social.enable`, `update`,
    /// `disable`); the row carries its whole new state.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_social_provider(
        &mut self,
        bound: &Bound,
        row: &SocialRow,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        let status = if row.active { "active" } else { "disabled" };
        let changed = row.client_changed_ms.map(i64_of).transpose()?;
        let domain = bound.domain.as_bytes().as_slice();
        let updated = sqlx::query!(
            "UPDATE access.idp_social_providers
                SET client_id = $4, client_secret_ref = $5, status = $6, previous_client_id = $7,
                    client_changed_ms = $8, domain_id = $9, decision_pos = $10
              WHERE tenant_id = $1 AND realm_id = $2 AND preset = $3",
            tenant,
            realm,
            row.preset,
            row.client_id,
            row.client_secret_ref,
            status,
            row.previous_client_id,
            changed,
            domain,
            bound.position,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        if updated == 0 {
            sqlx::query!(
                "INSERT INTO access.idp_social_providers (tenant_id, realm_id, preset, client_id,
                        client_secret_ref, status, previous_client_id, client_changed_ms,
                        domain_id, decision_pos)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
                tenant,
                realm,
                row.preset,
                row.client_id,
                row.client_secret_ref,
                status,
                row.previous_client_id,
                changed,
                domain,
                bound.position,
            )
            .execute(&mut *self.tx)
            .await?;
        }
        Ok(())
    }

    /// Opens a social attempt.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_social_attempt(&mut self, a: &NewAttempt<'_>) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        let purpose = if a.link_to.is_some() {
            "link"
        } else {
            "signin"
        };
        sqlx::query!(
            "INSERT INTO access.identity_social_attempts (tenant_id, realm_id, state_hash,
                    device_hash, provider, purpose, subject_id, nonce, verifier, created_ms,
                    expires_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
            tenant,
            realm,
            a.state_hash.as_slice(),
            a.device_hash.as_slice(),
            a.provider,
            purpose,
            a.link_to.map(Uuid::from_bytes),
            a.nonce,
            a.verifier,
            i64_of(a.now_ms)?,
            i64_of(a.expires_ms)?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Uses the open, unexpired attempt of `state_hash` that the same browser device opened for
    /// `provider`; `None` otherwise. An attempt is used once.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn take_social_attempt(
        &mut self,
        state_hash: &[u8; 32],
        device_hash: &[u8; 32],
        provider: &str,
        now_ms: u64,
    ) -> Result<Option<AttemptRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let r = sqlx::query!(
            "UPDATE access.identity_social_attempts SET status = 'used', used_ms = $6
              WHERE tenant_id = $1 AND realm_id = $2 AND state_hash = $3 AND device_hash = $4
                AND provider = $5 AND status = 'open' AND expires_ms > $6
             RETURNING provider, subject_id, nonce, verifier",
            tenant,
            realm,
            state_hash.as_slice(),
            device_hash.as_slice(),
            provider,
            i64_of(now_ms)?,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(r.map(|r| AttemptRow {
            provider: r.provider,
            link_to: r.subject_id.map(|u| *u.as_bytes()),
            nonce: r.nonce,
            verifier: r.verifier,
        }))
    }

    /// The live link of the external identity `key`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn federated_by_key(
        &mut self,
        key: &[u8; 32],
    ) -> Result<Option<FederatedRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let r = sqlx::query!(
            "SELECT link_id, subject_id, provider, identity_key, created_ms, verified_ms
               FROM access.identity_federated
              WHERE tenant_id = $1 AND realm_id = $2 AND identity_key = $3 AND ended_ms IS NULL",
            tenant,
            realm,
            key.as_slice(),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        r.map(|r| {
            Ok(FederatedRow {
                link: *r.link_id.as_bytes(),
                subject: *r.subject_id.as_bytes(),
                provider: r.provider,
                key: key32(r.identity_key)?,
                created_ms: u64_of(r.created_ms)?,
                verified_ms: u64_of(r.verified_ms)?,
            })
        })
        .transpose()
    }

    /// The live links of `subject`, oldest first.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn federated_of(
        &mut self,
        subject: [u8; 16],
    ) -> Result<Vec<FederatedRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            "SELECT link_id, subject_id, provider, identity_key, created_ms, verified_ms
               FROM access.identity_federated
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND ended_ms IS NULL
              ORDER BY link_id",
            tenant,
            realm,
            Uuid::from_bytes(subject),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(FederatedRow {
                    link: *r.link_id.as_bytes(),
                    subject: *r.subject_id.as_bytes(),
                    provider: r.provider,
                    key: key32(r.identity_key)?,
                    created_ms: u64_of(r.created_ms)?,
                    verified_ms: u64_of(r.verified_ms)?,
                })
            })
            .collect()
    }

    /// Links the external identity `key` of `provider` to `subject`, proven now, with the
    /// sealed address the provider gave; false when it is already linked to an account.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn link_federated(
        &mut self,
        subject: [u8; 16],
        provider: &str,
        key: &[u8; 32],
        address: Option<&ProviderAddress>,
        now_ms: u64,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let n = sqlx::query!(
            "INSERT INTO access.identity_federated (tenant_id, realm_id, subject_id, provider,
                    identity_key, created_ms, verified_ms, address_nonce, address_ciphertext,
                    address_index, address_vouched)
             VALUES ($1, $2, $3, $4, $5, $6, $6, $7, $8, $9, $10)
             ON CONFLICT (tenant_id, realm_id, identity_key) WHERE ended_ms IS NULL DO NOTHING",
            tenant,
            realm,
            Uuid::from_bytes(subject),
            provider,
            key.as_slice(),
            i64_of(now_ms)?,
            address.map(|a| a.nonce.to_vec()),
            address.map(|a| a.ciphertext.clone()),
            address.map(|a| a.index.to_vec()),
            address.map(|a| a.vouched),
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Records a fresh proof of control of the live link `link` (P-ID-9 `verified_at`).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn federated_verified(
        &mut self,
        link: [u8; 16],
        now_ms: u64,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "UPDATE access.identity_federated SET verified_ms = GREATEST(verified_ms, $4)
              WHERE tenant_id = $1 AND realm_id = $2 AND link_id = $3 AND ended_ms IS NULL",
            tenant,
            realm,
            Uuid::from_bytes(link),
            i64_of(now_ms)?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Ends `subject`'s live link `link` for `reason` (`unlinked` or `combined`); false when it
    /// is not one.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn end_federated(
        &mut self,
        subject: [u8; 16],
        link: [u8; 16],
        reason: &str,
        now_ms: u64,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let n = sqlx::query!(
            "UPDATE access.identity_federated SET ended_ms = $5, end_reason = $6
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND link_id = $4
                AND ended_ms IS NULL",
            tenant,
            realm,
            Uuid::from_bytes(subject),
            Uuid::from_bytes(link),
            i64_of(now_ms)?,
            reason,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Whether `subject` keeps a way to sign in without its live link `except` (TN-68): an
    /// active credential, a proven mailbox or another live link.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn keeps_a_method(
        &mut self,
        subject: [u8; 16],
        except: [u8; 16],
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let s = Uuid::from_bytes(subject);
        Ok(sqlx::query_scalar!(
            r#"SELECT (EXISTS (SELECT 1 FROM access.identity_credentials c
                               WHERE c.tenant_id = $1 AND c.realm_id = $2 AND c.subject_id = $3
                                 AND c.status = 'active')
                    OR EXISTS (SELECT 1 FROM access.identity_mailboxes m
                                 JOIN access.identity_identifiers i
                                   ON i.tenant_id = m.tenant_id AND i.realm_id = m.realm_id
                                  AND i.identifier_id = m.identifier_id
                                WHERE m.tenant_id = $1 AND m.realm_id = $2 AND m.subject_id = $3
                                  AND i.status = 'active')
                    OR EXISTS (SELECT 1 FROM access.identity_federated f
                                WHERE f.tenant_id = $1 AND f.realm_id = $2 AND f.subject_id = $3
                                  AND f.ended_ms IS NULL AND f.link_id <> $4)) AS "kept!""#,
            tenant,
            realm,
            s,
            Uuid::from_bytes(except),
        )
        .fetch_one(&mut *self.tx)
        .await?)
    }

    /// Issues a combine ticket for `subject`, authenticated at `auth_ms`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_combine_ticket(
        &mut self,
        hash: &[u8; 32],
        subject: [u8; 16],
        auth_ms: u64,
        now_ms: u64,
        expires_ms: u64,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.identity_combine_tickets (tenant_id, realm_id, ticket_hash,
                    subject_id, auth_ms, created_ms, expires_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            tenant,
            realm,
            hash.as_slice(),
            Uuid::from_bytes(subject),
            i64_of(auth_ms)?,
            i64_of(now_ms)?,
            i64_of(expires_ms)?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Spends the unexpired combine ticket `hash`: its subject and authentication time.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn take_combine_ticket(
        &mut self,
        hash: &[u8; 32],
        now_ms: u64,
    ) -> Result<Option<([u8; 16], u64)>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let r = sqlx::query!(
            "UPDATE access.identity_combine_tickets SET used_ms = $4
              WHERE tenant_id = $1 AND realm_id = $2 AND ticket_hash = $3 AND used_ms IS NULL
                AND expires_ms > $4
             RETURNING subject_id, auth_ms",
            tenant,
            realm,
            hash.as_slice(),
            i64_of(now_ms)?,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        r.map(|r| Ok((*r.subject_id.as_bytes(), u64_of(r.auth_ms)?)))
            .transpose()
    }

    /// Writes a combination with its snapshot, a JSON document, before anything moves (TN-67);
    /// false when the absorbed account was already combined.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_combination(
        &mut self,
        survivor: [u8; 16],
        absorbed: [u8; 16],
        snapshot: &str,
        digest: &[u8; 32],
        now_ms: u64,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let n = sqlx::query!(
            "INSERT INTO access.identity_combinations (tenant_id, realm_id, survivor_id,
                    absorbed_id, snapshot, snapshot_digest, created_ms)
             VALUES ($1, $2, $3, $4, ($5::text)::jsonb, $6, $7)
             ON CONFLICT (tenant_id, realm_id, absorbed_id) DO NOTHING",
            tenant,
            realm,
            Uuid::from_bytes(survivor),
            Uuid::from_bytes(absorbed),
            snapshot,
            digest.as_slice(),
            i64_of(now_ms)?,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }
}

/// One half of a cross-realm `IdentityBinding`, as this realm keeps it (§12.1.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingHalf {
    /// The id both halves share.
    pub binding: [u8; 16],
    /// `offer` or `accept`.
    pub role: String,
    /// The proof the person gave.
    pub proof: String,
    /// `offered`, `committed` or `ended`.
    pub state: String,
    /// When it was made.
    pub created_ms: u64,
    /// When it was committed.
    pub committed_ms: Option<u64>,
}

/// A half to write.
pub struct NewHalf<'a> {
    /// The id both halves share.
    pub binding: [u8; 16],
    /// The account.
    pub subject: [u8; 16],
    /// `offer` or `accept`.
    pub role: &'a str,
    /// The proof the person gave.
    pub proof: &'a str,
    /// Digest of this half's own secret.
    pub secret_hash: &'a [u8; 32],
    /// Digest of what the other realm handed over; an accepting half is committed with it.
    pub peer_evidence: Option<&'a [u8; 32]>,
    /// Now.
    pub now_ms: u64,
    /// When an offer lapses.
    pub expires_ms: u64,
}

impl TenantTx {
    /// Writes a half: an offer waits, an acceptance is committed with its peer evidence; false
    /// when this realm already keeps a half of the binding.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_binding_half(&mut self, h: &NewHalf<'_>) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let committed = h.peer_evidence.is_some();
        let n = sqlx::query!(
            "INSERT INTO access.identity_binding_halves (tenant_id, realm_id, binding_id,
                    subject_id, role, proof, secret_hash, peer_evidence, state, created_ms,
                    expires_ms, committed_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8,
                     CASE WHEN $9::boolean THEN 'committed' ELSE 'offered' END, $10::bigint, $11,
                     CASE WHEN $9::boolean THEN $10::bigint END)
             ON CONFLICT (tenant_id, realm_id, binding_id) DO NOTHING",
            tenant,
            realm,
            Uuid::from_bytes(h.binding),
            Uuid::from_bytes(h.subject),
            h.role,
            h.proof,
            h.secret_hash.as_slice(),
            h.peer_evidence.map(|e| e.to_vec()),
            committed,
            i64_of(h.now_ms)?,
            i64_of(h.expires_ms)?,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Commits `subject`'s unexpired offer `binding` with the digest of what the other realm
    /// handed over; false when there is none.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn commit_binding_half(
        &mut self,
        binding: [u8; 16],
        subject: [u8; 16],
        peer_evidence: &[u8; 32],
        now_ms: u64,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let n = sqlx::query!(
            "UPDATE access.identity_binding_halves
                SET state = 'committed', peer_evidence = $5, committed_ms = $6
              WHERE tenant_id = $1 AND realm_id = $2 AND binding_id = $3 AND subject_id = $4
                AND state = 'offered' AND role = 'offer' AND expires_ms > $6",
            tenant,
            realm,
            Uuid::from_bytes(binding),
            Uuid::from_bytes(subject),
            peer_evidence.as_slice(),
            i64_of(now_ms)?,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// The binding halves of `subject`, oldest first.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn binding_halves_of(
        &mut self,
        subject: [u8; 16],
    ) -> Result<Vec<BindingHalf>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            "SELECT binding_id, role, proof, state, created_ms, committed_ms
               FROM access.identity_binding_halves
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3
              ORDER BY created_ms, binding_id",
            tenant,
            realm,
            Uuid::from_bytes(subject),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(BindingHalf {
                    binding: *r.binding_id.as_bytes(),
                    role: r.role,
                    proof: r.proof,
                    state: r.state,
                    created_ms: u64_of(r.created_ms)?,
                    committed_ms: r.committed_ms.map(u64_of).transpose()?,
                })
            })
            .collect()
    }
}
