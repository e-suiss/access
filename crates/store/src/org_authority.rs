//! The rest of the identity plane's side of B2B organizations and households (TN-89, TN-90,
//! TN-91, TN-109, TN-120, E53, OP-153 m.3 (o), (p), (q)): domain verification bookkeeping, the
//! role Grant of a membership, ownership transfers, enterprise connection drafts, guardianships
//! and parent consents. Nothing is deleted (OP-73).

use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::TenantTx;
use crate::orgs::Source;

fn uuid(b: [u8; 16]) -> Uuid {
    Uuid::from_bytes(b)
}

fn id16(v: Vec<u8>) -> Result<[u8; 16], StoreError> {
    <[u8; 16]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn id32(v: Vec<u8>) -> Result<[u8; 32], StoreError> {
    <[u8; 32]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn secs(s: i64) -> Result<f64, StoreError> {
    Ok(f64::from(i32::try_from(s).map_err(|_| StoreError::Range)?))
}

/// One domain claim as the verifier and the daily watch read it (TN-90).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainClaim {
    /// Its id.
    pub id: [u8; 16],
    /// The organization.
    pub org: [u8; 16],
    /// The organization's Party.
    pub party: [u8; 16],
    /// The domain.
    pub domain: String,
    /// `dns_txt`, `https` or `idp`.
    pub method: String,
    /// SHA-256 of the challenge.
    pub challenge_hash: [u8; 32],
    /// When it was verified, Unix ms; `None` while unverified.
    pub verified_ms: Option<i64>,
    /// When it must be verified again, Unix ms.
    pub reverify_ms: Option<i64>,
    /// The MX digest seen at verification.
    pub mx: Option<[u8; 32]>,
    /// The registrar digest seen at verification.
    pub rdap: Option<[u8; 32]>,
    /// MX or registrar change seen and not re-verified since, Unix ms.
    pub changed_ms: Option<i64>,
    /// The autojoin rule is on.
    pub autojoin: bool,
    /// Another organization claimed the domain too, Unix ms of the alarm.
    pub contested_ms: Option<i64>,
    /// Its `domain_verification` Claim was issued and not retracted since.
    pub claimed: bool,
    /// When the watch last looked at it, Unix ms.
    pub checked_ms: Option<i64>,
}

/// A membership with its role Grant's state (TN-89 (3)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    /// The membership.
    pub id: [u8; 16],
    /// The organization.
    pub org: [u8; 16],
    /// The member's subject.
    pub subject: [u8; 16],
    /// How it began.
    pub source: Source,
    /// A root member.
    pub owner: bool,
    /// The role.
    pub role: Option<(String, u64)>,
    /// The inviter's Party.
    pub inviter: Option<[u8; 16]>,
    /// `pending`, `issued` or `denied`.
    pub grant_state: Option<String>,
    /// The role's Grant once issued.
    pub grant: Option<[u8; 16]>,
    /// Until when a reserved or CT3 scope of an autojoin rule is cooling, Unix ms (TN-109).
    pub cooling_until_ms: Option<i64>,
    /// Since, Unix ms.
    pub joined_ms: i64,
}

/// An ownership transfer (TN-91).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transfer {
    /// Its id.
    pub id: [u8; 16],
    /// The organization.
    pub org: [u8; 16],
    /// The proposing owner.
    pub from: [u8; 16],
    /// The recipient.
    pub to: [u8; 16],
    /// The recipient's Party.
    pub to_party: [u8; 16],
    /// The `anchor_transfer` Exercise nonce.
    pub nonce: Vec<u8>,
    /// Digest of its payload.
    pub payload_digest: [u8; 32],
    /// When the time-lock ends, Unix ms.
    pub effective_ms: i64,
    /// A declared DNS ownership recovery (TN-92).
    pub dns_recovery: bool,
    /// Where it stands.
    pub state: TransferState,
}

/// Where a transfer stands (TN-91).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferState {
    /// Proposed; the recipient has not contributed.
    Proposed,
    /// The recipient contributed; it completes once the time-lock ends.
    Contributed,
    /// Cancelled by a root or the recipient.
    Cancelled,
    /// Completed by its committed `anchor_transfer`.
    Completed,
}

impl TransferState {
    /// Its word.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Contributed => "contributed",
            Self::Cancelled => "cancelled",
            Self::Completed => "completed",
        }
    }
}

/// A new transfer.
pub struct NewTransfer<'a> {
    /// The organization.
    pub org: [u8; 16],
    /// The proposing owner.
    pub from: [u8; 16],
    /// The recipient.
    pub to: [u8; 16],
    /// The recipient's Party.
    pub to_party: [u8; 16],
    /// The Exercise nonce.
    pub nonce: &'a [u8],
    /// Digest of its payload.
    pub payload_digest: &'a [u8; 32],
    /// When the time-lock ends, Unix ms.
    pub effective_ms: u64,
    /// A declared DNS ownership recovery (TN-92).
    pub dns_recovery: bool,
}

/// An enterprise connection draft (TN-120).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SsoDraft {
    /// Its id.
    pub id: [u8; 16],
    /// The protocol.
    pub protocol: String,
    /// The upstream issuer.
    pub issuer: String,
    /// The client id at the upstream.
    pub client_id: String,
    /// Who drafted it.
    pub drafted_by: [u8; 16],
    /// Withdrawn.
    pub withdrawn: bool,
}

/// A guardianship (E53).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Guardianship {
    /// Its id.
    pub id: [u8; 16],
    /// The guardian.
    pub guardian: [u8; 16],
    /// The ward.
    pub ward: [u8; 16],
    /// `parent` or `legal_guardian`.
    pub basis: String,
    /// ISO 3166-1 alpha-2.
    pub country: String,
    /// The ward's majority, Unix ms.
    pub majority_ms: i64,
    /// Ended, and why.
    pub ended_by: Option<String>,
}

/// A parent consent (E53, E47).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Consent {
    /// Its id.
    pub id: [u8; 16],
    /// The guardianship.
    pub guardianship: [u8; 16],
    /// Digest of what is asked.
    pub purpose: [u8; 32],
    /// When it expires, Unix ms.
    pub expires_ms: i64,
    /// `approved` or `declined`.
    pub decision: Option<String>,
    /// Expired without a decision.
    pub expired: bool,
}

impl TenantTx {
    /// Records the Anchor `party_register` opened for organization Party `party`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn record_party_anchor(
        &mut self,
        party: [u8; 16],
        anchor: [u8; 16],
    ) -> Result<(), StoreError> {
        let (tenant, realm) = self.org_scope()?;
        sqlx::query!(
            r#"INSERT INTO access.org_party_anchors (tenant_id, realm_id, party, anchor)
               VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING"#,
            tenant,
            realm,
            party.as_slice(),
            anchor.as_slice(),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The Anchor of organization Party `party`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn party_anchor(&mut self, party: [u8; 16]) -> Result<Option<[u8; 16]>, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let a = sqlx::query_scalar!(
            r#"SELECT anchor FROM access.org_party_anchors
                WHERE tenant_id = $1 AND realm_id = $2 AND party = $3"#,
            tenant,
            realm,
            party.as_slice(),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        a.map(id16).transpose()
    }

    /// Records a domain claim committed by `exercise`, pending verification (TN-90).
    ///
    /// # Errors
    /// [`StoreError`]; the same organization's open claim of the domain is an integrity error.
    pub async fn claim_domain(
        &mut self,
        org: [u8; 16],
        (domain, method): (&str, &str),
        challenge_hash: &[u8; 32],
        exercise: &[u8; 32],
    ) -> Result<[u8; 16], StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let id = sqlx::query_scalar!(
            r#"INSERT INTO access.org_domains
                 (tenant_id, realm_id, org_id, domain, method, challenge_hash, created_exercise)
               VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING claim_id"#,
            tenant,
            realm,
            uuid(org),
            domain,
            method,
            challenge_hash.as_slice(),
            exercise.as_slice(),
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(*id.as_bytes())
    }

    /// Open domain claims of the realm; with `org`, only that organization's (TN-90).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn open_domain_claims(
        &mut self,
        org: Option<[u8; 16]>,
    ) -> Result<Vec<DomainClaim>, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let rows = sqlx::query!(
            r#"SELECT d.claim_id, d.org_id, o.party, d.domain, d.method, d.challenge_hash,
                      (extract(epoch FROM d.verified_at) * 1000)::bigint AS verified_ms,
                      (extract(epoch FROM d.reverify_by) * 1000)::bigint AS reverify_ms,
                      d.mx_digest, d.rdap_digest,
                      (extract(epoch FROM d.changed_at) * 1000)::bigint AS changed_ms,
                      d.autojoin,
                      (extract(epoch FROM d.contested_at) * 1000)::bigint AS contested_ms,
                      (d.claim_issued_at IS NOT NULL AND (d.claim_retracted_at IS NULL
                        OR d.claim_retracted_at < d.claim_issued_at)) AS "claimed!",
                      (extract(epoch FROM d.checked_at) * 1000)::bigint AS checked_ms
                 FROM access.org_domains d
                 JOIN access.organizations o
                   ON o.tenant_id = d.tenant_id AND o.realm_id = d.realm_id AND o.org_id = d.org_id
                WHERE d.tenant_id = $1 AND d.realm_id = $2 AND d.released_at IS NULL
                  AND o.ended_at IS NULL AND ($3::uuid IS NULL OR d.org_id = $3)
                ORDER BY d.claim_id"#,
            tenant,
            realm,
            org.map(uuid),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(DomainClaim {
                    id: *r.claim_id.as_bytes(),
                    org: *r.org_id.as_bytes(),
                    party: id16(r.party)?,
                    domain: r.domain,
                    method: r.method,
                    challenge_hash: id32(r.challenge_hash)?,
                    verified_ms: r.verified_ms,
                    reverify_ms: r.reverify_ms,
                    mx: r.mx_digest.map(id32).transpose()?,
                    rdap: r.rdap_digest.map(id32).transpose()?,
                    changed_ms: r.changed_ms,
                    autojoin: r.autojoin,
                    contested_ms: r.contested_ms,
                    claimed: r.claimed,
                    checked_ms: r.checked_ms,
                })
            })
            .collect()
    }

    /// Moves the realm's domain watch times back by `checked_s` and `changed_s` seconds; for the
    /// watch tests only.
    ///
    /// # Errors
    /// [`StoreError`].
    #[cfg(feature = "testing")]
    pub async fn age_domain_watch(
        &mut self,
        checked_s: i64,
        changed_s: i64,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = self.org_scope()?;
        sqlx::query!(
            r#"UPDATE access.org_domains
                  SET checked_at = checked_at - make_interval(secs => $3),
                      changed_at = changed_at - make_interval(secs => $4)
                WHERE tenant_id = $1 AND realm_id = $2"#,
            tenant,
            realm,
            secs(checked_s)?,
            secs(changed_s)?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Notes that the daily watch looked at the claim.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn domain_checked(&mut self, claim: [u8; 16]) -> Result<(), StoreError> {
        let (tenant, realm) = self.org_scope()?;
        sqlx::query!(
            r#"UPDATE access.org_domains SET checked_at = clock_timestamp()
                WHERE tenant_id = $1 AND realm_id = $2 AND claim_id = $3"#,
            tenant,
            realm,
            uuid(claim),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Raises the contested alarm on every open claim of `domain` not yet alarmed, when more
    /// than one organization claims it, and turns their autojoin rules off (TN-90). Returns the
    /// claims alarmed now.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn contest_domain(&mut self, domain: &str) -> Result<Vec<[u8; 16]>, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let rows = sqlx::query_scalar!(
            r#"UPDATE access.org_domains d
                  SET contested_at = coalesce(d.contested_at, clock_timestamp()), autojoin = false
                WHERE d.tenant_id = $1 AND d.realm_id = $2 AND d.domain = $3
                  AND d.released_at IS NULL
                  AND (SELECT count(DISTINCT x.org_id) FROM access.org_domains x
                        WHERE x.tenant_id = d.tenant_id AND x.realm_id = d.realm_id
                          AND x.domain = d.domain AND x.released_at IS NULL) > 1
                  AND (d.contested_at IS NULL OR d.autojoin)
               RETURNING claim_id"#,
            tenant,
            realm,
            domain,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(rows.into_iter().map(|u| *u.as_bytes()).collect())
    }

    /// Records that the claim's `domain_verification` Claim was issued (`true`) or retracted.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn domain_claim_issued(
        &mut self,
        claim: [u8; 16],
        issued: bool,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = self.org_scope()?;
        sqlx::query!(
            r#"UPDATE access.org_domains
                  SET claim_issued_at = CASE WHEN $4 THEN clock_timestamp() ELSE claim_issued_at END,
                      claim_retracted_at = CASE WHEN $4 THEN claim_retracted_at ELSE clock_timestamp() END
                WHERE tenant_id = $1 AND realm_id = $2 AND claim_id = $3"#,
            tenant,
            realm,
            uuid(claim),
            issued,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Opens a membership episode with its role pending issuance by the inviter's `grant_issue`
    /// (TN-89 (3)), or none; `cooling_s` starts a TN-109 cooling window.
    ///
    /// # Errors
    /// [`StoreError`]; an open episode of the same subject is an integrity error.
    pub async fn open_member(
        &mut self,
        (org, subject): ([u8; 16], [u8; 16]),
        source: Source,
        role: Option<(&str, u64)>,
        inviter: Option<[u8; 16]>,
        cooling_s: Option<i64>,
    ) -> Result<[u8; 16], StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let version = role
            .map(|(_, v)| i64::try_from(v).map_err(|_| StoreError::Range))
            .transpose()?;
        let cooling = cooling_s.map(secs).transpose()?;
        let id = sqlx::query_scalar!(
            r#"INSERT INTO access.org_memberships
                 (tenant_id, realm_id, org_id, subject_id, source, owner, role_name, role_version,
                  inviter_party, grant_state, cooling_until)
               VALUES ($1, $2, $3, $4, $5, false, $6, $7, $8,
                       CASE WHEN $6::text IS NULL THEN NULL ELSE 'pending' END,
                       CASE WHEN $9::float8 IS NULL THEN NULL
                            ELSE clock_timestamp() + make_interval(secs => $9) END)
               RETURNING membership_id"#,
            tenant,
            realm,
            uuid(org),
            uuid(subject),
            source.word(),
            role.map(|(n, _)| n),
            version,
            inviter.as_ref().map(<[u8; 16]>::as_slice),
            cooling,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(*id.as_bytes())
    }

    /// Re-opens a member's episode as an owner after a completed transfer: the old episode
    /// ends by `transfer` and a new one keeps its source and role (TN-91).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn promote_owner(
        &mut self,
        org: [u8; 16],
        subject: [u8; 16],
    ) -> Result<bool, StoreError> {
        let Some(m) = self.member(org, subject).await? else {
            return Ok(false);
        };
        if m.owner {
            return Ok(true);
        }
        if !self.end_membership(org, subject, "transfer").await? {
            return Ok(false);
        }
        self.insert_membership(org, subject, m.source, true, None)
            .await?;
        Ok(true)
    }

    /// The subject's open membership of `org`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn member(
        &mut self,
        org: [u8; 16],
        subject: [u8; 16],
    ) -> Result<Option<Member>, StoreError> {
        Ok(self
            .members(org)
            .await?
            .into_iter()
            .find(|m| m.subject == subject))
    }

    /// The organization's open memberships with their role Grants' state.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn members(&mut self, org: [u8; 16]) -> Result<Vec<Member>, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let rows = sqlx::query!(
            r#"SELECT membership_id, org_id, subject_id, source, owner, role_name, role_version,
                      inviter_party, grant_state, grant_id,
                      (extract(epoch FROM cooling_until) * 1000)::bigint AS cooling_ms,
                      (extract(epoch FROM joined_at) * 1000)::bigint AS "joined_ms!"
                 FROM access.org_memberships
                WHERE tenant_id = $1 AND realm_id = $2 AND org_id = $3 AND ended_at IS NULL
                ORDER BY membership_id"#,
            tenant,
            realm,
            uuid(org),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                let role = match (r.role_name, r.role_version) {
                    (Some(n), Some(v)) => {
                        Some((n, u64::try_from(v).map_err(|_| StoreError::Corrupt)?))
                    }
                    _ => None,
                };
                Ok(Member {
                    id: *r.membership_id.as_bytes(),
                    org: *r.org_id.as_bytes(),
                    subject: *r.subject_id.as_bytes(),
                    source: Source::parse(&r.source)?,
                    owner: r.owner,
                    role,
                    inviter: r.inviter_party.map(id16).transpose()?,
                    grant_state: r.grant_state,
                    grant: r.grant_id.map(id16).transpose()?,
                    cooling_until_ms: r.cooling_ms,
                    joined_ms: r.joined_ms,
                })
            })
            .collect()
    }

    /// Settles a pending role Grant once: issued as `grant` by `exercise`, or denied.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn settle_role_grant(
        &mut self,
        membership: [u8; 16],
        issued: Option<([u8; 16], [u8; 32])>,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let done = sqlx::query!(
            r#"UPDATE access.org_memberships
                  SET grant_state = CASE WHEN $4::bytea IS NULL THEN 'denied' ELSE 'issued' END,
                      grant_id = $4, grant_exercise = $5
                WHERE tenant_id = $1 AND realm_id = $2 AND membership_id = $3
                  AND ended_at IS NULL AND grant_state = 'pending'"#,
            tenant,
            realm,
            uuid(membership),
            issued.as_ref().map(|(g, _)| g.as_slice()),
            issued.as_ref().map(|(_, e)| e.as_slice()),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Invitations the organization sent since `since_s` seconds ago and how many of them were
    /// accepted (TN-89 (11)).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn invitation_outcomes(
        &mut self,
        org: [u8; 16],
        since_s: i64,
    ) -> Result<(i64, i64), StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let r = sqlx::query!(
            r#"SELECT count(*) AS "sent!", count(accepted_at) AS "accepted!"
                 FROM access.org_invitations
                WHERE tenant_id = $1 AND realm_id = $2 AND org_id = $3
                  AND created_at > clock_timestamp() - make_interval(secs => $4)"#,
            tenant,
            realm,
            uuid(org),
            secs(since_s)?,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok((r.sent, r.accepted))
    }

    /// Records a proposed transfer; another open transfer of the organization is an integrity
    /// error.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_transfer(&mut self, t: &NewTransfer<'_>) -> Result<[u8; 16], StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let effective = i64::try_from(t.effective_ms).map_err(|_| StoreError::Range)?;
        let id = sqlx::query_scalar!(
            r#"INSERT INTO access.org_transfers
                 (tenant_id, realm_id, org_id, from_subject, to_subject, to_party, nonce,
                  payload_digest, effective_at, dns_recovery)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8,
                       greatest(to_timestamp($9::bigint::float8 / 1000), clock_timestamp() + interval '24 hours'),
                       $10)
               RETURNING transfer_id"#,
            tenant,
            realm,
            uuid(t.org),
            uuid(t.from),
            uuid(t.to),
            t.to_party.as_slice(),
            t.nonce,
            t.payload_digest.as_slice(),
            effective,
            t.dns_recovery,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(*id.as_bytes())
    }

    /// One transfer of the realm.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn transfer(&mut self, id: [u8; 16]) -> Result<Option<Transfer>, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let r = sqlx::query!(
            r#"SELECT transfer_id, org_id, from_subject, to_subject, to_party, nonce, payload_digest,
                      (extract(epoch FROM effective_at) * 1000)::bigint AS "effective_ms!",
                      dns_recovery, contributed_at IS NOT NULL AS "contributed!",
                      cancelled_at IS NOT NULL AS "cancelled!",
                      completed_at IS NOT NULL AS "completed!"
                 FROM access.org_transfers
                WHERE tenant_id = $1 AND realm_id = $2 AND transfer_id = $3"#,
            tenant,
            realm,
            uuid(id),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        r.map(|r| {
            Ok(Transfer {
                id: *r.transfer_id.as_bytes(),
                org: *r.org_id.as_bytes(),
                from: *r.from_subject.as_bytes(),
                to: *r.to_subject.as_bytes(),
                to_party: id16(r.to_party)?,
                nonce: r.nonce,
                payload_digest: id32(r.payload_digest)?,
                effective_ms: r.effective_ms,
                dns_recovery: r.dns_recovery,
                state: if r.completed {
                    TransferState::Completed
                } else if r.cancelled {
                    TransferState::Cancelled
                } else if r.contributed {
                    TransferState::Contributed
                } else {
                    TransferState::Proposed
                },
            })
        })
        .transpose()
    }

    /// The organization's transfers, newest first.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn transfers(&mut self, org: [u8; 16]) -> Result<Vec<Transfer>, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let ids = sqlx::query_scalar!(
            r#"SELECT transfer_id FROM access.org_transfers
                WHERE tenant_id = $1 AND realm_id = $2 AND org_id = $3
                ORDER BY transfer_id DESC LIMIT 100"#,
            tenant,
            realm,
            uuid(org),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(t) = self.transfer(*id.as_bytes()).await? {
                out.push(t);
            }
        }
        Ok(out)
    }

    /// Records the recipient's contribution to an open transfer, once.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn contribute_transfer(&mut self, id: [u8; 16]) -> Result<bool, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let done = sqlx::query!(
            r#"UPDATE access.org_transfers SET contributed_at = clock_timestamp()
                WHERE tenant_id = $1 AND realm_id = $2 AND transfer_id = $3
                  AND contributed_at IS NULL AND cancelled_at IS NULL AND completed_at IS NULL"#,
            tenant,
            realm,
            uuid(id),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Cancels an open transfer by `by`, once.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn cancel_transfer(
        &mut self,
        id: [u8; 16],
        by: [u8; 16],
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let done = sqlx::query!(
            r#"UPDATE access.org_transfers SET cancelled_at = clock_timestamp(), cancelled_by = $4
                WHERE tenant_id = $1 AND realm_id = $2 AND transfer_id = $3
                  AND cancelled_at IS NULL AND completed_at IS NULL"#,
            tenant,
            realm,
            uuid(id),
            uuid(by),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Completes an open, contributed transfer by its committed `exercise`, once.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn complete_transfer(
        &mut self,
        id: [u8; 16],
        exercise: &[u8; 32],
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let done = sqlx::query!(
            r#"UPDATE access.org_transfers
                  SET completed_at = clock_timestamp(), completed_exercise = $4
                WHERE tenant_id = $1 AND realm_id = $2 AND transfer_id = $3
                  AND contributed_at IS NOT NULL AND cancelled_at IS NULL AND completed_at IS NULL"#,
            tenant,
            realm,
            uuid(id),
            exercise.as_slice(),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Records an enterprise connection draft committed by `exercise` (TN-120).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_sso_draft(
        &mut self,
        org: [u8; 16],
        (issuer, client_id): (&str, &str),
        drafted_by: [u8; 16],
        exercise: &[u8; 32],
    ) -> Result<[u8; 16], StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let id = sqlx::query_scalar!(
            r#"INSERT INTO access.org_sso_drafts
                 (tenant_id, realm_id, org_id, protocol, issuer, client_id, drafted_by, created_exercise)
               VALUES ($1, $2, $3, 'oidc', $4, $5, $6, $7) RETURNING draft_id"#,
            tenant,
            realm,
            uuid(org),
            issuer,
            client_id,
            drafted_by.as_slice(),
            exercise.as_slice(),
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(*id.as_bytes())
    }

    /// The organization's enterprise connection drafts.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn sso_drafts(&mut self, org: [u8; 16]) -> Result<Vec<SsoDraft>, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let rows = sqlx::query!(
            r#"SELECT draft_id, protocol, issuer, client_id, drafted_by,
                      withdrawn_at IS NOT NULL AS "withdrawn!"
                 FROM access.org_sso_drafts
                WHERE tenant_id = $1 AND realm_id = $2 AND org_id = $3
                ORDER BY draft_id"#,
            tenant,
            realm,
            uuid(org),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(SsoDraft {
                    id: *r.draft_id.as_bytes(),
                    protocol: r.protocol,
                    issuer: r.issuer,
                    client_id: r.client_id,
                    drafted_by: id16(r.drafted_by)?,
                    withdrawn: r.withdrawn,
                })
            })
            .collect()
    }

    /// Records a guardianship that ends at `majority_ms` (E53).
    ///
    /// # Errors
    /// [`StoreError`]; an open one of the same pair is an integrity error.
    pub async fn insert_guardianship(
        &mut self,
        (guardian, ward): ([u8; 16], [u8; 16]),
        basis: &str,
        country: &str,
        majority_ms: i64,
    ) -> Result<[u8; 16], StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let id = sqlx::query_scalar!(
            r#"INSERT INTO access.guardianships
                 (tenant_id, realm_id, guardian_subject, ward_subject, basis, country, majority_at)
               VALUES ($1, $2, $3, $4, $5, $6, to_timestamp($7::bigint::float8 / 1000))
               RETURNING guardianship_id"#,
            tenant,
            realm,
            uuid(guardian),
            uuid(ward),
            basis,
            country,
            majority_ms,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(*id.as_bytes())
    }

    /// Guardianships `subject` stands in, as guardian or ward, open ones first.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn guardianships_of(
        &mut self,
        subject: [u8; 16],
    ) -> Result<Vec<Guardianship>, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let rows = sqlx::query!(
            r#"SELECT guardianship_id, guardian_subject, ward_subject, basis, country, ended_by,
                      (extract(epoch FROM majority_at) * 1000)::bigint AS "majority_ms!"
                 FROM access.guardianships
                WHERE tenant_id = $1 AND realm_id = $2
                  AND (guardian_subject = $3 OR ward_subject = $3)
                ORDER BY ended_at IS NOT NULL, guardianship_id"#,
            tenant,
            realm,
            uuid(subject),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| Guardianship {
                id: *r.guardianship_id.as_bytes(),
                guardian: *r.guardian_subject.as_bytes(),
                ward: *r.ward_subject.as_bytes(),
                basis: r.basis,
                country: r.country,
                majority_ms: r.majority_ms,
                ended_by: r.ended_by,
            })
            .collect())
    }

    /// One guardianship.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn guardianship(&mut self, id: [u8; 16]) -> Result<Option<Guardianship>, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let r = sqlx::query!(
            r#"SELECT guardianship_id, guardian_subject, ward_subject, basis, country, ended_by,
                      (extract(epoch FROM majority_at) * 1000)::bigint AS "majority_ms!"
                 FROM access.guardianships
                WHERE tenant_id = $1 AND realm_id = $2 AND guardianship_id = $3"#,
            tenant,
            realm,
            uuid(id),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(r.map(|r| Guardianship {
            id: *r.guardianship_id.as_bytes(),
            guardian: *r.guardian_subject.as_bytes(),
            ward: *r.ward_subject.as_bytes(),
            basis: r.basis,
            country: r.country,
            majority_ms: r.majority_ms,
            ended_by: r.ended_by,
        }))
    }

    /// Ends every open guardianship whose ward reached majority; returns them (E53).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn end_majorities(&mut self) -> Result<Vec<[u8; 16]>, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let rows = sqlx::query_scalar!(
            r#"UPDATE access.guardianships SET ended_at = clock_timestamp(), ended_by = 'majority'
                WHERE tenant_id = $1 AND realm_id = $2 AND ended_at IS NULL
                  AND majority_at <= clock_timestamp()
               RETURNING guardianship_id"#,
            tenant,
            realm,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(rows.into_iter().map(|u| *u.as_bytes()).collect())
    }

    /// Asks a parent consent valid `ttl_s` seconds (E53, at most 72 hours).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_consent(
        &mut self,
        guardianship: [u8; 16],
        purpose: &[u8; 32],
        ttl_s: i64,
    ) -> Result<[u8; 16], StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let id = sqlx::query_scalar!(
            r#"INSERT INTO access.parent_consents
                 (tenant_id, realm_id, guardianship_id, purpose_digest, expires_at)
               VALUES ($1, $2, $3, $4, clock_timestamp() + make_interval(secs => $5))
               RETURNING consent_id"#,
            tenant,
            realm,
            uuid(guardianship),
            purpose.as_slice(),
            secs(ttl_s)?,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(*id.as_bytes())
    }

    /// One parent consent.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn consent(&mut self, id: [u8; 16]) -> Result<Option<Consent>, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let r = sqlx::query!(
            r#"SELECT consent_id, guardianship_id, purpose_digest, decision,
                      (extract(epoch FROM expires_at) * 1000)::bigint AS "expires_ms!",
                      (decided_at IS NULL AND expires_at <= clock_timestamp()) AS "expired!"
                 FROM access.parent_consents
                WHERE tenant_id = $1 AND realm_id = $2 AND consent_id = $3"#,
            tenant,
            realm,
            uuid(id),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        r.map(|r| {
            Ok(Consent {
                id: *r.consent_id.as_bytes(),
                guardianship: *r.guardianship_id.as_bytes(),
                purpose: id32(r.purpose_digest)?,
                expires_ms: r.expires_ms,
                decision: r.decision,
                expired: r.expired,
            })
        })
        .transpose()
    }

    /// Decides an open parent consent before it expires, once.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn decide_consent(
        &mut self,
        id: [u8; 16],
        approve: bool,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let done = sqlx::query!(
            r#"UPDATE access.parent_consents
                  SET decided_at = clock_timestamp(),
                      decision = CASE WHEN $4 THEN 'approved' ELSE 'declined' END
                WHERE tenant_id = $1 AND realm_id = $2 AND consent_id = $3
                  AND decided_at IS NULL AND expires_at > clock_timestamp()"#,
            tenant,
            realm,
            uuid(id),
            approve,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected() == 1)
    }
}
