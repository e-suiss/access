//! The identity plane's side of B2B organizations (TN-5, TN-89, TN-90, TN-91, OP-153 m.3 (b),
//! (o), (p)): the organization row bound to its Party, membership episodes, invitations, domain
//! claims and access requests. Nothing is deleted (OP-73); the last active owner is kept by the
//! database on every path.

use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::TenantTx;

fn uuid(b: [u8; 16]) -> Uuid {
    Uuid::from_bytes(b)
}

fn id16(v: Vec<u8>) -> Result<[u8; 16], StoreError> {
    <[u8; 16]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

/// Whether `e` is the database keeping the last owner (TN-91).
#[must_use]
pub fn last_owner(e: &StoreError) -> bool {
    matches!(e, StoreError::Db(sqlx::Error::Database(d)) if d.constraint() == Some("org_last_owner"))
}

/// An organization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrgRow {
    /// Its id.
    pub id: [u8; 16],
    /// Its Party in the realm's governing domain.
    pub party: [u8; 16],
    /// Its display name, attacker-controlled text (OP-153 m.3 (o)).
    pub display_name: String,
    /// Whether home realm discovery routes to it (TN-98).
    pub hrd: bool,
    /// Whether it ended.
    pub ended: bool,
}

/// How a membership began (§12.3.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// The founder who created the organization (OP-153 m.3 (b)).
    Founder,
    /// An accepted invitation.
    Invite,
    /// SCIM provisioning.
    Scim,
    /// Just-in-time at an upstream sign-in.
    Jit,
    /// A verified-domain autojoin rule.
    DomainAutojoin,
}

impl Source {
    /// Its stored word.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Founder => "founder",
            Self::Invite => "invite",
            Self::Scim => "scim",
            Self::Jit => "jit",
            Self::DomainAutojoin => "domain_autojoin",
        }
    }

    fn of(w: &str) -> Result<Self, StoreError> {
        match w {
            "founder" => Ok(Self::Founder),
            "invite" => Ok(Self::Invite),
            "scim" => Ok(Self::Scim),
            "jit" => Ok(Self::Jit),
            "domain_autojoin" => Ok(Self::DomainAutojoin),
            _ => Err(StoreError::Corrupt),
        }
    }
}

/// One active membership.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipRow {
    /// Its id.
    pub id: [u8; 16],
    /// The member's subject.
    pub subject: [u8; 16],
    /// How it began.
    pub source: Source,
    /// A root member.
    pub owner: bool,
    /// The role, as a named `AuthoritySet` and version.
    pub role: Option<(String, u64)>,
    /// The role's Grant.
    pub grant: Option<[u8; 16]>,
}

/// A new invitation.
pub struct NewInvitation<'a> {
    /// The organization.
    pub org: [u8; 16],
    /// SHA-256 of the link token.
    pub token_hash: &'a [u8; 32],
    /// SHA-256 of the magic code.
    pub code_hash: &'a [u8; 32],
    /// The realm's keyed blind index of the invitee's folded identifier.
    pub invitee_index: &'a [u8; 32],
    /// The invitee's domain, for the different-domain interstitial.
    pub invitee_domain: &'a str,
    /// The inviter's Party.
    pub inviter: [u8; 16],
    /// The role.
    pub role: (&'a str, u64),
    /// The `idp.org.invite` Exercise, when committed.
    pub exercise: Option<&'a [u8; 32]>,
    /// Lifetime in seconds.
    pub ttl_s: i64,
}

/// An invitation as a token or code finds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvitationRow {
    /// Its id.
    pub id: [u8; 16],
    /// The organization.
    pub org: [u8; 16],
    /// SHA-256 of the magic code.
    pub code_hash: [u8; 32],
    /// The invitee's blind index.
    pub invitee_index: [u8; 32],
    /// The invitee's domain.
    pub invitee_domain: String,
    /// The inviter's Party.
    pub inviter: [u8; 16],
    /// The role.
    pub role: (String, u64),
    /// Still open: not accepted, not revoked, not expired.
    pub open: bool,
    /// Browser and mail-scanner fetches seen.
    pub scanner_clicks: i32,
}

/// One domain claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainRow {
    /// Its id.
    pub id: [u8; 16],
    /// The organization.
    pub org: [u8; 16],
    /// The domain.
    pub domain: String,
    /// Verified and not past its re-verification time.
    pub verified: bool,
    /// The autojoin rule is on.
    pub autojoin: bool,
    /// MX or registrar change seen and not re-verified since, Unix milliseconds.
    pub changed_ms: Option<i64>,
}

impl TenantTx {
    fn org_scope(&self) -> Result<(Uuid, Uuid), StoreError> {
        let realm = self.realm().ok_or(StoreError::Range)?;
        Ok((uuid(*self.tenant.as_bytes()), uuid(*realm.as_bytes())))
    }

    /// Records an organization bound to its registered Party and the Exercise that created it.
    ///
    /// # Errors
    /// [`StoreError`]; a Party already bound is an integrity error.
    pub async fn insert_org(
        &mut self,
        party: [u8; 16],
        display_name: &str,
        exercise: &[u8; 32],
    ) -> Result<[u8; 16], StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let id = sqlx::query_scalar!(
            r#"INSERT INTO access.organizations (tenant_id, realm_id, party, display_name, created_exercise)
               VALUES ($1, $2, $3, $4, $5) RETURNING org_id"#,
            tenant,
            realm,
            party.as_slice(),
            display_name,
            exercise.as_slice(),
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(*id.as_bytes())
    }

    /// The organization `id` (TN-3: routing is by id).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn org(&mut self, id: [u8; 16]) -> Result<Option<OrgRow>, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let row = sqlx::query!(
            r#"SELECT org_id, party, display_name, hrd, ended_at IS NOT NULL AS "ended!"
                 FROM access.organizations
                WHERE tenant_id = $1 AND realm_id = $2 AND org_id = $3"#,
            tenant,
            realm,
            uuid(id),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        row.map(|r| {
            Ok(OrgRow {
                id: *r.org_id.as_bytes(),
                party: id16(r.party)?,
                display_name: r.display_name,
                hrd: r.hrd,
                ended: r.ended,
            })
        })
        .transpose()
    }

    /// The organization bound to `party`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn org_by_party(&mut self, party: [u8; 16]) -> Result<Option<OrgRow>, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let id = sqlx::query_scalar!(
            r#"SELECT org_id FROM access.organizations
                WHERE tenant_id = $1 AND realm_id = $2 AND party = $3"#,
            tenant,
            realm,
            party.as_slice(),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        match id {
            Some(id) => self.org(*id.as_bytes()).await,
            None => Ok(None),
        }
    }

    /// Turns home realm discovery to the organization on or off (TN-98: off by default).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn set_org_hrd(&mut self, id: [u8; 16], on: bool) -> Result<bool, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let done = sqlx::query!(
            r#"UPDATE access.organizations SET hrd = $4
                WHERE tenant_id = $1 AND realm_id = $2 AND org_id = $3 AND ended_at IS NULL"#,
            tenant,
            realm,
            uuid(id),
            on,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Opens a membership episode.
    ///
    /// # Errors
    /// [`StoreError`]; an open episode of the same subject is an integrity error.
    pub async fn insert_membership(
        &mut self,
        org: [u8; 16],
        subject: [u8; 16],
        source: Source,
        owner: bool,
        role: Option<(&str, u64)>,
    ) -> Result<[u8; 16], StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let version = role
            .map(|(_, v)| i64::try_from(v).map_err(|_| StoreError::Range))
            .transpose()?;
        let id = sqlx::query_scalar!(
            r#"INSERT INTO access.org_memberships
                 (tenant_id, realm_id, org_id, subject_id, source, owner, role_name, role_version)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING membership_id"#,
            tenant,
            realm,
            uuid(org),
            uuid(subject),
            source.word(),
            owner,
            role.map(|(n, _)| n),
            version,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(*id.as_bytes())
    }

    /// The organization's active memberships.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn memberships(&mut self, org: [u8; 16]) -> Result<Vec<MembershipRow>, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let rows = sqlx::query!(
            r#"SELECT membership_id, subject_id, source, owner, role_name, role_version, grant_id
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
                    (None, None) => None,
                    _ => return Err(StoreError::Corrupt),
                };
                Ok(MembershipRow {
                    id: *r.membership_id.as_bytes(),
                    subject: *r.subject_id.as_bytes(),
                    source: Source::of(&r.source)?,
                    owner: r.owner,
                    role,
                    grant: r.grant_id.map(id16).transpose()?,
                })
            })
            .collect()
    }

    /// Ends the subject's open membership, `by` one of `remove`, `scim`, `sweep`, `delete` or
    /// `leave`. The last active owner's membership does not end ([`last_owner`]).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn end_membership(
        &mut self,
        org: [u8; 16],
        subject: [u8; 16],
        by: &str,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let done = sqlx::query!(
            r#"UPDATE access.org_memberships SET ended_at = clock_timestamp(), ended_by = $5
                WHERE tenant_id = $1 AND realm_id = $2 AND org_id = $3 AND subject_id = $4
                  AND ended_at IS NULL"#,
            tenant,
            realm,
            uuid(org),
            uuid(subject),
            by,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Ends every open membership of the subject in every organization of the realm, as the
    /// account's deletion or the inactivity sweep does; the last owner is kept ([`last_owner`]).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn end_memberships_of(
        &mut self,
        subject: [u8; 16],
        by: &str,
    ) -> Result<u64, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let done = sqlx::query!(
            r#"UPDATE access.org_memberships SET ended_at = clock_timestamp(), ended_by = $4
                WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND ended_at IS NULL"#,
            tenant,
            realm,
            uuid(subject),
            by,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected())
    }

    /// Takes ownership from the subject's open membership; the last owner keeps it.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn drop_ownership(
        &mut self,
        org: [u8; 16],
        subject: [u8; 16],
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let done = sqlx::query!(
            r#"UPDATE access.org_memberships SET owner = false
                WHERE tenant_id = $1 AND realm_id = $2 AND org_id = $3 AND subject_id = $4
                  AND ended_at IS NULL AND owner"#,
            tenant,
            realm,
            uuid(org),
            uuid(subject),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Invitations the organization created since `since_s` seconds ago (OP-153 m.3 (o)).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn invitations_since(
        &mut self,
        org: [u8; 16],
        since_s: i64,
    ) -> Result<i64, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        Ok(sqlx::query_scalar!(
            r#"SELECT count(*) AS "n!" FROM access.org_invitations
                WHERE tenant_id = $1 AND realm_id = $2 AND org_id = $3
                  AND created_at > clock_timestamp() - make_interval(secs => $4)"#,
            tenant,
            realm,
            uuid(org),
            f64::from(i32::try_from(since_s).map_err(|_| StoreError::Range)?),
        )
        .fetch_one(&mut *self.tx)
        .await?)
    }

    /// Records an invitation.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_invitation(
        &mut self,
        i: &NewInvitation<'_>,
    ) -> Result<[u8; 16], StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let version = i64::try_from(i.role.1).map_err(|_| StoreError::Range)?;
        let ttl = f64::from(i32::try_from(i.ttl_s).map_err(|_| StoreError::Range)?);
        let id = sqlx::query_scalar!(
            r#"INSERT INTO access.org_invitations
                 (tenant_id, realm_id, org_id, token_hash, code_hash, invitee_index, invitee_domain,
                  inviter_party, role_name, role_version, created_exercise, expires_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                       clock_timestamp() + make_interval(secs => $12))
               RETURNING invitation_id"#,
            tenant,
            realm,
            uuid(i.org),
            i.token_hash.as_slice(),
            i.code_hash.as_slice(),
            i.invitee_index.as_slice(),
            i.invitee_domain,
            i.inviter.as_slice(),
            i.role.0,
            version,
            i.exercise.map(<[u8; 32]>::as_slice),
            ttl,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(*id.as_bytes())
    }

    /// The invitation whose token hashes to `token_hash`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn invitation_by_token(
        &mut self,
        token_hash: &[u8; 32],
    ) -> Result<Option<InvitationRow>, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let row = sqlx::query!(
            r#"SELECT invitation_id, org_id, code_hash, invitee_index, invitee_domain, inviter_party,
                      role_name, role_version, scanner_clicks,
                      (accepted_at IS NULL AND revoked_at IS NULL
                       AND expires_at > clock_timestamp()) AS "open!"
                 FROM access.org_invitations
                WHERE tenant_id = $1 AND realm_id = $2 AND token_hash = $3"#,
            tenant,
            realm,
            token_hash.as_slice(),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        row.map(|r| {
            Ok(InvitationRow {
                id: *r.invitation_id.as_bytes(),
                org: *r.org_id.as_bytes(),
                code_hash: <[u8; 32]>::try_from(r.code_hash).map_err(|_| StoreError::Corrupt)?,
                invitee_index: <[u8; 32]>::try_from(r.invitee_index)
                    .map_err(|_| StoreError::Corrupt)?,
                invitee_domain: r.invitee_domain,
                inviter: id16(r.inviter_party)?,
                role: (
                    r.role_name,
                    u64::try_from(r.role_version).map_err(|_| StoreError::Corrupt)?,
                ),
                open: r.open,
                scanner_clicks: r.scanner_clicks,
            })
        })
        .transpose()
    }

    /// Counts a browser or mail-scanner fetch of the link; it consumes nothing (TN-89).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn count_scanner_click(&mut self, invitation: [u8; 16]) -> Result<(), StoreError> {
        let (tenant, realm) = self.org_scope()?;
        sqlx::query!(
            r#"UPDATE access.org_invitations SET scanner_clicks = scanner_clicks + 1
                WHERE tenant_id = $1 AND realm_id = $2 AND invitation_id = $3
                  AND accepted_at IS NULL AND revoked_at IS NULL"#,
            tenant,
            realm,
            uuid(invitation),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Marks the open invitation accepted by `subject`, once.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn accept_invitation(
        &mut self,
        invitation: [u8; 16],
        subject: [u8; 16],
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let done = sqlx::query!(
            r#"UPDATE access.org_invitations SET accepted_at = clock_timestamp(), accepted_subject = $4
                WHERE tenant_id = $1 AND realm_id = $2 AND invitation_id = $3
                  AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > clock_timestamp()"#,
            tenant,
            realm,
            uuid(invitation),
            uuid(subject),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Revokes an open invitation.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn revoke_invitation(&mut self, invitation: [u8; 16]) -> Result<bool, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let done = sqlx::query!(
            r#"UPDATE access.org_invitations SET revoked_at = clock_timestamp()
                WHERE tenant_id = $1 AND realm_id = $2 AND invitation_id = $3
                  AND accepted_at IS NULL AND revoked_at IS NULL"#,
            tenant,
            realm,
            uuid(invitation),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Records a domain claim, pending verification.
    ///
    /// # Errors
    /// [`StoreError`]; the same organization's open claim of the domain is an integrity error.
    pub async fn insert_domain_claim(
        &mut self,
        org: [u8; 16],
        domain: &str,
        method: &str,
        challenge_hash: &[u8; 32],
    ) -> Result<[u8; 16], StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let id = sqlx::query_scalar!(
            r#"INSERT INTO access.org_domains (tenant_id, realm_id, org_id, domain, method, challenge_hash)
               VALUES ($1, $2, $3, $4, $5, $6) RETURNING claim_id"#,
            tenant,
            realm,
            uuid(org),
            domain,
            method,
            challenge_hash.as_slice(),
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(*id.as_bytes())
    }

    /// Marks the claim verified now, to be re-verified within `reverify_s` seconds, with the MX
    /// and registrar digests seen; clears a change seen before.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn verify_domain(
        &mut self,
        claim: [u8; 16],
        reverify_s: i64,
        mx: &[u8; 32],
        rdap: &[u8; 32],
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let secs = f64::from(i32::try_from(reverify_s).map_err(|_| StoreError::Range)?);
        let done = sqlx::query!(
            r#"UPDATE access.org_domains
                  SET verified_at = clock_timestamp(),
                      reverify_by = clock_timestamp() + make_interval(secs => $4),
                      mx_digest = $5, rdap_digest = $6, changed_at = NULL
                WHERE tenant_id = $1 AND realm_id = $2 AND claim_id = $3 AND released_at IS NULL"#,
            tenant,
            realm,
            uuid(claim),
            secs,
            mx.as_slice(),
            rdap.as_slice(),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Notes the MX or registrar digests the daily watch saw; a difference from the verified ones
    /// starts the re-verification window once (TN-90). Returns whether a change was seen now.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn watch_domain(
        &mut self,
        claim: [u8; 16],
        mx: &[u8; 32],
        rdap: &[u8; 32],
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let done = sqlx::query!(
            r#"UPDATE access.org_domains SET changed_at = clock_timestamp()
                WHERE tenant_id = $1 AND realm_id = $2 AND claim_id = $3 AND released_at IS NULL
                  AND verified_at IS NOT NULL AND changed_at IS NULL
                  AND (mx_digest IS DISTINCT FROM $4 OR rdap_digest IS DISTINCT FROM $5)"#,
            tenant,
            realm,
            uuid(claim),
            mx.as_slice(),
            rdap.as_slice(),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Withdraws the verification of claims whose re-verification time passed, or whose MX or
    /// registrar change is older than `grace_s` seconds without re-verification (TN-90); their
    /// autojoin rule goes off with it. Returns the claims withdrawn.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn lapse_domains(&mut self, grace_s: i64) -> Result<Vec<[u8; 16]>, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let secs = f64::from(i32::try_from(grace_s).map_err(|_| StoreError::Range)?);
        let rows = sqlx::query_scalar!(
            r#"UPDATE access.org_domains
                  SET verified_at = NULL, reverify_by = NULL, autojoin = false
                WHERE tenant_id = $1 AND realm_id = $2 AND released_at IS NULL
                  AND verified_at IS NOT NULL
                  AND (reverify_by <= clock_timestamp()
                       OR changed_at <= clock_timestamp() - make_interval(secs => $3))
               RETURNING claim_id"#,
            tenant,
            realm,
            secs,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(rows.into_iter().map(|u| *u.as_bytes()).collect())
    }

    /// Releases a claim.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn release_domain(&mut self, claim: [u8; 16]) -> Result<bool, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let done = sqlx::query!(
            r#"UPDATE access.org_domains SET released_at = clock_timestamp(), autojoin = false
                WHERE tenant_id = $1 AND realm_id = $2 AND claim_id = $3 AND released_at IS NULL"#,
            tenant,
            realm,
            uuid(claim),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Turns the claim's autojoin rule on or off; on needs a live verification.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn set_autojoin(&mut self, claim: [u8; 16], on: bool) -> Result<bool, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let done = sqlx::query!(
            r#"UPDATE access.org_domains SET autojoin = $4
                WHERE tenant_id = $1 AND realm_id = $2 AND claim_id = $3 AND released_at IS NULL
                  AND (NOT $4 OR (verified_at IS NOT NULL AND reverify_by > clock_timestamp()))"#,
            tenant,
            realm,
            uuid(claim),
            on,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Every open claim of `domain` in the realm, by any organization: more than one
    /// organization is a contested domain (TN-90).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn domain_claims(&mut self, domain: &str) -> Result<Vec<DomainRow>, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let rows = sqlx::query!(
            r#"SELECT claim_id, org_id, domain, autojoin,
                      (verified_at IS NOT NULL AND reverify_by > clock_timestamp()) AS "verified!",
                      (extract(epoch FROM changed_at) * 1000)::bigint AS changed_ms
                 FROM access.org_domains
                WHERE tenant_id = $1 AND realm_id = $2 AND domain = $3 AND released_at IS NULL
                ORDER BY claim_id"#,
            tenant,
            realm,
            domain,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| DomainRow {
                id: *r.claim_id.as_bytes(),
                org: *r.org_id.as_bytes(),
                domain: r.domain,
                verified: r.verified,
                autojoin: r.autojoin,
                changed_ms: r.changed_ms,
            })
            .collect())
    }

    /// Opens an access request (TN-90); an open one of the same subject is an integrity error.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_access_request(
        &mut self,
        org: [u8; 16],
        subject: [u8; 16],
    ) -> Result<[u8; 16], StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let id = sqlx::query_scalar!(
            r#"INSERT INTO access.org_access_requests (tenant_id, realm_id, org_id, subject_id)
               VALUES ($1, $2, $3, $4) RETURNING request_id"#,
            tenant,
            realm,
            uuid(org),
            uuid(subject),
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(*id.as_bytes())
    }

    /// Decides an open access request once; returns its subject when decided now.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn decide_access_request(
        &mut self,
        request: [u8; 16],
        approved: bool,
    ) -> Result<Option<[u8; 16]>, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let subject = sqlx::query_scalar!(
            r#"UPDATE access.org_access_requests
                  SET decided_at = clock_timestamp(),
                      decision = CASE WHEN $4 THEN 'approved' ELSE 'denied' END
                WHERE tenant_id = $1 AND realm_id = $2 AND request_id = $3 AND decided_at IS NULL
               RETURNING subject_id"#,
            tenant,
            realm,
            uuid(request),
            approved,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(subject.map(|s| *s.as_bytes()))
    }
}
