//! An organization's enterprise SSO on the identity plane (OP-155 m.3 (i), TN-94, TN-95, TN-134):
//! its SSO enforcement versions, what enforcing it would end, its setup links, its SCIM source
//! and the connection drafts a setup link or the connection manager writes. Nothing is deleted
//! (OP-73).

use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::TenantTx;
use crate::idp::Bound;

fn uuid(b: [u8; 16]) -> Uuid {
    Uuid::from_bytes(b)
}

fn count(n: i64) -> u64 {
    u64::try_from(n).unwrap_or(0)
}

/// An organization's newest SSO enforcement version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enforcement {
    /// Its version.
    pub version: u64,
    /// Whether SSO is enforced.
    pub enforced: bool,
    /// The pending invitations' fate when enforced: `cancel` or `redirect_to_sso`.
    pub invites: Option<String>,
}

/// One member as the enforcement preview reads it (TN-94, X20).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberImpact {
    /// The member's subject.
    pub subject: [u8; 16],
    /// Whether the member is one of the organization's roots.
    pub owner: bool,
    /// Live local sign-in methods: passwords, one-time-code and recovery credentials.
    pub local_methods: u64,
    /// Whether one of them is a password.
    pub password: bool,
    /// Live directory app passwords (API keys).
    pub api_keys: u64,
    /// Open identity sessions.
    pub sessions: u64,
    /// Live refresh token families.
    pub refresh_families: u64,
    /// Live linked upstream sign-ins.
    pub linked_sign_ins: u64,
}

/// A setup link as its holder reaches it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupLink {
    /// Its id.
    pub id: [u8; 16],
    /// The organization it is bound to.
    pub org: [u8; 16],
    /// The Exercise that issued it.
    pub exercise: [u8; 32],
    /// Whether it is past its expiry.
    pub expired: bool,
    /// The SHA-256 of the browser it was opened by, once opened.
    pub browser: Option<[u8; 32]>,
    /// Whether it was finished.
    pub finished: bool,
    /// When it expires, Unix ms.
    pub expires_ms: i64,
}

/// A connection draft to record (OP-153 m.3 (p), OP-155 m.3 (i)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DraftShape<'a> {
    /// OIDC: the issuer and the client id at it.
    Oidc {
        /// The issuer.
        issuer: &'a str,
        /// The client id.
        client_id: &'a str,
    },
    /// SAML: the identity provider's entity ID and metadata URL.
    Saml {
        /// The entity ID.
        entity_id: &'a str,
        /// The metadata URL.
        metadata_url: &'a str,
    },
}

/// A connection draft and where it came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NewDraft<'a> {
    /// The organization.
    pub org: [u8; 16],
    /// Its shape.
    pub shape: DraftShape<'a>,
    /// The wizard it was drafted with.
    pub provider: Option<&'a str>,
    /// The Party that drafted it; zero through a setup link.
    pub drafted_by: [u8; 16],
    /// The Exercise that allowed it: the draft's own, or the setup link's.
    pub exercise: &'a [u8; 32],
    /// The setup link it was drafted through.
    pub setup_link: Option<[u8; 16]>,
}

impl TenantTx {
    /// Writes the next SSO enforcement version of `org` under `bound`: enforced with the pending
    /// invitations' fate `invites`, or lifted when `None`. Returns the version written.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_sso_enforcement(
        &mut self,
        bound: &Bound,
        org: [u8; 16],
        invites: Option<&str>,
    ) -> Result<u64, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let version = sqlx::query_scalar!(
            r#"INSERT INTO access.org_sso_enforcements
                 (tenant_id, realm_id, org_id, version, enforced, invites, domain_id, decision_pos)
               SELECT $1, $2, $3, COALESCE(MAX(version), 0) + 1, $4, $5, $6, $7
                 FROM access.org_sso_enforcements
                WHERE tenant_id = $1 AND realm_id = $2 AND org_id = $3
               RETURNING version AS "version!""#,
            tenant,
            realm,
            uuid(org),
            invites.is_some(),
            invites,
            bound.domain().as_bytes().as_slice(),
            bound.position,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        u64::try_from(version).map_err(|_| StoreError::Corrupt)
    }

    /// The newest SSO enforcement version of `org`; `None` when it was never enforced.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn sso_enforcement(
        &mut self,
        org: [u8; 16],
    ) -> Result<Option<Enforcement>, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let row = sqlx::query!(
            "SELECT version, enforced, invites FROM access.org_sso_enforcements
              WHERE tenant_id = $1 AND realm_id = $2 AND org_id = $3
              ORDER BY version DESC LIMIT 1",
            tenant,
            realm,
            uuid(org),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        row.map(|r| {
            Ok(Enforcement {
                version: u64::try_from(r.version).map_err(|_| StoreError::Corrupt)?,
                enforced: r.enforced,
                invites: r.invites,
            })
        })
        .transpose()
    }

    /// The live organizations `subject` is an active member of whose SSO is enforced now.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn sso_enforced_orgs_of(
        &mut self,
        subject: [u8; 16],
    ) -> Result<Vec<[u8; 16]>, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let rows = sqlx::query_scalar!(
            r#"SELECT m.org_id AS "org!" FROM access.org_memberships m
                 JOIN access.organizations o
                   ON o.tenant_id = m.tenant_id AND o.realm_id = m.realm_id AND o.org_id = m.org_id
                WHERE m.tenant_id = $1 AND m.realm_id = $2 AND m.subject_id = $3
                  AND m.ended_at IS NULL AND o.ended_at IS NULL
                  AND (SELECT e.enforced FROM access.org_sso_enforcements e
                        WHERE e.tenant_id = m.tenant_id AND e.realm_id = m.realm_id
                          AND e.org_id = m.org_id
                        ORDER BY e.version DESC LIMIT 1)
                ORDER BY m.org_id"#,
            tenant,
            realm,
            uuid(subject),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(rows.into_iter().map(|u| *u.as_bytes()).collect())
    }

    /// The live `organization`-profile upstream connections of the organizations whose Parties
    /// are `parties` (OP-155 m.17 (i)), by name.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn organization_connections(
        &mut self,
        parties: &[String],
    ) -> Result<Vec<String>, StoreError> {
        if parties.is_empty() {
            return Ok(Vec::new());
        }
        let (tenant, realm) = self.org_scope()?;
        Ok(sqlx::query_scalar!(
            "SELECT name FROM access.idp_upstreams
              WHERE tenant_id = $1 AND realm_id = $2 AND status = 'active'
                AND profile IS NOT NULL
                AND (profile::jsonb ->> 'organization') = ANY($3)
              ORDER BY name",
            tenant,
            realm,
            parties,
        )
        .fetch_all(&mut *self.tx)
        .await?)
    }

    /// What enforcing SSO on `org` would end for each of its active members (TN-94, X20).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn sso_impact(&mut self, org: [u8; 16]) -> Result<Vec<MemberImpact>, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let rows = sqlx::query!(
            r#"SELECT m.subject_id, m.owner,
                      (SELECT count(*) FROM access.identity_credentials c
                        WHERE c.tenant_id = m.tenant_id AND c.realm_id = m.realm_id
                          AND c.subject_id = m.subject_id AND c.status = 'active') AS "local!",
                      EXISTS (SELECT 1 FROM access.identity_credentials c
                        WHERE c.tenant_id = m.tenant_id AND c.realm_id = m.realm_id
                          AND c.subject_id = m.subject_id AND c.status = 'active'
                          AND c.kind = 'password') AS "password!",
                      (SELECT count(*) FROM access.ldap_credentials l
                        WHERE l.tenant_id = m.tenant_id AND l.realm_id = m.realm_id
                          AND l.subject_id = m.subject_id AND l.status = 'active') AS "api_keys!",
                      (SELECT count(*) FROM access.login_sessions s
                        WHERE s.tenant_id = m.tenant_id AND s.realm_id = m.realm_id
                          AND s.subject_id = m.subject_id AND s.ended_ms IS NULL) AS "sessions!",
                      (SELECT count(*) FROM access.oauth_grants g
                        WHERE g.tenant_id = m.tenant_id AND g.realm_id = m.realm_id
                          AND g.subject_id = m.subject_id AND g.revoked_ms IS NULL
                          AND g.expires_ms > (extract(epoch FROM clock_timestamp()) * 1000)::bigint)
                        AS "refresh!",
                      (SELECT count(*) FROM access.identity_federated f
                        WHERE f.tenant_id = m.tenant_id AND f.realm_id = m.realm_id
                          AND f.subject_id = m.subject_id AND f.ended_ms IS NULL) AS "linked!"
                 FROM access.org_memberships m
                WHERE m.tenant_id = $1 AND m.realm_id = $2 AND m.org_id = $3
                  AND m.ended_at IS NULL
                ORDER BY m.joined_at, m.membership_id"#,
            tenant,
            realm,
            uuid(org),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| MemberImpact {
                subject: *r.subject_id.as_bytes(),
                owner: r.owner,
                local_methods: count(r.local),
                password: r.password,
                api_keys: count(r.api_keys),
                sessions: count(r.sessions),
                refresh_families: count(r.refresh),
                linked_sign_ins: count(r.linked),
            })
            .collect())
    }

    /// The ids of `org`'s open invitations: neither accepted, revoked nor expired.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn open_invitations(&mut self, org: [u8; 16]) -> Result<Vec<[u8; 16]>, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let rows = sqlx::query_scalar!(
            r#"SELECT invitation_id AS "id!" FROM access.org_invitations
                WHERE tenant_id = $1 AND realm_id = $2 AND org_id = $3
                  AND accepted_at IS NULL AND revoked_at IS NULL
                  AND expires_at > clock_timestamp()
                ORDER BY invitation_id"#,
            tenant,
            realm,
            uuid(org),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(rows.into_iter().map(|u| *u.as_bytes()).collect())
    }

    /// Revokes the open invitations of any of `orgs` sent to any of `invitees` (blind indexes)
    /// (TN-95); returns how many.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn revoke_invitations_to(
        &mut self,
        orgs: &[[u8; 16]],
        invitees: &[[u8; 32]],
    ) -> Result<u64, StoreError> {
        if orgs.is_empty() || invitees.is_empty() {
            return Ok(0);
        }
        let (tenant, realm) = self.org_scope()?;
        let orgs: Vec<Uuid> = orgs.iter().map(|o| uuid(*o)).collect();
        let invitees: Vec<Vec<u8>> = invitees.iter().map(|i| i.to_vec()).collect();
        let done = sqlx::query!(
            "UPDATE access.org_invitations SET revoked_at = clock_timestamp()
              WHERE tenant_id = $1 AND realm_id = $2 AND org_id = ANY($3)
                AND invitee_index = ANY($4)
                AND accepted_at IS NULL AND revoked_at IS NULL",
            tenant,
            realm,
            &orgs,
            &invitees,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected())
    }

    /// The blind indexes of every live identifier of `subject`, whatever its kind.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn identifier_indexes(
        &mut self,
        subject: [u8; 16],
    ) -> Result<Vec<[u8; 32]>, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let rows = sqlx::query_scalar!(
            r#"SELECT value_index AS "index!" FROM access.identity_identifiers
                WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND status = 'active'
                  AND value_index IS NOT NULL
                ORDER BY identifier_id"#,
            tenant,
            realm,
            uuid(subject),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|i| <[u8; 32]>::try_from(i).map_err(|_| StoreError::Corrupt))
            .collect()
    }

    /// Records a setup link of `org` as the SHA-256 of its token, issued by `exercise` and valid
    /// `ttl_s` seconds (TN-134).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_setup_link(
        &mut self,
        org: [u8; 16],
        token_hash: &[u8; 32],
        exercise: &[u8; 32],
        ttl_s: i64,
    ) -> Result<[u8; 16], StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let secs = f64::from(i32::try_from(ttl_s).map_err(|_| StoreError::Range)?);
        let id = sqlx::query_scalar!(
            r#"INSERT INTO access.org_setup_links
                 (tenant_id, realm_id, org_id, token_hash, created_exercise, created_at, expires_at)
               SELECT $1, $2, $3, $4, $5, n, n + make_interval(secs => $6)
                 FROM (SELECT clock_timestamp() AS n) t
               RETURNING link_id"#,
            tenant,
            realm,
            uuid(org),
            token_hash.as_slice(),
            exercise.as_slice(),
            secs,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(*id.as_bytes())
    }

    /// Records a setup link of `org` issued `ago_s` seconds ago with its full 72 hours, for
    /// tests of expiry.
    ///
    /// # Errors
    /// [`StoreError`].
    #[cfg(feature = "testing")]
    pub async fn insert_setup_link_ago(
        &mut self,
        org: [u8; 16],
        token_hash: &[u8; 32],
        exercise: &[u8; 32],
        ago_s: i64,
    ) -> Result<[u8; 16], StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let secs = f64::from(i32::try_from(ago_s).map_err(|_| StoreError::Range)?);
        let id = sqlx::query_scalar!(
            r#"INSERT INTO access.org_setup_links
                 (tenant_id, realm_id, org_id, token_hash, created_exercise, created_at, expires_at)
               SELECT $1, $2, $3, $4, $5, n, n + interval '72 hours'
                 FROM (SELECT clock_timestamp() - make_interval(secs => $6) AS n) t
               RETURNING link_id"#,
            tenant,
            realm,
            uuid(org),
            token_hash.as_slice(),
            exercise.as_slice(),
            secs,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(*id.as_bytes())
    }

    /// The action of the realm's `idp.*` decision at `position`, for tests.
    ///
    /// # Errors
    /// [`StoreError`].
    #[cfg(feature = "testing")]
    pub async fn idp_decision_action(
        &mut self,
        position: i64,
    ) -> Result<Option<String>, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        Ok(sqlx::query_scalar!(
            "SELECT action FROM access.idp_config_log
              WHERE tenant_id = $1 AND realm_id = $2 AND decision_pos = $3",
            tenant,
            realm,
            position,
        )
        .fetch_optional(&mut *self.tx)
        .await?)
    }

    /// The setup link whose token hashes to `token_hash`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn setup_link(
        &mut self,
        token_hash: &[u8; 32],
    ) -> Result<Option<SetupLink>, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let row = sqlx::query!(
            r#"SELECT link_id, org_id, created_exercise, browser_hash,
                      expires_at <= clock_timestamp() AS "expired!",
                      finished_at IS NOT NULL AS "finished!",
                      (extract(epoch FROM expires_at) * 1000)::bigint AS "expires_ms!"
                 FROM access.org_setup_links
                WHERE tenant_id = $1 AND realm_id = $2 AND token_hash = $3"#,
            tenant,
            realm,
            token_hash.as_slice(),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        row.map(|r| {
            Ok(SetupLink {
                id: *r.link_id.as_bytes(),
                org: *r.org_id.as_bytes(),
                exercise: <[u8; 32]>::try_from(r.created_exercise)
                    .map_err(|_| StoreError::Corrupt)?,
                expired: r.expired,
                browser: r
                    .browser_hash
                    .map(<[u8; 32]>::try_from)
                    .transpose()
                    .map_err(|_| StoreError::Corrupt)?,
                finished: r.finished,
                expires_ms: r.expires_ms,
            })
        })
        .transpose()
    }

    /// Binds the unopened, unexpired setup link `link` to the browser whose secret hashes to
    /// `browser`, once.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn open_setup_link(
        &mut self,
        link: [u8; 16],
        browser: &[u8; 32],
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let done = sqlx::query!(
            "UPDATE access.org_setup_links SET browser_hash = $4, opened_at = clock_timestamp()
              WHERE tenant_id = $1 AND realm_id = $2 AND link_id = $3
                AND opened_at IS NULL AND expires_at > clock_timestamp()",
            tenant,
            realm,
            uuid(link),
            browser.as_slice(),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Finishes the opened setup link `link`, once.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn finish_setup_link(&mut self, link: [u8; 16]) -> Result<bool, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let done = sqlx::query!(
            "UPDATE access.org_setup_links SET finished_at = clock_timestamp()
              WHERE tenant_id = $1 AND realm_id = $2 AND link_id = $3
                AND opened_at IS NOT NULL AND finished_at IS NULL
                AND expires_at > clock_timestamp()",
            tenant,
            realm,
            uuid(link),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Records a connection draft (OP-153 m.3 (p), OP-155 m.3 (i)).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_connection_draft(
        &mut self,
        d: &NewDraft<'_>,
    ) -> Result<[u8; 16], StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let (protocol, issuer, client_id, entity_id, metadata_url) = match d.shape {
            DraftShape::Oidc { issuer, client_id } => {
                ("oidc", Some(issuer), Some(client_id), None, None)
            }
            DraftShape::Saml {
                entity_id,
                metadata_url,
            } => ("saml", None, None, Some(entity_id), Some(metadata_url)),
        };
        let id = sqlx::query_scalar!(
            r#"INSERT INTO access.org_sso_drafts
                 (tenant_id, realm_id, org_id, protocol, issuer, client_id, saml_entity_id,
                  saml_metadata_url, provider, drafted_by, created_exercise, setup_link)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING draft_id"#,
            tenant,
            realm,
            uuid(d.org),
            protocol,
            issuer,
            client_id,
            entity_id,
            metadata_url,
            d.provider,
            d.drafted_by.as_slice(),
            d.exercise.as_slice(),
            d.setup_link.map(uuid),
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(*id.as_bytes())
    }

    /// Binds SCIM client `client` as `org`'s SCIM source, committed by `exercise` (TN-95).
    ///
    /// # Errors
    /// [`StoreError`]; a client bound to an organization already is an integrity error.
    pub async fn bind_scim_source(
        &mut self,
        org: [u8; 16],
        client: &str,
        exercise: &[u8; 32],
    ) -> Result<(), StoreError> {
        let (tenant, realm) = self.org_scope()?;
        sqlx::query!(
            "INSERT INTO access.org_scim_sources
               (tenant_id, realm_id, org_id, client_name, created_exercise)
             VALUES ($1, $2, $3, $4, $5)",
            tenant,
            realm,
            uuid(org),
            client,
            exercise.as_slice(),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Ends the binding of SCIM client `client`, if any.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn end_scim_source(&mut self, client: &str) -> Result<bool, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let done = sqlx::query!(
            "UPDATE access.org_scim_sources SET ended_at = clock_timestamp()
              WHERE tenant_id = $1 AND realm_id = $2 AND client_name = $3 AND ended_at IS NULL",
            tenant,
            realm,
            client,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// The SCIM clients bound to `org` now.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn scim_sources(&mut self, org: [u8; 16]) -> Result<Vec<String>, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        Ok(sqlx::query_scalar!(
            "SELECT client_name FROM access.org_scim_sources
              WHERE tenant_id = $1 AND realm_id = $2 AND org_id = $3 AND ended_at IS NULL
              ORDER BY client_name",
            tenant,
            realm,
            uuid(org),
        )
        .fetch_all(&mut *self.tx)
        .await?)
    }

    /// The organization SCIM client `client` is bound to now.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn scim_source_org(&mut self, client: &str) -> Result<Option<[u8; 16]>, StoreError> {
        let (tenant, realm) = self.org_scope()?;
        let row = sqlx::query_scalar!(
            "SELECT org_id FROM access.org_scim_sources
              WHERE tenant_id = $1 AND realm_id = $2 AND client_name = $3 AND ended_at IS NULL",
            tenant,
            realm,
            client,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(row.map(|u| *u.as_bytes()))
    }
}
