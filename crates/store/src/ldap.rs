//! The LDAP credential class and the reads behind the read-only LDAP directory (§10.6.3, IDP-16,
//! OP-155 m.3 (n)). Credentials are revoked, never deleted (OP-73); the directory reads only
//! active accounts, live identifiers and active group memberships of the transaction's realm.

use sqlx::types::Uuid;

use crate::StoreError;
use crate::accounts::{StoredValue, stored};
use crate::identity::TenantTx;

fn scope(t: &TenantTx) -> Result<(Uuid, Uuid), StoreError> {
    let realm = t.realm().ok_or(StoreError::Range)?;
    Ok((
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*realm.as_bytes()),
    ))
}

/// One LDAP credential as the account surface lists it; never the secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LdapCredentialRow {
    /// Its id.
    pub id: [u8; 16],
    /// The application it was issued for.
    pub application: String,
    /// When it was issued, Unix ms.
    pub created_ms: i64,
    /// When it last bound, Unix ms.
    pub last_used_ms: Option<i64>,
    /// When its secret was last replaced (RFC 3062), Unix ms.
    pub rotated_ms: Option<i64>,
}

/// One active LDAP credential with its verifier.
#[derive(Clone)]
pub struct LdapVerifier {
    /// Its subject.
    pub subject: [u8; 16],
    /// The application it was issued for.
    pub application: String,
    /// The Argon2id PHC string.
    pub phc: String,
}

impl core::fmt::Debug for LdapVerifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LdapVerifier")
            .field("application", &self.application)
            .finish_non_exhaustive()
    }
}

/// A live login identifier of an active account, for the directory tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryIdentifier {
    /// The subject.
    pub subject: [u8; 16],
    /// `username` or `email`.
    pub kind: String,
    /// The stored value.
    pub stored: StoredValue,
}

/// An active group of the realm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryGroup {
    /// Its name.
    pub name: String,
    /// Its display name.
    pub display_name: String,
}

impl TenantTx {
    /// Stores a new active LDAP credential `id` of `subject` for `application`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_ldap_credential(
        &mut self,
        id: [u8; 16],
        subject: [u8; 16],
        application: &str,
        phc: &str,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.ldap_credentials
                    (tenant_id, realm_id, credential_id, subject_id, application, phc)
             VALUES ($1, $2, $3, $4, $5, $6)",
            tenant,
            realm,
            Uuid::from_bytes(id),
            Uuid::from_bytes(subject),
            application,
            phc,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The subject's active LDAP credentials, oldest first.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn ldap_credentials(
        &mut self,
        subject: [u8; 16],
    ) -> Result<Vec<LdapCredentialRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            r#"SELECT credential_id, application,
                      (extract(epoch FROM created_at) * 1000)::bigint AS "created_ms!",
                      (extract(epoch FROM last_used_at) * 1000)::bigint AS last_used_ms,
                      (extract(epoch FROM rotated_at) * 1000)::bigint AS rotated_ms
                 FROM access.ldap_credentials
                WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND status = 'active'
                ORDER BY created_at, credential_id"#,
            tenant,
            realm,
            Uuid::from_bytes(subject),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| LdapCredentialRow {
                id: *r.credential_id.as_bytes(),
                application: r.application,
                created_ms: r.created_ms,
                last_used_ms: r.last_used_ms,
                rotated_ms: r.rotated_ms,
            })
            .collect())
    }

    /// The active LDAP credential `id`, locked for this transaction; `None` when unknown or
    /// revoked.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn ldap_verifier(
        &mut self,
        id: [u8; 16],
    ) -> Result<Option<LdapVerifier>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let row = sqlx::query!(
            "SELECT subject_id, application, phc FROM access.ldap_credentials
              WHERE tenant_id = $1 AND realm_id = $2 AND credential_id = $3 AND status = 'active'
              FOR UPDATE",
            tenant,
            realm,
            Uuid::from_bytes(id),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(row.map(|r| LdapVerifier {
            subject: *r.subject_id.as_bytes(),
            application: r.application,
            phc: r.phc,
        }))
    }

    /// Revokes the subject's active LDAP credential `id`; its application when it was active.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn revoke_ldap_credential(
        &mut self,
        subject: [u8; 16],
        id: [u8; 16],
    ) -> Result<Option<String>, StoreError> {
        let (tenant, realm) = scope(self)?;
        Ok(sqlx::query_scalar!(
            "UPDATE access.ldap_credentials
                SET status = 'revoked', revoked_at = clock_timestamp()
              WHERE tenant_id = $1 AND realm_id = $2 AND credential_id = $3 AND subject_id = $4
                AND status = 'active'
             RETURNING application",
            tenant,
            realm,
            Uuid::from_bytes(id),
            Uuid::from_bytes(subject),
        )
        .fetch_optional(&mut *self.tx)
        .await?)
    }

    /// Replaces the active LDAP credential `id`'s verifier (RFC 3062); false when it is not
    /// active.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn rotate_ldap_credential(
        &mut self,
        id: [u8; 16],
        phc: &str,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let n = sqlx::query!(
            "UPDATE access.ldap_credentials SET phc = $4, rotated_at = clock_timestamp()
              WHERE tenant_id = $1 AND realm_id = $2 AND credential_id = $3 AND status = 'active'",
            tenant,
            realm,
            Uuid::from_bytes(id),
            phc,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Records that the LDAP credential `id` bound.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn ldap_credential_used(&mut self, id: [u8; 16]) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "UPDATE access.ldap_credentials SET last_used_at = clock_timestamp()
              WHERE tenant_id = $1 AND realm_id = $2 AND credential_id = $3 AND status = 'active'",
            tenant,
            realm,
            Uuid::from_bytes(id),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Whether the LDAP credential `id` of `subject` is active.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn ldap_credential_active(
        &mut self,
        subject: [u8; 16],
        id: [u8; 16],
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        Ok(sqlx::query_scalar!(
            r#"SELECT EXISTS (SELECT 1 FROM access.ldap_credentials
                  WHERE tenant_id = $1 AND realm_id = $2 AND credential_id = $3
                    AND subject_id = $4 AND status = 'active') AS "active!""#,
            tenant,
            realm,
            Uuid::from_bytes(id),
            Uuid::from_bytes(subject),
        )
        .fetch_one(&mut *self.tx)
        .await?)
    }

    /// The live username and e-mail identifiers of the realm's active accounts, at most `limit`
    /// accounts, by subject; `only` narrows them to one subject.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn directory_identifiers(
        &mut self,
        only: Option<[u8; 16]>,
        limit: i64,
    ) -> Result<Vec<DirectoryIdentifier>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            "WITH people AS (
               SELECT subject_id FROM access.identity_subjects
                WHERE tenant_id = $1 AND realm_id = $2 AND status = 'active'
                  AND ($3::uuid IS NULL OR subject_id = $3)
                ORDER BY subject_id LIMIT $4)
             SELECT i.subject_id, i.kind, i.value, i.value_index, i.pii_class, i.nonce, i.ciphertext
               FROM access.identity_identifiers i JOIN people p ON p.subject_id = i.subject_id
              WHERE i.tenant_id = $1 AND i.realm_id = $2 AND i.status = 'active'
                AND i.kind IN ('username', 'email')
              ORDER BY i.subject_id, i.identifier_id",
            tenant,
            realm,
            only.map(Uuid::from_bytes),
            limit,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(DirectoryIdentifier {
                    subject: *r.subject_id.as_bytes(),
                    kind: r.kind,
                    stored: stored(r.value, r.value_index, r.pii_class, r.nonce, r.ciphertext)?,
                })
            })
            .collect()
    }

    /// The realm's active groups by name.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn directory_groups(&mut self) -> Result<Vec<DirectoryGroup>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            "SELECT name, display_name FROM access.idp_groups
              WHERE tenant_id = $1 AND realm_id = $2 AND status = 'active' ORDER BY name",
            tenant,
            realm,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| DirectoryGroup {
                name: r.name,
                display_name: r.display_name,
            })
            .collect())
    }

    /// The active memberships of the realm's active groups: (group, subject).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn directory_members(&mut self) -> Result<Vec<(String, [u8; 16])>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            "SELECT m.group_name, m.subject_id FROM access.idp_group_members m
               JOIN access.idp_groups g ON g.tenant_id = m.tenant_id AND g.realm_id = m.realm_id
                AND g.name = m.group_name
              WHERE m.tenant_id = $1 AND m.realm_id = $2 AND m.status = 'active'
                AND g.status = 'active'
              ORDER BY m.group_name, m.subject_id",
            tenant,
            realm,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| (r.group_name, *r.subject_id.as_bytes()))
            .collect())
    }
}
