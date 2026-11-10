//! Certificate, PIV and CAC sign-in and the published mTLS aliases of a realm (OP-155 m.3 (m),
//! §10.2.5, §10.4.3): the decided settings, newest version first. Scoped to the transaction's
//! realm by row-level security; nothing is deleted (OP-73).

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

/// A realm's certificate sign-in setting.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CertificateLoginRow {
    /// Whether certificate sign-in is on.
    pub enabled: bool,
    /// How a certificate names the account: `san_email` or `san_upn`.
    pub rule: String,
    /// The CAs whose paths are accepted, DER certificates.
    pub anchors: Vec<Vec<u8>>,
    /// Issuer policy OIDs mapped as hardware-bound PIV, dotted.
    pub piv_policies: Vec<String>,
}

impl TenantTx {
    /// The realm's certificate sign-in setting; `None` until one was decided (off).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn certificate_login(&mut self) -> Result<Option<CertificateLoginRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let row = sqlx::query!(
            "SELECT enabled, rule, anchors, piv_policies FROM access.idp_certificate_login_settings
              WHERE tenant_id = $1 AND realm_id = $2 ORDER BY version DESC LIMIT 1",
            tenant,
            realm,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(row.map(|r| CertificateLoginRow {
            enabled: r.enabled,
            rule: r.rule,
            anchors: r.anchors,
            piv_policies: r.piv_policies,
        }))
    }

    /// Writes the next certificate sign-in setting under `bound` (`idp.realm.certificate_login`).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_certificate_login(
        &mut self,
        bound: &Bound,
        row: &CertificateLoginRow,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.idp_certificate_login_settings
               (tenant_id, realm_id, version, enabled, rule, anchors, piv_policies, domain_id,
                decision_pos)
             SELECT $1, $2,
                    COALESCE((SELECT max(version) FROM access.idp_certificate_login_settings
                               WHERE tenant_id = $1 AND realm_id = $2), 0) + 1,
                    $3, $4, $5, $6, $7, $8",
            tenant,
            realm,
            row.enabled,
            row.rule,
            &row.anchors,
            &row.piv_policies,
            bound.domain().as_bytes().as_slice(),
            i64_of(bound.position())?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// This realm's identity outbox payloads of `kind`, oldest first; for tests that read the
    /// Claims a sign-in queued.
    ///
    /// # Errors
    /// [`StoreError`].
    #[cfg(feature = "testing")]
    pub async fn outbox_payloads(&mut self, kind: &str) -> Result<Vec<Vec<u8>>, StoreError> {
        let (tenant, realm) = scope(self)?;
        Ok(sqlx::query_scalar!(
            "SELECT payload FROM access.identity_outbox
              WHERE tenant_id = $1 AND realm_id = $2 AND kind = $3 ORDER BY id",
            tenant,
            realm,
            kind,
        )
        .fetch_all(&mut *self.tx)
        .await?)
    }

    /// Whether the realm publishes `mtls_endpoint_aliases`; off until decided.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn mtls_aliases(&mut self) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        Ok(sqlx::query_scalar!(
            "SELECT published FROM access.idp_mtls_alias_settings
              WHERE tenant_id = $1 AND realm_id = $2 ORDER BY version DESC LIMIT 1",
            tenant,
            realm,
        )
        .fetch_optional(&mut *self.tx)
        .await?
        .unwrap_or(false))
    }

    /// Writes the next alias setting under `bound` (`idp.realm.mtls_aliases`).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_mtls_aliases(
        &mut self,
        bound: &Bound,
        published: bool,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.idp_mtls_alias_settings
               (tenant_id, realm_id, version, published, domain_id, decision_pos)
             SELECT $1, $2,
                    COALESCE((SELECT max(version) FROM access.idp_mtls_alias_settings
                               WHERE tenant_id = $1 AND realm_id = $2), 0) + 1,
                    $3, $4, $5",
            tenant,
            realm,
            published,
            bound.domain().as_bytes().as_slice(),
            i64_of(bound.position())?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }
}
