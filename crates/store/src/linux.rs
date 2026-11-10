//! The Linux client's rows (OP-156 m.3 (p), IDP-32): the realm's hosts under `idp.linux.*`
//! decisions and the NSS ids handed to its Linux users and groups. Nothing is deleted (OP-73).

use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::TenantTx;
use crate::idp::Bound;

/// The first NSS id a realm hands out, above every local account.
pub const FIRST_ID: u32 = 200_000;

fn scope(t: &TenantTx) -> Result<(Uuid, Uuid), StoreError> {
    let realm = t.realm().ok_or(StoreError::Range)?;
    Ok((
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*realm.as_bytes()),
    ))
}

fn unsigned(n: i64) -> Result<u64, StoreError> {
    u64::try_from(n).map_err(|_| StoreError::Corrupt)
}

fn signed(n: u64) -> Result<i64, StoreError> {
    i64::try_from(n).map_err(|_| StoreError::Range)
}

/// The newest version of one host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinuxHostRow {
    /// Its name.
    pub name: String,
    /// Whether it is live.
    pub live: bool,
    /// The server group whose `ssh.login` Grants sign in to it.
    pub host_group: String,
    /// The `x5t#S256` of its client certificate.
    pub certificate: String,
    /// How long its NSS data is served offline, seconds (≤ 12 h).
    pub nss_ttl_s: u64,
    /// How long a console sign-in is reused offline, seconds (≤ 8 h).
    pub console_ttl_s: u64,
    /// The consequence tier of `sudo`: 2 or 3.
    pub sudo_ct: u8,
    /// Its users' login shell.
    pub shell: String,
    /// Whether local break-glass is allowed.
    pub break_glass: bool,
    /// Its version.
    pub version: u64,
    /// The position of the decision that wrote it.
    pub position: u64,
}

impl TenantTx {
    /// Writes a new version of host `h` under `bound`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_linux_host(
        &mut self,
        bound: &Bound,
        h: &LinuxHostRow,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.linux_hosts (tenant_id, realm_id, name, version, state, host_group,
                    certificate, nss_ttl_s, console_ttl_s, sudo_ct, shell, break_glass, domain_id,
                    decision_pos)
             SELECT $1, $2, $3, COALESCE(MAX(version), 0) + 1, $4, $5, $6, $7, $8, $9, $10, $11,
                    $12, $13
               FROM access.linux_hosts
              WHERE tenant_id = $1 AND realm_id = $2 AND name = $3",
            tenant,
            realm,
            h.name,
            if h.live { "live" } else { "retired" },
            h.host_group,
            h.certificate,
            signed(h.nss_ttl_s)?,
            signed(h.console_ttl_s)?,
            i16::from(h.sudo_ct),
            h.shell,
            h.break_glass,
            bound.domain().as_bytes().as_slice(),
            bound.raw_position(),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The newest version of every host, live and retired, by name.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn linux_hosts(&mut self) -> Result<Vec<LinuxHostRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            "SELECT DISTINCT ON (name) name, state, host_group, certificate, nss_ttl_s,
                    console_ttl_s, sudo_ct, shell, break_glass, version, decision_pos
               FROM access.linux_hosts
              WHERE tenant_id = $1 AND realm_id = $2
              ORDER BY name, version DESC",
            tenant,
            realm,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(LinuxHostRow {
                    name: r.name,
                    live: r.state == "live",
                    host_group: r.host_group,
                    certificate: r.certificate,
                    nss_ttl_s: unsigned(r.nss_ttl_s)?,
                    console_ttl_s: unsigned(r.console_ttl_s)?,
                    sudo_ct: u8::try_from(r.sudo_ct).map_err(|_| StoreError::Corrupt)?,
                    shell: r.shell,
                    break_glass: r.break_glass,
                    version: unsigned(r.version)?,
                    position: unsigned(r.decision_pos)?,
                })
            })
            .collect()
    }

    /// The live host whose client certificate is `certificate`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn linux_host_by_certificate(
        &mut self,
        certificate: &str,
    ) -> Result<Option<LinuxHostRow>, StoreError> {
        Ok(self
            .linux_hosts()
            .await?
            .into_iter()
            .find(|h| h.live && h.certificate == certificate))
    }

    /// The NSS id of the `kind` (`user` or `group`) named `name`, handed out now if it has none:
    /// one above the realm's highest, from [`FIRST_ID`]. `None` when a concurrent writer took
    /// the id; the caller asks again.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn linux_id(&mut self, kind: &str, name: &str) -> Result<Option<u32>, StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.linux_ids (tenant_id, realm_id, kind, name, id)
             SELECT $1, $2, $3, $4, GREATEST(COALESCE(MAX(id) + 1, $5), $5)
               FROM access.linux_ids
              WHERE tenant_id = $1 AND realm_id = $2
             ON CONFLICT DO NOTHING",
            tenant,
            realm,
            kind,
            name,
            i64::from(FIRST_ID),
        )
        .execute(&mut *self.tx)
        .await?;
        let id = sqlx::query_scalar!(
            "SELECT id FROM access.linux_ids
              WHERE tenant_id = $1 AND realm_id = $2 AND kind = $3 AND name = $4",
            tenant,
            realm,
            kind,
            name,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        id.map(|i| u32::try_from(i).map_err(|_| StoreError::Corrupt))
            .transpose()
    }
}
