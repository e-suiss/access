//! The SSH certificate authority's rows (OP-156 m.3 (o), IDP-32): the CA changes under
//! `idp.ssh.*` decisions, the phases of the CA keys, the server groups, issued certificates and
//! their revocations. Nothing is deleted (OP-73).

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

fn key32(b: &[u8]) -> Result<[u8; 32], StoreError> {
    <[u8; 32]>::try_from(b).map_err(|_| StoreError::Corrupt)
}

fn unsigned(n: i64) -> Result<u64, StoreError> {
    u64::try_from(n).map_err(|_| StoreError::Corrupt)
}

fn signed(n: u64) -> Result<i64, StoreError> {
    i64::try_from(n).map_err(|_| StoreError::Range)
}

/// The serial as stored: the u64 bit for bit.
const fn serial_in(s: u64) -> i64 {
    i64::from_be_bytes(s.to_be_bytes())
}

/// The serial as drawn.
const fn serial_out(s: i64) -> u64 {
    u64::from_be_bytes(s.to_be_bytes())
}

/// The newest CA change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaChange {
    /// Its version.
    pub version: u64,
    /// `enable`, `disable`, `rotate` or `emergency`.
    pub change: String,
    /// The position of the decision that wrote it.
    pub position: u64,
}

/// The newest phase of one CA key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaKeyRow {
    /// The Ed25519 public key.
    pub public_key: [u8; 32],
    /// `published`, `active`, `retiring`, `removed` or `revoked`.
    pub phase: String,
    /// When it entered the phase, ms.
    pub since_ms: u64,
    /// The CA change it carries out.
    pub change_version: u64,
}

/// The newest version of one server group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostGroupRow {
    /// Its name.
    pub name: String,
    /// Whether it is live.
    pub live: bool,
    /// Its description.
    pub description: String,
    /// Its version.
    pub version: u64,
    /// The position of the decision that wrote it.
    pub position: u64,
}

/// An issued certificate to record.
pub struct NewCertificate<'a> {
    /// The CA key that signed it.
    pub ca_key: [u8; 32],
    /// Its serial, never 0.
    pub serial: u64,
    /// Its key identifier.
    pub key_id: &'a str,
    /// The governing domain.
    pub domain: [u8; 32],
    /// The `projection.issue` `ExerciseID`.
    pub exercise: [u8; 32],
    /// The position of its decision.
    pub position: u64,
    /// The intent it was allowed for, deterministic CBOR.
    pub intent: &'a [u8],
    /// `person` or `agent`.
    pub holder: &'a str,
    /// The holder's Party.
    pub party: [u8; 16],
    /// The server group.
    pub host_group: &'a str,
    /// The principals.
    pub principals: &'a [String],
    /// The holder's key.
    pub public_key: [u8; 32],
    /// Unix seconds.
    pub valid_after: u64,
    /// Unix seconds.
    pub valid_before: u64,
    /// When it was issued, ms.
    pub issued_ms: u64,
}

/// An issued certificate as recorded, with its revocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateRow {
    /// The CA key that signed it.
    pub ca_key: [u8; 32],
    /// Its serial.
    pub serial: u64,
    /// Its key identifier.
    pub key_id: String,
    /// The governing domain.
    pub domain: [u8; 32],
    /// The `projection.issue` `ExerciseID`.
    pub exercise: [u8; 32],
    /// The intent it was allowed for.
    pub intent: Vec<u8>,
    /// `person` or `agent`.
    pub holder: String,
    /// The holder's Party.
    pub party: [u8; 16],
    /// The server group.
    pub host_group: String,
    /// The principals.
    pub principals: Vec<String>,
    /// Unix seconds.
    pub valid_after: u64,
    /// Unix seconds.
    pub valid_before: u64,
    /// When it was issued, ms.
    pub issued_ms: u64,
    /// Why and when it was revoked.
    pub revoked: Option<(String, u64)>,
}

impl TenantTx {
    /// Serialises the realm's CA work until this transaction ends (one reconciliation at a
    /// time across the cell).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn lock_ssh_ca(&mut self) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        let name = format!("access/ssh-ca/{tenant}/{realm}");
        sqlx::query!(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            name
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Writes the next CA change under `bound`; returns its version.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_ssh_ca_change(
        &mut self,
        bound: &Bound,
        change: &str,
    ) -> Result<u64, StoreError> {
        let (tenant, realm) = scope(self)?;
        let v = sqlx::query_scalar!(
            "INSERT INTO access.ssh_ca_changes (tenant_id, realm_id, version, change, domain_id,
                    decision_pos)
             SELECT $1, $2, COALESCE(MAX(version), 0) + 1, $3, $4, $5
               FROM access.ssh_ca_changes
              WHERE tenant_id = $1 AND realm_id = $2
             RETURNING version",
            tenant,
            realm,
            change,
            bound.domain().as_bytes().as_slice(),
            bound.raw_position(),
        )
        .fetch_one(&mut *self.tx)
        .await?;
        unsigned(v)
    }

    /// The newest CA change, if the CA was ever turned on.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn ssh_ca_change(&mut self) -> Result<Option<CaChange>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let row = sqlx::query!(
            "SELECT version, change, decision_pos FROM access.ssh_ca_changes
              WHERE tenant_id = $1 AND realm_id = $2
              ORDER BY version DESC LIMIT 1",
            tenant,
            realm,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        row.map(|r| {
            Ok(CaChange {
                version: unsigned(r.version)?,
                change: r.change,
                position: unsigned(r.decision_pos)?,
            })
        })
        .transpose()
    }

    /// The newest phase of every CA key the realm ever had.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn ssh_ca_keys(&mut self) -> Result<Vec<CaKeyRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            "SELECT DISTINCT ON (public_key) public_key, phase, since_ms, change_version
               FROM access.ssh_ca_keys
              WHERE tenant_id = $1 AND realm_id = $2
              ORDER BY public_key, version DESC",
            tenant,
            realm,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(CaKeyRow {
                    public_key: key32(&r.public_key)?,
                    phase: r.phase,
                    since_ms: unsigned(r.since_ms)?,
                    change_version: unsigned(r.change_version)?,
                })
            })
            .collect()
    }

    /// Records that CA key `key` entered `phase` at `since_ms`, carrying out change
    /// `change_version`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_ssh_ca_key(
        &mut self,
        key: &[u8; 32],
        phase: &str,
        since_ms: u64,
        change_version: u64,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.ssh_ca_keys (tenant_id, realm_id, public_key, version, phase,
                    since_ms, change_version)
             SELECT $1, $2, $3, COALESCE(MAX(version), 0) + 1, $4, $5, $6
               FROM access.ssh_ca_keys
              WHERE tenant_id = $1 AND realm_id = $2 AND public_key = $3",
            tenant,
            realm,
            key.as_slice(),
            phase,
            signed(since_ms)?,
            signed(change_version)?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The newest CA change any key row carries out; 0 when none was carried out yet.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn ssh_ca_applied(&mut self) -> Result<u64, StoreError> {
        let (tenant, realm) = scope(self)?;
        let v = sqlx::query_scalar!(
            "SELECT MAX(change_version) FROM access.ssh_ca_keys
              WHERE tenant_id = $1 AND realm_id = $2",
            tenant,
            realm,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        v.map_or(Ok(0), unsigned)
    }

    /// Writes the next version of server group `name` under `bound`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_ssh_host_group(
        &mut self,
        bound: &Bound,
        name: &str,
        live: bool,
        description: &str,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.ssh_host_groups (tenant_id, realm_id, name, version, state,
                    description, domain_id, decision_pos)
             SELECT $1, $2, $3, COALESCE(MAX(version), 0) + 1, $4, $5, $6, $7
               FROM access.ssh_host_groups
              WHERE tenant_id = $1 AND realm_id = $2 AND name = $3",
            tenant,
            realm,
            name,
            if live { "live" } else { "retired" },
            description,
            bound.domain().as_bytes().as_slice(),
            bound.raw_position(),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The newest version of every server group, live and retired, by name.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn ssh_host_groups(&mut self) -> Result<Vec<HostGroupRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            "SELECT DISTINCT ON (name) name, state, description, version, decision_pos
               FROM access.ssh_host_groups
              WHERE tenant_id = $1 AND realm_id = $2
              ORDER BY name, version DESC",
            tenant,
            realm,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(HostGroupRow {
                    name: r.name,
                    live: r.state == "live",
                    description: r.description,
                    version: unsigned(r.version)?,
                    position: unsigned(r.decision_pos)?,
                })
            })
            .collect()
    }

    /// Records an issued certificate.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_ssh_certificate(
        &mut self,
        c: &NewCertificate<'_>,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.ssh_certificates (tenant_id, realm_id, ca_key, serial, key_id,
                    domain_id, exercise, decision_pos, intent, holder, party, host_group,
                    principals, public_key, valid_after, valid_before, issued_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)",
            tenant,
            realm,
            c.ca_key.as_slice(),
            serial_in(c.serial),
            c.key_id,
            c.domain.as_slice(),
            c.exercise.as_slice(),
            signed(c.position)?,
            c.intent,
            c.holder,
            c.party.as_slice(),
            c.host_group,
            c.principals,
            c.public_key.as_slice(),
            signed(c.valid_after)?,
            signed(c.valid_before)?,
            signed(c.issued_ms)?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The certificates still valid after `now_s` (Unix seconds), newest first, at most
    /// `limit`, with their revocations.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn ssh_certificates(
        &mut self,
        now_s: u64,
        limit: u32,
    ) -> Result<Vec<CertificateRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            r#"SELECT c.ca_key, c.serial, c.key_id, c.domain_id, c.exercise, c.intent, c.holder,
                      c.party, c.host_group, c.principals, c.valid_after, c.valid_before,
                      c.issued_ms, r.reason AS "reason?", r.revoked_ms AS "revoked_ms?"
                 FROM access.ssh_certificates c
                 LEFT JOIN access.ssh_revocations r
                   ON r.tenant_id = c.tenant_id AND r.realm_id = c.realm_id
                  AND r.ca_key = c.ca_key AND r.serial = c.serial
                WHERE c.tenant_id = $1 AND c.realm_id = $2 AND c.valid_before > $3
                ORDER BY c.issued_ms DESC LIMIT $4"#,
            tenant,
            realm,
            signed(now_s)?,
            i64::from(limit),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(CertificateRow {
                    ca_key: key32(&r.ca_key)?,
                    serial: serial_out(r.serial),
                    key_id: r.key_id,
                    domain: key32(&r.domain_id)?,
                    exercise: key32(&r.exercise)?,
                    intent: r.intent,
                    holder: r.holder,
                    party: <[u8; 16]>::try_from(r.party.as_slice())
                        .map_err(|_| StoreError::Corrupt)?,
                    host_group: r.host_group,
                    principals: r.principals,
                    valid_after: unsigned(r.valid_after)?,
                    valid_before: unsigned(r.valid_before)?,
                    issued_ms: unsigned(r.issued_ms)?,
                    revoked: match (r.reason, r.revoked_ms) {
                        (Some(reason), Some(at)) => Some((reason, unsigned(at)?)),
                        _ => None,
                    },
                })
            })
            .collect()
    }

    /// Revokes certificate `serial` of `ca_key` for `reason`; `false` when it already was.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn revoke_ssh_certificate(
        &mut self,
        ca_key: &[u8; 32],
        serial: u64,
        reason: &str,
        now_ms: u64,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let n = sqlx::query!(
            "INSERT INTO access.ssh_revocations (tenant_id, realm_id, ca_key, serial, reason,
                    revoked_ms)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT DO NOTHING",
            tenant,
            realm,
            ca_key.as_slice(),
            serial_in(serial),
            reason,
            signed(now_ms)?,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// How many revocations and key phases the realm ever recorded: the KRL version, which
    /// only grows.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn ssh_krl_version(&mut self) -> Result<u64, StoreError> {
        let (tenant, realm) = scope(self)?;
        let n = sqlx::query_scalar!(
            r#"SELECT ((SELECT COUNT(*) FROM access.ssh_revocations
                          WHERE tenant_id = $1 AND realm_id = $2)
                     + (SELECT COUNT(*) FROM access.ssh_ca_keys
                          WHERE tenant_id = $1 AND realm_id = $2)) AS "n!""#,
            tenant,
            realm,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        unsigned(n)
    }
}

#[cfg(test)]
mod tests {
    use super::{serial_in, serial_out};

    #[test]
    fn serials_are_stored_bit_for_bit() {
        for s in [1, u64::MAX, 1 << 63, 42] {
            assert_eq!(serial_out(serial_in(s)), s);
        }
    }
}
