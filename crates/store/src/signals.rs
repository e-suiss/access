//! The realm's signal sources (OP-156 m.3 (r)): each a Claim issuer of KYC, MDM, risk or DLP
//! signals, written under its `idp.signal.*` decision. A retired name is never reused and
//! nothing is deleted (OP-73).

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

fn unsigned(n: i64) -> Result<u64, StoreError> {
    u64::try_from(n).map_err(|_| StoreError::Corrupt)
}

/// One version of a signal source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignalSourceRow {
    /// Its name.
    pub name: String,
    /// Whether it is live.
    pub live: bool,
    /// `kyc`, `mdm`, `risk` or `dlp`.
    pub kind: String,
    /// The provider's display name.
    pub provider: String,
    /// The issuer Party its Claims are signed as.
    pub issuer: [u8; 16],
    /// The vendor format its answers arrive in.
    pub format: String,
    /// The SSF transmitter it is heard through, when it has one.
    pub transmitter: Option<String>,
    /// How often it is expected to be heard from, seconds.
    pub expected_interval_s: u32,
    /// Its version.
    pub version: u64,
    /// The position of the decision that wrote it.
    pub position: u64,
    /// When the source was first registered, Unix ms.
    pub created_ms: u64,
}

/// What a new version of a signal source says.
#[derive(Clone, Copy, Debug)]
pub struct NewSignalSource<'a> {
    /// Its name.
    pub name: &'a str,
    /// Whether it is live.
    pub live: bool,
    /// Its kind.
    pub kind: &'a str,
    /// Its provider.
    pub provider: &'a str,
    /// Its issuer Party.
    pub issuer: &'a [u8; 16],
    /// Its format.
    pub format: &'a str,
    /// Its SSF transmitter.
    pub transmitter: Option<&'a str>,
    /// Its expected interval, seconds.
    pub expected_interval_s: u32,
}

impl TenantTx {
    /// Writes the next version of signal source `s.name` under `bound`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_signal_source(
        &mut self,
        bound: &Bound,
        s: &NewSignalSource<'_>,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        let interval = i32::try_from(s.expected_interval_s).map_err(|_| StoreError::Range)?;
        sqlx::query!(
            "INSERT INTO access.signal_sources (tenant_id, realm_id, name, version, state, kind,
                    provider, issuer, format, transmitter, expected_interval_s, domain_id,
                    decision_pos)
             SELECT $1, $2, $3, COALESCE(MAX(version), 0) + 1, $4, $5, $6, $7, $8, $9, $10, $11,
                    $12
               FROM access.signal_sources
              WHERE tenant_id = $1 AND realm_id = $2 AND name = $3",
            tenant,
            realm,
            s.name,
            if s.live { "live" } else { "retired" },
            s.kind,
            s.provider,
            s.issuer.as_slice(),
            s.format,
            s.transmitter,
            interval,
            bound.domain().as_bytes().as_slice(),
            bound.raw_position(),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The newest version of every signal source, live and retired, by name, each with the
    /// time its name was first registered.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn signal_sources(&mut self) -> Result<Vec<SignalSourceRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            r#"SELECT DISTINCT ON (s.name) s.name, s.state, s.kind, s.provider, s.issuer, s.format,
                      s.transmitter, s.expected_interval_s, s.version, s.decision_pos,
                      (SELECT (EXTRACT(EPOCH FROM MIN(f.created_at)) * 1000)::bigint
                         FROM access.signal_sources f
                        WHERE f.tenant_id = s.tenant_id AND f.realm_id = s.realm_id
                          AND f.name = s.name) AS "created_ms!"
                 FROM access.signal_sources s
                WHERE s.tenant_id = $1 AND s.realm_id = $2
                ORDER BY s.name, s.version DESC"#,
            tenant,
            realm,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(SignalSourceRow {
                    name: r.name,
                    live: r.state == "live",
                    kind: r.kind,
                    provider: r.provider,
                    issuer: <[u8; 16]>::try_from(r.issuer.as_slice())
                        .map_err(|_| StoreError::Corrupt)?,
                    format: r.format,
                    transmitter: r.transmitter,
                    expected_interval_s: u32::try_from(r.expected_interval_s)
                        .map_err(|_| StoreError::Corrupt)?,
                    version: unsigned(r.version)?,
                    position: unsigned(r.decision_pos)?,
                    created_ms: unsigned(r.created_ms)?,
                })
            })
            .collect()
    }
}
