//! SSF beyond delivery (OP-151 m.3 (k), (l); TN-39…TN-43; E30): a stream's profile and
//! algorithm, the reads the identity plane's CAEP and RISC SETs need, the inbound transmitters
//! of a realm with their delay state, the SETs taken from them by `jti`, the upstream subject
//! links, and receiver acknowledgements. Nothing is deleted (OP-73).

use sqlx::types::Uuid;

use crate::StoreError;
use crate::events::SealedKey;
use crate::identity::{RealmId, TenantTx};
use crate::idp::Bound;

fn uuid(b: &[u8; 16]) -> Uuid {
    Uuid::from_bytes(*b)
}

fn scope(t: &TenantTx) -> Result<(Uuid, Uuid), StoreError> {
    let realm = t.realm().ok_or(StoreError::Range)?;
    Ok((uuid(t.tenant.as_bytes()), uuid(realm.as_bytes())))
}

fn ms(t: Option<i64>) -> Option<u64> {
    t.and_then(|t| u64::try_from(t).ok())
}

fn signed(ms: u64) -> Result<i64, StoreError> {
    i64::try_from(ms).map_err(|_| StoreError::Range)
}

/// A stream's SSF profile and algorithm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamProfile {
    /// The stream.
    pub subscription: [u8; 16],
    /// `access`, `caep` or `both`.
    pub profile: String,
    /// The JOSE `alg` its SETs are signed with.
    pub alg: String,
}

/// A transmitter a realm takes SETs from, as `idp.upstream.register` declared it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransmitterRow {
    /// Its id, the `{stream}` of the inbound push path.
    pub id: [u8; 16],
    /// The SET `iss` it signs with.
    pub issuer: String,
    /// Where its keys are published.
    pub jwks_uri: String,
    /// The `aud` its SETs must name.
    pub audience: String,
    /// The standard event type URIs it may send.
    pub events: Vec<String>,
    /// `push` (RFC 8935) or `poll` (RFC 8936).
    pub delivery: String,
    /// The poll endpoint of a `poll` transmitter.
    pub poll_endpoint: Option<String>,
    /// The poll credential, sealed under the realm KEK.
    pub secret: Option<SealedKey>,
    /// How often it is expected to be heard from, seconds.
    pub expected_interval_s: u32,
    /// The `ExerciseID` that declared it.
    pub exercise: Option<[u8; 32]>,
    /// When it was last heard from, Unix ms.
    pub last_seen_ms: Option<u64>,
    /// When it was declared, Unix ms.
    pub created_ms: u64,
    /// Whether it has ended.
    pub disabled: bool,
}

struct RawTransmitter {
    transmitter_id: Uuid,
    issuer: String,
    jwks_uri: String,
    audience: String,
    events: Vec<String>,
    delivery: String,
    poll_endpoint: Option<String>,
    secret_kek_id: Option<String>,
    secret_wrapped_dek: Option<Vec<u8>>,
    secret_nonce: Option<Vec<u8>>,
    secret_ciphertext: Option<Vec<u8>>,
    expected_interval_s: i32,
    exercise: Option<Vec<u8>>,
    last_seen_ms: Option<i64>,
    created_ms: Option<i64>,
    disabled: bool,
}

impl RawTransmitter {
    fn row(self) -> Result<TransmitterRow, StoreError> {
        let secret = match (
            self.secret_kek_id,
            self.secret_wrapped_dek,
            self.secret_nonce,
            self.secret_ciphertext,
        ) {
            (Some(kek_id), Some(wrapped_dek), Some(nonce), Some(ciphertext)) => Some(SealedKey {
                kek_id,
                wrapped_dek,
                nonce: <[u8; 12]>::try_from(nonce.as_slice()).map_err(|_| StoreError::Corrupt)?,
                ciphertext,
            }),
            (None, None, None, None) => None,
            _ => return Err(StoreError::Corrupt),
        };
        Ok(TransmitterRow {
            id: *self.transmitter_id.as_bytes(),
            issuer: self.issuer,
            jwks_uri: self.jwks_uri,
            audience: self.audience,
            events: self.events,
            delivery: self.delivery,
            poll_endpoint: self.poll_endpoint,
            secret,
            expected_interval_s: u32::try_from(self.expected_interval_s)
                .map_err(|_| StoreError::Corrupt)?,
            exercise: self
                .exercise
                .map(|e| <[u8; 32]>::try_from(e.as_slice()).map_err(|_| StoreError::Corrupt))
                .transpose()?,
            last_seen_ms: ms(self.last_seen_ms),
            created_ms: ms(self.created_ms).unwrap_or(0),
            disabled: self.disabled,
        })
    }
}

/// Receiver acknowledgement counts of a realm's streams (E30), for the staleness exposure view.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AckCounts {
    /// Deliveries a receiver took (push `2xx` or poll ack).
    pub delivered: u64,
    /// Semantic acks: applied.
    pub applied: u64,
    /// Semantic acks: ignored.
    pub ignored: u64,
    /// Authority-state acks.
    pub authority_state: u64,
}

fn count(n: Option<i64>) -> u64 {
    n.and_then(|n| u64::try_from(n).ok()).unwrap_or(0)
}

impl TenantTx {
    /// Records the profile and algorithm of a new stream of this realm.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn set_stream_profile(&mut self, p: &StreamProfile) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.event_subscription_ssf (tenant_id, realm_id, subscription_id, profile, alg)
             VALUES ($1, $2, $3, $4, $5)",
            tenant,
            realm,
            uuid(&p.subscription),
            p.profile,
            p.alg,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The profiles of the streams of `realm` that have one.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn stream_profiles(
        &mut self,
        realm: RealmId,
    ) -> Result<Vec<StreamProfile>, StoreError> {
        let rows = sqlx::query!(
            "SELECT subscription_id, profile, alg FROM access.event_subscription_ssf
              WHERE tenant_id = $1 AND realm_id = $2",
            uuid(self.tenant.as_bytes()),
            uuid(realm.as_bytes()),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| StreamProfile {
                subscription: *r.subscription_id.as_bytes(),
                profile: r.profile,
                alg: r.alg,
            })
            .collect())
    }

    /// The pairwise `sub` the subject already has at the client `client_uuid`; never creates
    /// one, so a receiver learns of a subject only through a `sub` it was given (MD-10).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn existing_pairwise(
        &mut self,
        subject: [u8; 16],
        client_uuid: [u8; 16],
    ) -> Result<Option<String>, StoreError> {
        let (tenant, realm) = scope(self)?;
        Ok(sqlx::query_scalar!(
            "SELECT value FROM access.pairwise_subjects
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND sector = $4",
            tenant,
            realm,
            uuid(&subject),
            uuid(&client_uuid),
        )
        .fetch_optional(&mut *self.tx)
        .await?)
    }

    /// The subject whose device key is the Instance `instance`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn device_subject(
        &mut self,
        instance: &[u8; 16],
    ) -> Result<Option<[u8; 16]>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let row = sqlx::query_scalar!(
            "SELECT subject_id FROM access.device_keys
              WHERE tenant_id = $1 AND realm_id = $2 AND instance_id = $3
              ORDER BY created_at LIMIT 1",
            tenant,
            realm,
            instance.as_slice(),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(row.map(|s| *s.as_bytes()))
    }

    /// The subjects of the realm with a live grant.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn granted_subjects(&mut self) -> Result<Vec<[u8; 16]>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query_scalar!(
            "SELECT DISTINCT subject_id FROM access.oauth_grants
              WHERE tenant_id = $1 AND realm_id = $2 AND revoked_ms IS NULL
                AND expires_ms > (extract(epoch FROM clock_timestamp()) * 1000)::bigint
              ORDER BY subject_id",
            tenant,
            realm,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(rows.into_iter().map(|s| *s.as_bytes()).collect())
    }

    /// The live grants of clients that registered a back-channel logout endpoint (CR-27).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn backchannel_grants(&mut self) -> Result<Vec<Uuid>, StoreError> {
        let (tenant, realm) = scope(self)?;
        Ok(sqlx::query_scalar!(
            "SELECT g.grant_id FROM access.oauth_grants g
               JOIN access.idp_clients c
                 ON c.tenant_id = g.tenant_id AND c.realm_id = g.realm_id AND c.client_uuid = g.client_uuid
              WHERE g.tenant_id = $1 AND g.realm_id = $2 AND g.revoked_ms IS NULL
                AND c.backchannel_logout_uri IS NOT NULL
              ORDER BY g.grant_id",
            tenant,
            realm,
        )
        .fetch_all(&mut *self.tx)
        .await?)
    }

    /// Declares an inbound transmitter of this realm under the `idp.upstream.register` decision
    /// `bound` (EI-25, MD-14).
    ///
    /// # Errors
    /// [`StoreError`]; a second live transmitter with the same issuer is a unique violation, and
    /// a decision of another action is refused by the database.
    pub async fn register_transmitter(
        &mut self,
        bound: &Bound,
        t: &TransmitterRow,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.ssf_transmitter
                (tenant_id, realm_id, transmitter_id, issuer, jwks_uri, audience, events, delivery,
                 poll_endpoint, secret_kek_id, secret_wrapped_dek, secret_nonce, secret_ciphertext,
                 expected_interval_s, exercise, domain_id, decision_pos)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)",
            tenant,
            realm,
            uuid(&t.id),
            t.issuer,
            t.jwks_uri,
            t.audience,
            &t.events,
            t.delivery,
            t.poll_endpoint,
            t.secret.as_ref().map(|k| k.kek_id.clone()),
            t.secret.as_ref().map(|k| k.wrapped_dek.clone()),
            t.secret.as_ref().map(|k| k.nonce.to_vec()),
            t.secret.as_ref().map(|k| k.ciphertext.clone()),
            i32::try_from(t.expected_interval_s).map_err(|_| StoreError::Range)?,
            t.exercise.map(|e| e.to_vec()),
            bound.domain().as_bytes().as_slice(),
            bound.raw_position(),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Ends a transmitter under the `idp.upstream.retire` decision `bound` (EI-25, OP-73:
    /// nothing is deleted); false when it was not live.
    ///
    /// # Errors
    /// [`StoreError`]; a decision of another action is refused by the database.
    pub async fn disable_transmitter(
        &mut self,
        bound: &Bound,
        id: [u8; 16],
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let n = sqlx::query!(
            "UPDATE access.ssf_transmitter SET disabled_at = now(), domain_id = $4, decision_pos = $5
              WHERE tenant_id = $1 AND realm_id = $2 AND transmitter_id = $3 AND disabled_at IS NULL",
            tenant,
            realm,
            uuid(&id),
            bound.domain().as_bytes().as_slice(),
            bound.raw_position(),
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// The transmitters of this realm, live first.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn transmitters(&mut self) -> Result<Vec<TransmitterRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let raws = sqlx::query_as!(
            RawTransmitter,
            r#"SELECT transmitter_id, issuer, jwks_uri, audience, events, delivery, poll_endpoint,
                      secret_kek_id, secret_wrapped_dek, secret_nonce, secret_ciphertext,
                      expected_interval_s, exercise,
                      (extract(epoch FROM last_seen_at) * 1000)::bigint AS last_seen_ms,
                      (extract(epoch FROM created_at) * 1000)::bigint AS created_ms,
                      disabled_at IS NOT NULL AS "disabled!"
                 FROM access.ssf_transmitter WHERE tenant_id = $1 AND realm_id = $2
                ORDER BY disabled_at IS NOT NULL, created_at"#,
            tenant,
            realm,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        raws.into_iter().map(RawTransmitter::row).collect()
    }

    /// The transmitter `id` of this realm, ended or not.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn transmitter(
        &mut self,
        id: [u8; 16],
    ) -> Result<Option<TransmitterRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let raw = sqlx::query_as!(
            RawTransmitter,
            r#"SELECT transmitter_id, issuer, jwks_uri, audience, events, delivery, poll_endpoint,
                      secret_kek_id, secret_wrapped_dek, secret_nonce, secret_ciphertext,
                      expected_interval_s, exercise,
                      (extract(epoch FROM last_seen_at) * 1000)::bigint AS last_seen_ms,
                      (extract(epoch FROM created_at) * 1000)::bigint AS created_ms,
                      disabled_at IS NOT NULL AS "disabled!"
                 FROM access.ssf_transmitter
                WHERE tenant_id = $1 AND realm_id = $2 AND transmitter_id = $3"#,
            tenant,
            realm,
            uuid(&id),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        raw.map(RawTransmitter::row).transpose()
    }

    /// Records that the transmitter `id` was heard from at `now_ms`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn transmitter_seen(&mut self, id: [u8; 16], now_ms: u64) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "UPDATE access.ssf_transmitter SET last_seen_at = GREATEST(last_seen_at, to_timestamp($4::bigint / 1000.0))
              WHERE tenant_id = $1 AND realm_id = $2 AND transmitter_id = $3",
            tenant,
            realm,
            uuid(&id),
            signed(now_ms)?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Records a SET taken from transmitter `id` by its `jti` digest; false when it was taken
    /// before (replay).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn take_inbound(
        &mut self,
        id: [u8; 16],
        jti_digest: &[u8; 32],
        event_type: &str,
        outcome: &str,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let n = sqlx::query!(
            "INSERT INTO access.ssf_inbound_set (tenant_id, realm_id, transmitter_id, jti_digest, event_type, outcome)
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
            tenant,
            realm,
            uuid(&id),
            jti_digest.as_slice(),
            event_type,
            outcome,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Links the upstream subject digest H(iss, sub) to `subject`; the federation adapter writes
    /// it when an upstream sign-in binds the two.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn link_upstream_subject(
        &mut self,
        digest: &[u8; 32],
        subject: [u8; 16],
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.upstream_subject (tenant_id, realm_id, subject_digest, subject_id)
             VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
            tenant,
            realm,
            digest.as_slice(),
            uuid(&subject),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Links the upstream subject digest H(iss, sub) to `subject` under the `idp.upstream.link`
    /// decision `bound` (EI-25, OP-152 m.7 (d) E6): `Some(true)` when linked now, `Some(false)`
    /// when it is linked to `subject` already, `None` when another account holds it.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn link_upstream_subject_decided(
        &mut self,
        bound: &Bound,
        digest: &[u8; 32],
        subject: [u8; 16],
    ) -> Result<Option<bool>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let n = sqlx::query!(
            "INSERT INTO access.upstream_subject
               (tenant_id, realm_id, subject_digest, subject_id, domain_id, decision_pos)
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
            tenant,
            realm,
            digest.as_slice(),
            uuid(&subject),
            bound.domain().as_bytes().as_slice(),
            i64::try_from(bound.position()).map_err(|_| StoreError::Range)?,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        if n == 1 {
            return Ok(Some(true));
        }
        let held = sqlx::query_scalar!(
            "SELECT subject_id FROM access.upstream_subject
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_digest = $3",
            tenant,
            realm,
            digest.as_slice(),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(held.filter(|s| *s.as_bytes() == subject).map(|_| false))
    }

    /// The realm subject linked to the upstream subject digest.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn upstream_subject(
        &mut self,
        digest: &[u8; 32],
    ) -> Result<Option<[u8; 16]>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let row = sqlx::query_scalar!(
            "SELECT subject_id FROM access.upstream_subject
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_digest = $3 AND status = 'active'",
            tenant,
            realm,
            digest.as_slice(),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(row.map(|s| *s.as_bytes()))
    }

    /// Records a receiver's acknowledgement of an event of its stream (E30): `semantic` with
    /// `applied` or `ignored`, or `authority_state` with `current`. False when the event was
    /// never delivered to the stream or the same kind of ack was recorded before.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn record_ack(
        &mut self,
        subscription: [u8; 16],
        event_id: &str,
        kind: &str,
        state: &str,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let n = sqlx::query!(
            "INSERT INTO access.event_ack (tenant_id, realm_id, subscription_id, event_id, kind, state)
             SELECT $1, $2, $3, $4, $5, $6 WHERE EXISTS (
               SELECT 1 FROM access.event_delivery
                WHERE tenant_id = $1 AND realm_id = $2 AND subscription_id = $3 AND event_id = $4
                  AND state IN ('delivered', 'acknowledged'))
             ON CONFLICT DO NOTHING",
            tenant,
            realm,
            uuid(&subscription),
            event_id,
            kind,
            state,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// The acknowledgement counts of this realm's streams (E30).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn ack_counts(&mut self) -> Result<AckCounts, StoreError> {
        let (tenant, realm) = scope(self)?;
        let delivered = sqlx::query_scalar!(
            "SELECT count(*) FROM access.event_delivery
              WHERE tenant_id = $1 AND realm_id = $2 AND state IN ('delivered', 'acknowledged')",
            tenant,
            realm,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        let row = sqlx::query!(
            r#"SELECT count(*) FILTER (WHERE state = 'applied') AS "applied",
                      count(*) FILTER (WHERE state = 'ignored') AS "ignored",
                      count(*) FILTER (WHERE kind = 'authority_state') AS "authority"
                 FROM access.event_ack WHERE tenant_id = $1 AND realm_id = $2"#,
            tenant,
            realm,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(AckCounts {
            delivered: count(delivered),
            applied: count(row.applied),
            ignored: count(row.ignored),
            authority_state: count(row.authority),
        })
    }

    /// The kinds of this realm's identity outbox entries, oldest first; for tests that cannot
    /// wait for the outbox watermark.
    ///
    /// # Errors
    /// [`StoreError`].
    #[cfg(feature = "testing")]
    pub async fn outbox_kinds(&mut self) -> Result<Vec<String>, StoreError> {
        let (tenant, realm) = scope(self)?;
        Ok(sqlx::query_scalar!(
            "SELECT kind FROM access.identity_outbox WHERE tenant_id = $1 AND realm_id = $2 ORDER BY id",
            tenant,
            realm,
        )
        .fetch_all(&mut *self.tx)
        .await?)
    }
}
