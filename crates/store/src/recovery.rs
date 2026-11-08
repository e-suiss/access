//! Account recovery (§12.3.2, TN-52–TN-62, OP-153 m.3 (c)–(f)): notice addresses, recovery
//! methods, the account's and the realm's recovery policies, attempts with their append-only
//! transitions, the evidence an attempt consumes, the single-use tokens that open a
//! credential-only window, and a forwarded `instance_recover`. Nothing is ever deleted (OP-73).

use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::TenantTx;

fn uuid(b: [u8; 16]) -> Uuid {
    Uuid::from_bytes(b)
}

fn bytes16(v: Vec<u8>) -> Result<[u8; 16], StoreError> {
    <[u8; 16]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn unique(e: sqlx::Error) -> StoreError {
    match &e {
        sqlx::Error::Database(d) if d.is_unique_violation() => StoreError::Consumed,
        _ => StoreError::Db(e),
    }
}

/// A live notice address.
#[derive(Clone, PartialEq, Eq)]
pub struct AddressRow {
    /// Its id.
    pub id: [u8; 16],
    /// `email` or `phone`.
    pub kind: String,
    /// The account's own identifier it names, if it is one.
    pub identifier: Option<[u8; 16]>,
    /// The sealed address of another address: nonce and ciphertext under the subject's
    /// `contact` key.
    pub sealed: Option<([u8; 12], Vec<u8>)>,
    /// Whether recovery codes go to it; then it is never the recovery's notice channel.
    pub recovery_target: bool,
    /// Whether it is a recovery contact's (TN-52).
    pub recovery_contact: bool,
    /// When it was added, Unix ms: its owner proved it then (RFC 7293).
    pub since_ms: i64,
}

impl core::fmt::Debug for AddressRow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AddressRow")
            .field("kind", &self.kind)
            .field("recovery_target", &self.recovery_target)
            .field("recovery_contact", &self.recovery_contact)
            .finish_non_exhaustive()
    }
}

/// A new notice address.
pub struct NewAddress<'a> {
    /// The subject.
    pub subject: [u8; 16],
    /// `email` or `phone`.
    pub kind: &'a str,
    /// The account's own identifier, or
    pub identifier: Option<[u8; 16]>,
    /// another address, sealed: nonce and ciphertext.
    pub sealed: Option<(&'a [u8; 12], &'a [u8])>,
    /// Recovery codes go to it.
    pub recovery_target: bool,
    /// It is a recovery contact's.
    pub recovery_contact: bool,
}

/// A live recovery method.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MethodRow {
    /// Its id.
    pub id: [u8; 16],
    /// The recovery class.
    pub class: String,
    /// Its assurance label: `aal1`, `aal2` or `aal3`.
    pub assurance: String,
    /// The address a sent code goes to.
    pub address: Option<[u8; 16]>,
}

/// The account's own recovery settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountPolicyRow {
    /// Whether assisted recovery is on (TN-60).
    pub assisted_recovery: bool,
    /// When the permanent loss risk was acknowledged.
    pub permanent_loss_acknowledged_ms: Option<i64>,
    /// A high-value account (OP-153 m.3 (e)).
    pub high_value: bool,
}

/// A new attempt.
pub struct NewAttempt<'a> {
    /// The subject, when the identifier named one.
    pub subject: Option<[u8; 16]>,
    /// Digest of the browser's attempt handle.
    pub handle_hash: &'a [u8; 32],
    /// The recovery path it started on.
    pub path: &'a str,
    /// The AAL the account needs (TN-53 rule 1).
    pub required_aal: &'a str,
    /// The realm's cooling table when it started, encoded: the attempt keeps it whatever the
    /// table becomes (TN-55).
    pub cooling: &'a [u8],
    /// A high-value account.
    pub high_value: bool,
    /// Now, Unix milliseconds.
    pub at_ms: i64,
}

/// An attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttemptRow {
    /// Its id.
    pub id: [u8; 16],
    /// The subject; `None` for an identifier that named no account.
    pub subject: Option<[u8; 16]>,
    /// The path it started on.
    pub path: String,
    /// The required AAL.
    pub required_aal: String,
    /// The cooling table it keeps, encoded.
    pub cooling: Vec<u8>,
    /// A high-value account.
    pub high_value: bool,
    /// When it was opened.
    pub opened_ms: i64,
}

/// One transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionRow {
    /// Its place in the attempt.
    pub seq: i32,
    /// The state entered.
    pub state: String,
    /// The required AAL.
    pub required_aal: Option<String>,
    /// The achieved AAL.
    pub achieved_aal: Option<String>,
    /// The evidence classes spent so far.
    pub evidence: Vec<String>,
    /// Why.
    pub reason: String,
    /// The end of a throttle, cooling or grace period.
    pub until_ms: Option<i64>,
    /// When.
    pub at_ms: i64,
}

/// A new transition.
pub struct NewTransition<'a> {
    /// Its place: one past the last.
    pub seq: i32,
    /// The state entered.
    pub state: &'a str,
    /// The required AAL.
    pub required_aal: Option<&'a str>,
    /// The achieved AAL.
    pub achieved_aal: Option<&'a str>,
    /// The evidence classes spent so far.
    pub evidence: &'a [String],
    /// Why.
    pub reason: &'a str,
    /// The end of a throttle, cooling or grace period.
    pub until_ms: Option<i64>,
    /// Now.
    pub at_ms: i64,
}

/// A code sent for an attempt.
#[derive(Clone, PartialEq, Eq)]
pub struct EvidenceRow {
    /// Its id.
    pub id: [u8; 16],
    /// `sent_code` or `recovery_contact`.
    pub class: String,
    /// The code's digest.
    pub code_hash: [u8; 32],
    /// Tries left.
    pub tries_left: i16,
    /// When it stops being worth anything.
    pub expires_ms: i64,
}

impl core::fmt::Debug for EvidenceRow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EvidenceRow")
            .field("class", &self.class)
            .field("tries_left", &self.tries_left)
            .field("expires_ms", &self.expires_ms)
            .finish_non_exhaustive()
    }
}

/// A new single-use token.
pub struct NewToken<'a> {
    /// Whose.
    pub subject: [u8; 16],
    /// `reset_intent`, `temporary_access_pass`, `rebind` or `link_code`.
    pub kind: &'a str,
    /// Its digest.
    pub token_hash: &'a [u8; 32],
    /// The attempt it belongs to.
    pub attempt: Option<[u8; 16]>,
    /// The Exercise that issued it.
    pub exercise: Option<&'a [u8; 32]>,
    /// The address it was sent to.
    pub address: Option<[u8; 16]>,
    /// Its entropy.
    pub entropy_bits: i16,
    /// Used once.
    pub one_time: bool,
    /// Now.
    pub at_ms: i64,
    /// Its end.
    pub expires_ms: i64,
}

/// A live token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenRow {
    /// Its id.
    pub id: [u8; 16],
    /// Whose.
    pub subject: [u8; 16],
    /// Its kind.
    pub kind: String,
    /// The attempt it belongs to.
    pub attempt: Option<[u8; 16]>,
    /// Used once.
    pub one_time: bool,
    /// Its uses so far.
    pub uses: i32,
    /// Its end.
    pub expires_ms: i64,
}

/// A forwarded `instance_recover`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RebindRow {
    /// The attempt.
    pub attempt: [u8; 16],
    /// The predecessor Instance.
    pub predecessor: [u8; 16],
    /// The Exercise nonce.
    pub nonce: Vec<u8>,
    /// The successor key's raw public material.
    pub public_key: Vec<u8>,
    /// `OKP` or `EC2`.
    pub key_type: String,
    /// The intent's validity.
    pub valid: (i64, i64),
    /// The AIS.
    pub ais: Vec<u8>,
    /// The `recovery_result` Claim.
    pub claim: Option<[u8; 16]>,
}

/// Milliseconds to a timestamp in SQL: `to_timestamp($n / 1000.0)`.
const MS: f64 = 1000.0;

#[expect(
    clippy::cast_precision_loss,
    reason = "Unix milliseconds fit an f64 mantissa"
)]
fn seconds(ms: i64) -> f64 {
    ms as f64 / MS
}

impl TenantTx {
    /// Records a new set of registered recovery codes, waiting for its acknowledgement (TN-59).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_code_set(&mut self, subject: [u8; 16]) -> Result<(), StoreError> {
        let (tenant, realm) = self.recovery_scope()?;
        sqlx::query!(
            "INSERT INTO access.recovery_code_sets (tenant_id, realm_id, subject_id)
             VALUES ($1, $2, $3)",
            tenant,
            realm,
            uuid(subject),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Acknowledges the subject's newest set of recovery codes; false when it has none waiting.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn acknowledge_code_set(&mut self, subject: [u8; 16]) -> Result<bool, StoreError> {
        let (tenant, realm) = self.recovery_scope()?;
        let n = sqlx::query!(
            "UPDATE access.recovery_code_sets SET acknowledged_at = clock_timestamp()
              WHERE tenant_id = $1 AND realm_id = $2 AND acknowledged_at IS NULL
                AND set_id = (SELECT s.set_id FROM access.recovery_code_sets s
                               WHERE s.tenant_id = $1 AND s.realm_id = $2 AND s.subject_id = $3
                               ORDER BY s.issued_at DESC, s.set_id DESC LIMIT 1)",
            tenant,
            realm,
            uuid(subject),
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Whether the subject's newest set of recovery codes still waits for its acknowledgement.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn code_set_pending(&mut self, subject: [u8; 16]) -> Result<bool, StoreError> {
        let (tenant, realm) = self.recovery_scope()?;
        let pending = sqlx::query_scalar!(
            r#"SELECT acknowledged_at IS NULL AS "pending!" FROM access.recovery_code_sets
                WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3
                ORDER BY issued_at DESC, set_id DESC LIMIT 1"#,
            tenant,
            realm,
            uuid(subject),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(pending.unwrap_or(false))
    }

    fn recovery_scope(&self) -> Result<(Uuid, Uuid), StoreError> {
        let realm = self.realm().ok_or(StoreError::Range)?;
        Ok((uuid(*self.tenant.as_bytes()), uuid(*realm.as_bytes())))
    }

    /// Serialises the transactions that move one attempt or one subject's recovery (TN-54): a
    /// transaction-scoped advisory lock on `key`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn recovery_lock(&mut self, key: &[u8; 16]) -> Result<(), StoreError> {
        let name = format!("recovery:{}", uuid(*key));
        sqlx::query!(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            name
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Adds a notice address.
    ///
    /// # Errors
    /// [`StoreError`]; a recovery target that would be the only notice address fails at commit
    /// (TN-57).
    pub async fn insert_notification_address(
        &mut self,
        a: &NewAddress<'_>,
    ) -> Result<[u8; 16], StoreError> {
        let (tenant, realm) = self.recovery_scope()?;
        let id = sqlx::query_scalar!(
            "INSERT INTO access.notification_addresses
               (tenant_id, realm_id, subject_id, kind, identifier_id, nonce, ciphertext,
                recovery_target, recovery_contact)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             RETURNING address_id",
            tenant,
            realm,
            uuid(a.subject),
            a.kind,
            a.identifier.map(uuid),
            a.sealed.map(|(n, _)| n.as_slice()),
            a.sealed.map(|(_, c)| c),
            a.recovery_target,
            a.recovery_contact,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(*id.as_bytes())
    }

    /// The subject's live notice addresses, oldest first.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn notification_addresses(
        &mut self,
        subject: [u8; 16],
    ) -> Result<Vec<AddressRow>, StoreError> {
        let (tenant, realm) = self.recovery_scope()?;
        let rows = sqlx::query!(
            r#"SELECT address_id, kind, identifier_id, nonce, ciphertext, recovery_target,
                    recovery_contact,
                    (extract(epoch FROM created_at) * 1000)::bigint AS "since_ms!"
               FROM access.notification_addresses
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND retired_at IS NULL
              ORDER BY address_id"#,
            tenant,
            realm,
            uuid(subject),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                let sealed = match (r.nonce, r.ciphertext) {
                    (Some(n), Some(c)) => {
                        Some((<[u8; 12]>::try_from(n).map_err(|_| StoreError::Corrupt)?, c))
                    }
                    (None, None) => None,
                    _ => return Err(StoreError::Corrupt),
                };
                Ok(AddressRow {
                    id: *r.address_id.as_bytes(),
                    kind: r.kind,
                    identifier: r.identifier_id.map(|u| *u.as_bytes()),
                    sealed,
                    recovery_target: r.recovery_target,
                    recovery_contact: r.recovery_contact,
                    since_ms: r.since_ms,
                })
            })
            .collect()
    }

    /// Retires a notice address; `false` when it was not live.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn retire_notification_address(
        &mut self,
        subject: [u8; 16],
        address: [u8; 16],
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.recovery_scope()?;
        let n = sqlx::query!(
            "UPDATE access.notification_addresses SET retired_at = clock_timestamp()
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND address_id = $4
                AND retired_at IS NULL",
            tenant,
            realm,
            uuid(subject),
            uuid(address),
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Adds a recovery method with its assurance label.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_recovery_method(
        &mut self,
        subject: [u8; 16],
        class: &str,
        assurance: &str,
        address: Option<[u8; 16]>,
    ) -> Result<[u8; 16], StoreError> {
        let (tenant, realm) = self.recovery_scope()?;
        let id = sqlx::query_scalar!(
            "INSERT INTO access.recovery_methods
               (tenant_id, realm_id, subject_id, class, assurance, address_id)
             VALUES ($1, $2, $3, $4, $5::text::access.aal, $6)
             RETURNING method_id",
            tenant,
            realm,
            uuid(subject),
            class,
            assurance,
            address.map(uuid),
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(*id.as_bytes())
    }

    /// The subject's live recovery methods.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn recovery_methods(
        &mut self,
        subject: [u8; 16],
    ) -> Result<Vec<MethodRow>, StoreError> {
        let (tenant, realm) = self.recovery_scope()?;
        let rows = sqlx::query!(
            r#"SELECT method_id, class, assurance::text AS "assurance!", address_id
                 FROM access.recovery_methods
                WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND retired_at IS NULL
                ORDER BY method_id"#,
            tenant,
            realm,
            uuid(subject),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| MethodRow {
                id: *r.method_id.as_bytes(),
                class: r.class,
                assurance: r.assurance,
                address: r.address_id.map(|u| *u.as_bytes()),
            })
            .collect())
    }

    /// Retires a recovery method; `false` when it was not live.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn retire_recovery_method(
        &mut self,
        subject: [u8; 16],
        method: [u8; 16],
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.recovery_scope()?;
        let n = sqlx::query!(
            "UPDATE access.recovery_methods SET retired_at = clock_timestamp()
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND method_id = $4
                AND retired_at IS NULL",
            tenant,
            realm,
            uuid(subject),
            uuid(method),
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Records the account's recovery settings (TN-60).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_account_recovery_policy(
        &mut self,
        subject: [u8; 16],
        p: &AccountPolicyRow,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = self.recovery_scope()?;
        sqlx::query!(
            "INSERT INTO access.account_recovery_policies
               (tenant_id, realm_id, subject_id, assisted_recovery, permanent_loss_acknowledged_at,
                high_value)
             VALUES ($1, $2, $3, $4,
                     CASE WHEN $5::float8 IS NULL THEN NULL ELSE to_timestamp($5::float8) END, $6)",
            tenant,
            realm,
            uuid(subject),
            p.assisted_recovery,
            p.permanent_loss_acknowledged_ms.map(seconds),
            p.high_value,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The account's latest recovery settings.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn account_recovery_policy(
        &mut self,
        subject: [u8; 16],
    ) -> Result<Option<AccountPolicyRow>, StoreError> {
        let (tenant, realm) = self.recovery_scope()?;
        let row = sqlx::query!(
            r#"SELECT assisted_recovery, high_value,
                      (extract(epoch FROM permanent_loss_acknowledged_at) * 1000)::bigint AS ack
                 FROM access.account_recovery_policies
                WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3
                ORDER BY change_id DESC LIMIT 1"#,
            tenant,
            realm,
            uuid(subject),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(row.map(|r| AccountPolicyRow {
            assisted_recovery: r.assisted_recovery,
            permanent_loss_acknowledged_ms: r.ack,
            high_value: r.high_value,
        }))
    }

    /// Records the realm's recovery policy under the committed decision `bound` (EI-25).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_recovery_realm_policy(
        &mut self,
        policy: &[u8],
        bound: &crate::idp::Bound,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = self.recovery_scope()?;
        sqlx::query!(
            "INSERT INTO access.recovery_realm_policies
               (tenant_id, realm_id, policy, domain_id, decision_pos)
             VALUES ($1, $2, $3, $4, $5)",
            tenant,
            realm,
            policy,
            bound.domain().as_bytes().as_slice(),
            bound.raw_position(),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The realm's latest recovery policy, encoded.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn recovery_realm_policy(&mut self) -> Result<Option<Vec<u8>>, StoreError> {
        let (tenant, realm) = self.recovery_scope()?;
        Ok(sqlx::query_scalar!(
            "SELECT policy FROM access.recovery_realm_policies
              WHERE tenant_id = $1 AND realm_id = $2
              ORDER BY change_id DESC LIMIT 1",
            tenant,
            realm,
        )
        .fetch_optional(&mut *self.tx)
        .await?)
    }

    /// Opens an attempt.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_recovery_attempt(
        &mut self,
        a: &NewAttempt<'_>,
    ) -> Result<[u8; 16], StoreError> {
        let (tenant, realm) = self.recovery_scope()?;
        let id = sqlx::query_scalar!(
            "INSERT INTO access.recovery_attempts
               (tenant_id, realm_id, subject_id, handle_hash, path, required_aal, cooling,
                high_value, opened_at)
             VALUES ($1, $2, $3, $4, $5, $6::text::access.aal, $7, $8, to_timestamp($9::float8))
             RETURNING attempt_id",
            tenant,
            realm,
            a.subject.map(uuid),
            a.handle_hash.as_slice(),
            a.path,
            a.required_aal,
            a.cooling,
            a.high_value,
            seconds(a.at_ms),
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(*id.as_bytes())
    }

    /// The attempt of a handle digest.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn recovery_attempt(
        &mut self,
        handle_hash: &[u8; 32],
    ) -> Result<Option<AttemptRow>, StoreError> {
        let (tenant, realm) = self.recovery_scope()?;
        let row = sqlx::query!(
            r#"SELECT attempt_id, subject_id, path, required_aal::text AS "required!", cooling,
                      high_value, (extract(epoch FROM opened_at) * 1000)::bigint AS "opened!"
                 FROM access.recovery_attempts
                WHERE tenant_id = $1 AND realm_id = $2 AND handle_hash = $3"#,
            tenant,
            realm,
            handle_hash.as_slice(),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(row.map(|r| AttemptRow {
            id: *r.attempt_id.as_bytes(),
            subject: r.subject_id.map(|u| *u.as_bytes()),
            path: r.path,
            required_aal: r.required,
            cooling: r.cooling,
            high_value: r.high_value,
            opened_ms: r.opened,
        }))
    }

    /// The attempt `id`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn recovery_attempt_by_id(
        &mut self,
        id: [u8; 16],
    ) -> Result<Option<AttemptRow>, StoreError> {
        let (tenant, realm) = self.recovery_scope()?;
        let row = sqlx::query!(
            r#"SELECT attempt_id, subject_id, path, required_aal::text AS "required!", cooling,
                      high_value, (extract(epoch FROM opened_at) * 1000)::bigint AS "opened!"
                 FROM access.recovery_attempts
                WHERE tenant_id = $1 AND realm_id = $2 AND attempt_id = $3"#,
            tenant,
            realm,
            uuid(id),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(row.map(|r| AttemptRow {
            id: *r.attempt_id.as_bytes(),
            subject: r.subject_id.map(|u| *u.as_bytes()),
            path: r.path,
            required_aal: r.required,
            cooling: r.cooling,
            high_value: r.high_value,
            opened_ms: r.opened,
        }))
    }

    /// The subject's attempts opened at or after `since_ms`, newest first.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn recovery_attempts_since(
        &mut self,
        subject: [u8; 16],
        since_ms: i64,
    ) -> Result<Vec<AttemptRow>, StoreError> {
        let (tenant, realm) = self.recovery_scope()?;
        let rows = sqlx::query!(
            r#"SELECT attempt_id, subject_id, path, required_aal::text AS "required!", cooling,
                      high_value, (extract(epoch FROM opened_at) * 1000)::bigint AS "opened!"
                 FROM access.recovery_attempts
                WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3
                  AND opened_at >= to_timestamp($4::float8)
                ORDER BY attempt_id DESC"#,
            tenant,
            realm,
            uuid(subject),
            seconds(since_ms),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| AttemptRow {
                id: *r.attempt_id.as_bytes(),
                subject: r.subject_id.map(|u| *u.as_bytes()),
                path: r.path,
                required_aal: r.required,
                cooling: r.cooling,
                high_value: r.high_value,
                opened_ms: r.opened,
            })
            .collect())
    }

    /// The end of the subject's grace period still running at `now_ms` (TN-56): the latest
    /// `until` among its attempts whose last step is `grace_period`; `None` when none runs. A
    /// read for the surfaces outside the session crate; the session crate closes elapsed ones.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn recovery_grace_until(
        &mut self,
        subject: [u8; 16],
        now_ms: i64,
    ) -> Result<Option<i64>, StoreError> {
        let (tenant, realm) = self.recovery_scope()?;
        let until = sqlx::query_scalar!(
            r#"SELECT max((extract(epoch FROM t.until) * 1000)::bigint) AS until_ms
                 FROM access.recovery_attempts a
                 JOIN LATERAL (
                   SELECT state, until FROM access.recovery_transitions r
                    WHERE r.tenant_id = a.tenant_id AND r.realm_id = a.realm_id
                      AND r.attempt_id = a.attempt_id
                    ORDER BY seq DESC LIMIT 1
                 ) t ON true
                WHERE a.tenant_id = $1 AND a.realm_id = $2 AND a.subject_id = $3
                  AND t.state = 'grace_period' AND t.until > to_timestamp($4::float8)"#,
            tenant,
            realm,
            uuid(subject),
            seconds(now_ms),
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(until)
    }

    /// Records a change of the realm's RP ID (RR-45, TN-17); `previous` is the stored value it
    /// replaces, `None` for the issuer's host.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_rp_id_change(
        &mut self,
        previous: Option<&str>,
        rp_id: &str,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = self.recovery_scope()?;
        sqlx::query!(
            "INSERT INTO access.realm_rp_id_changes (tenant_id, realm_id, previous, rp_id)
             VALUES ($1, $2, $3, $4)",
            tenant,
            realm,
            previous,
            rp_id,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// When the realm's RP ID last changed, Unix ms (RR-45); `None` when it never did.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn last_rp_id_change(&mut self) -> Result<Option<i64>, StoreError> {
        let (tenant, realm) = self.recovery_scope()?;
        Ok(sqlx::query_scalar!(
            r#"SELECT max((extract(epoch FROM changed_at) * 1000)::bigint) AS at_ms
                 FROM access.realm_rp_id_changes WHERE tenant_id = $1 AND realm_id = $2"#,
            tenant,
            realm,
        )
        .fetch_one(&mut *self.tx)
        .await?)
    }

    /// The attempt's transitions, in order.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn recovery_transitions(
        &mut self,
        attempt: [u8; 16],
    ) -> Result<Vec<TransitionRow>, StoreError> {
        let (tenant, realm) = self.recovery_scope()?;
        let rows = sqlx::query!(
            r#"SELECT seq, state, required_aal::text AS required, achieved_aal::text AS achieved,
                      evidence, reason, (extract(epoch FROM until) * 1000)::bigint AS until_ms,
                      (extract(epoch FROM at) * 1000)::bigint AS "at_ms!"
                 FROM access.recovery_transitions
                WHERE tenant_id = $1 AND realm_id = $2 AND attempt_id = $3
                ORDER BY seq"#,
            tenant,
            realm,
            uuid(attempt),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| TransitionRow {
                seq: r.seq,
                state: r.state,
                required_aal: r.required,
                achieved_aal: r.achieved,
                evidence: r.evidence,
                reason: r.reason,
                until_ms: r.until_ms,
                at_ms: r.at_ms,
            })
            .collect())
    }

    /// Appends a transition (TN-54).
    ///
    /// # Errors
    /// [`StoreError::Consumed`] when another transaction took the same place first;
    /// [`StoreError`].
    pub async fn insert_recovery_transition(
        &mut self,
        attempt: [u8; 16],
        t: &NewTransition<'_>,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = self.recovery_scope()?;
        sqlx::query!(
            "INSERT INTO access.recovery_transitions
               (tenant_id, realm_id, attempt_id, seq, state, required_aal, achieved_aal, evidence,
                reason, until, at)
             VALUES ($1, $2, $3, $4, $5, $6::text::access.aal, $7::text::access.aal, $8, $9,
                     CASE WHEN $10::float8 IS NULL THEN NULL ELSE to_timestamp($10::float8) END,
                     to_timestamp($11::float8))",
            tenant,
            realm,
            uuid(attempt),
            t.seq,
            t.state,
            t.required_aal,
            t.achieved_aal,
            t.evidence,
            t.reason,
            t.until_ms.map(seconds),
            seconds(t.at_ms),
        )
        .execute(&mut *self.tx)
        .await
        .map_err(unique)?;
        Ok(())
    }

    /// Stores a sent code.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_recovery_evidence(
        &mut self,
        attempt: [u8; 16],
        class: &str,
        code_hash: &[u8; 32],
        address: Option<[u8; 16]>,
        tries: i16,
        expires_ms: i64,
    ) -> Result<[u8; 16], StoreError> {
        let (tenant, realm) = self.recovery_scope()?;
        let id = sqlx::query_scalar!(
            "INSERT INTO access.recovery_evidence
               (tenant_id, realm_id, attempt_id, class, code_hash, address_id, tries_left,
                expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, to_timestamp($8::float8))
             RETURNING evidence_id",
            tenant,
            realm,
            uuid(attempt),
            class,
            code_hash.as_slice(),
            address.map(uuid),
            tries,
            seconds(expires_ms),
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(*id.as_bytes())
    }

    /// The attempt's unspent codes.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn recovery_evidence(
        &mut self,
        attempt: [u8; 16],
    ) -> Result<Vec<EvidenceRow>, StoreError> {
        let (tenant, realm) = self.recovery_scope()?;
        let rows = sqlx::query!(
            r#"SELECT evidence_id, class, code_hash, tries_left,
                      (extract(epoch FROM expires_at) * 1000)::bigint AS "expires!"
                 FROM access.recovery_evidence
                WHERE tenant_id = $1 AND realm_id = $2 AND attempt_id = $3
                  AND consumed_at IS NULL AND tries_left > 0
                ORDER BY evidence_id"#,
            tenant,
            realm,
            uuid(attempt),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(EvidenceRow {
                    id: *r.evidence_id.as_bytes(),
                    class: r.class,
                    code_hash: <[u8; 32]>::try_from(r.code_hash)
                        .map_err(|_| StoreError::Corrupt)?,
                    tries_left: r.tries_left,
                    expires_ms: r.expires,
                })
            })
            .collect()
    }

    /// Spends a code once (TN-54): `false` when another transaction spent it first.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn consume_recovery_evidence(
        &mut self,
        evidence: [u8; 16],
        at_ms: i64,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.recovery_scope()?;
        let n = sqlx::query!(
            "UPDATE access.recovery_evidence SET consumed_at = to_timestamp($4::float8)
              WHERE tenant_id = $1 AND realm_id = $2 AND evidence_id = $3 AND consumed_at IS NULL",
            tenant,
            realm,
            uuid(evidence),
            seconds(at_ms),
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Counts one wrong try against a code.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn spend_recovery_try(&mut self, evidence: [u8; 16]) -> Result<(), StoreError> {
        let (tenant, realm) = self.recovery_scope()?;
        sqlx::query!(
            "UPDATE access.recovery_evidence SET tries_left = tries_left - 1
              WHERE tenant_id = $1 AND realm_id = $2 AND evidence_id = $3 AND consumed_at IS NULL
                AND tries_left > 0",
            tenant,
            realm,
            uuid(evidence),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Stores a single-use token.
    ///
    /// # Errors
    /// [`StoreError::Consumed`] for a second live pass of the user (TN-62); [`StoreError`].
    pub async fn insert_recovery_token(
        &mut self,
        t: &NewToken<'_>,
    ) -> Result<[u8; 16], StoreError> {
        let (tenant, realm) = self.recovery_scope()?;
        let id = sqlx::query_scalar!(
            "INSERT INTO access.recovery_tokens
               (tenant_id, realm_id, subject_id, kind, token_hash, attempt_id, exercise_id,
                address_id, entropy_bits, one_time, issued_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, to_timestamp($11::float8),
                     to_timestamp($12::float8))
             RETURNING token_id",
            tenant,
            realm,
            uuid(t.subject),
            t.kind,
            t.token_hash.as_slice(),
            t.attempt.map(uuid),
            t.exercise.map(<[u8; 32]>::as_slice),
            t.address.map(uuid),
            t.entropy_bits,
            t.one_time,
            seconds(t.at_ms),
            seconds(t.expires_ms),
        )
        .fetch_one(&mut *self.tx)
        .await
        .map_err(unique)?;
        Ok(*id.as_bytes())
    }

    /// The live token of a digest, of one of `kinds`, at `at_ms`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn recovery_token(
        &mut self,
        token_hash: &[u8; 32],
        kinds: &[String],
        at_ms: i64,
    ) -> Result<Option<TokenRow>, StoreError> {
        let (tenant, realm) = self.recovery_scope()?;
        let row = sqlx::query!(
            r#"SELECT token_id, subject_id, kind, attempt_id, one_time, uses,
                      (extract(epoch FROM expires_at) * 1000)::bigint AS "expires!"
                 FROM access.recovery_tokens
                WHERE tenant_id = $1 AND realm_id = $2 AND token_hash = $3
                  AND kind = ANY($4) AND used_at IS NULL AND revoked_at IS NULL
                  AND expires_at > to_timestamp($5::float8)"#,
            tenant,
            realm,
            token_hash.as_slice(),
            kinds,
            seconds(at_ms),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(row.map(|r| TokenRow {
            id: *r.token_id.as_bytes(),
            subject: *r.subject_id.as_bytes(),
            kind: r.kind,
            attempt: r.attempt_id.map(|u| *u.as_bytes()),
            one_time: r.one_time,
            uses: r.uses,
            expires_ms: r.expires,
        }))
    }

    /// Uses a token: a one-time token is spent, a multi-use pass counts one more use. `false`
    /// when another transaction spent it first (TN-54).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn use_recovery_token(
        &mut self,
        token: [u8; 16],
        at_ms: i64,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.recovery_scope()?;
        let n = sqlx::query!(
            "UPDATE access.recovery_tokens
                SET uses = uses + 1,
                    used_at = CASE WHEN one_time THEN to_timestamp($4::float8) ELSE NULL END
              WHERE tenant_id = $1 AND realm_id = $2 AND token_id = $3 AND used_at IS NULL
                AND revoked_at IS NULL",
            tenant,
            realm,
            uuid(token),
            seconds(at_ms),
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Revokes the subject's live tokens of `kinds`; how many.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn revoke_recovery_tokens(
        &mut self,
        subject: [u8; 16],
        kinds: &[String],
    ) -> Result<u64, StoreError> {
        let (tenant, realm) = self.recovery_scope()?;
        Ok(sqlx::query!(
            "UPDATE access.recovery_tokens SET revoked_at = clock_timestamp()
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND kind = ANY($4)
                AND used_at IS NULL AND revoked_at IS NULL",
            tenant,
            realm,
            uuid(subject),
            kinds,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected())
    }

    /// Keeps a forwarded `instance_recover`; `false` when the attempt has one already.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_recovery_rebind(
        &mut self,
        subject: [u8; 16],
        r: &RebindRow,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.recovery_scope()?;
        let n = sqlx::query!(
            "INSERT INTO access.recovery_rebinds
               (tenant_id, realm_id, attempt_id, subject_id, predecessor, nonce, public_key,
                key_type, valid_from, valid_until, ais, claim_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
             ON CONFLICT DO NOTHING",
            tenant,
            realm,
            uuid(r.attempt),
            uuid(subject),
            uuid(r.predecessor),
            &r.nonce,
            &r.public_key,
            &r.key_type,
            r.valid.0,
            r.valid.1,
            &r.ais,
            r.claim.as_ref().map(<[u8; 16]>::as_slice),
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// The forwarded `instance_recover` of an attempt.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn recovery_rebind(
        &mut self,
        attempt: [u8; 16],
    ) -> Result<Option<RebindRow>, StoreError> {
        let (tenant, realm) = self.recovery_scope()?;
        let row = sqlx::query!(
            "SELECT attempt_id, predecessor, nonce, public_key, key_type, valid_from, valid_until,
                    ais, claim_id
               FROM access.recovery_rebinds
              WHERE tenant_id = $1 AND realm_id = $2 AND attempt_id = $3",
            tenant,
            realm,
            uuid(attempt),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        row.map(|r| {
            Ok(RebindRow {
                attempt: *r.attempt_id.as_bytes(),
                predecessor: *r.predecessor.as_bytes(),
                nonce: r.nonce,
                public_key: r.public_key,
                key_type: r.key_type,
                valid: (r.valid_from, r.valid_until),
                ais: r.ais,
                claim: r.claim_id.map(bytes16).transpose()?,
            })
        })
        .transpose()
    }

    /// How many live federated links the subject has (TN-64).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn federated_links(&mut self, subject: [u8; 16]) -> Result<u64, StoreError> {
        let (tenant, realm) = self.recovery_scope()?;
        let n = sqlx::query_scalar!(
            r#"SELECT count(*) AS "n!" FROM access.upstream_subject
                WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND status = 'active'"#,
            tenant,
            realm,
            uuid(subject),
        )
        .fetch_one(&mut *self.tx)
        .await?;
        u64::try_from(n).map_err(|_| StoreError::Corrupt)
    }

    /// Releases the subject's federated links (TN-64): a password reset cuts them by default.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn release_federated_links(&mut self, subject: [u8; 16]) -> Result<u64, StoreError> {
        let (tenant, realm) = self.recovery_scope()?;
        Ok(sqlx::query!(
            "UPDATE access.upstream_subject SET status = 'released'
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND status = 'active'",
            tenant,
            realm,
            uuid(subject),
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected())
    }
}
