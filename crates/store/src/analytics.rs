//! Tenant analytics summaries (IDP-36, OP-151 m.3 (n)): one DERIVED row of counters per realm
//! and day, recomputed from the day's sign-in flows, the realm's credentials, the audit log and
//! the risk review queue; and the failed-login surge alert. Counters only, no identifier and no
//! pseudonym; read only through a realm-scoped transaction (viewer-rechecked) and never by a
//! decision path (TI-18).

use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::TenantTx;

fn scope(t: &TenantTx) -> Result<(Uuid, Uuid), StoreError> {
    let realm = t.realm().ok_or(StoreError::Range)?;
    Ok((
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*realm.as_bytes()),
    ))
}

/// The columns of `access.analytics_daily` besides its key: every one a non-negative count.
pub const COUNTERS: [&str; 19] = [
    "flows_started",
    "identifier_entered",
    "first_factor_passed",
    "second_factor_passed",
    "sessions_created",
    "method_password",
    "method_passkey",
    "method_email_code",
    "method_magic_link",
    "accounts_active",
    "accounts_with_passkey",
    "accounts_with_mfa",
    "mfa_setup_started",
    "mfa_setup_completed",
    "failed_logins",
    "risk_step_ups",
    "risk_reviews",
    "risk_false_positives",
    "legacy_password_accounts",
];

/// The other columns of `access.analytics_daily`: the realm, the day and when it was computed.
pub const KEY: [&str; 4] = ["tenant_id", "realm_id", "day", "computed_at"];

fn count(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt)
}

/// One realm's day.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AnalyticsDay {
    /// Days since the Unix epoch.
    pub day: u32,
    /// Sign-in flows started.
    pub flows_started: u64,
    /// ...with an identifier typed.
    pub identifier_entered: u64,
    /// ...with a first step passed.
    pub first_factor_passed: u64,
    /// ...with a second step passed.
    pub second_factor_passed: u64,
    /// ...ending in a session.
    pub sessions_created: u64,
    /// Sessions opened by a password.
    pub method_password: u64,
    /// ...by a passkey.
    pub method_passkey: u64,
    /// ...by an e-mail code.
    pub method_email_code: u64,
    /// ...by an e-mail link.
    pub method_magic_link: u64,
    /// Active accounts when computed.
    pub accounts_active: u64,
    /// ...with a live passkey.
    pub accounts_with_passkey: u64,
    /// ...with a second factor (TOTP or passkey).
    pub accounts_with_mfa: u64,
    /// TOTP or passkey enrolments started.
    pub mfa_setup_started: u64,
    /// ...completed.
    pub mfa_setup_completed: u64,
    /// Failed sign-in attempts.
    pub failed_logins: u64,
    /// SL2 step-ups asked of users.
    pub risk_step_ups: u64,
    /// Review items opened.
    pub risk_reviews: u64,
    /// Review items marked false positive.
    pub risk_false_positives: u64,
    /// Active accounts whose password is still an imported hash (TN-85, CR-37).
    pub legacy_password_accounts: u64,
}

/// A failed-login surge (IDP-36).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SurgeAlert {
    /// The day.
    pub day: u32,
    /// Failed logins that day.
    pub observed: u64,
    /// The day before.
    pub baseline: u64,
}

impl TenantTx {
    /// Recomputes the transaction realm's row of `day` and returns it with the day before's
    /// failed-login count (0 without a row).
    ///
    /// # Errors
    /// [`StoreError`].
    #[expect(clippy::too_many_lines, reason = "one derived row, column by column")]
    pub async fn aggregate_day(&mut self, day: u32) -> Result<(AnalyticsDay, u64), StoreError> {
        let (tenant, realm) = scope(self)?;
        let d = i32::try_from(day).map_err(|_| StoreError::Range)?;
        let r = sqlx::query!(
            r#"WITH f AS (
                 SELECT status, convert_from(state, 'UTF8')::jsonb AS s
                   FROM access.auth_flows
                  WHERE tenant_id = $1 AND realm_id = $2 AND day = $3),
               l AS (SELECT * FROM f WHERE s -> 'purpose' = '"login"'::jsonb),
               e AS (SELECT * FROM f WHERE jsonb_typeof(s -> 'purpose') = 'object'
                       AND (s -> 'purpose' ? 'enroll_totp' OR s -> 'purpose' ? 'register_passkey')),
               a AS (SELECT subject_id FROM access.identity_subjects
                      WHERE tenant_id = $1 AND realm_id = $2 AND status = 'active'),
               c AS (SELECT DISTINCT c.subject_id, c.kind FROM access.identity_credentials c
                       JOIN a USING (subject_id)
                      WHERE c.tenant_id = $1 AND c.realm_id = $2 AND c.status = 'active'
                        AND c.kind IN ('webauthn', 'totp')),
               lp AS (SELECT DISTINCT c.subject_id FROM access.identity_credentials c
                       JOIN a USING (subject_id)
                      WHERE c.tenant_id = $1 AND c.realm_id = $2 AND c.status = 'active'
                        AND c.kind = 'password' AND c.algorithm LIKE 'legacy-%'),
               w AS (SELECT to_timestamp($3::bigint * 86400) AS lo,
                            to_timestamp(($3::bigint + 1) * 86400) AS hi)
             INSERT INTO access.analytics_daily AS t (tenant_id, realm_id, day, flows_started,
                    identifier_entered, first_factor_passed, second_factor_passed,
                    sessions_created, method_password, method_passkey, method_email_code,
                    method_magic_link, accounts_active, accounts_with_passkey, accounts_with_mfa,
                    mfa_setup_started, mfa_setup_completed, failed_logins, risk_step_ups,
                    risk_reviews, risk_false_positives, legacy_password_accounts)
             SELECT $1, $2, $3,
                    (SELECT count(*) FROM l),
                    (SELECT count(*) FROM l WHERE jsonb_typeof(s -> 'identifier') = 'array'),
                    (SELECT count(*) FROM l WHERE jsonb_array_length(s -> 'factors') >= 1),
                    (SELECT count(*) FROM l WHERE jsonb_array_length(s -> 'factors') >= 2),
                    (SELECT count(*) FROM l WHERE status = 'done'),
                    (SELECT count(*) FROM l WHERE status = 'done'
                       AND s -> 'factors' -> 0 ->> 'method' = 'password'),
                    (SELECT count(*) FROM l WHERE status = 'done'
                       AND s -> 'factors' -> 0 ->> 'method' = 'passkey'),
                    (SELECT count(*) FROM l WHERE status = 'done'
                       AND s -> 'factors' -> 0 ->> 'method' = 'email_otp'),
                    (SELECT count(*) FROM l WHERE status = 'done'
                       AND s -> 'factors' -> 0 ->> 'method' = 'magic_link'),
                    (SELECT count(*) FROM a),
                    (SELECT count(DISTINCT subject_id) FROM c WHERE kind = 'webauthn'),
                    (SELECT count(DISTINCT subject_id) FROM c),
                    (SELECT count(*) FROM e),
                    (SELECT count(*) FROM e WHERE status = 'done'),
                    (SELECT count(*) FROM access.identity_audit, w
                      WHERE tenant_id = $1 AND realm_id = $2
                        AND event_type IN ('login.password.failed', 'login.failed')
                        AND at >= w.lo AND at < w.hi),
                    (SELECT count(*) FROM l WHERE s -> 'risk' ->> 'step_up' = 'true'),
                    (SELECT count(*) FROM access.risk_review, w
                      WHERE tenant_id = $1 AND realm_id = $2
                        AND created_at >= w.lo AND created_at < w.hi),
                    (SELECT count(*) FROM access.risk_review, w
                      WHERE tenant_id = $1 AND realm_id = $2 AND state = 'false_positive'
                        AND decided_at >= w.lo AND decided_at < w.hi),
                    (SELECT count(*) FROM lp)
             ON CONFLICT (tenant_id, realm_id, day) DO UPDATE
                SET flows_started = EXCLUDED.flows_started,
                    identifier_entered = EXCLUDED.identifier_entered,
                    first_factor_passed = EXCLUDED.first_factor_passed,
                    second_factor_passed = EXCLUDED.second_factor_passed,
                    sessions_created = EXCLUDED.sessions_created,
                    method_password = EXCLUDED.method_password,
                    method_passkey = EXCLUDED.method_passkey,
                    method_email_code = EXCLUDED.method_email_code,
                    method_magic_link = EXCLUDED.method_magic_link,
                    accounts_active = EXCLUDED.accounts_active,
                    accounts_with_passkey = EXCLUDED.accounts_with_passkey,
                    accounts_with_mfa = EXCLUDED.accounts_with_mfa,
                    mfa_setup_started = EXCLUDED.mfa_setup_started,
                    mfa_setup_completed = EXCLUDED.mfa_setup_completed,
                    failed_logins = EXCLUDED.failed_logins,
                    risk_step_ups = EXCLUDED.risk_step_ups,
                    risk_reviews = EXCLUDED.risk_reviews,
                    risk_false_positives = EXCLUDED.risk_false_positives,
                    legacy_password_accounts = EXCLUDED.legacy_password_accounts,
                    computed_at = now()
             RETURNING t.day, t.flows_started, t.identifier_entered, t.first_factor_passed,
                    t.second_factor_passed, t.sessions_created, t.method_password,
                    t.method_passkey, t.method_email_code, t.method_magic_link,
                    t.accounts_active, t.accounts_with_passkey, t.accounts_with_mfa,
                    t.mfa_setup_started, t.mfa_setup_completed, t.failed_logins,
                    t.risk_step_ups, t.risk_reviews, t.risk_false_positives,
                    t.legacy_password_accounts,
                    (SELECT p.failed_logins FROM access.analytics_daily p
                      WHERE p.tenant_id = $1 AND p.realm_id = $2 AND p.day = $3 - 1)
                      AS previous"#,
            tenant,
            realm,
            d,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        let row = AnalyticsDay {
            day: u32::try_from(r.day).map_err(|_| StoreError::Corrupt)?,
            flows_started: count(r.flows_started)?,
            identifier_entered: count(r.identifier_entered)?,
            first_factor_passed: count(r.first_factor_passed)?,
            second_factor_passed: count(r.second_factor_passed)?,
            sessions_created: count(r.sessions_created)?,
            method_password: count(r.method_password)?,
            method_passkey: count(r.method_passkey)?,
            method_email_code: count(r.method_email_code)?,
            method_magic_link: count(r.method_magic_link)?,
            accounts_active: count(r.accounts_active)?,
            accounts_with_passkey: count(r.accounts_with_passkey)?,
            accounts_with_mfa: count(r.accounts_with_mfa)?,
            mfa_setup_started: count(r.mfa_setup_started)?,
            mfa_setup_completed: count(r.mfa_setup_completed)?,
            failed_logins: count(r.failed_logins)?,
            risk_step_ups: count(r.risk_step_ups)?,
            risk_reviews: count(r.risk_reviews)?,
            risk_false_positives: count(r.risk_false_positives)?,
            legacy_password_accounts: count(r.legacy_password_accounts)?,
        };
        Ok((row, r.previous.map(count).transpose()?.unwrap_or(0)))
    }

    /// Records a failed-login surge of the transaction realm; false when one is already
    /// recorded for the day.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn record_surge(&mut self, alert: &SurgeAlert) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let done = sqlx::query!(
            "INSERT INTO access.analytics_alert (tenant_id, realm_id, day, kind, observed, baseline)
             VALUES ($1, $2, $3, 'failed_login_surge', $4, $5) ON CONFLICT DO NOTHING",
            tenant,
            realm,
            i32::try_from(alert.day).map_err(|_| StoreError::Range)?,
            i64::try_from(alert.observed).map_err(|_| StoreError::Range)?,
            i64::try_from(alert.baseline).map_err(|_| StoreError::Range)?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// The transaction realm's rows of days `from..=to`, oldest first.
    ///
    /// # Errors
    /// [`StoreError`]; [`StoreError::Range`] for a transaction without a realm.
    pub async fn analytics_days(
        &mut self,
        from: u32,
        to: u32,
    ) -> Result<Vec<AnalyticsDay>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            "SELECT day, flows_started, identifier_entered, first_factor_passed,
                    second_factor_passed, sessions_created, method_password, method_passkey,
                    method_email_code, method_magic_link, accounts_active, accounts_with_passkey,
                    accounts_with_mfa, mfa_setup_started, mfa_setup_completed, failed_logins,
                    risk_step_ups, risk_reviews, risk_false_positives, legacy_password_accounts
               FROM access.analytics_daily
              WHERE tenant_id = $1 AND realm_id = $2 AND day BETWEEN $3 AND $4
              ORDER BY day",
            tenant,
            realm,
            i32::try_from(from).map_err(|_| StoreError::Range)?,
            i32::try_from(to).map_err(|_| StoreError::Range)?,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(AnalyticsDay {
                    day: u32::try_from(r.day).map_err(|_| StoreError::Corrupt)?,
                    flows_started: count(r.flows_started)?,
                    identifier_entered: count(r.identifier_entered)?,
                    first_factor_passed: count(r.first_factor_passed)?,
                    second_factor_passed: count(r.second_factor_passed)?,
                    sessions_created: count(r.sessions_created)?,
                    method_password: count(r.method_password)?,
                    method_passkey: count(r.method_passkey)?,
                    method_email_code: count(r.method_email_code)?,
                    method_magic_link: count(r.method_magic_link)?,
                    accounts_active: count(r.accounts_active)?,
                    accounts_with_passkey: count(r.accounts_with_passkey)?,
                    accounts_with_mfa: count(r.accounts_with_mfa)?,
                    mfa_setup_started: count(r.mfa_setup_started)?,
                    mfa_setup_completed: count(r.mfa_setup_completed)?,
                    failed_logins: count(r.failed_logins)?,
                    risk_step_ups: count(r.risk_step_ups)?,
                    risk_reviews: count(r.risk_reviews)?,
                    risk_false_positives: count(r.risk_false_positives)?,
                    legacy_password_accounts: count(r.legacy_password_accounts)?,
                })
            })
            .collect()
    }

    /// The transaction realm's surge alerts of days `from..=to`, oldest first.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn surge_alerts(
        &mut self,
        from: u32,
        to: u32,
    ) -> Result<Vec<SurgeAlert>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            "SELECT day, observed, baseline FROM access.analytics_alert
              WHERE tenant_id = $1 AND realm_id = $2 AND kind = 'failed_login_surge'
                AND day BETWEEN $3 AND $4
              ORDER BY day",
            tenant,
            realm,
            i32::try_from(from).map_err(|_| StoreError::Range)?,
            i32::try_from(to).map_err(|_| StoreError::Range)?,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(SurgeAlert {
                    day: u32::try_from(r.day).map_err(|_| StoreError::Corrupt)?,
                    observed: count(r.observed)?,
                    baseline: count(r.baseline)?,
                })
            })
            .collect()
    }
}
