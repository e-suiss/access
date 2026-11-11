//! Test databases (OP-66): one migrated template per migration set, one clone per test, and
//! connections as the application, sequencer and owner roles, never as the superuser
//! (OP-130 m.2).

use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{AssertSqlSafe, Connection, Executor, PgConnection, PgPool};

/// Password of the test login roles; the test cluster is local or CI-only.
pub const TEST_PASSWORD: &str = "test-only-not-a-secret";

/// Why a test database could not be prepared.
#[derive(Debug, thiserror::Error)]
pub enum TestDbError {
    /// `DATABASE_URL` is missing; run `just pg-up` or use the CI service.
    #[error("store tests need DATABASE_URL, a superuser URL (`just pg-up` prints one)")]
    NoDatabaseUrl,
    /// The cluster refused.
    #[error("{0}: {1}")]
    Db(&'static str, sqlx::Error),
    /// The migrations failed.
    #[error("migrations: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
}

/// A fresh database with pools for each role.
pub struct TestDb {
    /// Name of the clone.
    pub name: String,
    /// Logged in as a member of `access_app`.
    pub app: PgPool,
    /// Logged in as a member of `access_sequencer`.
    pub sequencer: PgPool,
    /// Logged in as a member of `access_migrator`, the table owner.
    pub owner: PgPool,
    /// Logged in as a member of `access_outbox_reader`.
    pub reader: PgPool,
    /// Logged in as a member of `access_router`.
    pub router: PgPool,
    /// Logged in as a member of `access_checkpointer`.
    pub checkpointer: PgPool,
    /// Logged in as a member of `access_archive`.
    pub archive: PgPool,
    /// Logged in as a member of `access_deriver`.
    pub deriver: PgPool,
    /// The administrator connection options, for schema checks only.
    pub admin: PgConnectOptions,
}

trait Context<T> {
    fn at(self, what: &'static str) -> Result<T, TestDbError>;
}

impl<T> Context<T> for Result<T, sqlx::Error> {
    fn at(self, what: &'static str) -> Result<T, TestDbError> {
        self.map_err(|e| TestDbError::Db(what, e))
    }
}

async fn exec(c: &mut PgConnection, sql: String, what: &'static str) -> Result<(), TestDbError> {
    c.execute(AssertSqlSafe(sql)).await.at(what).map(drop)
}

fn admin_options() -> Result<PgConnectOptions, TestDbError> {
    let url = std::env::var("DATABASE_URL").map_err(|_| TestDbError::NoDatabaseUrl)?;
    PgConnectOptions::from_str(&url).at("DATABASE_URL")
}

fn template_name() -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let bootstrap = super::BOOTSTRAP_ROLES
        .bytes()
        .chain(super::BOOTSTRAP_DATABASE.bytes());
    for b in super::MIGRATOR
        .iter()
        .flat_map(|m| m.checksum.iter().copied())
        .chain(bootstrap)
    {
        h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
    }
    format!("access_tpl_{h:016x}")
}

fn unique_name() -> String {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!(
        "access_t_{}_{}_{}",
        std::process::id(),
        nanos,
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// A clone is swept when nobody is connected to it and it is older than five minutes: a live
/// test holds its pools open, so a connected clone is never dropped, however old (a long test
/// or a debugger session). Clones are never dropped by their own test, so the cluster would
/// otherwise grow with every run.
fn sweepable_clone(name: &str, now_nanos: u128, connected: bool) -> bool {
    const IDLE_NANOS: u128 = 300_000_000_000;
    let created = name.split('_').nth(3).and_then(|n| n.parse::<u128>().ok());
    !connected
        && generated_name(name, "access_t_")
        && created.is_some_and(|t| now_nanos.saturating_sub(t) > IDLE_NANOS)
}

/// A template is swept when it is not this migration set's, nobody is connected to it, and it
/// was created more than a day ago: another worktree's suite builds its own template, and an
/// abandoned `_building` copy or a template of an old migration set holds a full schema.
fn sweepable_template(name: &str, current: &str, connected: bool, age_secs: f64) -> bool {
    !connected && name != current && generated_name(name, "access_tpl_") && age_secs > 86_400.0
}

fn generated_name(name: &str, prefix: &str) -> bool {
    name.starts_with(prefix) && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Drops `name` unless someone connected to it meanwhile (`55006`, object in use).
async fn drop_idle(
    c: &mut PgConnection,
    name: &str,
    what: &'static str,
) -> Result<(), TestDbError> {
    match exec(c, format!("DROP DATABASE IF EXISTS {name}"), what).await {
        Err(TestDbError::Db(_, sqlx::Error::Database(e)))
            if e.code().as_deref() == Some("55006") =>
        {
            Ok(())
        }
        other => other,
    }
}

async fn sweep_stale(c: &mut PgConnection, template: &str) -> Result<(), TestDbError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let rows: Vec<(String, bool, Option<f64>)> = sqlx::query_as(
        "SELECT d.datname, \
                EXISTS (SELECT FROM pg_stat_activity a WHERE a.datname = d.datname), \
                EXTRACT(EPOCH FROM now() - (pg_stat_file('base/' || d.oid || '/PG_VERSION', true)).modification)::float8 \
         FROM pg_database d WHERE d.datname LIKE 'access\\_t\\_%' OR d.datname LIKE 'access\\_tpl\\_%'",
    )
    .fetch_all(&mut *c)
    .await
    .at("list test databases")?;
    for (name, connected, age_secs) in rows {
        if sweepable_clone(&name, now, connected) {
            drop_idle(c, &name, "drop stale clone").await?;
        } else if sweepable_template(&name, template, connected, age_secs.unwrap_or(0.0)) {
            drop_idle(c, &name, "drop stale template").await?;
        }
    }
    Ok(())
}

/// Cluster roles and the test logins, every run: logins are not part of the template.
async fn ensure_roles(c: &mut PgConnection) -> Result<(), TestDbError> {
    c.execute(super::BOOTSTRAP_ROLES)
        .await
        .at("bootstrap roles")?;
    for (login, role) in [
        ("access_test_app", "access_app"),
        ("access_test_sequencer", "access_sequencer"),
        ("access_test_migrator", "access_migrator"),
        ("access_test_reader", "access_outbox_reader"),
        ("access_test_router", "access_router"),
        ("access_test_checkpointer", "access_checkpointer"),
        ("access_test_archive", "access_archive"),
        ("access_test_deriver", "access_deriver"),
    ] {
        let sql = format!(
            "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{login}') THEN \
             CREATE ROLE {login} LOGIN NOBYPASSRLS PASSWORD '{TEST_PASSWORD}' IN ROLE {role}; END IF; END $$"
        );
        exec(c, sql, "test login role").await?;
    }
    Ok(())
}

async fn build_template(
    c: &mut PgConnection,
    admin: &PgConnectOptions,
    template: &str,
) -> Result<(), TestDbError> {
    let building = format!("{template}_building");
    exec(
        c,
        format!("DROP DATABASE IF EXISTS {building}"),
        "drop stale build",
    )
    .await?;
    exec(c, format!("CREATE DATABASE {building}"), "create template").await?;
    let mut t = PgConnection::connect_with(&admin.clone().database(&building))
        .await
        .at("connect template")?;
    t.execute(super::BOOTSTRAP_DATABASE)
        .await
        .at("bootstrap database")?;
    super::MIGRATOR.run(&mut t).await?;
    t.close().await.at("close template")?;
    exec(
        c,
        format!("ALTER DATABASE {building} RENAME TO {template}"),
        "publish template",
    )
    .await
}

async fn ensure_template(admin: &PgConnectOptions, template: &str) -> Result<(), TestDbError> {
    let mut c = PgConnection::connect_with(admin)
        .await
        .at("connect as administrator")?;
    c.execute("SELECT pg_advisory_lock(7130)")
        .await
        .at("lock")?;
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT FROM pg_database WHERE datname = $1)")
            .bind(template)
            .fetch_one(&mut c)
            .await
            .at("template lookup")?;
    let swept = sweep_stale(&mut c, template).await;
    let roles = match swept {
        Ok(()) => ensure_roles(&mut c).await,
        Err(e) => Err(e),
    };
    let built = if roles.is_err() {
        roles
    } else if exists {
        Ok(())
    } else {
        build_template(&mut c, admin, template).await
    };
    c.execute("SELECT pg_advisory_unlock(7130)")
        .await
        .at("unlock")?;
    c.close().await.at("close")?;
    built
}

async fn pool(admin: &PgConnectOptions, db: &str, login: &str) -> Result<PgPool, TestDbError> {
    let opts = admin
        .clone()
        .database(db)
        .username(login)
        .password(TEST_PASSWORD);
    PgPoolOptions::new()
        .max_connections(4)
        .connect_with(opts)
        .await
        .at("connect as test role")
}

/// Creates a fresh database cloned from the migrated template.
///
/// # Errors
/// [`TestDbError`] when `DATABASE_URL` is missing or the cluster refuses.
pub async fn fresh() -> Result<TestDb, TestDbError> {
    fresh_on(admin_options()?).await
}

/// [`fresh`] on the cluster `admin` reaches, such as a replicated test cell (OP-158 m.3 (n)).
///
/// # Errors
/// [`TestDbError`] when the cluster refuses.
pub async fn fresh_on(admin: PgConnectOptions) -> Result<TestDb, TestDbError> {
    let template = template_name();
    ensure_template(&admin, &template).await?;
    let name = unique_name();
    let mut c = PgConnection::connect_with(&admin)
        .await
        .at("connect as administrator")?;
    exec(
        &mut c,
        format!("CREATE DATABASE {name} TEMPLATE {template}"),
        "clone template",
    )
    .await?;
    c.close().await.at("close")?;
    attach(admin, &name).await
}

/// [`fresh_on`] on the cluster of the superuser URL `url`.
///
/// # Errors
/// [`TestDbError`].
pub async fn fresh_at(url: &str) -> Result<TestDb, TestDbError> {
    fresh_on(PgConnectOptions::from_str(url).at("cluster URL")?).await
}

/// [`attach`] on the cluster of the superuser URL `url`.
///
/// # Errors
/// [`TestDbError`].
pub async fn attach_at(url: &str, name: &str) -> Result<TestDb, TestDbError> {
    attach(PgConnectOptions::from_str(url).at("cluster URL")?, name).await
}

/// A superuser connection's single-row text answer to `sql` on `db`: the cluster checks of the
/// failover tests (OP-158 m.3 (n)).
///
/// # Errors
/// [`TestDbError`].
pub async fn admin_text(db: &TestDb, sql: &str) -> Result<Option<String>, TestDbError> {
    let mut c = PgConnection::connect_with(&db.admin)
        .await
        .at("connect as administrator")?;
    let v: Option<String> = sqlx::query_scalar(AssertSqlSafe(sql.to_owned()))
        .fetch_optional(&mut c)
        .await
        .at("administrator statement")?
        .flatten();
    c.close().await.at("close")?;
    Ok(v)
}

/// The role pools of the existing database `name` on the cluster `admin` reaches: the same
/// database seen on a promoted standby or a point-in-time restore (OP-158 m.3 (n), (r)).
///
/// # Errors
/// [`TestDbError`] when the cluster refuses.
pub async fn attach(admin: PgConnectOptions, name: &str) -> Result<TestDb, TestDbError> {
    Ok(TestDb {
        app: pool(&admin, name, "access_test_app").await?,
        sequencer: pool(&admin, name, "access_test_sequencer").await?,
        owner: pool(&admin, name, "access_test_migrator").await?,
        reader: pool(&admin, name, "access_test_reader").await?,
        router: pool(&admin, name, "access_test_router").await?,
        checkpointer: pool(&admin, name, "access_test_checkpointer").await?,
        archive: pool(&admin, name, "access_test_archive").await?,
        deriver: pool(&admin, name, "access_test_deriver").await?,
        admin: admin.database(name),
        name: name.to_owned(),
    })
}

/// A fresh database as the database administrator leaves it before the first migration
/// (OP-130 m.2, OP-55): the cluster roles and the per-database setup, no migration.
pub struct Unmigrated {
    /// Name of the database.
    pub name: String,
    /// Logged in as a member of `access_migrator`.
    pub migrator: PgPool,
    /// Logged in as a member of `access_app`.
    pub app: PgPool,
}

/// Creates a fresh, unmigrated database.
///
/// # Errors
/// [`TestDbError`] when `DATABASE_URL` is missing or the cluster refuses.
pub async fn unmigrated() -> Result<Unmigrated, TestDbError> {
    let admin = admin_options()?;
    ensure_template(&admin, &template_name()).await?;
    let name = unique_name();
    let mut c = PgConnection::connect_with(&admin)
        .await
        .at("connect as administrator")?;
    exec(&mut c, format!("CREATE DATABASE {name}"), "create database").await?;
    c.close().await.at("close")?;
    let mut d = PgConnection::connect_with(&admin.clone().database(&name))
        .await
        .at("connect database")?;
    d.execute(super::BOOTSTRAP_DATABASE)
        .await
        .at("bootstrap database")?;
    d.close().await.at("close database")?;
    Ok(Unmigrated {
        migrator: pool(&admin, &name, "access_test_migrator").await?,
        app: pool(&admin, &name, "access_test_app").await?,
        name,
    })
}

impl TestDb {
    /// Overwrites a stored state value as the table owner, to simulate a corruption no
    /// application path can cause (§17.6.12 tests).
    ///
    /// # Errors
    /// [`TestDbError::Db`].
    pub async fn corrupt_state(
        &self,
        domain: &crate::scope::DomainId,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), TestDbError> {
        let mut tx = self.owner.begin().await.at("begin")?;
        tx.execute("SET LOCAL ROLE access_migrator")
            .await
            .at("role")?;
        sqlx::query("SELECT set_config('app.domain_id', $1, true)")
            .bind(domain.hex())
            .execute(&mut *tx)
            .await
            .at("scope")?;
        sqlx::query(
            "UPDATE access.authority_state SET value = $1 WHERE domain_id = $2 AND key = $3",
        )
        .bind(value)
        .bind(domain.as_bytes().as_slice())
        .bind(key)
        .execute(&mut *tx)
        .await
        .at("corrupt")?;
        tx.commit().await.at("commit")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINUTE: u128 = 60_000_000_000;

    // OP-66, SA-59
    #[test]
    fn only_idle_clones_are_swept() {
        let now = 1_000 * MINUTE;
        let name = |created: u128| format!("access_t_4242_{created}_0");
        assert!(!sweepable_clone(&name(now - 600 * MINUTE), now, true));
        assert!(sweepable_clone(&name(now - 6 * MINUTE), now, false));
        assert!(!sweepable_clone(&name(now - 4 * MINUTE), now, false));
        assert!(!sweepable_clone("access_t_x; DROP", now, false));
    }

    // OP-66
    #[test]
    fn stale_templates_are_swept() {
        let day = 86_400.0;
        let current = "access_tpl_00000000000000aa";
        let other = "access_tpl_00000000000000bb";
        assert!(sweepable_template(other, current, false, day + 1.0));
        assert!(sweepable_template(
            &format!("{other}_building"),
            current,
            false,
            day + 1.0
        ));
        assert!(!sweepable_template(other, current, false, day - 1.0));
        assert!(!sweepable_template(other, current, true, 10.0 * day));
        assert!(!sweepable_template(current, current, false, 10.0 * day));
    }
}

/// A step of a deletion a test moves into the past (OP-153 m.3 (bb)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeletionStep {
    /// The end of the cancellation window.
    Effective,
    /// The end of the destruction delay.
    DestroyAfter,
}

/// Moves `step` of the subject's deletion one second into the past, as time would: the table
/// lets each step be written once, so the owner lifts its trigger for the change.
///
/// # Errors
/// [`TestDbError`].
pub async fn age_deletion(
    db: &TestDb,
    subject: [u8; 16],
    step: DeletionStep,
) -> Result<(), TestDbError> {
    let column = match step {
        DeletionStep::Effective => {
            "requested_at = clock_timestamp() - interval '2 seconds', effective_at"
        }
        DeletionStep::DestroyAfter => {
            "deleted_at = clock_timestamp() - interval '25 hours', destroy_after"
        }
    };
    let mut c = db.owner.acquire().await.at("acquire owner")?;
    exec(
        &mut c,
        String::from(
            "ALTER TABLE access.identity_deletion_facts DISABLE TRIGGER deletion_fact_transition",
        ),
        "lift trigger",
    )
    .await?;
    sqlx::query(AssertSqlSafe(format!(
        "UPDATE access.identity_deletion_facts SET {column} = clock_timestamp() - interval '1 second' \
         WHERE subject_id = $1"
    )))
    .bind(sqlx::types::Uuid::from_bytes(subject))
    .execute(&mut *c)
    .await
    .at("age deletion")?;
    exec(
        &mut c,
        String::from(
            "ALTER TABLE access.identity_deletion_facts ENABLE TRIGGER deletion_fact_transition",
        ),
        "restore trigger",
    )
    .await
}

/// Moves the end of every throttle, cooling or grace period of the attempt one second into the
/// past, as time would (TN-55): the transitions only grow, so the owner lifts their trigger for
/// the change.
///
/// # Errors
/// [`TestDbError`].
pub async fn age_recovery(db: &TestDb, attempt: [u8; 16]) -> Result<(), TestDbError> {
    let mut c = db.owner.acquire().await.at("acquire owner")?;
    exec(
        &mut c,
        String::from("ALTER TABLE access.recovery_transitions DISABLE TRIGGER append_only_row"),
        "lift trigger",
    )
    .await?;
    sqlx::query(
        "UPDATE access.recovery_transitions SET until = clock_timestamp() - interval '1 second', \
         at = LEAST(at, clock_timestamp() - interval '2 seconds') \
         WHERE attempt_id = $1 AND until IS NOT NULL",
    )
    .bind(sqlx::types::Uuid::from_bytes(attempt))
    .execute(&mut *c)
    .await
    .at("age recovery")?;
    exec(
        &mut c,
        String::from("ALTER TABLE access.recovery_transitions ENABLE TRIGGER append_only_row"),
        "restore trigger",
    )
    .await
}

/// Moves every record time of `domain` and its head `ms` into the past, as time would: a CT3
/// time-lock counted from an opening and the 24 hours of a new Instance (SEC18) then run out.
/// The leaves keep their hashes; only the times readers count from move.
///
/// # Errors
/// [`TestDbError`].
pub async fn age_authority(db: &TestDb, domain: [u8; 32], ms: u64) -> Result<(), TestDbError> {
    let ms = i64::try_from(ms).unwrap_or(i64::MAX);
    let mut t = db.owner.begin().await.at("begin owner")?;
    let hex = domain.iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    });
    sqlx::query("SELECT set_config('app.domain_id', $1, true)")
        .bind(hex)
        .execute(&mut *t)
        .await
        .at("domain scope")?;
    for statement in [
        "ALTER TABLE access.authority_log DISABLE TRIGGER append_only_row",
        "ALTER TABLE access.authority_log_default DISABLE TRIGGER append_only_row",
    ] {
        sqlx::query(statement)
            .execute(&mut *t)
            .await
            .at("lift trigger")?;
    }
    for statement in [
        "UPDATE access.authority_log SET recorded_at = GREATEST(recorded_at - $2, 0) \
         WHERE domain_id = $1",
        "UPDATE access.domain_head SET recorded_at = GREATEST(recorded_at - $2, 0) \
         WHERE domain_id = $1",
    ] {
        let done = sqlx::query(statement)
            .bind(domain.as_slice())
            .bind(ms)
            .execute(&mut *t)
            .await
            .at("age authority")?;
        if done.rows_affected() == 0 {
            return Err(TestDbError::Db("age authority", sqlx::Error::RowNotFound));
        }
    }
    for statement in [
        "ALTER TABLE access.authority_log ENABLE TRIGGER append_only_row",
        "ALTER TABLE access.authority_log_default ENABLE TRIGGER append_only_row",
    ] {
        sqlx::query(statement)
            .execute(&mut *t)
            .await
            .at("restore trigger")?;
    }
    t.commit().await.at("commit")
}

/// Tries to rewrite every recovery step as the schema owner, triggers in force: the record only
/// grows, so this fails (OP-73, TN-54).
///
/// # Errors
/// [`TestDbError`] carrying the database's refusal.
pub async fn rewrite_recovery_steps(db: &TestDb) -> Result<(), TestDbError> {
    let mut c = db.owner.acquire().await.at("acquire owner")?;
    exec(
        &mut c,
        String::from("UPDATE access.recovery_transitions SET reason = 'rewritten'"),
        "rewrite recovery steps",
    )
    .await
}

/// Marks `subject`'s live memberships as break-glass, as a committed
/// `idp.org.member_breakglass` at position 1 would (OP-157 m.3 (h)).
///
/// # Errors
/// [`TestDbError`].
pub async fn mark_breakglass(db: &TestDb, subject: [u8; 16]) -> Result<(), TestDbError> {
    sqlx::query(
        "UPDATE access.org_memberships SET is_breakglass = true, breakglass_position = 1,
                breakglass_marked_at = clock_timestamp()
          WHERE subject_id = $1 AND ended_at IS NULL",
    )
    .bind(sqlx::types::Uuid::from_bytes(subject))
    .execute(&db.owner)
    .await
    .at("mark break-glass")?;
    Ok(())
}

fn audit_partition_name(name: &str) -> Result<&str, TestDbError> {
    if name.starts_with("identity_audit_")
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        Ok(name)
    } else {
        Err(TestDbError::Db(
            "audit partition name",
            sqlx::Error::Protocol(String::from("not an audit partition")),
        ))
    }
}

async fn admin_connection(db: &TestDb) -> Result<PgConnection, TestDbError> {
    PgConnection::connect_with(&db.admin)
        .await
        .at("connect admin")
}

/// Writes identity audit row `n` of `tenant` (its realm the same id) at `at` (RFC 3339), as a
/// row of a past month would be (OP-158 m.3 (w)).
///
/// # Errors
/// [`TestDbError`].
pub async fn past_audit_row(
    db: &TestDb,
    tenant: [u8; 16],
    at: &str,
    n: u32,
) -> Result<(), TestDbError> {
    let mut c = admin_connection(db).await?;
    sqlx::query(
        "INSERT INTO access.identity_audit (tenant_id, realm_id, at, event_type, actor, target, correlation)
         VALUES ($1, $1, $2::timestamptz, 'session.created', 'usr_1', $3, $4)",
    )
    .bind(sqlx::types::Uuid::from_bytes(tenant))
    .bind(at)
    .bind(format!("ses_{n}"))
    .bind(format!("req_{n}"))
    .execute(&mut c)
    .await
    .at("past audit row")?;
    Ok(())
}

/// Sets `tenant`'s audit hot window directly; the database refuses one under 30 days.
///
/// # Errors
/// [`TestDbError`] carrying the refusal.
pub async fn set_audit_hot_days(
    db: &TestDb,
    tenant: [u8; 16],
    days: i32,
) -> Result<(), TestDbError> {
    let mut c = admin_connection(db).await?;
    sqlx::query("UPDATE access.tenants SET audit_hot_days = $2 WHERE tenant_id = $1")
        .bind(sqlx::types::Uuid::from_bytes(tenant))
        .bind(days)
        .execute(&mut c)
        .await
        .at("set hot days")?;
    Ok(())
}

/// Rows of `access.identity_audit` in month `YYYY-MM`.
///
/// # Errors
/// [`TestDbError`].
pub async fn hot_audit_rows(db: &TestDb, month: &str) -> Result<i64, TestDbError> {
    let mut c = admin_connection(db).await?;
    sqlx::query_scalar(
        "SELECT count(*) FROM access.identity_audit WHERE to_char(at, 'YYYY-MM') = $1",
    )
    .bind(month)
    .fetch_one(&mut c)
    .await
    .at("hot rows")
}

/// Rows of the detached partition `name` in `access_audit_cold`.
///
/// # Errors
/// [`TestDbError`].
pub async fn cold_audit_rows(db: &TestDb, name: &str) -> Result<i64, TestDbError> {
    let name = audit_partition_name(name)?;
    let mut c = admin_connection(db).await?;
    sqlx::query_scalar(AssertSqlSafe(format!(
        "SELECT count(*) FROM access_audit_cold.{name}"
    )))
    .fetch_one(&mut c)
    .await
    .at("cold rows")
}

/// Tries to rewrite every row of the detached partition `name`, as the database administrator.
///
/// # Errors
/// [`TestDbError`] carrying the refusal.
pub async fn rewrite_cold_audit(db: &TestDb, name: &str) -> Result<(), TestDbError> {
    let name = audit_partition_name(name)?;
    let mut c = admin_connection(db).await?;
    exec(
        &mut c,
        format!("UPDATE access_audit_cold.{name} SET actor = 'rewritten'"),
        "rewrite cold rows",
    )
    .await
}

/// Tries to read the detached partition `name` as the application role.
///
/// # Errors
/// [`TestDbError`] carrying the refusal.
pub async fn app_reads_cold_audit(db: &TestDb, name: &str) -> Result<(), TestDbError> {
    let name = audit_partition_name(name)?;
    sqlx::query(AssertSqlSafe(format!(
        "SELECT count(*) FROM access_audit_cold.{name}"
    )))
    .execute(&db.app)
    .await
    .at("app reads cold")?;
    Ok(())
}

/// The cluster's `server_version`, for measurements that print their environment (OP-158 m.3 (z)).
///
/// # Errors
/// [`TestDbError`].
pub async fn server_version(db: &TestDb) -> Result<String, TestDbError> {
    sqlx::query_scalar("SHOW server_version")
        .fetch_one(&db.app)
        .await
        .at("server version")
}

/// Writes `n` identity audit rows of `tenant` (its realm the same id) in one transaction, as a
/// busy cell would (OP-158 m.3 (w)).
///
/// # Errors
/// [`TestDbError`].
pub async fn bulk_audit_rows(db: &TestDb, tenant: [u8; 16], n: i32) -> Result<(), TestDbError> {
    let mut c = admin_connection(db).await?;
    sqlx::query(
        "INSERT INTO access.identity_audit (tenant_id, realm_id, event_type, actor, target, correlation)
         SELECT $1, $1, 'session.created', 'usr_1', 'ses_' || g, 'req_' || g FROM generate_series(1, $2) g",
    )
    .bind(sqlx::types::Uuid::from_bytes(tenant))
    .bind(n)
    .execute(&mut c)
    .await
    .at("bulk audit rows")?;
    Ok(())
}

/// Moves every identity audit checkpoint `years` years into the past, as time would: the table
/// only grows, so the administrator lifts its trigger for the change.
///
/// # Errors
/// [`TestDbError`].
pub async fn age_audit_checkpoints(db: &TestDb, years: i32) -> Result<(), TestDbError> {
    let mut c = admin_connection(db).await?;
    exec(
        &mut c,
        String::from("ALTER TABLE access_ops.audit_checkpoint DISABLE TRIGGER append_only_row"),
        "lift trigger",
    )
    .await?;
    sqlx::query(
        "UPDATE access_ops.audit_checkpoint SET created_at = created_at - make_interval(years => $1)",
    )
    .bind(years)
    .execute(&mut c)
    .await
    .at("age checkpoints")?;
    exec(
        &mut c,
        String::from("ALTER TABLE access_ops.audit_checkpoint ENABLE TRIGGER append_only_row"),
        "restore trigger",
    )
    .await
}

/// What a backup taken before a destruction holds of one subject: its status and wrapped keys.
#[derive(Clone, Debug)]
pub struct SubjectBackup {
    tenant: sqlx::types::Uuid,
    realm: sqlx::types::Uuid,
    subject: sqlx::types::Uuid,
    status: String,
    own: Option<Vec<u8>>,
    classes: Vec<(String, Option<Vec<u8>>)>,
}

/// Reads `subject`'s status and wrapped keys as a backup would hold them (OP-42).
///
/// # Errors
/// [`TestDbError`].
pub async fn backup_subject(
    db: &TestDb,
    tenant: [u8; 16],
    realm: [u8; 16],
    subject: [u8; 16],
) -> Result<SubjectBackup, TestDbError> {
    use sqlx::Row as _;
    let (t, r, s) = (
        sqlx::types::Uuid::from_bytes(tenant),
        sqlx::types::Uuid::from_bytes(realm),
        sqlx::types::Uuid::from_bytes(subject),
    );
    let mut c = admin_connection(db).await?;
    let row = sqlx::query(
        "SELECT status, wrapped_dek FROM access.identity_subjects
          WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3",
    )
    .bind(t)
    .bind(r)
    .bind(s)
    .fetch_one(&mut c)
    .await
    .at("backup subject")?;
    let classes = sqlx::query(
        "SELECT class, wrapped_dek FROM access.identity_subject_keys
          WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 ORDER BY class",
    )
    .bind(t)
    .bind(r)
    .bind(s)
    .fetch_all(&mut c)
    .await
    .at("backup subject keys")?
    .iter()
    .map(|k| (k.get::<String, _>(0), k.get::<Option<Vec<u8>>, _>(1)))
    .collect();
    Ok(SubjectBackup {
        tenant: t,
        realm: r,
        subject: s,
        status: row.get(0),
        own: row.get(1),
        classes,
    })
}

/// Puts `backup` back, as restoring a backup taken before the destruction would: the
/// administrator lifts the tables' transition triggers for it.
///
/// # Errors
/// [`TestDbError`].
pub async fn restore_subject(db: &TestDb, backup: &SubjectBackup) -> Result<(), TestDbError> {
    let mut c = admin_connection(db).await?;
    for t in [
        "ALTER TABLE access.identity_subjects DISABLE TRIGGER subject_transition",
        "ALTER TABLE access.identity_subject_keys DISABLE TRIGGER subject_key_transition",
    ] {
        exec(&mut c, String::from(t), "lift trigger").await?;
    }
    sqlx::query(
        "UPDATE access.identity_subjects SET status = $4, wrapped_dek = $5,
                shredded_at = CASE WHEN $5::bytea IS NULL THEN shredded_at END
          WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3",
    )
    .bind(backup.tenant)
    .bind(backup.realm)
    .bind(backup.subject)
    .bind(&backup.status)
    .bind(&backup.own)
    .execute(&mut c)
    .await
    .at("restore subject")?;
    for (class, wrapped) in &backup.classes {
        sqlx::query(
            "UPDATE access.identity_subject_keys SET wrapped_dek = $5,
                    shredded_at = CASE WHEN $5::bytea IS NULL THEN shredded_at END
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND class = $4",
        )
        .bind(backup.tenant)
        .bind(backup.realm)
        .bind(backup.subject)
        .bind(class)
        .bind(wrapped)
        .execute(&mut c)
        .await
        .at("restore subject key")?;
    }
    for t in [
        "ALTER TABLE access.identity_subjects ENABLE TRIGGER subject_transition",
        "ALTER TABLE access.identity_subject_keys ENABLE TRIGGER subject_key_transition",
    ] {
        exec(&mut c, String::from(t), "restore trigger").await?;
    }
    Ok(())
}

/// The plain SQL dump of the test database `name`, as `pg_dump` writes a backup of it (CR-35).
/// It blocks; call it off the runtime.
///
/// # Errors
/// [`TestDbError`] when `pg_dump` cannot run or fails.
pub fn dump(name: &str) -> Result<String, TestDbError> {
    let url = std::env::var("DATABASE_URL").map_err(|_| TestDbError::NoDatabaseUrl)?;
    let base = url.rsplit_once('/').map_or(url.as_str(), |(b, _)| b);
    let out = std::process::Command::new("pg_dump")
        .arg("--no-owner")
        .arg("--no-privileges")
        .arg(format!("{base}/{name}"))
        .output()
        .map_err(|e| TestDbError::Db("pg_dump", sqlx::Error::Io(e)))?;
    if !out.status.success() {
        return Err(TestDbError::Db(
            "pg_dump",
            sqlx::Error::Protocol(String::from_utf8_lossy(&out.stderr).into_owned()),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Copies the hot nonce row of `nonce` in `domain` into the nonce archive under `archived`, a
/// nonce the hot rows do not hold, as the archive of a nonce past the hot horizon would hold it
/// (TI-RT3, OP-158 m.3 (u)).
///
/// # Errors
/// [`TestDbError`].
pub async fn archive_only_nonce(
    db: &TestDb,
    domain: [u8; 32],
    nonce: &[u8],
    archived: &[u8],
) -> Result<(), TestDbError> {
    let mut c = admin_connection(db).await?;
    let done = sqlx::query(
        "INSERT INTO access.authority_nonce_archive
           (domain_id, tenant_id, nonce, actor, intent_digest, decision_pos, outcome, render_digest, tier)
         SELECT domain_id, tenant_id, $3, actor, intent_digest, decision_pos, outcome, render_digest, tier
           FROM access.authority_nonce WHERE domain_id = $1 AND nonce = $2",
    )
    .bind(domain.as_slice())
    .bind(nonce)
    .bind(archived)
    .execute(&mut c)
    .await
    .at("archive only nonce")?;
    if done.rows_affected() == 0 {
        return Err(TestDbError::Db(
            "archive only nonce",
            sqlx::Error::RowNotFound,
        ));
    }
    Ok(())
}

/// A superuser pool on `db`, for the restore drill's schema check (OP-57 item 4).
///
/// # Errors
/// [`TestDbError`].
pub async fn superuser(db: &TestDb) -> Result<PgPool, TestDbError> {
    PgPoolOptions::new()
        .max_connections(1)
        .connect_with(db.admin.clone())
        .await
        .at("connect as administrator")
}

/// How many operational authority audit rows of `event` there are, with `target` when given
/// (OP-41, OP-158 m.3 (n), (r)).
///
/// # Errors
/// [`TestDbError`].
pub async fn authority_events(
    db: &TestDb,
    event: &str,
    target: Option<&str>,
) -> Result<i64, TestDbError> {
    let mut c = PgConnection::connect_with(&db.admin)
        .await
        .at("connect as administrator")?;
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM access_ops.authority_audit
          WHERE event_type = $1 AND ($2::text IS NULL OR target = $2)",
    )
    .bind(event)
    .bind(target)
    .fetch_one(&mut c)
    .await
    .at("authority audit rows")?;
    c.close().await.at("close")?;
    Ok(n)
}

/// Switches to a new WAL segment and returns the name of the one just closed, so it is
/// archived (OP-57, the PITR drill).
///
/// # Errors
/// [`TestDbError`].
pub async fn switch_wal(db: &TestDb) -> Result<String, TestDbError> {
    Ok(admin_text(db, "SELECT pg_walfile_name(pg_switch_wal())")
        .await?
        .unwrap_or_default())
}

/// The newest archived WAL segment's name; empty before the first.
///
/// # Errors
/// [`TestDbError`].
pub async fn archived_wal(db: &TestDb) -> Result<String, TestDbError> {
    Ok(admin_text(
        db,
        "SELECT coalesce(last_archived_wal, '') FROM pg_stat_archiver",
    )
    .await?
    .unwrap_or_default())
}

/// The server's clock as PostgreSQL writes a timestamp, for a recovery target.
///
/// # Errors
/// [`TestDbError`].
pub async fn clock_text(db: &TestDb) -> Result<String, TestDbError> {
    Ok(admin_text(db, "SELECT clock_timestamp()::text")
        .await?
        .unwrap_or_default())
}

/// Cuts the database off as an outage would (OP-158 m.3 (t), §16.7.1): no new connection is
/// accepted and every open one is ended, so every pool's next statement fails. `false` lets
/// connections in again. Other databases of the cluster are untouched.
///
/// # Errors
/// [`TestDbError`].
pub async fn refuse_connections(db: &TestDb, refuse: bool) -> Result<(), TestDbError> {
    let mut c = PgConnection::connect_with(&db.admin.clone().database("postgres"))
        .await
        .at("connect admin")?;
    let allow = if refuse { "false" } else { "true" };
    exec(
        &mut c,
        format!(
            "ALTER DATABASE \"{}\" WITH ALLOW_CONNECTIONS {allow}",
            db.name.replace('"', "")
        ),
        "allow connections",
    )
    .await?;
    if refuse {
        sqlx::query(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()",
        )
        .bind(&db.name)
        .execute(&mut c)
        .await
        .at("terminate")?;
    }
    Ok(())
}
