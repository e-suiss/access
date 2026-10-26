//! Test databases (OP-66): one migrated template per migration set, one clone per test, and
//! connections as the application, sequencer and owner roles, never as the superuser
//! (OP-130 m.2).

use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{AssertSqlSafe, Connection, Executor, PgConnection, PgPool};

/// Password of the test login roles; the test cluster is local or CI-only.
const TEST_PASSWORD: &str = "test-only-not-a-secret";

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
    // The names in `sql` are generated here, never taken from input.
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

async fn build_template(
    c: &mut PgConnection,
    admin: &PgConnectOptions,
    template: &str,
) -> Result<(), TestDbError> {
    c.execute(super::BOOTSTRAP_ROLES)
        .await
        .at("bootstrap roles")?;
    for (login, role) in [
        ("access_test_app", "access_app"),
        ("access_test_sequencer", "access_sequencer"),
        ("access_test_migrator", "access_migrator"),
    ] {
        let sql = format!(
            "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{login}') THEN \
             CREATE ROLE {login} LOGIN NOBYPASSRLS PASSWORD '{TEST_PASSWORD}' IN ROLE {role}; END IF; END $$"
        );
        exec(c, sql, "test login role").await?;
    }
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
    let built = if exists {
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
    let admin = admin_options()?;
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
    Ok(TestDb {
        app: pool(&admin, &name, "access_test_app").await?,
        sequencer: pool(&admin, &name, "access_test_sequencer").await?,
        owner: pool(&admin, &name, "access_test_migrator").await?,
        admin: admin.database(&name),
        name,
    })
}
