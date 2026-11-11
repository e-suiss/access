//! Opening the database safely (OP-52, OP-53, OP-130 m.10, OP-131 m.4): TLS with full
//! verification against an explicit root, SCRAM only, PostgreSQL 18 or later, bounded
//! transactions, and one pool per role whose sizes fit the server. The cell's durability is
//! checked before anything is served (OP-24, OP-28, OP-158 m.3 (n)): a synchronous quorum of at
//! least two standbys in other zones, `synchronous_commit = on` on every security connection, no
//! logical replication or multi-primary writing into the canonical store. Pools follow the
//! writable host across a failover (OP-26, OP-88).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};

use crate::StoreError;

/// Oldest server major version accepted (OP-7).
pub const MIN_SERVER_VERSION: i32 = 180_000;

/// Longest transaction of an application role (OP-131 m.4, PD).
pub const TRANSACTION_TIMEOUT: &str = "30s";

/// Longest idle-in-transaction pause (OP-131 m.4, PD).
pub const IDLE_IN_TRANSACTION_TIMEOUT: &str = "10s";

/// Share of `max_connections` the pools may take together (OP-53).
pub const POOL_SHARE_PERCENT: u32 = 70;

/// Where and as whom to connect.
pub struct Target<'a> {
    /// Server host name, checked against its certificate.
    pub host: &'a str,
    /// Port.
    pub port: u16,
    /// Database.
    pub database: &'a str,
    /// Login role.
    pub user: &'a str,
    /// Its password, read from a credential file by the caller.
    pub password: &'a str,
    /// PEM of the root the server certificate must chain to, read before the lockdown.
    pub root_cert: &'a [u8],
}

/// Why the database is not safe to use; the process does not start (OP-52).
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    /// The server refused or the query failed.
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
    /// Server older than PostgreSQL 18.
    #[error("server version {0} is older than PostgreSQL 18")]
    Version(i32),
    /// Passwords are not stored as SCRAM.
    #[error("password_encryption is {0}, not scram-sha-256")]
    Scram(String),
    /// The connection is not encrypted.
    #[error("the connection does not use TLS")]
    NoTls,
    /// A commit may be acknowledged before it is durable (U51, OP-24).
    #[error(
        "synchronous_commit is {commit} with standbys {standbys:?}; commits must wait for durability"
    )]
    Durability {
        /// `synchronous_commit`.
        commit: String,
        /// `synchronous_standby_names`.
        standbys: String,
    },
    /// `synchronous_standby_names` is not a quorum of two or more standbys (OP-24, OP-54-RL6).
    #[error(
        "synchronous_standby_names is {0:?}; it must be ANY k of at least two standbys, more than k"
    )]
    Quorum(String),
    /// Logical replication or a multi-primary extension writes into the canonical store
    /// (OPI-5, OP-54-RL3, OP-54-RL4).
    #[error("{0} writes into the canonical store; last-writer-wins and multi-primary are refused")]
    MultiWriter(String),
    /// The declared standbys do not give zone or region safety (OP-24, OP-28, OP-54-RL5).
    #[error("topology: {0}")]
    Topology(String),
    /// No candidate host accepts writes (OP-26, OP-88).
    #[error("no writable host among {0:?}")]
    NoWritable(Vec<String>),
    /// The pools would take more than their share of `max_connections`.
    #[error(
        "pools need {need} connections, more than {POOL_SHARE_PERCENT}% of max_connections ({max})"
    )]
    PoolSize {
        /// Connections the pools need.
        need: u32,
        /// `max_connections`.
        max: u32,
    },
}

/// Connection options: `verify-full` against `root_cert`, the timeouts as startup parameters.
#[must_use]
pub fn options(t: &Target<'_>) -> PgConnectOptions {
    PgConnectOptions::new()
        .host(t.host)
        .port(t.port)
        .database(t.database)
        .username(t.user)
        .password(t.password)
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert_from_pem(t.root_cert.to_vec())
        .application_name("access")
        .options([
            // OP-24, OP-54-RL6
            ("synchronous_commit", "on"),
            ("transaction_timeout", TRANSACTION_TIMEOUT),
            (
                "idle_in_transaction_session_timeout",
                IDLE_IN_TRANSACTION_TIMEOUT,
            ),
        ])
}

/// A pool of `size` connections with a short acquire timeout; the queue lives in the
/// application (OP-53).
///
/// # Errors
/// [`ConnectError::Db`].
pub async fn pool(opts: PgConnectOptions, size: u32) -> Result<PgPool, ConnectError> {
    Ok(PgPoolOptions::new()
        .max_connections(size)
        .min_connections(size.min(2))
        .acquire_timeout(Duration::from_secs(2))
        .connect_with(opts)
        .await?)
}

/// Whether the pool hands out a connection that answers a ping: the readiness check of a pool
/// (OP-67 m.3). The caller bounds it with its own deadline.
pub async fn ping(pool: &PgPool) -> bool {
    use sqlx::Connection as _;
    match pool.acquire().await {
        Ok(mut conn) => conn.ping().await.is_ok(),
        Err(_) => false,
    }
}

/// Whether a `server_version_num` is supported.
#[must_use]
pub const fn supported(version: i32) -> bool {
    version >= MIN_SERVER_VERSION
}

/// Whether `pools` connections fit `max_connections`.
#[must_use]
pub const fn fits(pools: u32, max_connections: u32) -> bool {
    (pools as u64).saturating_mul(100)
        <= (max_connections as u64).saturating_mul(POOL_SHARE_PERCENT as u64)
}

/// How the deployment declares its durability (OP-24, OP-48).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Durability {
    /// Synchronous standbys required (`synchronous_standby_names` set).
    Replicated,
    /// The small-provider `durability: single-node` declaration (HL-40).
    SingleNode,
}

/// A parsed `synchronous_standby_names` (OP-24).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Quorum {
    /// The standbys that must confirm each commit.
    pub k: u32,
    /// The candidate standbys, by `application_name`.
    pub names: Vec<String>,
}

fn standby_name(s: &str) -> Option<String> {
    let s = s.trim();
    let s = s
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(s);
    (!s.is_empty()
        && s != "*"
        && !s.contains([',', '(', ')', '"'])
        && !s.contains(char::is_whitespace))
    .then(|| s.to_owned())
}

/// Parses the quorum form `ANY k (a, b, ...)`; any other form (a priority list, `FIRST`, `*`)
/// is `None` (OP-24).
#[must_use]
pub fn quorum(setting: &str) -> Option<Quorum> {
    let rest = setting.trim();
    let rest = rest
        .get(..3)
        .filter(|w| w.eq_ignore_ascii_case("any"))
        .and_then(|_| rest.get(3..))?
        .trim_start();
    let open = rest.find('(')?;
    let k = rest.get(..open)?.trim().parse::<u32>().ok()?;
    let list = rest
        .get(open.checked_add(1)?..)?
        .trim_end()
        .strip_suffix(')')?;
    let names = list
        .split(',')
        .map(standby_name)
        .collect::<Option<Vec<_>>>()?;
    Some(Quorum { k, names })
}

/// Whether the settings acknowledge a commit only once it is durable as declared (U51, OP-24,
/// OP-54-RL6): `on` (or session `remote_apply`) everywhere, and in the replicated profile a
/// quorum of at least two standbys of which more than `k` are named, so losing one standby
/// neither loses an acknowledged write nor hangs every write.
///
/// # Errors
/// [`ConnectError::Durability`] or [`ConnectError::Quorum`].
pub fn check_durability(
    commit: &str,
    standbys: &str,
    durability: Durability,
) -> Result<Option<Quorum>, ConnectError> {
    if !matches!(commit, "on" | "remote_apply") {
        return Err(ConnectError::Durability {
            commit: commit.to_owned(),
            standbys: standbys.to_owned(),
        });
    }
    if durability == Durability::SingleNode {
        return Ok(None);
    }
    if standbys.trim().is_empty() {
        return Err(ConnectError::Durability {
            commit: commit.to_owned(),
            standbys: standbys.to_owned(),
        });
    }
    let q = quorum(standbys).ok_or_else(|| ConnectError::Quorum(standbys.to_owned()))?;
    let n = u32::try_from(q.names.len()).unwrap_or(u32::MAX);
    let distinct = q
        .names
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        == q.names.len();
    if q.k == 0 || n < 2 || n <= q.k || !distinct {
        return Err(ConnectError::Quorum(standbys.to_owned()));
    }
    Ok(Some(q))
}

/// The OP-28 ceiling on the round trip of a synchronous standby in another region.
pub const SYNC_RTT_CEILING_MS: u32 = 10;

/// Where a node of the cell runs (OP-24, OP-28).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Site {
    /// Availability zone.
    pub zone: String,
    /// Region.
    pub region: String,
}

/// A declared synchronous standby.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Standby {
    /// Its `application_name`.
    pub name: String,
    /// Where it runs.
    pub site: Site,
    /// Measured round trip from the primary, milliseconds.
    pub rtt_ms: Option<u32>,
}

/// The cell's declared topology.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Topology {
    /// Where the primary runs.
    pub primary: Site,
    /// The `multi-region sync` DR class: standbys in other regions under the round-trip ceiling.
    pub multi_region_sync: bool,
    /// The synchronous standbys.
    pub standbys: Vec<Standby>,
}

/// Checks the quorum against the declared topology (OP-24, OP-28, OP-54-RL5): every quorum
/// name is declared, every standby is in a zone of its own away from the primary's, and a
/// standby in another region is accepted only in the `multi-region sync` class and only under
/// [`SYNC_RTT_CEILING_MS`]; synchronous writing across continents is refused.
///
/// # Errors
/// [`ConnectError::Topology`].
pub fn check_topology(q: &Quorum, t: &Topology) -> Result<(), ConnectError> {
    let bad = |m: String| Err(ConnectError::Topology(m));
    let mut zones = std::collections::BTreeSet::from([t.primary.zone.as_str()]);
    for name in &q.names {
        let Some(s) = t.standbys.iter().find(|s| &s.name == name) else {
            return bad(format!("standby {name} is not declared"));
        };
        if !zones.insert(s.site.zone.as_str()) {
            return bad(format!("standby {name} shares zone {}", s.site.zone));
        }
        if s.site.region != t.primary.region {
            if !t.multi_region_sync {
                return bad(format!(
                    "standby {name} is in {}, the primary in {}: synchronous writing across regions needs the multi-region sync class",
                    s.site.region, t.primary.region
                ));
            }
            if s.rtt_ms.is_none_or(|r| r >= SYNC_RTT_CEILING_MS) {
                return bad(format!(
                    "standby {name} is not under the {SYNC_RTT_CEILING_MS} ms round trip of synchronous writing"
                ));
            }
        }
    }
    Ok(())
}

/// The extensions that make a PostgreSQL node one of several primaries (OPI-5, OP-54-RL4).
pub const MULTI_PRIMARY: [&str; 4] = ["bdr", "pglogical", "spock", "pgactive"];

/// Checks the server before the process serves anything (OP-52): version, SCRAM, TLS on this
/// connection, durable commits as declared, the declared topology, no other writer into the
/// canonical store, and room for `pools` connections.
///
/// # Errors
/// [`ConnectError`].
pub async fn check_server(
    pool: &PgPool,
    pools: u32,
    require_tls: bool,
    durability: Durability,
    topology: Option<&Topology>,
) -> Result<(), StoreError> {
    let row = sqlx::query!(
        r#"SELECT current_setting('server_version_num')::int AS "version!",
                  current_setting('password_encryption') AS "scram!",
                  current_setting('max_connections')::int AS "max!",
                  coalesce((SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()), false) AS "tls!",
                  current_setting('synchronous_commit') AS "commit!",
                  current_setting('synchronous_standby_names') AS "standbys!",
                  (SELECT count(*) FROM pg_subscription s
                     WHERE s.subdbid = (SELECT oid FROM pg_database WHERE datname = current_database())) AS "subscriptions!",
                  (SELECT string_agg(extname, ',' ORDER BY extname) FROM pg_extension
                     WHERE extname = ANY ($1::text[])) AS "multi_primary""#,
        &MULTI_PRIMARY.map(String::from),
    )
    .fetch_one(pool)
    .await?;
    let fail = |e: ConnectError| StoreError::Unsafe(e.to_string());
    if !supported(row.version) {
        return Err(fail(ConnectError::Version(row.version)));
    }
    if row.scram != "scram-sha-256" {
        return Err(fail(ConnectError::Scram(row.scram)));
    }
    if require_tls && !row.tls {
        return Err(fail(ConnectError::NoTls));
    }
    // U51, OP-24, OP-54-RL6
    let q = check_durability(&row.commit, &row.standbys, durability).map_err(fail)?;
    // OP-28, OP-54-RL5
    if let (Some(q), Some(t)) = (&q, topology) {
        check_topology(q, t).map_err(fail)?;
    }
    // OPI-5, OP-54-RL3
    if row.subscriptions > 0 {
        return Err(fail(ConnectError::MultiWriter(String::from(
            "a logical replication subscription",
        ))));
    }
    // OPI-5, OP-54-RL4
    if let Some(ext) = row.multi_primary {
        return Err(fail(ConnectError::MultiWriter(format!("extension {ext}"))));
    }
    let max = u32::try_from(row.max).map_err(|_| StoreError::Corrupt)?;
    if !fits(pools, max) {
        return Err(fail(ConnectError::PoolSize { need: pools, max }));
    }
    Ok(())
}

/// Whether the connection's server accepts writes: `pg_is_in_recovery()` is false (OP-88).
///
/// # Errors
/// [`StoreError::Db`].
pub async fn writable(conn: &mut sqlx::PgConnection) -> Result<bool, StoreError> {
    Ok(
        sqlx::query_scalar!(r#"SELECT NOT pg_is_in_recovery() AS "w!""#)
            .fetch_one(conn)
            .await?,
    )
}

/// The first of `hosts`, tried in order, that accepts writes (OP-26, OP-88): the
/// `target_session_attrs=read-write` semantics sqlx does not have.
///
/// # Errors
/// [`ConnectError::NoWritable`] when none answers as a primary.
pub async fn select_writable(
    base: &PgConnectOptions,
    hosts: &[String],
) -> Result<String, ConnectError> {
    use sqlx::Connection as _;
    for host in hosts {
        let Ok(Ok(mut c)) = tokio::time::timeout(
            PROBE_TIMEOUT,
            sqlx::PgConnection::connect_with(&at(base, host)),
        )
        .await
        else {
            continue;
        };
        let ok = matches!(
            tokio::time::timeout(PROBE_TIMEOUT, writable(&mut c)).await,
            Ok(Ok(true))
        );
        let _ = c.close().await;
        if ok {
            return Ok(host.clone());
        }
    }
    Err(ConnectError::NoWritable(hosts.to_vec()))
}

/// `base` pointed at `host`, written `name` or `name:port`.
fn at(base: &PgConnectOptions, host: &str) -> PgConnectOptions {
    match host
        .rsplit_once(':')
        .and_then(|(h, p)| Some((h, p.parse::<u16>().ok()?)))
    {
        Some((h, port)) => base.clone().host(h).port(port),
        None => base.clone().host(host),
    }
}

/// How long one probe of a candidate host may take (OP-26, PD).
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// The first wait after a failed probe round; it doubles up to [`BACKOFF_MAX`] (OP-26, PD).
pub const BACKOFF_MIN: Duration = Duration::from_millis(100);

/// The longest wait between probe rounds while no host accepts writes (OP-26, PD).
pub const BACKOFF_MAX: Duration = Duration::from_secs(5);

/// A pool that follows the writable host of the cell across a failover (OP-26, OP-88):
/// connections are opened only to a host that is not in recovery, and once the writable host
/// changes every connection opened before the change is evicted instead of handed out.
#[derive(Clone)]
pub struct Failover {
    pool: PgPool,
    base: PgConnectOptions,
    hosts: Vec<String>,
    current: Arc<std::sync::Mutex<String>>,
    origin: Instant,
    switched_ms: Arc<AtomicU64>,
}

impl Failover {
    /// Opens a pool of `size` on the first writable host of `hosts`, each `name` or `name:port`.
    ///
    /// # Errors
    /// [`ConnectError`].
    pub async fn open(
        base: PgConnectOptions,
        hosts: Vec<String>,
        size: u32,
    ) -> Result<Self, ConnectError> {
        let host = select_writable(&base, &hosts).await?;
        let origin = Instant::now();
        let switched_ms = Arc::new(AtomicU64::new(0));
        let since = switched_ms.clone();
        let pool = PgPoolOptions::new()
            .max_connections(size)
            .min_connections(size.min(2))
            .acquire_timeout(Duration::from_secs(2))
            .after_connect(|conn, _| {
                Box::pin(async move {
                    match writable(conn).await {
                        Ok(true) => Ok(()),
                        Ok(false) => Err(sqlx::Error::Protocol(String::from(
                            "the host is in recovery (OP-88)",
                        ))),
                        Err(_) => Err(sqlx::Error::Protocol(String::from(
                            "the host did not answer (OP-88)",
                        ))),
                    }
                })
            })
            .before_acquire(move |_, meta| {
                let switched = since.load(Ordering::SeqCst);
                let alive_ms = u64::try_from(origin.elapsed().as_millis()).unwrap_or(u64::MAX);
                let age_ms = u64::try_from(meta.age.as_millis()).unwrap_or(u64::MAX);
                let opened_at = alive_ms.saturating_sub(age_ms);
                Box::pin(async move { Ok(switched == 0 || opened_at >= switched) })
            })
            .connect_with(at(&base, &host))
            .await?;
        Ok(Self {
            pool,
            base,
            hosts,
            current: Arc::new(std::sync::Mutex::new(host)),
            origin,
            switched_ms,
        })
    }

    /// The pool; it stays the same object across failovers.
    #[must_use]
    pub fn pool(&self) -> PgPool {
        self.pool.clone()
    }

    /// The host connections are opened to now.
    #[must_use]
    pub fn host(&self) -> String {
        self.current.lock().map(|h| h.clone()).unwrap_or_default()
    }

    /// One health round: when the current host no longer accepts writes the pool moves to the
    /// one that does and evicts what it opened before. `Ok(Some(host))` after a move.
    ///
    /// # Errors
    /// [`ConnectError::NoWritable`] while no candidate accepts writes; the pool keeps its host,
    /// and its connections answer with errors, never with a read-only write (U32).
    pub async fn check(&self) -> Result<Option<String>, ConnectError> {
        let now = self.host();
        if select_writable(&self.base, std::slice::from_ref(&now))
            .await
            .is_ok()
        {
            return Ok(None);
        }
        let next = select_writable(&self.base, &self.hosts).await?;
        if next == now {
            return Ok(None);
        }
        self.pool.set_connect_options(at(&self.base, &next));
        let at = u64::try_from(self.origin.elapsed().as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        self.switched_ms.store(at, Ordering::SeqCst);
        if let Ok(mut h) = self.current.lock() {
            h.clone_from(&next);
        }
        tracing::warn!(
            event = "db.failover.followed",
            outcome = "moved",
            "the writable host changed; the pool follows it (OP-26)"
        );
        Ok(Some(next))
    }

    /// Runs [`Failover::check`] every `every`, backing off exponentially while no host
    /// accepts writes (OP-26).
    pub async fn watch(self, every: Duration) {
        let mut wait = every;
        loop {
            tokio::time::sleep(wait).await;
            wait = match self.check().await {
                Ok(_) => every,
                Err(_) => backoff(wait),
            };
        }
    }
}

/// The next wait after a failed round: double, between [`BACKOFF_MIN`] and [`BACKOFF_MAX`].
#[must_use]
pub fn backoff(last: Duration) -> Duration {
    last.saturating_mul(2).clamp(BACKOFF_MIN, BACKOFF_MAX)
}

/// Runs the migrations as a member of `access_migrator`, from the separate migration job and
/// never at application start (OP-55).
///
/// # Errors
/// [`StoreError`].
pub async fn migrate(migrator: &PgPool) -> Result<(), StoreError> {
    crate::MIGRATOR
        .run(migrator)
        .await
        .map_err(|e| StoreError::Unsafe(e.to_string()))
}

/// One migration a run applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Applied {
    /// Its version, the file name's timestamp.
    pub version: i64,
    /// Its description.
    pub description: String,
}

/// Runs the migrations as [`migrate`] does and returns the ones this run applied, in order
/// (OP-55, OP-138): the migration job prints them.
///
/// # Errors
/// [`StoreError`].
pub async fn migrate_listed(migrator: &PgPool) -> Result<Vec<Applied>, StoreError> {
    use sqlx::migrate::Migrate as _;
    let failed = |e: sqlx::migrate::MigrateError| StoreError::Unsafe(e.to_string());
    let table = &crate::MIGRATOR.table_name;
    let before: std::collections::BTreeSet<i64> = {
        let mut conn = migrator.acquire().await?;
        conn.ensure_migrations_table(table).await.map_err(failed)?;
        conn.list_applied_migrations(table)
            .await
            .map_err(failed)?
            .into_iter()
            .map(|m| m.version)
            .collect()
    };
    migrate(migrator).await?;
    Ok(crate::MIGRATOR
        .iter()
        .filter(|m| m.migration_type.is_up_migration() && !before.contains(&m.version))
        .map(|m| Applied {
            version: m.version,
            description: m.description.to_string(),
        })
        .collect())
}

/// The newest schema migration applied, read with the migration login (OP-55, OP-57 item 4).
///
/// # Errors
/// [`StoreError::Db`].
pub async fn applied_newest(migrator: &PgPool) -> Result<Option<i64>, StoreError> {
    Ok(
        sqlx::query_scalar!("SELECT max(version) FROM public._sqlx_migrations WHERE success")
            .fetch_one(migrator)
            .await?,
    )
}
