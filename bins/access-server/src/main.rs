//! Access server (OP-2). Thin by design: it reads configuration, installs
//! telemetry and composes crates; business logic lives in `crates/` (OP-62).
//!
//! The one-shot commands share the configuration and the lockdown: `access-server migrate`
//! runs the schema migrations as the migration role (OP-55); `access-server bootstrap
//! <plan.toml>` creates the platform tenant, sample tenants, platform clients and test fixtures
//! a local deployment starts from (OP-69, OP-149 m.21, m.26); `access-server client-update
//! <plan.toml> <product> <display name>` and `access-server client-retire <plan.toml> <product>`
//! commit an `idp.client.update` or `idp.client.retire` of a platform client, so a product sees
//! `api_client.updated` and `api_client.disabled` (OP-149 m.26 (c)). A command's standard
//! output is its result, so its logs go to standard error.

mod admin;
mod bootstrap;
mod checkpoints;
mod claims;
mod config;
mod console;
mod events;
mod idp;
mod ids;
mod ingest;
mod jobs;
mod login;
mod oauth;
mod platform;
mod product;
mod risk;
mod startup;
mod status;
#[cfg(test)]
mod testing;

use std::ffi::OsString;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use access_authority_core::adapters::{Domains, OsSalts, Setup};
use access_authority_sequencer::LEASE_TTL;
use access_authority_sequencer::adapters::SourcesClock;
use access_crypto::secret_file::SecretFile;
use access_http::adp::adapters::{Discovery, router as adp_router};
use access_http::adp::app::Service;
use access_http::api::app::{RequestIds, request_id};
use access_http::declarations::{Declarations, router as declared};
use access_http::internal::{Readiness, ReadyFlag, router as internal_router};
use access_http::login::{Assets, me_router, router as login_router};
use access_http::oauth::router as oauth_router;
use access_http::realm::router as realm_router;
use access_http::{Health, Limits, SandboxHealth, router};
use access_identity_account::adapters::system::{SystemClock, cgroup_memory_budget, cores};
use access_identity_account::app::hasher::{Hasher, HasherConfig};
use access_identity_account::app::local::LocalLimiter;
use access_identity_account::app::login::LoginGate;
use access_identity_account::domain::password::Argon2Params;
use access_identity_account::domain::throttle::ThrottlePolicy;
use access_identity_account::notify::delivery::Backoff;
use access_identity_oauth::adapters::clients::{CachePolicy, HttpClientKeys, HttpLogoutDelivery};
use access_identity_oauth::adapters::dpop::SystemClock as OAuthClock;
use access_identity_oauth::adapters::oauth::{OsRandom, PgLogoutQueue, PgOAuth};
use access_identity_oauth::adapters::outbound::{DeclaredTarget, Outbound};
use access_identity_oauth::adapters::{PgDirectory, SignerKeys};
use access_identity_oauth::app::Discovery as RealmDiscovery;
use access_identity_oauth::app::backchannel::Courier;
use access_identity_oauth::app::oauth::OAuth;
use access_identity_oauth::domain::dpop::DpopProfile;
use access_identity_oauth::domain::issuer::RealmBase;
use access_identity_ui::adapters::Outbox;
use access_identity_ui::app::{Devices, Hosted};
use access_identity_ui::domain::frontend::IDENTITY_PEP;
use access_identity_ui::ports::DeviceInstances;
use access_store::Pool;
use access_store::connect::{Target, check_server, options, pool};
use config::{Config, Durability, Role};
use suiss_crypto::pkcs11::KeyStore;
use suiss_sandbox::{LandlockAbi, Lockdown, LockdownReport, Profile};

/// What the resolver reads when the database host is a name (OP-141 m.18 (g)).
const RESOLVER: [&str; 5] = [
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/nsswitch.conf",
    "/etc/host.conf",
    "/etc/gai.conf",
];

/// Where the system's trust anchors usually are, for clients' own endpoints.
const SYSTEM_ROOTS: [&str; 3] = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
];

/// The deadline of one request to a client's endpoint (PD).
const OUTBOUND_TIMEOUT: Duration = Duration::from_secs(5);

/// Everything read from the file system before the lockdown closes it.
struct Prepared {
    tls: Arc<access_http::tls::ServerConfig>,
    root_cert: Vec<u8>,
    sequencer_password: SecretFile,
    app_password: SecretFile,
    deriver_password: SecretFile,
    router_password: SecretFile,
    archive_password: SecretFile,
    outbox_password: SecretFile,
    checkpointer_password: SecretFile,
    keys: KeyStore,
    login_keys: Arc<KeyStore>,
    identity_keys: Arc<KeyStore>,
    assets: Option<Assets>,
    console_assets: Option<Assets>,
    outbound: Outbound,
    /// OP-148: whether the TLS certificate covers the configured origins, read before the
    /// lockdown.
    tls_names: Result<(), String>,
}

/// The database pools of the server's roles.
struct Pools {
    sequencer: Pool,
    app: Pool,
    /// Admin search and listing (OP-27): the replica when one is configured, else `app`.
    reads: Pool,
    deriver: Pool,
    router: Pool,
    archive: Pool,
    outbox_reader: Pool,
    checkpointer: Pool,
}

/// What the process was asked to do.
enum Command {
    /// Serve (no arguments).
    Serve,
    /// `migrate`: apply the schema migrations and exit (OP-55).
    Migrate,
    /// A one-shot job over a local deployment's plan (OP-69, OP-149 m.26 (c)).
    Local(PathBuf, Job),
}

/// A one-shot job over the bootstrap plan.
enum Job {
    /// `bootstrap <plan.toml>`: make sure of a local deployment's tenants and exit (OP-69).
    Bootstrap,
    /// `client-update <plan.toml> <product> <display name>`: `idp.client.update`.
    ClientUpdate {
        product: String,
        display_name: String,
    },
    /// `client-retire <plan.toml> <product>`: `idp.client.retire`.
    ClientRetire { product: String },
}

fn text(arg: &OsString) -> Option<String> {
    arg.to_str().map(String::from)
}

fn command(args: &[OsString]) -> Option<Command> {
    match args {
        [] => Some(Command::Serve),
        [c] if c == "migrate" => Some(Command::Migrate),
        [c, plan] if c == "bootstrap" => Some(Command::Local(PathBuf::from(plan), Job::Bootstrap)),
        [c, plan, product, name] if c == "client-update" => Some(Command::Local(
            PathBuf::from(plan),
            Job::ClientUpdate {
                product: text(product)?,
                display_name: text(name)?,
            },
        )),
        [c, plan, product] if c == "client-retire" => Some(Command::Local(
            PathBuf::from(plan),
            Job::ClientRetire {
                product: text(product)?,
            },
        )),
        _ => None,
    }
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let Some(command) = command(&args) else {
        #[allow(clippy::print_stderr)]
        {
            eprintln!(
                "usage: access-server [migrate | bootstrap <plan.toml> | client-update <plan.toml> \
                 <product> <display name> | client-retire <plan.toml> <product>]"
            );
        }
        return ExitCode::FAILURE;
    };
    let config = match Config::load() {
        Ok(config) => config,
        Err(error) => {
            #[allow(clippy::print_stderr)]
            {
                eprintln!("access-server: invalid configuration: {error}");
            }
            return ExitCode::FAILURE;
        }
    };

    // OP-47, OP-67
    let mut settings =
        config
            .telemetry
            .config(&config.log, "access-server", env!("CARGO_PKG_VERSION"));
    let logged = match command {
        Command::Serve => access_telemetry::install(&settings, std::io::stdout),
        Command::Migrate | Command::Local(..) => {
            settings.otlp_endpoint = None;
            access_telemetry::install(&settings, std::io::stderr)
        }
    };
    let telemetry = match logged {
        Ok(telemetry) => telemetry,
        Err(error) => {
            #[allow(clippy::print_stderr)]
            {
                eprintln!("access-server: {error}");
            }
            return ExitCode::FAILURE;
        }
    };

    match command {
        Command::Serve => {
            let code = serve_main(&config, &telemetry);
            telemetry.shutdown();
            code
        }
        Command::Migrate => migrate_main(&config),
        Command::Local(plan, job) => local_main(&config, &plan, job),
    }
}

/// SA-22, OP-90: the lockdown, then the runtime, then the narrowed seccomp phase, as the server
/// does; the one-shot commands run under it too.
fn locked(config: &Config) -> Result<tokio::runtime::Runtime, String> {
    let locked = lockdown(config)
        .apply()
        .map_err(|e| format!("runtime lockdown failed; refusing to start (OP-90): {e}"))?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("cannot start the async runtime: {e}"))?;
    locked
        .narrow()
        .map_err(|e| format!("seccomp phase 2 failed: {e}"))?;
    Ok(runtime)
}

const fn durability(db: &config::Database) -> access_store::connect::Durability {
    match db.durability {
        Durability::Replicated => access_store::connect::Durability::Replicated,
        Durability::SingleNode => access_store::connect::Durability::SingleNode,
    }
}

/// The migration role's root certificate and password, read before the lockdown.
fn migrator_credentials(config: &Config) -> Result<(Vec<u8>, SecretFile), String> {
    let db = config.database.as_ref().ok_or("no database section")?;
    let role = db
        .migrator
        .as_ref()
        .ok_or("database.migrator is required to migrate (OP-55)")?;
    let root = std::fs::read(&db.root_cert_file)
        .map_err(|e| format!("{}: {e}", db.root_cert_file.display()))?;
    let password = SecretFile::load(&role.password_file).map_err(|e| e.to_string())?;
    Ok((root, password))
}

/// OP-55: the migrations as the migration role, from a command of their own and never at
/// server start. Applied migrations are skipped, so a second run changes nothing.
fn migrate(config: &Config) -> Result<(), String> {
    let (root, password) = migrator_credentials(config)?;
    let db = config.database.as_ref().ok_or("no database section")?;
    let role = db.migrator.as_ref().ok_or("no migrator")?;
    let runtime = locked(config)?;
    runtime.block_on(async {
        let target = Target {
            host: &db.host,
            port: db.port,
            database: &db.name,
            user: &role.user,
            password: password.value().expose(),
            root_cert: &root,
        };
        let migrator = pool(options(&target), 1)
            .await
            .map_err(|e| format!("{}: {e}", role.user))?;
        // OP-52
        check_server(&migrator, 1, true, durability(db))
            .await
            .map_err(|e| e.to_string())?;
        access_store::connect::migrate(&migrator)
            .await
            .map_err(|e| e.to_string())
    })
}

fn migrate_main(config: &Config) -> ExitCode {
    match migrate(config) {
        Ok(()) => {
            tracing::info!(
                migrations = access_store::MIGRATOR.iter().count(),
                "schema migrated (OP-55)"
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            tracing::error!(%error, "migration failed");
            ExitCode::FAILURE
        }
    }
}

/// OP-69, OP-149 m.21, m.26 (c): a plan job over the same pools, token and signers as the
/// server.
fn local(config: &Config, plan: &Path, job: Job) -> Result<serde_json::Value, String> {
    let plan = bootstrap::Plan::load(plan).map_err(|e| e.to_string())?;
    let prepared = prepare(config, tls_config(config)?)?;
    let runtime = locked(config)?;
    runtime.block_on(seed(config, prepared, &plan, job))
}

/// Runs a plan job; its result goes to standard output as JSON.
fn local_main(config: &Config, plan: &Path, job: Job) -> ExitCode {
    let result = local(config, plan, job)
        .and_then(|s| serde_json::to_string_pretty(&s).map_err(|e| e.to_string()));
    match result {
        Ok(json) => {
            #[allow(clippy::print_stdout)]
            {
                println!("{json}");
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            tracing::error!(%error, "the plan job failed");
            ExitCode::FAILURE
        }
    }
}

fn json<T: serde::Serialize>(value: T) -> Result<serde_json::Value, String> {
    serde_json::to_value(value).map_err(|e| e.to_string())
}

/// A plan job over this process's pools, token and signers.
async fn seed(
    config: &Config,
    prepared: Prepared,
    plan: &bootstrap::Plan,
    job: Job,
) -> Result<serde_json::Value, String> {
    let all = pools(config, &prepared).await?;
    let identity = config.identity.as_ref().ok_or("no identity section")?;
    let base = RealmBase::parse(&identity.realm_base).map_err(|e| e.to_string())?;
    let actors = idp::ActorBindings::default();
    let domains = Arc::new(Domains::new(Setup {
        sequencer: all.sequencer.clone(),
        app: all.app.clone(),
        keys: prepared.keys,
        holder: holder()?,
        ttl: LEASE_TTL,
        binding: actors.clone(),
        salts: OsSalts,
        clock: SourcesClock::new(all.sequencer.clone()),
        deriver: all.deriver.clone(),
        signer: config.signer.clone(),
        api_base: config.issuer.clone().ok_or("no issuer")?,
        // OP-105
        analysis: Arc::new(access_authority_core::ports::NoAnalysis),
    }));
    let plane = idp::Plane::new(
        domains.clone(),
        all.app.clone(),
        SourcesClock::new(all.sequencer.clone()),
        actors,
    );
    let keyring = idp::RealmKeyring::new(
        SignerKeys::new(identity.signer.clone()),
        prepared.identity_keys.clone(),
    );
    let declared = prepared.outbound.declared();
    let bootstrap = bootstrap::Bootstrap {
        app: &all.app,
        router: &all.router,
        plane: &plane,
        realm_keys: &keyring,
        hsm: &prepared.identity_keys,
        base: &base,
        declared: &declared,
        console: config.suiss.as_ref().map(|s| s.management_api.as_str()),
    };
    let result = match job {
        Job::Bootstrap => Box::pin(bootstrap.run(plan))
            .await
            .map_err(|e| e.to_string())
            .and_then(json),
        Job::ClientUpdate {
            product,
            display_name,
        } => bootstrap
            .change_product_client(
                plan,
                &product,
                bootstrap::local::ProductChange::Update { display_name },
            )
            .await
            .map_err(|e| e.to_string())
            .and_then(json),
        Job::ClientRetire { product } => bootstrap
            .change_product_client(plan, &product, bootstrap::local::ProductChange::Retire)
            .await
            .map_err(|e| e.to_string())
            .and_then(json),
    };
    // OP-31
    domains.release().await;
    result
}

fn serve_main(config: &Config, telemetry: &access_telemetry::Telemetry) -> ExitCode {
    // CR-12, OP-52: the TLS files are read before the lockdown closes the file system
    let tls = match tls_config(config) {
        Ok(tls) => tls,
        Err(error) => {
            tracing::error!(%error, "TLS configuration unusable; refusing to start (OP-52)");
            return ExitCode::FAILURE;
        }
    };
    // OP-129 m.3, OP-141 m.18 (g), (h)
    let prepared = match prepare(config, tls) {
        Ok(prepared) => prepared,
        Err(error) => {
            tracing::error!(%error, "credentials unusable; refusing to start (OP-52)");
            return ExitCode::FAILURE;
        }
    };

    // §14.5, OP-151 m.3 (b): the three listeners are bound before the lockdown closes bind
    let listeners = match Listeners::bind(config) {
        Ok(listeners) => listeners,
        Err(error) => {
            tracing::error!(%error, "cannot bind the listening sockets");
            return ExitCode::FAILURE;
        }
    };

    // SA-22, OP-90, OP-92
    let locked = match lockdown(config).apply() {
        Ok(locked) => locked,
        Err(error) => {
            tracing::error!(%error, "runtime lockdown failed; refusing to start (OP-90)");
            return ExitCode::FAILURE;
        }
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!(%error, "cannot start the async runtime");
            return ExitCode::FAILURE;
        }
    };

    let report = match locked.narrow() {
        Ok(report) => report,
        Err(error) => {
            tracing::error!(%error, "seccomp phase 2 failed; refusing to continue");
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(
        profile = report.profile.as_str(),
        seccomp_phase = report.seccomp_phase,
        landlock_required_abi = report.landlock_required_abi.as_u32(),
        landlock_kernel_abi = report.landlock_kernel_abi,
        "runtime lockdown in force"
    );

    let served = runtime.block_on(async {
        let exporting = export(telemetry);
        let served = serve(config, listeners, prepared, &report).await;
        if let Some(exporting) = exporting {
            exporting.abort();
        }
        served
    });
    match served {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "server stopped with an error");
            ExitCode::FAILURE
        }
    }
}

fn prepare(config: &Config, tls: Arc<access_http::tls::ServerConfig>) -> Result<Prepared, String> {
    let db = config.database.as_ref().ok_or("no database section")?;
    let hsm = config.hsm.as_ref().ok_or("no hsm section")?;
    let root_cert = std::fs::read(&db.root_cert_file)
        .map_err(|e| format!("{}: {e}", db.root_cert_file.display()))?;
    let password = |r: &Role| SecretFile::load(&r.password_file).map_err(|e| e.to_string());
    let pin = SecretFile::load(&hsm.pin_file).map_err(|e| e.to_string())?;
    let keys = KeyStore::open(&hsm.module, &hsm.token, pin.value()).map_err(|e| e.to_string())?;
    let login_keys =
        Arc::new(KeyStore::open(&hsm.module, &hsm.token, pin.value()).map_err(|e| e.to_string())?);
    let identity_keys =
        Arc::new(KeyStore::open(&hsm.module, &hsm.token, pin.value()).map_err(|e| e.to_string())?);
    // OP-146 m.12 (f): the built login app is read before the lockdown closes the file system
    let assets = config
        .login
        .dist_dir
        .as_deref()
        .map(Assets::load)
        .transpose()
        .map_err(|e| e.to_string())?;
    // TN-128: the built console, read before the lockdown as well
    let console_assets = config
        .console
        .dist_dir
        .as_deref()
        .map(Assets::load)
        .transpose()
        .map_err(|e| e.to_string())?;
    Ok(Prepared {
        tls,
        root_cert,
        sequencer_password: password(&db.sequencer)?,
        app_password: password(&db.app)?,
        deriver_password: password(&db.deriver)?,
        router_password: password(&db.router)?,
        archive_password: password(&db.archive)?,
        outbox_password: password(&db.outbox_reader)?,
        checkpointer_password: password(&db.checkpointer)?,
        keys,
        login_keys,
        identity_keys,
        assets,
        console_assets,
        outbound: outbound(config)?,
        tls_names: tls_names(config),
    })
}

/// OP-148, §17.9.6: the certificate covers the issuer and the management origin.
fn tls_names(config: &Config) -> Result<(), String> {
    let tls = config.tls.as_ref().ok_or("no tls section")?;
    let chain = std::fs::read(&tls.cert_file)
        .map_err(|e| format!("{}: {}", tls.cert_file.display(), e.kind()))?;
    startup::tls_names(config, &chain)
}

/// Requests to clients' own endpoints (§10.4.6, §11.3.6): the configured trust anchors, else
/// the system's; without either they fail and the server still starts. The declared delivery
/// targets and their own trust anchors are read here too (OP-149 m.23).
fn outbound(config: &Config) -> Result<Outbound, String> {
    let configured = config
        .identity
        .as_ref()
        .and_then(|i| i.outbound_ca_file.clone());
    let pem = match configured {
        Some(f) => Some(std::fs::read(&f).map_err(|e| format!("{}: {e}", f.display()))?),
        None => SYSTEM_ROOTS.iter().find_map(|f| std::fs::read(f).ok()),
    };
    let outbound = if let Some(pem) = pem {
        let tls = access_http::tls::client_config(&pem).map_err(|e| e.to_string())?;
        Outbound::new(tls, OUTBOUND_TIMEOUT)
    } else {
        tracing::warn!(
            "no trust anchors for clients' endpoints; jwks_uri and back-channel logout fail"
        );
        Outbound::disabled(OUTBOUND_TIMEOUT)
    };
    let declared = declared_targets(config)?;
    if !declared.is_empty() {
        let urls: Vec<&str> = declared.iter().map(DeclaredTarget::url).collect();
        tracing::info!(targets = ?urls, "declared delivery targets (OP-149 m.23)");
    }
    Ok(outbound.declaring(declared))
}

/// The operator's declared delivery targets, each with its own trust anchors when it names a
/// CA file (OP-149 m.23).
fn declared_targets(config: &Config) -> Result<Vec<DeclaredTarget>, String> {
    config
        .delivery_targets
        .iter()
        .map(|t| {
            let tls = t
                .ca_file
                .as_ref()
                .map(|f| {
                    let pem = std::fs::read(f).map_err(|e| format!("{}: {e}", f.display()))?;
                    access_http::tls::client_config(&pem)
                        .map_err(|e| format!("{}: {e}", f.display()))
                })
                .transpose()?;
            DeclaredTarget::new(&t.url, tls).map_err(|e| format!("{}: {e}", t.url))
        })
        .collect()
}

/// SA-22 with what the authority plane reaches after it (OP-141 m.18 (g), (h)).
fn lockdown(config: &Config) -> Lockdown {
    let mut lockdown = Lockdown::new(Profile::Server, LandlockAbi::REQUIRED);
    if let Some(db) = &config.database {
        lockdown = lockdown.allow_tcp_connect(db.port);
    }
    // §10.4.6, §11.3.6
    lockdown = lockdown.allow_tcp_connect(access_identity_oauth::adapters::outbound::PORT);
    // OP-67
    if let Some(port) = config.telemetry.otlp_port() {
        lockdown = lockdown.allow_tcp_connect(port);
    }
    // OP-149 m.23
    let mut declared: Vec<u16> = config
        .delivery_targets
        .iter()
        .filter_map(|t| DeclaredTarget::new(&t.url, None).ok().map(|t| t.port()))
        .filter(|p| *p != access_identity_oauth::adapters::outbound::PORT)
        .collect();
    declared.sort_unstable();
    declared.dedup();
    for port in declared {
        lockdown = lockdown.allow_tcp_connect(port);
    }
    for file in RESOLVER.iter().filter(|f| Path::new(f).exists()) {
        lockdown = lockdown.allow_read(file);
    }
    if let Some(hsm) = &config.hsm {
        for path in &hsm.paths {
            lockdown = lockdown.allow_read_write(path);
        }
    }
    // OP-151 m.1 (b): the MMDB file is read again when replaced, so its directory stays readable
    if let Some(dir) = config.risk.geo_mmdb_path.as_deref().and_then(Path::parent) {
        lockdown = lockdown.allow_read(dir);
    }
    if let Some(dir) = &config.risk.breach_ranges_dir {
        lockdown = lockdown.allow_read(dir);
    }
    lockdown
}

/// A fresh lease holder name: 16 random bytes in hex (OP-141 m.18 (a)).
fn holder() -> Result<String, String> {
    let bytes = access_crypto::random::bytes::<16>().map_err(|e| e.to_string())?;
    let mut out = String::with_capacity(32);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    Ok(out)
}

async fn pools(config: &Config, prepared: &Prepared) -> Result<Pools, String> {
    let db = config.database.as_ref().ok_or("no database section")?;
    let open = async |role: &Role, password: &SecretFile| {
        let target = Target {
            host: &db.host,
            port: db.port,
            database: &db.name,
            user: &role.user,
            password: password.value().expose(),
            root_cert: &prepared.root_cert,
        };
        pool(options(&target), role.pool)
            .await
            .map_err(|e| format!("{}: {e}", role.user))
    };
    let sequencer = open(&db.sequencer, &prepared.sequencer_password).await?;
    let app = open(&db.app, &prepared.app_password).await?;
    // OP-27: only admin search and listing read from the replica
    let reads = match &db.replica_host {
        Some(host) => {
            let target = Target {
                host,
                port: db.port,
                database: &db.name,
                user: &db.app.user,
                password: prepared.app_password.value().expose(),
                root_cert: &prepared.root_cert,
            };
            pool(options(&target), db.app.pool)
                .await
                .map_err(|e| format!("replica {}: {e}", db.app.user))?
        }
        None => app.clone(),
    };
    let deriver = open(&db.deriver, &prepared.deriver_password).await?;
    let router = open(&db.router, &prepared.router_password).await?;
    let archive = open(&db.archive, &prepared.archive_password).await?;
    let outbox_reader = open(&db.outbox_reader, &prepared.outbox_password).await?;
    let checkpointer = open(&db.checkpointer, &prepared.checkpointer_password).await?;
    let durability = durability(db);
    let total = db
        .sequencer
        .pool
        .saturating_add(db.app.pool)
        .saturating_add(db.deriver.pool)
        .saturating_add(db.router.pool)
        .saturating_add(db.archive.pool)
        .saturating_add(db.outbox_reader.pool)
        .saturating_add(db.checkpointer.pool);
    // OP-52
    for p in [
        &sequencer,
        &app,
        &deriver,
        &router,
        &archive,
        &outbox_reader,
        &checkpointer,
    ] {
        check_server(p, total, true, durability)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(Pools {
        sequencer,
        app,
        reads,
        deriver,
        router,
        archive,
        outbox_reader,
        checkpointer,
    })
}

/// The realm surface, once the identity plane's start-up checks pass: the signer answers,
/// every realm's issuer is the one the configuration forms and its JWKS loads (OP-138,
/// §17.9.6, §17.9.7, CMP-22b).
async fn identity(
    config: &Config,
    router: Pool,
    app: Pool,
    tls_names: Result<(), String>,
) -> Result<axum::Router, String> {
    let identity = config.identity.as_ref().ok_or("no identity section")?;
    let base = RealmBase::parse(&identity.realm_base).map_err(|e| e.to_string())?;
    let suiss = config.suiss.as_ref().ok_or("no suiss section")?;
    let api_base = config.issuer.as_deref().ok_or("no issuer")?;
    // OP-149 m.3
    // MD-10, §9.15.1 k.2: discovery also reads the realm's public sub opt-ins and its domain
    let discovery = RealmDiscovery::new(
        PgDirectory::new(router).with_facts(app),
        SignerKeys::new(identity.signer.clone()),
    )
    .with_suiss(suiss.settings(api_base));
    // OP-148, OP-138, MD-8: one report of every start-up check; any failure stops the start
    let mut report = startup::Report::default();
    report.record(
        "listeners",
        config::check_listeners(config).map_err(|e| e.to_string()),
    );
    report.record("tls-names", tls_names);
    report.record(
        "authority-signer",
        startup::authority_signer(config.signer.as_deref()).await,
    );
    startup::identity(&discovery.check(&base).await, &mut report);
    report.emit();
    report.into_result()?;
    Ok(realm_router(discovery))
}

/// The hosted login of this process.
type HostedLogin = Arc<Hosted<login::HsmKits, SystemClock, Outbox>>;

/// The Frontend API for products (OP-149 m.6, m.8, m.9) beside the hosted login: artifacts
/// signed by the identity signer, device Instances through the authority plane.
fn frontend<I, Q>(
    config: &Config,
    router: Pool,
    hosted: HostedLogin,
    plane: I,
    claims: Q,
) -> Result<axum::Router, String>
where
    I: DeviceInstances + access_identity_ui::ports::Approvals + Clone + 'static,
    Q: access_identity_ui::ports::ApprovalClaims + 'static,
{
    let identity = config.identity.as_ref().ok_or("no identity section")?;
    let me = me_router(
        RealmDiscovery::new(
            PgDirectory::new(router),
            SignerKeys::new(identity.signer.clone()),
        ),
        hosted,
        Devices {
            signer: SignerKeys::new(identity.signer.clone()),
            instances: plane.clone(),
            approvals: plane,
            claims,
            pep: String::from(IDENTITY_PEP),
        },
    );
    // OP-65, OP-67 m.1: the Frontend API answers with Request-Id too
    Ok(me.layer(axum::middleware::from_fn_with_state(
        RequestIds::new(Arc::new(admin::OsEntropy)),
        request_id,
    )))
}

/// The hosted login (OP-146 m.12): the request's `Host` selects the realm as for discovery;
/// realm keys come from the HSM on first use.
fn login(
    config: &Config,
    router: Pool,
    app: Pool,
    products: Pool,
    keks: login::RealmKeks,
    assets: Option<Assets>,
    (hooks, risk): (
        Arc<dyn access_identity_hooks::ports::HookCaller + Sync>,
        access_identity_session::app::RiskServices,
    ),
) -> Result<(axum::Router, HostedLogin), String> {
    let identity = config.identity.as_ref().ok_or("no identity section")?;
    let lifetimes = config.login.lifetimes().ok_or("login session lifetimes")?;
    let discovery = RealmDiscovery::new(
        PgDirectory::new(router.clone()),
        SignerKeys::new(identity.signer.clone()),
    );
    let hosted = Arc::new(Hosted {
        kits: login::HsmKits::new(keks, router, app.clone(), lifetimes),
        db: app,
        products,
        clock: SystemClock,
        messages: Outbox,
        gate: LoginGate::new(
            LocalLimiter::default(),
            ThrottlePolicy::DEFAULT,
            config.login.hash_mean_ms,
        ),
        hasher: Hasher::new(HasherConfig::sized(
            Argon2Params::CANONICAL,
            cores(),
            cgroup_memory_budget(),
        )),
        redirect_to: config.login.redirect_to.clone(),
        hooks,
        risk,
    });
    Ok((login_router(discovery, hosted.clone(), assets), hosted))
}

/// What the realm authorization server is built over: the application, router and outbox reader
/// pools, the HSM's nonce keys and the outbound client.
type OAuthInputs = (Pool, Pool, Pool, Arc<KeyStore>, Outbound);

fn oauth_inputs(pools: &Pools, prepared: &Prepared) -> OAuthInputs {
    (
        pools.app.clone(),
        pools.router.clone(),
        pools.outbox_reader.clone(),
        prepared.identity_keys.clone(),
        prepared.outbound.clone(),
    )
}

/// The realm authorization server (OP-146 I7) over the application pool, the identity signer,
/// clients' endpoints, the HSM's DPoP nonce keys and the authority plane's token projections
/// (OP-150 m.2).
fn authorization<P>(
    config: &Config,
    (app, router, reader, nonce_keys, outbound): OAuthInputs,
    projections: P,
    tenant_ids: Arc<ids::CellIds>,
    hooks: Arc<dyn access_identity_hooks::ports::HookCaller + Sync>,
) -> Result<axum::Router, String>
where
    P: access_internal_api::projections::Projections + admin::realm::LiveKeys + Clone + 'static,
{
    let identity = config.identity.as_ref().ok_or("no identity section")?;
    // TN-130
    let management = Arc::new(admin::tokens::PlaneHolders(
        projections.clone(),
        config.suiss.as_ref().and_then(|s| s.platform_realm.clone()),
    ));
    let env = oauth::ServerEnv {
        // OP-149 m.26 (a)
        db: PgOAuth::with_reader(app.clone(), reader),
        signer: SignerKeys::new(identity.signer.clone()),
        client_keys: HttpClientKeys::new(outbound, CachePolicy::default()),
        directory: PgDirectory::new(router),
        app,
        nonces: oauth::HsmNonces::new(nonce_keys),
        dpop: DpopProfile::default(),
        projections,
        tenant_ids,
        hooks,
        management,
    };
    Ok(oauth_router(OAuth::new(env)))
}

/// The back-channel logout courier (§10.4.6, OP-131): its own outbox cursor, at least once.
type LogoutCourier =
    Courier<PgOAuth, SignerKeys, OsRandom, OAuthClock, PgLogoutQueue, HttpLogoutDelivery>;

fn courier(config: &Config, pools: &Pools, outbound: Outbound) -> Result<LogoutCourier, String> {
    let identity = config.identity.as_ref().ok_or("no identity section")?;
    Ok(Courier::new(
        PgOAuth::new(pools.app.clone()),
        SignerKeys::new(identity.signer.clone()),
        OsRandom,
        OAuthClock,
        PgLogoutQueue {
            reader: pools.outbox_reader.clone(),
            app: pools.app.clone(),
        },
        HttpLogoutDelivery::new(outbound),
        Backoff::default(),
    ))
}

/// The identity plane's background work: the back-channel courier, event delivery and the
/// day-partition opener, and the start-up flags readiness waits for (OP-67 m.3).
struct Background {
    stop: tokio::sync::watch::Sender<bool>,
    delivering: tokio::task::JoinHandle<()>,
    events: events::Delivery,
    opening: tokio::task::JoinHandle<()>,
    sampling: tokio::task::JoinHandle<()>,
    ready: Readiness,
    /// Every realm's JWKS loaded at start-up (OP-138, §17.9.7).
    jwks: ReadyFlag,
}

impl Background {
    fn start(
        config: &Config,
        pools: &Pools,
        outbound: Outbound,
        keks: login::RealmKeks,
        ids: &Arc<ids::CellIds>,
    ) -> Result<Self, String> {
        let identity = config.identity.as_ref().ok_or("no identity section")?;
        let logout = courier(config, pools, outbound.clone())?;
        let ready = readiness(config, pools);
        // OP-67 m.3: unset again as soon as any courier or consumer task ends
        let consumers = ready.flag("outbox.consumers");
        // OP-149 m.4, m.7, m.17
        let events = events::Delivery::outbound(
            &event_pools(pools, ids, &outbound),
            outbound,
            SignerKeys::new(identity.signer.clone()),
            keks,
            &consumers,
        );
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let ended = consumers.clone();
        let delivering = tokio::spawn(async move {
            logout.run(&stopped).await;
            ended.set(false);
        });
        // OP-146 m.5 (f)
        let opening = tokio::spawn(jobs::run(
            pools.app.clone(),
            pools.archive.clone(),
            pools.router.clone(),
            holder()?,
        ));
        consumers.set(true);
        Ok(Self {
            stop,
            delivering,
            events,
            opening,
            // §17.8.2, OP-53
            sampling: tokio::spawn(sample_pools(PoolGauges::of(pools))),
            jwks: ready.flag("jwks.realms"),
            ready,
        })
    }

    /// The couriers and the fan-out finish their step; the opener is stopped.
    async fn stop(self) {
        let _ = self.stop.send(true);
        let _ = self.delivering.await;
        self.events.stop().await;
        self.opening.abort();
        self.sampling.abort();
    }
}

fn event_pools(pools: &Pools, ids: &Arc<ids::CellIds>, outbound: &Outbound) -> events::EventPools {
    events::EventPools {
        declared: outbound.declared(),
        outbound: Some(outbound.clone()),
        app: pools.app.clone(),
        reader: pools.outbox_reader.clone(),
        router: pools.router.clone(),
        ids: ids.clone(),
    }
}

fn tls_config(config: &Config) -> Result<std::sync::Arc<access_http::tls::ServerConfig>, String> {
    let tls = config.tls.as_ref().ok_or("no tls section")?;
    let chain =
        std::fs::read(&tls.cert_file).map_err(|e| format!("{}: {e}", tls.cert_file.display()))?;
    let key = access_crypto::secret::Secret::new(
        std::fs::read(&tls.key_file).map_err(|e| format!("{}: {e}", tls.key_file.display()))?,
    );
    let client_ca = tls
        .client_ca_file
        .as_ref()
        .map(|f| std::fs::read(f).map_err(|e| format!("{}: {e}", f.display())))
        .transpose()?;
    access_http::tls::server_config(&chain, key.expose(), client_ca.as_deref())
        .map_err(|e| e.to_string())
}

#[expect(
    clippy::too_many_lines,
    reason = "the composition root wires every plane and listener in one place (OP-62)"
)]
async fn serve(
    config: &Config,
    listeners: Listeners,
    prepared: Prepared,
    report: &LockdownReport,
) -> Result<(), String> {
    let all = pools(config, &prepared).await?;
    let oauth_inputs = oauth_inputs(&all, &prepared);
    let keks = login::RealmKeks::new(prepared.login_keys);
    // OP-137, OP-149 m.15 (i), m.22 (g)
    ids::open_root(&all.app, &prepared.identity_keys).await?;
    // TN-46, OP-151 m.1 (b), m.3 (o)
    let (risk_services, mmdb) = risk::services(
        config,
        &all.app,
        &prepared.identity_keys,
        prepared.outbound.clone(),
    )
    .await?;
    let _geo_watch =
        mmdb.map(|m| tokio::spawn(m.watch(access_identity_risk::adapters::mmdb::WATCH_EVERY)));
    let cell_ids = Arc::new(ids::CellIds::new(prepared.identity_keys.clone()));
    let (admin_app, admin_ids) = (all.app.clone(), cell_ids.clone());
    let admin_reads = all.reads.clone();
    let admin_targets = prepared.outbound.declared();
    let console_assets = prepared.console_assets;
    let admin_outbound = prepared.outbound.clone();
    let admin_geo = risk_services.geo.clone();
    let admin_pseudonyms = risk_services.ips.clone();
    // OP-146 m.5 (f): today's day partitions exist before anything writes to them
    jobs::open_now(&all.app, &all.archive, &holder()?).await;
    let background = Background::start(
        config,
        &all,
        prepared.outbound.clone(),
        keks.clone(),
        &cell_ids,
    )?;
    let identity_section = config.identity.as_ref().ok_or("no identity section")?;
    let signer = || SignerKeys::new(identity_section.signer.clone());
    let (platform_outbound, platform_keks) = (prepared.outbound.clone(), keks.clone());
    let admin_keks = keks.clone();
    let platform_pools = event_pools(&all, &cell_ids, &prepared.outbound);
    // TN-135, OP-151 m.3 (j)
    let hooks = oauth::hooks(all.app.clone(), prepared.outbound.clone(), keks.clone());
    // OP-149 m.7
    let ssf = events::ssf(&platform_pools, signer(), keks.clone());
    // OP-146 m.16 (m)
    let realm_keys = Arc::new(idp::RealmKeyring::new(
        signer(),
        prepared.identity_keys.clone(),
    ));
    let Pools {
        sequencer,
        app,
        deriver,
        router: router_pool,
        outbox_reader,
        checkpointer: checkpointer_pool,
        ..
    } = all;
    let admin_checkpointer = checkpointer_pool.clone();
    let (sign_in, hosted) = login(
        config,
        router_pool.clone(),
        app.clone(),
        outbox_reader,
        keks,
        prepared.assets,
        (hooks.clone(), risk_services),
    )?;
    let tenants_pool = router_pool.clone();
    let sandbox_pool = router_pool.clone();
    let realms = identity(config, router_pool, app.clone(), prepared.tls_names.clone()).await?;
    // OP-67 m.3, OP-138: the start-up checks loaded every realm's JWKS
    background.jwks.set(true);
    let (idp_sequencer, idp_app, product_app) = (sequencer.clone(), app.clone(), app.clone());
    let (issuer, limits) = (config.issuer.clone().ok_or("no issuer")?, Limits::default());
    // OP-141 m.18 (a), (e), (f), OP-149 m.16 (a)
    let actors = idp::ActorBindings::default();
    let domains = Arc::new(Domains::new(Setup {
        sequencer: sequencer.clone(),
        app,
        keys: prepared.keys,
        holder: holder()?,
        ttl: LEASE_TTL,
        binding: actors.clone(),
        salts: OsSalts,
        clock: SourcesClock::new(sequencer.clone()),
        deriver,
        signer: config.signer.clone(),
        api_base: issuer.clone(),
        // OP-105
        analysis: Arc::new(access_authority_core::ports::NoAnalysis),
    }));
    // OP-150 L2, CMP-8
    let (renewing, courier) = claims::start(signer(), &platform_pools, domains.clone(), renew);
    let _publishing = status::spawn(&domains, &product_app, &sequencer, config.signer.as_ref());
    // OP-38, OP-44, CMP-6, T16
    let led = domains.clone();
    let checkpointing = checkpoints::Checkpointers::start(
        checkpoints::Inputs {
            checkpointer: checkpointer_pool,
            app: product_app.clone(),
            sequencer: sequencer.clone(),
            identity_signer: identity_section.signer.clone(),
            authority_signer: config.signer.clone().ok_or("no signer")?,
            holder: holder()?,
        },
        move || led.led(),
    );
    // OP-62, MD-14, TN-111: the identity plane's idp.* write path and realm Genesis
    let idp_plane = idp::Plane::new(
        domains.clone(),
        idp_app,
        SourcesClock::new(idp_sequencer),
        actors,
    );
    // OP-149 m.4, m.16 (a), m.17 (e), (g), m.37
    let (platform, platform_api) = platform::routes(
        &platform_pools,
        platform_outbound,
        platform_keks,
        idp_plane.clone(),
        issuer.clone(),
    );
    // OP-150 m.2: authority tokens are the authority plane's projection.issue decisions
    let authorize = authorization(
        config,
        oauth_inputs,
        idp_plane.clone(),
        cell_ids.clone(),
        hooks,
    )?;
    // OP-151 m.3 (m): no request brings authority across the sandbox line
    let adp = adp_router(
        Service::new(
            access_http::adp::sandbox::SandboxLine {
                inner: domains.clone(),
                regimes: admin::platform::SandboxRegimes(sandbox_pool),
            },
            limits.max_body_bytes,
        ),
        Discovery { issuer },
    );
    // OP-151 m.3 (b)-(d), m.2 M1, m.12: the management API and the console, on their own
    // listener; the console signs in through the realms' authorization servers and forwards its
    // ADP reads, both in process
    let management_origin = config
        .suiss
        .as_ref()
        .map(|s| s.management_api.clone())
        .ok_or("no suiss section")?;
    let management = admin::router(
        (management_origin, identity_section.signer.clone()),
        &prepared.identity_keys,
        admin::realm::Realms {
            app: admin_app,
            reads: admin_reads,
            checkpointer: admin_checkpointer,
            router: tenants_pool.clone(),
            ids: admin_ids,
            plane: idp_plane.clone(),
            base: RealmBase::parse(&identity_section.realm_base).map_err(|e| e.to_string())?,
            keys: realm_keys,
            declared: admin_targets,
            platform: config.suiss.as_ref().and_then(|s| s.platform_realm.clone()),
            outbound: admin_outbound,
            vault: access_identity_events::adapters::KekSealer(admin_keks),
            geo: admin_geo,
            ips: admin_pseudonyms,
        },
        admin::InProcessRoutes {
            oauth: authorize.clone(),
            adp: adp.clone(),
        },
        console_assets,
    )?;
    let authorize = authorize.merge(ssf);
    // OP-149 m.6, m.8, m.9
    let me = frontend(config, tenants_pool.clone(), hosted, idp_plane, courier)?;
    let products = product::routes(
        config,
        domains.clone(),
        (tenants_pool, product_app),
        cell_ids,
        platform_api,
    )?;
    let app = router(
        config.security_txt(),
        limits,
        adp.merge(products)
            .merge(platform)
            .merge(realms)
            .merge(sign_in.merge(me))
            .merge(authorize)
            .merge(declared(&Declarations::of(config.provider))),
    );
    let served = listen(
        config,
        listeners,
        &prepared.tls,
        [app, management],
        (health(report), background.ready.clone()),
    )
    .await;
    // OP-31
    background.stop().await;
    checkpointing.stop();
    renewing.stop().await;
    domains.release().await;
    served
}

/// The three listening sockets (OP-151 m.3 (b)), bound before the lockdown.
struct Listeners {
    public: std::net::TcpListener,
    management: std::net::TcpListener,
    internal: std::net::TcpListener,
}

impl Listeners {
    fn bind(config: &Config) -> Result<Self, String> {
        let bind = |addr: std::net::SocketAddr, what: &str| {
            std::net::TcpListener::bind(addr).map_err(|e| format!("{what} {addr}: {e}"))
        };
        let management = config
            .management_listen
            .ok_or("management_listen is required")?;
        let internal = config
            .internal_listen
            .ok_or("internal_listen is required")?;
        Ok(Self {
            public: bind(config.listen, "listen")?,
            management: bind(management, "management_listen")?,
            internal: bind(internal, "internal_listen")?,
        })
    }
}

fn nonblocking(listener: std::net::TcpListener) -> Result<tokio::net::TcpListener, String> {
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    tokio::net::TcpListener::from_std(listener).map_err(|e| e.to_string())
}

/// Serves the public, management and internal routers on their listeners until a shutdown
/// signal; the process is ready once all three accept. Each speaks TLS 1.3 (TI-9).
async fn listen(
    config: &Config,
    listeners: Listeners,
    tls: &Arc<access_http::tls::ServerConfig>,
    [public, management]: [axum::Router; 2],
    (health, ready): (Health, Readiness),
) -> Result<(), String> {
    // OP-67 m.3, OP-151 m.3 (b)
    let ready = &ready;
    let inside = internal_router(health, ready.clone(), Limits::default(), now_ms);
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let signal = |mut rx: tokio::sync::watch::Receiver<bool>| async move {
        let _ = rx.wait_for(|s| *s).await;
    };
    let public_l = nonblocking(listeners.public)?;
    let management_l = nonblocking(listeners.management)?;
    let internal_l = nonblocking(listeners.internal)?;
    tracing::info!(
        listen = %config.listen,
        management_listen = ?config.management_listen,
        internal_listen = ?config.internal_listen,
        "access-server listening (TLS 1.3)"
    );
    let public = access_http::tls::serve(public_l, tls.clone(), public, signal(stopped.clone()));
    let management = access_http::tls::serve(
        management_l,
        tls.clone(),
        management,
        signal(stopped.clone()),
    );
    let inside = access_http::tls::serve(internal_l, tls.clone(), inside, signal(stopped.clone()));
    let shutdown = async {
        shutdown_signal().await;
        ready.unready();
        let _ = stop.send(true);
    };
    ready.ready();
    let ((), p, m, i) = tokio::join!(shutdown, public, management, inside);
    p.and(m).and(i).map_err(|e| e.to_string())
}

/// What `/healthz` reports: the lockdown in force (SA-22).
fn health(report: &LockdownReport) -> Health {
    Health {
        status: "ok",
        sandbox: SandboxHealth {
            profile: report.profile.as_str(),
            seccomp_phase: report.seccomp_phase,
            landlock_required_abi: report.landlock_required_abi.as_u32(),
            landlock_kernel_abi: report.landlock_kernel_abi,
        },
    }
}

/// The clock port's Unix milliseconds, for the oracle-watch windows (§17.8.2, SEC31).
fn now_ms() -> u64 {
    use access_identity_account::ports::Clock as _;
    SystemClock.now_ms()
}

/// The readiness checks of this process (OP-67 m.3): every database pool answers a ping and
/// both signers accept a connection, each within its budget.
fn readiness(config: &Config, pools: &Pools) -> Readiness {
    use access_http::internal::{Probe, SignerSocket};
    let ready = Readiness::default();
    for (name, pool) in PoolGauges::of(pools).0 {
        let check: &'static str = match name {
            "sequencer" => "db.sequencer",
            "app" => "db.app",
            "deriver" => "db.deriver",
            "router" => "db.router",
            "archive" => "db.archive",
            "checkpointer" => "db.checkpointer",
            _ => "db.outbox_reader",
        };
        ready.add_fn(check, move || -> Probe {
            let pool = pool.clone();
            Box::pin(async move { access_store::connect::ping(&pool).await })
        });
    }
    if let Some(path) = config.signer.clone() {
        ready.add(SignerSocket {
            name: "signer.authority",
            path,
        });
    }
    if let Some(identity) = &config.identity {
        ready.add(SignerSocket {
            name: "signer.identity",
            path: identity.signer.clone(),
        });
    }
    ready
}

/// The pools whose occupancy is sampled, by role (§17.8.2 "Havuz kuyruk derinliği", OP-53).
struct PoolGauges(Vec<(&'static str, Pool)>);

impl PoolGauges {
    fn of(pools: &Pools) -> Self {
        Self(vec![
            ("sequencer", pools.sequencer.clone()),
            ("app", pools.app.clone()),
            ("deriver", pools.deriver.clone()),
            ("router", pools.router.clone()),
            ("archive", pools.archive.clone()),
            ("outbox_reader", pools.outbox_reader.clone()),
            ("checkpointer", pools.checkpointer.clone()),
        ])
    }
}

/// OP-67, TI-18: starts the OTLP export; one that cannot start is logged and serving does not
/// depend on it.
fn export(telemetry: &access_telemetry::Telemetry) -> Option<tokio::task::JoinHandle<()>> {
    telemetry.start_export().unwrap_or_else(|error| {
        tracing::error!(
            %error,
            event = "telemetry.export.failed",
            outcome = "error",
            "OTLP export not started"
        );
        None
    })
}

/// How often pool occupancy is sampled (PD).
const POOL_SAMPLE: Duration = Duration::from_secs(10);

/// Samples each pool's connections in use, idle and configured until aborted.
async fn sample_pools(pools: PoolGauges) {
    use access_telemetry::signals::{POOL_IDLE, POOL_IN_USE, POOL_MAX};
    let mut tick = tokio::time::interval(POOL_SAMPLE);
    loop {
        tick.tick().await;
        for (role, pool) in &pools.0 {
            let size = pool.size();
            let idle = u32::try_from(pool.num_idle()).unwrap_or(u32::MAX);
            POOL_IN_USE.set(i64::from(size.saturating_sub(idle)), [*role]);
            POOL_IDLE.set(i64::from(idle), [*role]);
            POOL_MAX.set(i64::from(pool.options().get_max_connections()), [*role]);
        }
    }
}

/// The domains of this process.
type ServerDomains = Domains<KeyStore, idp::ActorBindings, OsSalts, SourcesClock>;

/// Renews the held leases and brings the derived indexes up to their heads, every third of the
/// lease, until the task is aborted.
async fn renew(domains: Arc<ServerDomains>) {
    let mut tick = tokio::time::interval(LEASE_TTL.checked_div(3).unwrap_or(LEASE_TTL));
    loop {
        tick.tick().await;
        domains.renew().await;
        // OP-141 m.22 (g)
        for error in domains.derive().await {
            tracing::warn!(%error, "derived index not brought up to the head");
        }
    }
}

/// Resolves on SIGTERM (orchestrators, OP-50) or SIGINT. In-flight requests finish.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = terminate.recv() => tracing::info!("SIGTERM received; shutting down"),
                    _ = tokio::signal::ctrl_c() => tracing::info!("SIGINT received; shutting down"),
                }
            }
            Err(error) => {
                tracing::error!(%error, "cannot listen for SIGTERM; only SIGINT stops the server");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod commands {
    use std::ffi::OsString;

    use super::{Command, Job, command};

    fn args(a: &[&str]) -> Vec<OsString> {
        a.iter().map(OsString::from).collect()
    }

    // OP-2, OP-55, OP-69, TI-9: no argument serves; the one-shot commands take exactly their own
    // arguments and nothing else is a mode
    #[test]
    fn the_commands_are_closed() {
        assert!(matches!(command(&args(&[])), Some(Command::Serve)));
        assert!(matches!(
            command(&args(&["migrate"])),
            Some(Command::Migrate)
        ));
        assert!(matches!(
            command(&args(&["bootstrap", "/etc/access/bootstrap.toml"])),
            Some(Command::Local(p, Job::Bootstrap)) if p.ends_with("bootstrap.toml")
        ));
        // OP-149 m.26 (c)
        assert!(matches!(
            command(&args(&["client-update", "/etc/access/bootstrap-work.toml", "work", "Suiss Work 2"])),
            Some(Command::Local(p, Job::ClientUpdate { product, display_name }))
                if p.ends_with("bootstrap-work.toml") && product == "work" && display_name == "Suiss Work 2"
        ));
        assert!(matches!(
            command(&args(&["client-retire", "/etc/access/bootstrap-work.toml", "work"])),
            Some(Command::Local(p, Job::ClientRetire { product }))
                if p.ends_with("bootstrap-work.toml") && product == "work"
        ));
        for bad in [
            &["bootstrap"][..],
            &["migrate", "--force"],
            &["serve"],
            &["--dev"],
            &["client-update", "/etc/access/bootstrap-work.toml", "work"],
            &["client-retire", "/etc/access/bootstrap-work.toml"],
            &[
                "client-retire",
                "/etc/access/bootstrap-work.toml",
                "work",
                "--now",
            ],
        ] {
            assert!(command(&args(bad)).is_none(), "{bad:?}");
        }
    }
}
