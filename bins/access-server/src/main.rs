//! Access server (OP-2). Thin by design: it reads configuration, installs
//! telemetry and composes crates; business logic lives in `crates/` (OP-62).

mod config;

use std::fmt::Write as _;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use access_authority_core::adapters::{Domains, OsSalts, Setup, Unbound};
use access_authority_sequencer::LEASE_TTL;
use access_authority_sequencer::adapters::SourcesClock;
use access_crypto::secret_file::SecretFile;
use access_http::adp::adapters::{Discovery, router as adp_router};
use access_http::adp::app::Service;
use access_http::{Health, Limits, SandboxHealth, router};
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

/// Everything read from the file system before the lockdown closes it.
struct Prepared {
    tls: Arc<access_http::tls::ServerConfig>,
    root_cert: Vec<u8>,
    sequencer_password: SecretFile,
    app_password: SecretFile,
    deriver_password: SecretFile,
    keys: KeyStore,
}

fn main() -> ExitCode {
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

    if let Err(error) = access_telemetry::init(&config.log) {
        #[allow(clippy::print_stderr)]
        {
            eprintln!("access-server: {error}");
        }
        return ExitCode::FAILURE;
    }

    // CR-12, OP-52: the TLS files are read before the lockdown closes the file system
    let tls = match tls_config(&config) {
        Ok(tls) => tls,
        Err(error) => {
            tracing::error!(%error, "TLS configuration unusable; refusing to start (OP-52)");
            return ExitCode::FAILURE;
        }
    };
    // OP-129 m.3, OP-141 m.18 (g), (h)
    let prepared = match prepare(&config, tls) {
        Ok(prepared) => prepared,
        Err(error) => {
            tracing::error!(%error, "credentials unusable; refusing to start (OP-52)");
            return ExitCode::FAILURE;
        }
    };

    // §14.5
    let listener = match std::net::TcpListener::bind(config.listen) {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!(%error, listen = %config.listen, "cannot bind the listening socket");
            return ExitCode::FAILURE;
        }
    };

    // SA-22, OP-90, OP-92
    let locked = match lockdown(&config).apply() {
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

    match runtime.block_on(serve(&config, listener, prepared, &report)) {
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
    Ok(Prepared {
        tls,
        root_cert,
        sequencer_password: password(&db.sequencer)?,
        app_password: password(&db.app)?,
        deriver_password: password(&db.deriver)?,
        keys,
    })
}

/// SA-22 with what the authority plane reaches after it (OP-141 m.18 (g), (h)).
fn lockdown(config: &Config) -> Lockdown {
    let mut lockdown = Lockdown::new(Profile::Server, LandlockAbi::REQUIRED);
    if let Some(db) = &config.database {
        lockdown = lockdown.allow_tcp_connect(db.port);
    }
    for file in RESOLVER.iter().filter(|f| Path::new(f).exists()) {
        lockdown = lockdown.allow_read(file);
    }
    if let Some(hsm) = &config.hsm {
        for path in &hsm.paths {
            lockdown = lockdown.allow_read_write(path);
        }
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

async fn pools(config: &Config, prepared: &Prepared) -> Result<(Pool, Pool, Pool), String> {
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
    let deriver = open(&db.deriver, &prepared.deriver_password).await?;
    let durability = match db.durability {
        Durability::Replicated => access_store::connect::Durability::Replicated,
        Durability::SingleNode => access_store::connect::Durability::SingleNode,
    };
    let total = db
        .sequencer
        .pool
        .saturating_add(db.app.pool)
        .saturating_add(db.deriver.pool);
    // OP-52
    for p in [&sequencer, &app, &deriver] {
        check_server(p, total, true, durability)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok((sequencer, app, deriver))
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

async fn serve(
    config: &Config,
    listener: std::net::TcpListener,
    prepared: Prepared,
    report: &LockdownReport,
) -> Result<(), String> {
    let (sequencer, app, deriver) = pools(config, &prepared).await?;
    let sequencer_for_time = sequencer.clone();
    let issuer = config.issuer.clone().ok_or("no issuer")?;
    let limits = Limits::default();
    // OP-141 m.18 (a), (e), (f)
    let domains = Arc::new(Domains::new(Setup {
        sequencer,
        app,
        keys: prepared.keys,
        holder: holder()?,
        ttl: LEASE_TTL,
        binding: Unbound,
        salts: OsSalts,
        clock: SourcesClock::new(sequencer_for_time),
        deriver,
    }));
    let renewing = tokio::spawn({
        let domains = domains.clone();
        async move {
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
    });
    let adp = adp_router(
        Service::new(domains.clone(), limits.max_body_bytes),
        Discovery { issuer },
    );
    let health = Health {
        status: "ok",
        sandbox: SandboxHealth {
            profile: report.profile.as_str(),
            seccomp_phase: report.seccomp_phase,
            landlock_required_abi: report.landlock_required_abi.as_u32(),
            landlock_kernel_abi: report.landlock_kernel_abi,
        },
    };
    let app = router(config.security_txt(), health, limits, adp);
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let listener = tokio::net::TcpListener::from_std(listener).map_err(|e| e.to_string())?;
    tracing::info!(listen = %config.listen, "access-server listening (TLS 1.3)");
    let served = access_http::tls::serve(listener, prepared.tls, app, shutdown_signal()).await;
    // OP-31
    renewing.abort();
    domains.release().await;
    served.map_err(|e| e.to_string())
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
