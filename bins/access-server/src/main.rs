//! Access server (OP-2). Thin by design: it reads configuration, installs
//! telemetry and composes crates; business logic lives in `crates/` (OP-62).

mod config;

use std::process::ExitCode;

use access_http::{Health, Limits, SandboxHealth, router};
use access_sandbox::{LandlockAbi, Lockdown, LockdownReport, Profile};
use config::Config;

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

    // §14.5
    let listener = match std::net::TcpListener::bind(config.listen) {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!(%error, listen = %config.listen, "cannot bind the listening socket");
            return ExitCode::FAILURE;
        }
    };

    // SA-22, OP-90, OP-92
    let locked = match Lockdown::new(Profile::Server, LandlockAbi::REQUIRED).apply() {
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

    match runtime.block_on(serve(&config, listener, tls, &report)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "server stopped with an error");
            ExitCode::FAILURE
        }
    }
}

fn tls_config(config: &Config) -> Result<std::sync::Arc<access_http::tls::ServerConfig>, String> {
    let tls = config.tls.as_ref().ok_or("no tls section")?;
    let chain =
        std::fs::read(&tls.cert_file).map_err(|e| format!("{}: {e}", tls.cert_file.display()))?;
    let key = access_crypto::secret::Secret::new(
        std::fs::read(&tls.key_file).map_err(|e| format!("{}: {e}", tls.key_file.display()))?,
    );
    access_http::tls::server_config(&chain, key.expose()).map_err(|e| e.to_string())
}

async fn serve(
    config: &Config,
    listener: std::net::TcpListener,
    tls: std::sync::Arc<access_http::tls::ServerConfig>,
    report: &LockdownReport,
) -> std::io::Result<()> {
    let health = Health {
        status: "ok",
        sandbox: SandboxHealth {
            profile: report.profile.as_str(),
            seccomp_phase: report.seccomp_phase,
            landlock_required_abi: report.landlock_required_abi.as_u32(),
            landlock_kernel_abi: report.landlock_kernel_abi,
        },
    };
    let app = router(config.security_txt(), health, Limits::default());
    listener.set_nonblocking(true)?;
    let listener = tokio::net::TcpListener::from_std(listener)?;
    tracing::info!(listen = %config.listen, "access-server listening (TLS 1.3)");
    access_http::tls::serve(listener, tls, app, shutdown_signal()).await
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
