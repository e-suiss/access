//! Access Kerberos/SPNEGO gateway (§10.6.4, IDP-17, OP-155 m.3 (o)): reads its configuration,
//! installs its keytab from secret memory, acquires its acceptor credential and binds its
//! listener, locks itself down (SA-22; it refuses to start without the lockdown, OP-90), asks
//! access-server who it is over the edge channel, then serves HTTP Negotiate.

use std::process::ExitCode;
use std::sync::Arc;

use access_edge_core::EdgeCore;
use access_edge_core::channel::Channel;
use access_edge_core::governor::Governor;
use access_edge_core::parser::ParserClient;
use access_gw_kerberos::accept::Acceptor;
use access_gw_kerberos::http::{self, Endpoint};
use access_gw_kerberos::proxy::Proxy;
use access_gw_kerberos::{config, keytab, log};
use access_internal_api::edge::GatewayKind;
use suiss_sandbox::{LandlockAbi, Lockdown, Profile};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log(&e);
            ExitCode::FAILURE
        }
    }
}

fn port_of(addr: &str, name: &str) -> Result<u16, String> {
    addr.rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .ok_or_else(|| format!("{name}: not host:port"))
}

#[allow(
    unsafe_code,
    reason = "setting libkrb5's environment before any thread exists"
)]
fn run() -> Result<(), String> {
    let config = config::from_env()?;
    // SAFETY: still single-threaded: no runtime and no other thread exists yet, so nothing reads
    // the environment concurrently. libkrb5 keeps its replay cache in this directory.
    unsafe { std::env::set_var("KRB5RCACHEDIR", &config.rcache) };
    // SAFETY: as above; libkrb5 reads its configuration from this file.
    unsafe { std::env::set_var("KRB5_CONFIG", &config.krb5_conf) };
    let installed = keytab::install(&config.keytab, &config.spn).map_err(|e| e.to_string())?;
    log(&format!("keytab key versions {:?}", installed.kvnos));
    let acceptor = Acceptor::new(&config.spn, config.backend.is_some())
        .map_err(|e| format!("acceptor: {e}"))?;
    let proxy = config
        .backend
        .as_ref()
        .map(Proxy::new)
        .transpose()
        .map_err(|e| format!("backend: {e}"))?;
    let listener =
        std::net::TcpListener::bind(config.listen).map_err(|e| format!("listen: {e}"))?;
    let mut lockdown = Lockdown::new(Profile::Server, LandlockAbi::REQUIRED)
        .allow_tcp_connect(port_of(&config.channel.addr, "ACCESS_GW_KERBEROS_SERVER")?)
        .allow_read(&config.krb5_conf)
        .allow_read_write(&config.rcache);
    if let Some(dir) = config.parser.parent() {
        lockdown = lockdown.allow_read_write(dir);
    }
    if let Some(b) = &config.backend {
        lockdown = lockdown
            .allow_tcp_connect(b.kdc_port)
            .allow_tcp_connect(port_of(&b.addr, "ACCESS_GW_KERBEROS_BACKEND")?);
    }
    if let Some(run_as) = config.run_as {
        lockdown = lockdown.run_as(run_as);
    }
    // OP-90, SA-22
    let locked = lockdown
        .apply()
        .map_err(|e| format!("runtime lockdown failed; refusing to start (OP-90): {e}"))?;
    let tls = http::acceptor(&config.tls_chain, &config.tls_key).map_err(|e| e.to_string())?;
    let channel = Channel::new(&config.channel).map_err(|e| e.to_string())?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    let served = runtime.block_on(async move {
        let core = EdgeCore::connect(channel)
            .await
            .map_err(|e| format!("edge channel: {e}"))?;
        if core.gateway().kind != GatewayKind::Kerberos {
            return Err(String::from("the edge channel names no Kerberos gateway"));
        }
        locked
            .narrow()
            .map_err(|e| format!("seccomp phase 2 failed; refusing to serve (OP-90): {e}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("listener: {e}"))?;
        let listener =
            tokio::net::TcpListener::from_std(listener).map_err(|e| format!("listener: {e}"))?;
        let endpoint = Endpoint {
            core: Arc::new(core),
            parser: ParserClient::new(config.parser.clone(), config.parser_uid),
            acceptor,
            spn: config.spn.clone(),
            login: config.login.clone(),
            proxy,
            tls,
            governor: Arc::new(Governor::new(20, 100)),
        };
        endpoint.serve(listener).await;
        Ok(())
    });
    drop(installed);
    served
}
