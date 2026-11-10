//! Access RADIUS gateway (§10.6.5, IDP-18, OP-155 m.3 (f)): reads its configuration and binds its
//! `RadSec` listener, locks itself down (SA-22; it refuses to start without the lockdown, OP-90),
//! asks access-server who it is over the edge channel, then serves `RadSec`.

use std::process::ExitCode;
use std::sync::Arc;

use access_edge_core::EdgeCore;
use access_edge_core::channel::Channel;
use access_edge_core::governor::Governor;
use access_gw_radius::server::{self, Listener};
use access_gw_radius::{config, log};
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

fn run() -> Result<(), String> {
    let config = config::from_env()?;
    let radsec = std::net::TcpListener::bind(config.listen).map_err(|e| format!("listen: {e}"))?;
    let port = config
        .channel
        .addr
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .ok_or("ACCESS_GW_RADIUS_SERVER: not host:port")?;
    let mut lockdown =
        Lockdown::new(Profile::Server, LandlockAbi::REQUIRED).allow_tcp_connect(port);
    if let Some(run_as) = config.run_as {
        lockdown = lockdown.run_as(run_as);
    }
    // OP-90, SA-22
    let locked = lockdown
        .apply()
        .map_err(|e| format!("runtime lockdown failed; refusing to start (OP-90): {e}"))?;
    let tls = server::acceptor(&config.tls_chain, &config.tls_key).map_err(|e| e.to_string())?;
    let channel = Channel::new(&config.channel).map_err(|e| e.to_string())?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    runtime.block_on(async move {
        let core = EdgeCore::connect(channel)
            .await
            .map_err(|e| format!("edge channel: {e}"))?;
        if core.gateway().kind != GatewayKind::Radius {
            return Err(String::from("the edge channel names no RADIUS gateway"));
        }
        locked
            .narrow()
            .map_err(|e| format!("seccomp phase 2 failed; refusing to serve (OP-90): {e}"))?;
        radsec
            .set_nonblocking(true)
            .map_err(|e| format!("listener: {e}"))?;
        let radsec =
            tokio::net::TcpListener::from_std(radsec).map_err(|e| format!("listener: {e}"))?;
        let listener = Listener {
            core: Arc::new(core),
            tls,
            governor: Arc::new(Governor::new(20, 100)),
        };
        server::radsec(radsec, listener).await;
        Ok(())
    })
}
