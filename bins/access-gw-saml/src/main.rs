//! Access SAML gateway (OP-155 m.3 (c), (d), MD-18, IDP-26, IDI-7, IDI-11).
//!
//! access-server binds the browser endpoints and forwards each SAML or WS-Federation request
//! here with a one-use attestation handle. The gateway has the parser worker read and verify the
//! message, then redeems the handle over the edge channel, where access-server decides and
//! signs. The gateway holds only its channel identity: no store, no signing key, no session.
//!
//! Configuration, from the environment (read before the lockdown):
//! - `ACCESS_GW_LISTEN`: `host:port` of the forward listener (required);
//! - `ACCESS_GW_SERVER`, `ACCESS_GW_SERVER_NAME`: access-server's TLS listener and its name;
//! - `ACCESS_GW_ROOTS`, `ACCESS_GW_CERT`, `ACCESS_GW_KEY`: PEM files of access-server's roots
//!   and of the gateway's client certificate (SAN `urn:suiss:access:gw:saml:<name>`) and key;
//! - `ACCESS_PARSER_SOCKET`: the parser worker supervisor's socket; `ACCESS_PARSER_UID`: the
//!   user id it must run as.

mod forward;
mod serve;

use std::path::PathBuf;
use std::process::ExitCode;

use access_edge_core::channel::{Channel, ChannelConfig};
use access_edge_core::parser::ParserClient;
use suiss_sandbox::{LandlockAbi, Lockdown, Profile};

fn log(message: &str) {
    #[allow(
        clippy::print_stderr,
        reason = "the gateway logs one line to standard error before its runtime starts"
    )]
    {
        eprintln!("access-gw-saml: {message}");
    }
}

struct Config {
    listen: String,
    channel: ChannelConfig,
    parser: PathBuf,
    parser_uid: Option<u32>,
}

fn config() -> Result<Config, String> {
    let var = |k: &str| {
        std::env::var(k)
            .ok()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| format!("{k} is not set"))
    };
    let read = |k: &str| -> Result<Vec<u8>, String> {
        std::fs::read(var(k)?).map_err(|e| format!("{k}: {e}"))
    };
    Ok(Config {
        listen: var("ACCESS_GW_LISTEN")?,
        channel: ChannelConfig {
            addr: var("ACCESS_GW_SERVER")?,
            server_name: var("ACCESS_GW_SERVER_NAME")?,
            roots_pem: read("ACCESS_GW_ROOTS")?,
            chain_pem: read("ACCESS_GW_CERT")?,
            key_pem: read("ACCESS_GW_KEY")?,
        },
        parser: PathBuf::from(var("ACCESS_PARSER_SOCKET")?),
        parser_uid: std::env::var("ACCESS_PARSER_UID")
            .ok()
            .and_then(|v| v.parse().ok()),
    })
}

fn port(addr: &str) -> Option<u16> {
    addr.rsplit_once(':').and_then(|(_, p)| p.parse().ok())
}

fn main() -> ExitCode {
    let c = match config() {
        Ok(c) => c,
        Err(e) => {
            log(&e);
            return ExitCode::FAILURE;
        }
    };
    let channel = match Channel::new(&c.channel) {
        Ok(ch) => ch,
        Err(e) => {
            log(&format!("edge channel refused: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let listener = match std::net::TcpListener::bind(&c.listen) {
        Ok(l) => l,
        Err(e) => {
            log(&format!("cannot listen on {}: {e}", c.listen));
            return ExitCode::FAILURE;
        }
    };
    let mut lockdown = Lockdown::new(Profile::Server, LandlockAbi::REQUIRED);
    if let Some(p) = port(&c.channel.addr) {
        lockdown = lockdown.allow_tcp_connect(p);
    }
    if let Some(dir) = c.parser.parent() {
        lockdown = lockdown.allow_read_write(dir);
    }
    // SA-22, OP-90
    let locked = match lockdown.apply() {
        Ok(l) => l,
        Err(e) => {
            log(&format!("lockdown failed: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            log(&format!("runtime: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let parser = ParserClient::new(c.parser, c.parser_uid);
    match runtime.block_on(serve::run(listener, channel, parser, locked)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log(&e);
            ExitCode::FAILURE
        }
    }
}
