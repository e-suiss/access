//! Access parser worker (OP-155 m.3 (c), MD-18, IDP-15, U43).
//!
//! `access-parser-worker` is the supervisor: it locks itself down (Unix sockets only, no
//! network), keeps a pool of workers and answers gateways on its socket. `access-parser-worker
//! work` is one worker: it limits its own memory and CPU, locks itself down (no socket call, no
//! file, no key) and parses one request at a time from the socket pair it was started on. A
//! crash, a panic or a limit kills only that worker.

mod c14n;
mod dom;
mod dsig;
mod parse;
mod saml;
#[cfg(test)]
mod saml_tests;
mod supervisor;
mod trusted_list;
mod work;

use std::ffi::OsString;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    match args.as_slice() {
        [] => supervisor::run(),
        [a] if a == "work" => work::run(),
        _ => {
            supervisor::log("usage: access-parser-worker [work]");
            ExitCode::FAILURE
        }
    }
}
