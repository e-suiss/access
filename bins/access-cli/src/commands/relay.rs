//! `access-cli relay`: the realm's Relay messages the courier gave up on, and their resend
//! (OP-156 m.3 (c), Ek B 5401). A resend is one `idp.relay.resend` Exercise signed with the
//! Instance key: the message goes out again as a new outbox row citing the original. A message
//! whose content was crypto-shredded answers `content-shredded`, an expired one
//! `message-expired`.

use clap::{Args, Subcommand};
use serde_json::{Map, Value};

use super::{Connect, failed, load_key, note, out};
use crate::api;
use crate::client::{Client, System};
use crate::exit::{self, Code};
use crate::http::Https;

/// The `listUndeliveredRelayMessages` operation.
pub(crate) const LIST: &str = "listUndeliveredRelayMessages";
/// The `resendRelayMessage` operation.
pub(crate) const RESEND: &str = "resendRelayMessage";

/// `relay` arguments.
#[derive(Debug, Args)]
pub(crate) struct RelayArgs {
    #[command(flatten)]
    pub(crate) connect: Connect,
    #[command(subcommand)]
    pub(crate) verb: RelayVerb,
}

/// What to do.
#[derive(Debug, Subcommand)]
pub(crate) enum RelayVerb {
    /// Lists the undelivered messages: id, kind, reason, Relay's status; never their content.
    Undelivered,
    /// Resends one undelivered message by its `CloudEvents` id (`idp.relay.resend`, CT1).
    Resend {
        /// The message's `CloudEvents` id.
        event_id: String,
    },
}

/// Whether `id` is a lower-case hyphenated UUID, as the courier writes event ids.
pub(crate) fn event_id(id: &str) -> bool {
    let b = id.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(c),
        })
}

/// Runs `relay`.
pub(crate) async fn run(args: RelayArgs) -> Code {
    let (op_id, key) = match &args.verb {
        RelayVerb::Undelivered => (LIST, None),
        RelayVerb::Resend { event_id: id } if event_id(id) => (RESEND, Some(id.clone())),
        RelayVerb::Resend { .. } => {
            note("access-cli: the event id is a lower-case UUID, as `relay undelivered` lists it");
            return exit::USAGE;
        }
    };
    let Some(op) = api::contract().operation(op_id) else {
        note(&format!("access-cli: the contract has no `{op_id}`"));
        return exit::USAGE;
    };
    let target = match args.connect.target() {
        Ok(t) => t,
        Err(e) => {
            note(&format!("access-cli: {e}"));
            return exit::USAGE;
        }
    };
    let instance = match load_key(&args.connect) {
        Ok(k) => k,
        Err(c) => return c,
    };
    let https = match Https::new(&args.connect.ca) {
        Ok(h) => h,
        Err(e) => {
            note(&format!("access-cli: {e}"));
            return exit::CONFIG;
        }
    };
    let client = Client::new(&https, &instance, &target, &System);
    let path = op.url_path(&target.realm, key.as_deref());
    match args.verb {
        RelayVerb::Undelivered => match client.list(&path).await {
            Ok(items) => out(&format!("{:#}\n", Value::Array(items))),
            Err(e) => failed(&e),
        },
        RelayVerb::Resend { .. } => {
            super::admin::write(&client, op, key.as_deref(), &Map::new(), &path).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-156 m.3 (c)
    #[test]
    fn the_resend_names_an_event_id_and_its_operations_are_in_the_contract() {
        assert!(event_id("0a1b2c3d-4e5f-4a6b-8c7d-0e1f2a3b4c5d"));
        assert!(!event_id("0A1B2C3D-4E5F-4A6B-8C7D-0E1F2A3B4C5D"));
        assert!(!event_id("../../admin"));
        let c = api::contract();
        for id in [LIST, RESEND] {
            assert!(c.operation(id).is_some(), "{id}");
        }
        assert!(c.operation(RESEND).is_some_and(api::Operation::writes));
    }
}
