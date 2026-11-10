//! CIBA of a realm (`idp.realm.ciba`, CT2; `ciba_close`, CT1; OP-155 m.3 (l), IDP-14, §10.5.3):
//! whether the backchannel endpoint is on, whether a free `login_hint` is accepted, and which
//! clients are told by ping at which `https` endpoint. Push is never offered.

use std::collections::BTreeSet;

use suiss_crypto::dcbor::Value;

use super::{ClientId, Invalid};

/// Most clients told by ping (PD).
pub const MAX_PING_CLIENTS: usize = 64;

/// Longest notification endpoint, in bytes.
pub const MAX_ENDPOINT: usize = 2048;

/// A realm's CIBA setting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CibaSetting {
    /// Whether the realm offers CIBA; `false` is `ciba_close`.
    pub enabled: bool,
    /// Whether a free `login_hint` is accepted (enumeration-safe; §10.2.1).
    pub login_hint: bool,
    /// The clients told by ping, each with its `backchannel_client_notification_endpoint`.
    pub ping: Vec<(ClientId, String)>,
}

/// Whether `e` can be a notification endpoint: an absolute `https` URL without a fragment or
/// credentials.
#[must_use]
pub fn endpoint_ok(e: &str) -> bool {
    let Some(rest) = e.strip_prefix("https://") else {
        return false;
    };
    let host = rest.split(['/', '?']).next().unwrap_or_default();
    e.len() <= MAX_ENDPOINT
        && !host.is_empty()
        && !host.contains('@')
        && !e.contains('#')
        && !e.chars().any(|c| c.is_control() || c.is_whitespace())
}

/// A coordinator's Needs Attention endpoint, when named, is one `https` URL (OP-156 m.3 (t)).
///
/// # Errors
/// [`Invalid::Body`].
pub fn coordinator_ok(url: Option<&str>) -> Result<(), Invalid> {
    if url.is_none_or(endpoint_ok) {
        Ok(())
    } else {
        Err(Invalid::Body)
    }
}

impl CibaSetting {
    /// Checks the setting on its own.
    ///
    /// # Errors
    /// [`Invalid::Body`]: a closed realm that keeps a flag or a ping client, too many ping
    /// clients, the same client twice, or an endpoint that is not `https`.
    pub fn check(&self) -> Result<(), Invalid> {
        let clients: BTreeSet<&str> = self.ping.iter().map(|(c, _)| c.as_str()).collect();
        let ok = (self.enabled || (!self.login_hint && self.ping.is_empty()))
            && self.ping.len() <= MAX_PING_CLIENTS
            && clients.len() == self.ping.len()
            && self.ping.iter().all(|(_, e)| endpoint_ok(e));
        if ok { Ok(()) } else { Err(Invalid::Body) }
    }

    /// The change body the intent digests (EI-25).
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::text("enabled"), Value::Bool(self.enabled)),
            (Value::text("login_hint"), Value::Bool(self.login_hint)),
            (
                Value::text("ping"),
                Value::Array(
                    self.ping
                        .iter()
                        .map(|(c, e)| {
                            Value::Array(vec![Value::text(c.as_str()), Value::text(e.as_str())])
                        })
                        .collect(),
                ),
            ),
        ])
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // OP-155 m.3 (l)
    #[test]
    fn a_closed_realm_keeps_no_flag_and_ping_needs_https() {
        let client = ClientId::parse("cli_aaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let on = CibaSetting {
            enabled: true,
            login_hint: true,
            ping: vec![(client.clone(), String::from("https://rp.example/ciba"))],
        };
        assert!(on.check().is_ok());
        let closed = CibaSetting {
            enabled: false,
            ..on.clone()
        };
        assert!(closed.check().is_err());
        let plain = CibaSetting {
            ping: vec![(client.clone(), String::from("http://rp.example/ciba"))],
            ..on.clone()
        };
        assert!(plain.check().is_err());
        let twice = CibaSetting {
            ping: vec![
                (client.clone(), String::from("https://rp.example/a")),
                (client, String::from("https://rp.example/b")),
            ],
            ..on
        };
        assert!(twice.check().is_err());
        assert!(!endpoint_ok("https://user@rp.example/"));
        assert!(!endpoint_ok("https://rp.example/#f"));
    }
}
