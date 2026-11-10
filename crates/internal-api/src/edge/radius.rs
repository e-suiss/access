//! The RADIUS gateway's edge call (§10.6.5, IDP-18, OP-155 m.3 (f)): `authenticate` checks that
//! the `RadSec` client is registered with the gateway and, for PAP, checks a directory app
//! password of the named holder. MS-CHAPv2 has no body: the gateway refuses it itself.

use suiss_crypto::dcbor::Value;

use super::{WireError, decode_map, encode, fixed, only, opt_bytes, required, text};

/// Longest RADIUS `User-Name` (RFC 2865 §5.1: at most 253 octets).
pub const MAX_NAME: usize = 253;

/// Longest PAP `User-Password` (RFC 2865 §5.2: at most 128 octets).
pub const MAX_SECRET: usize = 128;

/// What one `authenticate` asks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mechanism {
    /// Only whether the `RadSec` client is registered with this gateway.
    Client,
    /// PAP inside TLS: a user name and a directory app password.
    Pap,
}

impl Mechanism {
    /// The wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Pap => "pap",
        }
    }

    fn parse(name: &str) -> Option<Self> {
        match name {
            "client" => Some(Self::Client),
            "pap" => Some(Self::Pap),
            _ => None,
        }
    }
}

/// [`super::Call::Authenticate`] of a RADIUS gateway.
#[derive(Clone, PartialEq, Eq)]
pub struct Authenticate {
    /// The realm; it must be the gateway's own.
    pub realm: String,
    /// What is asked.
    pub mechanism: Mechanism,
    /// SHA-256 of the `RadSec` client's TLS certificate.
    pub client: [u8; 32],
    /// PAP: the `User-Name`.
    pub name: Option<String>,
    /// PAP: the `User-Password`. Never logged, never kept by the gateway.
    pub secret: Option<Vec<u8>>,
}

impl core::fmt::Debug for Authenticate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Authenticate")
            .field("realm", &self.realm)
            .field("mechanism", &self.mechanism)
            .finish_non_exhaustive()
    }
}

/// The answer to [`Authenticate`]. An unregistered client is a refusal (`edge-radius-client`);
/// an unknown name and a wrong secret answer the same: no subject.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Authenticated {
    /// PAP: the subject, when the password checked out.
    pub subject: Option<[u8; 16]>,
}

impl Authenticate {
    /// The body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut entries = vec![
            ("realm", Value::text(&self.realm)),
            ("mechanism", Value::text(self.mechanism.name())),
            ("client", Value::Bytes(self.client.to_vec())),
        ];
        if let Some(n) = &self.name {
            entries.push(("name", Value::text(n)));
        }
        if let Some(s) = &self.secret {
            entries.push(("secret", Value::Bytes(s.clone())));
        }
        encode(entries)
    }

    /// Reads the body: `client` carries no name and no secret, `pap` carries both.
    ///
    /// # Errors
    /// [`WireError`].
    pub fn decode(body: &[u8]) -> Result<Self, WireError> {
        let v = decode_map(body)?;
        only(&v, &["realm", "mechanism", "client", "name", "secret"])?;
        let mechanism =
            Mechanism::parse(&text(&v, "mechanism", 16)?).ok_or(WireError::Malformed)?;
        let name = match v.get("name") {
            None => None,
            Some(Value::Text(t)) if !t.is_empty() && t.len() <= MAX_NAME => Some(t.clone()),
            Some(_) => return Err(WireError::Malformed),
        };
        let secret = match v.get("secret") {
            None => None,
            Some(Value::Bytes(b)) if !b.is_empty() && b.len() <= MAX_SECRET => Some(b.clone()),
            Some(_) => return Err(WireError::Malformed),
        };
        let shaped = match mechanism {
            Mechanism::Client => name.is_none() && secret.is_none(),
            Mechanism::Pap => name.is_some() && secret.is_some(),
        };
        if !shaped {
            return Err(WireError::Malformed);
        }
        Ok(Self {
            realm: text(&v, "realm", 64)?,
            mechanism,
            client: required::<32>(&v, "client")?,
            name,
            secret,
        })
    }
}

impl Authenticated {
    /// The body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut entries = Vec::new();
        opt_bytes(&mut entries, "subject", self.subject);
        encode(entries)
    }

    /// Reads the body.
    ///
    /// # Errors
    /// [`WireError`].
    pub fn decode(body: &[u8]) -> Result<Self, WireError> {
        let v = decode_map(body)?;
        only(&v, &["subject"])?;
        Ok(Self {
            subject: fixed::<16>(v.get("subject"))?,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // IDP-18, OP-155 m.3 (f)
    #[test]
    fn pap_carries_a_name_and_a_secret_and_a_probe_carries_neither() {
        let pap = Authenticate {
            realm: String::from("corp"),
            mechanism: Mechanism::Pap,
            client: [3; 32],
            name: Some(String::from("ada")),
            secret: Some(b"app-password".to_vec()),
        };
        assert_eq!(Authenticate::decode(&pap.encode()).unwrap(), pap);
        assert!(!format!("{pap:?}").contains("app-password"));
        let probe = Authenticate {
            mechanism: Mechanism::Client,
            name: None,
            secret: None,
            ..pap.clone()
        };
        assert_eq!(Authenticate::decode(&probe.encode()).unwrap(), probe);
        let half = Authenticate {
            secret: None,
            ..pap.clone()
        };
        assert_eq!(
            Authenticate::decode(&half.encode()),
            Err(WireError::Malformed)
        );
        let chap = encode(vec![
            ("realm", Value::text("corp")),
            ("mechanism", Value::text("mschapv2")),
            ("client", Value::Bytes(vec![3; 32])),
        ]);
        assert_eq!(Authenticate::decode(&chap), Err(WireError::Malformed));
        let a = Authenticated {
            subject: Some([1; 16]),
        };
        assert_eq!(Authenticated::decode(&a.encode()).unwrap(), a);
    }
}
