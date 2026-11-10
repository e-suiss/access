//! The Kerberos gateway's edge call (§10.6.4, IDP-17, OP-155 m.3 (o)): `authenticate` reports the
//! facts of one SPNEGO acceptance (who, for which SPN, under which key version and enctype) and
//! access-server holds them to the realm's keytab policy and names the subject. The ticket
//! itself never leaves the gateway.

use suiss_crypto::dcbor::Value;

use super::{WireError, decode_map, encode, fixed, only, opt_bytes, text};

/// Longest client principal or SPN (`name@REALM`).
pub const MAX_PRINCIPAL: usize = 512;

/// `aes256-cts-hmac-sha1-96` (RFC 3962).
pub const AES256_SHA1: i32 = 18;

/// `aes256-cts-hmac-sha384-192` (RFC 8009).
pub const AES256_SHA384: i32 = 20;

/// The only enctypes a ticket may use (OP-155 m.3 (o)): AES256.
pub const ENCTYPES: [i32; 2] = [AES256_SHA1, AES256_SHA384];

/// [`super::Call::Authenticate`] of a Kerberos gateway.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authenticate {
    /// The realm; it must be the gateway's own.
    pub realm: String,
    /// The authenticated client principal, `user@REALM`.
    pub principal: String,
    /// The service principal the ticket was issued for, `service/host@REALM`.
    pub spn: String,
    /// The key version the ticket is encrypted under.
    pub kvno: u32,
    /// The ticket's enctype.
    pub etype: i32,
}

/// The answer to [`Authenticate`]: the subject, or none when the principal names no active
/// account. A policy refusal is a problem answer (`edge-spn`, `edge-enctype`, `edge-kvno`,
/// `edge-keytab`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Authenticated {
    /// The subject.
    pub subject: Option<[u8; 16]>,
}

impl Authenticate {
    /// The body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        encode(vec![
            ("realm", Value::text(&self.realm)),
            ("mechanism", Value::text("kerberos")),
            ("principal", Value::text(&self.principal)),
            ("spn", Value::text(&self.spn)),
            ("kvno", Value::Unsigned(u64::from(self.kvno))),
            ("etype", Value::int(i64::from(self.etype))),
        ])
    }

    /// Reads the body.
    ///
    /// # Errors
    /// [`WireError`].
    pub fn decode(body: &[u8]) -> Result<Self, WireError> {
        let v = decode_map(body)?;
        only(
            &v,
            &["realm", "mechanism", "principal", "spn", "kvno", "etype"],
        )?;
        if text(&v, "mechanism", 16)? != "kerberos" {
            return Err(WireError::Malformed);
        }
        let kvno = match v.get("kvno") {
            Some(Value::Unsigned(n)) => u32::try_from(*n).map_err(|_| WireError::Malformed)?,
            _ => return Err(WireError::Malformed),
        };
        let etype = match v.get("etype") {
            Some(Value::Unsigned(n)) => i32::try_from(*n).map_err(|_| WireError::Malformed)?,
            Some(Value::Negative(n)) => i32::try_from(*n)
                .ok()
                .and_then(|n| (-1_i32).checked_sub(n))
                .ok_or(WireError::Malformed)?,
            _ => return Err(WireError::Malformed),
        };
        Ok(Self {
            realm: text(&v, "realm", 64)?,
            principal: text(&v, "principal", MAX_PRINCIPAL)?,
            spn: text(&v, "spn", MAX_PRINCIPAL)?,
            kvno,
            etype,
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

    // IDP-17, OP-155 m.3 (o)
    #[test]
    fn acceptance_facts_round_trip() {
        let q = Authenticate {
            realm: String::from("corp"),
            principal: String::from("ada@CORP.EXAMPLE"),
            spn: String::from("HTTP/access.corp.example@CORP.EXAMPLE"),
            kvno: 3,
            etype: AES256_SHA1,
        };
        assert_eq!(Authenticate::decode(&q.encode()).unwrap(), q);
        let odd = Authenticate { etype: -128, ..q };
        assert_eq!(Authenticate::decode(&odd.encode()).unwrap(), odd);
        let a = Authenticated {
            subject: Some([1; 16]),
        };
        assert_eq!(Authenticated::decode(&a.encode()).unwrap(), a);
    }
}
