//! RADIUS/1.1 packets (RFC 9765 over RFC 6614 `RadSec`; RFC 2865 attributes). Sans-I/O.
//!
//! RADIUS/1.1 keeps no MD5: the Identifier byte is reserved, the 16-byte Authenticator becomes a
//! 4-byte Token and 12 reserved bytes, `User-Password` travels as it is inside TLS, and
//! `Message-Authenticator` is ignored. A request is classified before anything is asked of
//! access-server: only PAP goes on; MS-CHAP and MS-CHAPv2 are refused by name (IDP-18), CHAP and
//! EAP as other methods.

/// Shortest packet: the header.
pub const HEADER: usize = 20;

/// Longest packet (RFC 2865 §3).
pub const MAX_PACKET: usize = 4096;

/// Access-Request.
pub const ACCESS_REQUEST: u8 = 1;
/// Access-Accept.
pub const ACCESS_ACCEPT: u8 = 2;
/// Access-Reject.
pub const ACCESS_REJECT: u8 = 3;
/// Status-Server (RFC 5997).
pub const STATUS_SERVER: u8 = 12;

const USER_NAME: u8 = 1;
const USER_PASSWORD: u8 = 2;
const CHAP_PASSWORD: u8 = 3;
const VENDOR_SPECIFIC: u8 = 26;
const CHAP_CHALLENGE: u8 = 60;
const EAP_MESSAGE: u8 = 79;
const MICROSOFT: u32 = 311;
const MS_CHAP_RESPONSE: u8 = 1;
const MS_CHAP_CHALLENGE: u8 = 11;
const MS_CHAP2_RESPONSE: u8 = 25;

/// Why bytes are not a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PacketError {
    /// The length field is below the header or above [`MAX_PACKET`].
    #[error("packet length out of range")]
    Length,
    /// An attribute runs past the packet or is shorter than its own header.
    #[error("malformed attribute")]
    Attribute,
}

/// The length a packet header announces; checked before the body is read.
///
/// # Errors
/// [`PacketError::Length`].
pub fn length(header: [u8; 4]) -> Result<usize, PacketError> {
    let n = usize::from(u16::from_be_bytes([header[2], header[3]]));
    if (HEADER..=MAX_PACKET).contains(&n) {
        Ok(n)
    } else {
        Err(PacketError::Length)
    }
}

/// One request as read.
#[derive(Clone, PartialEq, Eq)]
pub struct Request {
    /// The code.
    pub code: u8,
    /// The Token the answer echoes.
    pub token: [u8; 4],
    attributes: Vec<(u8, Vec<u8>)>,
}

impl core::fmt::Debug for Request {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Request")
            .field("code", &self.code)
            .finish_non_exhaustive()
    }
}

/// What a request asks, as the gateway answers it.
#[derive(Clone, PartialEq, Eq)]
pub enum Verdict {
    /// PAP: a user name and a password.
    Pap {
        /// `User-Name`.
        name: String,
        /// `User-Password`, trailing NUL padding removed.
        password: Vec<u8>,
    },
    /// MS-CHAP or MS-CHAPv2: never served (IDP-18).
    MsChap,
    /// CHAP, EAP, or anything that is not exactly one name and one password.
    OtherMethod,
    /// Status-Server: answered when the client is registered.
    Status,
    /// Any other code: not answered.
    Drop,
}

impl core::fmt::Debug for Verdict {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Pap { .. } => "Pap",
            Self::MsChap => "MsChap",
            Self::OtherMethod => "OtherMethod",
            Self::Status => "Status",
            Self::Drop => "Drop",
        })
    }
}

impl Request {
    /// Reads one whole packet.
    ///
    /// # Errors
    /// [`PacketError`].
    pub fn parse(packet: &[u8]) -> Result<Self, PacketError> {
        let head: [u8; 4] = packet
            .get(..4)
            .and_then(|h| h.try_into().ok())
            .ok_or(PacketError::Length)?;
        if length(head)? != packet.len() {
            return Err(PacketError::Length);
        }
        let token: [u8; 4] = packet
            .get(4..8)
            .and_then(|t| t.try_into().ok())
            .ok_or(PacketError::Length)?;
        let mut attributes = Vec::new();
        let mut rest = packet.get(HEADER..).ok_or(PacketError::Length)?;
        while !rest.is_empty() {
            let (Some(&kind), Some(&len)) = (rest.first(), rest.get(1)) else {
                return Err(PacketError::Attribute);
            };
            let len = usize::from(len);
            if len < 2 {
                return Err(PacketError::Attribute);
            }
            let value = rest.get(2..len).ok_or(PacketError::Attribute)?;
            attributes.push((kind, value.to_vec()));
            rest = rest.get(len..).ok_or(PacketError::Attribute)?;
        }
        Ok(Self {
            code: head[0],
            token,
            attributes,
        })
    }

    fn all(&self, kind: u8) -> impl Iterator<Item = &[u8]> {
        self.attributes
            .iter()
            .filter(move |(k, _)| *k == kind)
            .map(|(_, v)| v.as_slice())
    }

    fn microsoft(&self) -> bool {
        self.all(VENDOR_SPECIFIC).any(|v| {
            let vendor = v
                .get(..4)
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
                .map(u32::from_be_bytes);
            vendor == Some(MICROSOFT)
                && v.get(4).is_some_and(|t| {
                    [MS_CHAP_RESPONSE, MS_CHAP_CHALLENGE, MS_CHAP2_RESPONSE].contains(t)
                })
        })
    }

    /// What the request asks.
    #[must_use]
    pub fn verdict(&self) -> Verdict {
        match self.code {
            STATUS_SERVER => return Verdict::Status,
            ACCESS_REQUEST => {}
            _ => return Verdict::Drop,
        }
        if self.microsoft() {
            return Verdict::MsChap;
        }
        let other = [CHAP_PASSWORD, CHAP_CHALLENGE, EAP_MESSAGE]
            .iter()
            .any(|k| self.all(*k).next().is_some());
        let names: Vec<&[u8]> = self.all(USER_NAME).collect();
        let passwords: Vec<&[u8]> = self.all(USER_PASSWORD).collect();
        let (false, [name], [password]) = (other, names.as_slice(), passwords.as_slice()) else {
            return Verdict::OtherMethod;
        };
        let end = password
            .iter()
            .rposition(|b| *b != 0)
            .map_or(0, |i| i.saturating_add(1));
        let password = password.get(..end).unwrap_or_default();
        match core::str::from_utf8(name) {
            Ok(name) if !name.is_empty() && !password.is_empty() => Verdict::Pap {
                name: String::from(name),
                password: password.to_vec(),
            },
            _ => Verdict::OtherMethod,
        }
    }
}

/// An answer with no attributes: `code` with the request's Token.
#[must_use]
pub fn answer(code: u8, token: [u8; 4]) -> [u8; HEADER] {
    let mut out = [0_u8; HEADER];
    out[0] = code;
    out[2..4].copy_from_slice(&u16::try_from(HEADER).unwrap_or(20).to_be_bytes());
    out[4..8].copy_from_slice(&token);
    out
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        reason = "test code"
    )]

    use super::*;

    fn packet(code: u8, attrs: &[(u8, &[u8])]) -> Vec<u8> {
        let mut p = vec![code, 0, 0, 0, 9, 8, 7, 6];
        p.extend_from_slice(&[0; 12]);
        for (k, v) in attrs {
            p.push(*k);
            p.push(u8::try_from(v.len() + 2).unwrap());
            p.extend_from_slice(v);
        }
        let n = u16::try_from(p.len()).unwrap().to_be_bytes();
        p[2] = n[0];
        p[3] = n[1];
        p
    }

    // IDP-18, OP-155 m.3 (f)
    #[test]
    fn only_pap_goes_on_and_ms_chap_is_refused_by_name() {
        let pap = packet(
            ACCESS_REQUEST,
            &[(USER_NAME, b"ada"), (USER_PASSWORD, b"pw\0\0")],
        );
        let r = Request::parse(&pap).unwrap();
        assert_eq!(r.token, [9, 8, 7, 6]);
        assert_eq!(
            r.verdict(),
            Verdict::Pap {
                name: String::from("ada"),
                password: b"pw".to_vec()
            }
        );
        let mut ms = vec![0, 0, 1, 55, MS_CHAP2_RESPONSE, 52];
        ms.extend_from_slice(&[0; 50]);
        let chap2 = packet(
            ACCESS_REQUEST,
            &[(USER_NAME, b"ada"), (VENDOR_SPECIFIC, &ms)],
        );
        assert_eq!(Request::parse(&chap2).unwrap().verdict(), Verdict::MsChap);
        let both = packet(
            ACCESS_REQUEST,
            &[
                (USER_NAME, b"ada"),
                (USER_PASSWORD, b"pw"),
                (VENDOR_SPECIFIC, &ms),
            ],
        );
        assert_eq!(Request::parse(&both).unwrap().verdict(), Verdict::MsChap);
        for other in [
            packet(
                ACCESS_REQUEST,
                &[(USER_NAME, b"ada"), (CHAP_PASSWORD, b"x")],
            ),
            packet(ACCESS_REQUEST, &[(USER_NAME, b"ada"), (EAP_MESSAGE, b"x")]),
            packet(ACCESS_REQUEST, &[(USER_NAME, b"ada")]),
            packet(
                ACCESS_REQUEST,
                &[
                    (USER_NAME, b"ada"),
                    (USER_NAME, b"bob"),
                    (USER_PASSWORD, b"pw"),
                ],
            ),
            packet(
                ACCESS_REQUEST,
                &[(USER_NAME, b"ada"), (USER_PASSWORD, b"\0")],
            ),
        ] {
            assert_eq!(
                Request::parse(&other).unwrap().verdict(),
                Verdict::OtherMethod
            );
        }
        assert_eq!(
            Request::parse(&packet(STATUS_SERVER, &[]))
                .unwrap()
                .verdict(),
            Verdict::Status
        );
        assert_eq!(
            Request::parse(&packet(4, &[])).unwrap().verdict(),
            Verdict::Drop
        );
    }

    // OP-155 m.3 (f)
    #[test]
    fn lengths_are_checked_before_reading() {
        assert_eq!(length([1, 0, 0, 19]), Err(PacketError::Length));
        assert_eq!(length([1, 0, 0x10, 1]), Err(PacketError::Length));
        assert_eq!(length([1, 0, 0, 20]), Ok(20));
        let mut bad = packet(ACCESS_REQUEST, &[(USER_NAME, b"ada")]);
        bad[21] = 40;
        assert_eq!(Request::parse(&bad), Err(PacketError::Attribute));
        let mut short = packet(ACCESS_REQUEST, &[(USER_NAME, b"ada")]);
        short[21] = 1;
        assert_eq!(Request::parse(&short), Err(PacketError::Attribute));
        let a = answer(ACCESS_REJECT, [9, 8, 7, 6]);
        assert_eq!(&a[..8], &[3, 0, 0, 20, 9, 8, 7, 6]);
        assert!(a[8..].iter().all(|b| *b == 0));
    }
}
