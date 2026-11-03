//! The outbox payload of a Relay message (OP-73, OP-74 m.1, m.6): the address and the code
//! are personal or secret, and the outbox is never deleted, so the message is sealed under its
//! own DEK wrapped by the subject's DEK. Shredding the subject makes every queued message to
//! it unreadable; nothing linkable stays beside the ciphertext but internal ids.
//!
//! Layout, version 1:
//! `0x01 ‖ tenant(16) ‖ realm(16) ‖ event id(16) ‖ subject(16) ‖ occurred ms(8, BE) ‖
//! wrapped DEK length(2, BE) ‖ wrapped DEK ‖ nonce(12) ‖ ciphertext`.
//! The AEAD context binds every header field and the kind.

use core::fmt;
use core::fmt::Write as _;

use suiss_crypto::envelope::{Dek, DekKek, Kek as _, Sealed, open_body, seal_body};

use crate::app::sealing::subject_dek_id;
use crate::notify::message::Message;

const VERSION: u8 = 1;
const CONTEXT: &[u8] = b"access/relay-message/v1\0";
const HEADER: usize = 1 + 16 * 4 + 8;
const NONCE: usize = 12;

/// A `CloudEvents` id: a random UUID, also Relay's idempotency key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct EventId(pub [u8; 16]);

impl EventId {
    /// From 16 random bytes, as a version 4 UUID.
    #[must_use]
    pub fn from_random(mut b: [u8; 16]) -> Self {
        if let Some(v) = b.get_mut(6) {
            *v = (*v & 0x0f) | 0x40;
        }
        if let Some(v) = b.get_mut(8) {
            *v = (*v & 0x3f) | 0x80;
        }
        Self(b)
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, b) in self.0.iter().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                f.write_char('-')?;
            }
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EventId({self})")
    }
}

/// The clear header of a queued message: internal ids and a time, no personal data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// Tenant.
    pub tenant: [u8; 16],
    /// Realm.
    pub realm: [u8; 16],
    /// Event id.
    pub event: EventId,
    /// Subject.
    pub subject: [u8; 16],
    /// When it was queued, Unix ms.
    pub occurred_ms: u64,
}

/// A payload that does not parse or open.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("malformed relay envelope")]
pub struct Malformed;

fn context(kind: &str, h: &Header) -> Vec<u8> {
    let mut c = CONTEXT.to_vec();
    c.extend_from_slice(&h.tenant);
    c.extend_from_slice(&h.realm);
    c.extend_from_slice(&h.event.0);
    c.extend_from_slice(&h.subject);
    c.extend_from_slice(&h.occurred_ms.to_be_bytes());
    c.extend_from_slice(kind.as_bytes());
    c
}

/// Seals `message` under a fresh DEK wrapped by `subject_dek`.
///
/// # Errors
/// [`Malformed`] when sealing fails or the wrapped key is too long.
pub fn seal(header: &Header, subject_dek: &Dek, message: &Message) -> Result<Vec<u8>, Malformed> {
    let plain = zeroize::Zeroizing::new(
        serde_json::to_vec(&message.to_sealed_json()).map_err(|_| Malformed)?,
    );
    let kind = message.body.kind();
    let dek = Dek::generate().map_err(|_| Malformed)?;
    let wrapped = DekKek::new(&subject_dek_id(&header.subject), subject_dek)
        .wrap(&dek)
        .map_err(|_| Malformed)?;
    let wrapped_len = u16::try_from(wrapped.len()).map_err(|_| Malformed)?;
    let sealed = seal_body(dek, &context(kind, header), &plain).map_err(|_| Malformed)?;
    let mut out = Vec::with_capacity(HEADER);
    out.push(VERSION);
    out.extend_from_slice(&header.tenant);
    out.extend_from_slice(&header.realm);
    out.extend_from_slice(&header.event.0);
    out.extend_from_slice(&header.subject);
    out.extend_from_slice(&header.occurred_ms.to_be_bytes());
    out.extend_from_slice(&wrapped_len.to_be_bytes());
    out.extend_from_slice(&wrapped);
    out.extend_from_slice(&sealed.nonce);
    out.extend_from_slice(&sealed.ciphertext);
    Ok(out)
}

fn take<const N: usize>(b: &[u8], at: &mut usize) -> Result<[u8; N], Malformed> {
    let end = at.checked_add(N).ok_or(Malformed)?;
    let s = b.get(*at..end).ok_or(Malformed)?;
    *at = end;
    <[u8; N]>::try_from(s).map_err(|_| Malformed)
}

/// A parsed, still sealed payload.
pub struct Envelope<'a> {
    /// The clear header.
    pub header: Header,
    wrapped: &'a [u8],
    nonce: [u8; NONCE],
    ciphertext: &'a [u8],
}

impl fmt::Debug for Envelope<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Envelope")
            .field("header", &self.header)
            .finish_non_exhaustive()
    }
}

/// Parses the clear header.
///
/// # Errors
/// [`Malformed`].
pub fn parse(payload: &[u8]) -> Result<Envelope<'_>, Malformed> {
    let mut at = 0;
    if take::<1>(payload, &mut at)? != [VERSION] {
        return Err(Malformed);
    }
    let header = Header {
        tenant: take(payload, &mut at)?,
        realm: take(payload, &mut at)?,
        event: EventId(take(payload, &mut at)?),
        subject: take(payload, &mut at)?,
        occurred_ms: u64::from_be_bytes(take(payload, &mut at)?),
    };
    let len = usize::from(u16::from_be_bytes(take(payload, &mut at)?));
    let end = at.checked_add(len).ok_or(Malformed)?;
    let wrapped = payload.get(at..end).ok_or(Malformed)?;
    at = end;
    let nonce = take(payload, &mut at)?;
    let ciphertext = payload.get(at..).ok_or(Malformed)?;
    Ok(Envelope {
        header,
        wrapped,
        nonce,
        ciphertext,
    })
}

impl Envelope<'_> {
    /// Opens the message with the subject's DEK.
    ///
    /// # Errors
    /// [`Malformed`] for a wrong key, a modified payload or content outside the contract.
    pub fn open(&self, kind: &str, subject_dek: &Dek) -> Result<Message, Malformed> {
        let dek = DekKek::new(&subject_dek_id(&self.header.subject), subject_dek)
            .unwrap(self.wrapped)
            .map_err(|_| Malformed)?;
        let plain = open_body(
            &dek,
            &context(kind, &self.header),
            &Sealed {
                nonce: self.nonce,
                ciphertext: self.ciphertext.to_vec(),
            },
        )
        .map_err(|_| Malformed)?;
        let v: serde_json::Value = serde_json::from_slice(&plain).map_err(|_| Malformed)?;
        Message::from_sealed_json(kind, self.header.subject, &v).map_err(|_| Malformed)
    }
}
