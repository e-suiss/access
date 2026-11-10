//! A local security key (OP-156 m.3 (p), m.3 (z)): our own CTAP2 `authenticatorGetAssertion`
//! over CTAPHID, sans I/O, and the check of its answer against a credential Access listed for
//! the user. User presence and user verification are both required; a signature counter that
//! did not move forward is refused (cloned key).

use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::sha256;
use suiss_crypto::sig::PureBackend;

/// One HID report.
pub const REPORT: usize = 64;

/// `CTAPHID_INIT`.
pub const CMD_INIT: u8 = 0x06;
/// `CTAPHID_CBOR`.
pub const CMD_CBOR: u8 = 0x10;
/// `CTAPHID_KEEPALIVE`.
pub const CMD_KEEPALIVE: u8 = 0x3b;
/// `CTAPHID_ERROR`.
pub const CMD_ERROR: u8 = 0x3f;
/// The broadcast channel.
pub const BROADCAST: [u8; 4] = [0xff; 4];

/// `authenticatorGetAssertion`.
pub const GET_ASSERTION: u8 = 0x02;

/// Largest CTAPHID message (one init and 128 continuation packets).
pub const MAX_MESSAGE: usize = 57 + 128 * 59;

/// COSE ES256.
pub const ES256: i64 = -7;
/// COSE `EdDSA` (Ed25519).
pub const EDDSA: i64 = -8;

const UP: u8 = 0x01;
const UV: u8 = 0x04;

/// Why a key's answer is not taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FidoError {
    /// The message does not fit CTAPHID.
    #[error("fido-frame")]
    Frame,
    /// The key answered an error or something outside CTAP2.
    #[error("fido-answer")]
    Answer,
    /// The assertion is not for this relying party, lacks UP or UV, or its counter went back.
    #[error("fido-assertion")]
    Assertion,
    /// The signature does not verify with the listed credential.
    #[error("fido-signature")]
    Signature,
}

/// A credential Access listed for the user at their last online sign-in.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Credential {
    /// Credential id.
    #[serde(with = "b64")]
    pub id: Vec<u8>,
    /// COSE algorithm: [`ES256`] or [`EDDSA`].
    pub alg: i64,
    /// SEC1 uncompressed P-256 point, or the 32-byte Ed25519 key.
    #[serde(with = "b64")]
    pub public_key: Vec<u8>,
    /// The relying party the credential is scoped to.
    pub rp_id: String,
    /// The last signature counter seen.
    #[serde(default)]
    pub sign_count: u32,
}

mod b64 {
    use access_kernel::json::{b64url_decode, b64url_encode};
    use serde::{Deserialize as _, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&b64url_encode(v))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let t = String::deserialize(d)?;
        b64url_decode(&t).map_err(|_| serde::de::Error::custom("base64url"))
    }
}

fn put(buf: &mut [u8; REPORT], at: usize, bytes: &[u8]) -> Result<(), FidoError> {
    let end = at.checked_add(bytes.len()).ok_or(FidoError::Frame)?;
    buf.get_mut(at..end)
        .ok_or(FidoError::Frame)?
        .copy_from_slice(bytes);
    Ok(())
}

/// The packets of one CTAPHID message on channel `cid`.
///
/// # Errors
/// [`FidoError::Frame`] past [`MAX_MESSAGE`].
pub fn packets(cid: [u8; 4], cmd: u8, payload: &[u8]) -> Result<Vec<[u8; REPORT]>, FidoError> {
    if payload.len() > MAX_MESSAGE {
        return Err(FidoError::Frame);
    }
    let len = u16::try_from(payload.len()).map_err(|_| FidoError::Frame)?;
    let mut out = Vec::new();
    let mut p = [0u8; REPORT];
    put(&mut p, 0, &cid)?;
    put(&mut p, 4, &[cmd | 0x80])?;
    put(&mut p, 5, &len.to_be_bytes())?;
    let (first, mut rest) = payload.split_at(payload.len().min(57));
    put(&mut p, 7, first)?;
    out.push(p);
    let mut seq = 0u8;
    while !rest.is_empty() {
        let mut c = [0u8; REPORT];
        put(&mut c, 0, &cid)?;
        put(&mut c, 4, &[seq])?;
        let (chunk, tail) = rest.split_at(rest.len().min(59));
        put(&mut c, 5, chunk)?;
        out.push(c);
        rest = tail;
        seq = seq.checked_add(1).ok_or(FidoError::Frame)?;
    }
    Ok(out)
}

/// Reassembles one CTAPHID answer on a channel, skipping keepalives.
#[derive(Debug)]
pub struct Reassembly {
    cid: [u8; 4],
    cmd: Option<u8>,
    want: usize,
    seq: u8,
    data: Vec<u8>,
}

impl Reassembly {
    /// Waits for an answer on `cid`.
    #[must_use]
    pub const fn new(cid: [u8; 4]) -> Self {
        Self {
            cid,
            cmd: None,
            want: 0,
            seq: 0,
            data: Vec::new(),
        }
    }

    /// Feeds one report; `Some((cmd, payload))` once the answer is whole.
    ///
    /// # Errors
    /// [`FidoError::Frame`] on a report out of order; [`FidoError::Answer`] on `ERROR`.
    pub fn feed(&mut self, r: &[u8; REPORT]) -> Result<Option<(u8, Vec<u8>)>, FidoError> {
        let [c0, c1, c2, c3, head, b5, b6, ..] = *r;
        if [c0, c1, c2, c3] != self.cid {
            return Ok(None);
        }
        let data = |from: usize, n: usize| {
            from.checked_add(n)
                .and_then(|end| r.get(from..end))
                .ok_or(FidoError::Frame)
        };
        if self.cmd.is_none() {
            {
                if head & 0x80 == 0 {
                    return Err(FidoError::Frame);
                }
                let cmd = head & 0x7f;
                if cmd == CMD_KEEPALIVE {
                    return Ok(None);
                }
                if cmd == CMD_ERROR {
                    return Err(FidoError::Answer);
                }
                let want = usize::from(u16::from_be_bytes([b5, b6]));
                if want > MAX_MESSAGE {
                    return Err(FidoError::Frame);
                }
                self.cmd = Some(cmd);
                self.want = want;
                self.data.extend_from_slice(data(7, want.min(57))?);
            }
        } else {
            {
                if head != self.seq {
                    return Err(FidoError::Frame);
                }
                self.seq = self.seq.checked_add(1).ok_or(FidoError::Frame)?;
                let left = self.want.saturating_sub(self.data.len());
                self.data.extend_from_slice(data(5, left.min(59))?);
            }
        }
        match self.cmd {
            Some(cmd) if self.data.len() >= self.want => {
                Ok(Some((cmd, std::mem::take(&mut self.data))))
            }
            _ => Ok(None),
        }
    }
}

/// The `CTAPHID_INIT` answer's new channel, if it answers `nonce`.
#[must_use]
pub fn init_channel(payload: &[u8], nonce: &[u8; 8]) -> Option<[u8; 4]> {
    if payload.get(..8)? != nonce {
        return None;
    }
    <[u8; 4]>::try_from(payload.get(8..12)?).ok()
}

/// The CTAP2 `authenticatorGetAssertion` command for `rp_id` over `client_data_hash`,
/// limited to `allow`, asking for presence and verification.
///
/// # Errors
/// [`FidoError::Frame`].
pub fn get_assertion(
    rp_id: &str,
    client_data_hash: &[u8; 32],
    allow: &[&[u8]],
) -> Result<Vec<u8>, FidoError> {
    let list = allow
        .iter()
        .map(|id| {
            Value::Map(vec![
                (Value::text("id"), Value::Bytes(id.to_vec())),
                (Value::text("type"), Value::text("public-key")),
            ])
        })
        .collect();
    let params = Value::Map(vec![
        (Value::Unsigned(1), Value::text(rp_id)),
        (Value::Unsigned(2), Value::Bytes(client_data_hash.to_vec())),
        (Value::Unsigned(3), Value::Array(list)),
        (
            Value::Unsigned(5),
            Value::Map(vec![(Value::text("up"), Value::Bool(true))]),
        ),
    ]);
    let mut out = vec![GET_ASSERTION];
    out.extend(dcbor::encode(&params, Limits::CEILING).map_err(|_| FidoError::Frame)?);
    Ok(out)
}

/// An `authenticatorGetAssertion` answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assertion {
    /// The credential that signed.
    pub credential: Vec<u8>,
    /// Authenticator data.
    pub auth_data: Vec<u8>,
    /// Signature over `auth_data ‖ client_data_hash`.
    pub signature: Vec<u8>,
}

fn int_key(entries: &[(Value, Value)], k: u64) -> Option<&Value> {
    entries
        .iter()
        .find(|(key, _)| *key == Value::Unsigned(k))
        .map(|(_, v)| v)
}

fn byte_value(v: Option<&Value>) -> Option<Vec<u8>> {
    match v? {
        Value::Bytes(b) => Some(b.clone()),
        _ => None,
    }
}

/// Parses the key's answer to `authenticatorGetAssertion`: status 0, then the CBOR map.
/// Authenticators encode CBOR canonically (CTAP2 §8), so the strict decoder is used.
///
/// # Errors
/// [`FidoError::Answer`].
pub fn parse_assertion(answer: &[u8]) -> Result<Assertion, FidoError> {
    let (status, body) = answer.split_first().ok_or(FidoError::Answer)?;
    if *status != 0 {
        return Err(FidoError::Answer);
    }
    let Value::Map(m) = dcbor::decode(body, Limits::CEILING).map_err(|_| FidoError::Answer)? else {
        return Err(FidoError::Answer);
    };
    let credential = match int_key(&m, 1) {
        Some(c @ Value::Map(_)) => byte_value(c.get("id")).ok_or(FidoError::Answer)?,
        _ => return Err(FidoError::Answer),
    };
    Ok(Assertion {
        credential,
        auth_data: byte_value(int_key(&m, 2)).ok_or(FidoError::Answer)?,
        signature: byte_value(int_key(&m, 3)).ok_or(FidoError::Answer)?,
    })
}

/// An ASN.1 DER ECDSA signature as the raw 64-byte `r ‖ s`.
#[must_use]
pub fn der_to_raw(der: &[u8]) -> Option<[u8; 64]> {
    let rest = der.strip_prefix(&[0x30])?;
    let (&len, rest) = rest.split_first()?;
    if usize::from(len) != rest.len() {
        return None;
    }
    let mut out = [0u8; 64];
    let mut rest = rest;
    for half in out.chunks_mut(32) {
        let r = rest.strip_prefix(&[0x02])?;
        let (&n, r) = r.split_first()?;
        let n = usize::from(n);
        let (int, tail) = (r.get(..n)?, r.get(n..)?);
        let int = match int {
            [0, tail @ ..] if tail.first().is_some_and(|b| b & 0x80 != 0) => tail,
            i => i,
        };
        if int.len() > 32 || int.is_empty() {
            return None;
        }
        half.get_mut(32usize.checked_sub(int.len())?..)?
            .copy_from_slice(int);
        rest = tail;
    }
    rest.is_empty().then_some(out)
}

/// Checks `a` against `credential` for `client_data_hash`; the new signature counter.
///
/// # Errors
/// [`FidoError`].
pub fn verify(
    credential: &Credential,
    client_data_hash: &[u8; 32],
    a: &Assertion,
) -> Result<u32, FidoError> {
    if a.credential != credential.id || a.auth_data.len() < 37 {
        return Err(FidoError::Assertion);
    }
    let rp_hash = sha256(credential.rp_id.as_bytes());
    let flags = a.auth_data.get(32).copied().ok_or(FidoError::Assertion)?;
    if a.auth_data.get(..32) != Some(rp_hash.as_slice()) || flags & UP == 0 || flags & UV == 0 {
        return Err(FidoError::Assertion);
    }
    let count = a
        .auth_data
        .get(33..37)
        .and_then(|c| <[u8; 4]>::try_from(c).ok())
        .map(u32::from_be_bytes)
        .ok_or(FidoError::Assertion)?;
    if (count != 0 || credential.sign_count != 0) && count <= credential.sign_count {
        return Err(FidoError::Assertion);
    }
    let mut message = a.auth_data.clone();
    message.extend_from_slice(client_data_hash);
    match credential.alg {
        ES256 => {
            let raw = der_to_raw(&a.signature).ok_or(FidoError::Signature)?;
            suiss_crypto::sig::p256(&PureBackend, &credential.public_key, &message, &raw, false)
                .map_err(|_| FidoError::Signature)?;
        }
        EDDSA => {
            let key = <[u8; 32]>::try_from(credential.public_key.as_slice())
                .map_err(|_| FidoError::Signature)?;
            suiss_crypto::sig::ed25519(&PureBackend, &key, &message, &a.signature)
                .map_err(|_| FidoError::Signature)?;
        }
        _ => return Err(FidoError::Signature),
    }
    Ok(count)
}
