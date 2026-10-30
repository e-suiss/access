//! C2SP `signed-note`, `tlog-checkpoint` and Ed25519 `tlog-cosignature/v1` (OP-86, OP-140 m.2).

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use sha2::{Digest as _, Sha256};

use crate::sig::{Backend, SignatureError, ed25519};

/// Signature type byte of an Ed25519 note signature.
pub const ED25519: u8 = 0x01;
/// Signature type byte of a timestamped Ed25519 checkpoint cosignature.
pub const COSIGNATURE: u8 = 0x04;
/// Most signature lines a note may carry; C2SP requires accepting at least 16.
pub const MAX_SIGNATURES: usize = 64;
/// Largest note accepted, in bytes.
pub const MAX_NOTE: usize = 256 * 1024;
/// Longest key name or log origin, in bytes.
pub const MAX_NAME: usize = 255;

const DASH: &str = "\u{2014} ";

/// Why a note, checkpoint or verifier key is rejected.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NoteError {
    /// Larger than [`MAX_NOTE`] or more than [`MAX_SIGNATURES`] signatures.
    #[error("note too large")]
    TooLarge,
    /// Not of the form body, blank line, signature lines.
    #[error("malformed note")]
    Malformed,
    /// A control character other than newline in the body.
    #[error("control character in body")]
    Control,
    /// A key name or origin breaks the naming rules.
    #[error("bad key name")]
    Name,
    /// Base64 that is not canonical standard base64 with padding.
    #[error("non-canonical base64")]
    Base64,
    /// A verifier key string is malformed.
    #[error("bad verifier key")]
    VerifierKey,
    /// Two signature lines with the same name and key ID.
    #[error("duplicate signature")]
    Duplicate,
    /// A signature from a known key does not verify.
    #[error("signature: {0}")]
    Signature(SignatureError),
    /// No signature from a known key.
    #[error("no signature from a known key")]
    Unverified,
    /// The body is not a checkpoint.
    #[error("malformed checkpoint")]
    Checkpoint,
}

impl NoteError {
    /// Stable reason code for problem details (RFC 9457).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::TooLarge => "note-too-large",
            Self::Malformed => "note-malformed",
            Self::Control => "note-control",
            Self::Name => "note-name",
            Self::Base64 => "note-base64",
            Self::VerifierKey => "note-verifier-key",
            Self::Duplicate => "note-duplicate",
            Self::Signature(e) => e.code(),
            Self::Unverified => "note-unverified",
            Self::Checkpoint => "checkpoint-malformed",
        }
    }
}

/// Checks a key name, log origin or cosigner name: non-empty UTF-8 of at most 255 bytes, no
/// whitespace, `+` or control characters.
///
/// # Errors
/// [`NoteError::Name`].
pub fn check_name(name: &str) -> Result<(), NoteError> {
    let bad = name.is_empty()
        || name.len() > MAX_NAME
        || name
            .chars()
            .any(|c| c.is_whitespace() || c == '+' || c.is_control());
    if bad { Err(NoteError::Name) } else { Ok(()) }
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn symbol(index: u32) -> char {
    ALPHABET
        .get(usize::try_from(index & 0x3f).unwrap_or(0))
        .map_or('=', |b| char::from(*b))
}

/// Standard base64 with padding (RFC 4648 §4).
#[must_use]
pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let mut b = [0_u8; 3];
        for (d, s) in b.iter_mut().zip(chunk) {
            *d = *s;
        }
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let digits = [n >> 18, n >> 12, n >> 6, n];
        for (i, d) in digits.iter().enumerate() {
            out.push(if i <= chunk.len() { symbol(*d) } else { '=' });
        }
    }
    out
}

fn sextet(c: u8) -> Option<u32> {
    ALPHABET
        .iter()
        .position(|a| *a == c)
        .and_then(|p| u32::try_from(p).ok())
}

/// Decodes canonical standard base64 with padding; any other spelling is rejected (RFC 4648
/// §3.5).
///
/// # Errors
/// [`NoteError::Base64`].
pub fn base64_decode(text: &str) -> Result<Vec<u8>, NoteError> {
    let input = text.as_bytes();
    if !input.len().is_multiple_of(4) {
        return Err(NoteError::Base64);
    }
    let quads: Vec<&[u8]> = input.chunks(4).collect();
    let mut out = Vec::new();
    for (q, chunk) in quads.iter().enumerate() {
        let last = q.checked_add(1) == Some(quads.len());
        let pad = chunk.iter().rev().take_while(|c| **c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return Err(NoteError::Base64);
        }
        let data = chunk.len().saturating_sub(pad);
        let mut acc = 0_u32;
        for (i, c) in chunk.iter().enumerate() {
            let v = if i < data {
                sextet(*c).ok_or(NoteError::Base64)?
            } else {
                0
            };
            acc = (acc << 6) | v;
        }
        let unused = match pad {
            1 => 0xff,
            2 => 0xffff,
            _ => 0,
        };
        if acc & unused != 0 {
            return Err(NoteError::Base64);
        }
        let [_, b0, b1, b2] = acc.to_be_bytes();
        out.extend([b0, b1, b2].iter().take(3_usize.saturating_sub(pad)));
    }
    Ok(out)
}

fn key_id(name: &str, kind: u8, key: &[u8; 32]) -> u32 {
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    h.update([0x0a, kind]);
    h.update(key);
    let d: [u8; 32] = h.finalize().into();
    d.first_chunk::<4>().map_or(0, |b| u32::from_be_bytes(*b))
}

/// A key that verifies note signatures: an Ed25519 note signer or an Ed25519 checkpoint
/// cosigner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verifier {
    name: String,
    id: u32,
    kind: u8,
    key: [u8; 32],
}

impl Verifier {
    /// An Ed25519 note signer, e.g. a log signing its own checkpoints.
    ///
    /// # Errors
    /// [`NoteError::Name`].
    pub fn ed25519(name: &str, key: [u8; 32]) -> Result<Self, NoteError> {
        Self::new(name, ED25519, key)
    }

    /// An Ed25519 checkpoint cosigner (`tlog-cosignature`).
    ///
    /// # Errors
    /// [`NoteError::Name`].
    pub fn cosigner(name: &str, key: [u8; 32]) -> Result<Self, NoteError> {
        Self::new(name, COSIGNATURE, key)
    }

    fn new(name: &str, kind: u8, key: [u8; 32]) -> Result<Self, NoteError> {
        check_name(name)?;
        Ok(Self {
            name: name.to_string(),
            id: key_id(name, kind, &key),
            kind,
            key,
        })
    }

    /// Parses a verifier key `<name>+<hex id>+<base64(type ‖ key)>` and checks that the ID is
    /// the one the key derives.
    ///
    /// # Errors
    /// [`NoteError::VerifierKey`] or [`NoteError::Name`].
    pub fn parse(vkey: &str) -> Result<Self, NoteError> {
        let mut parts = vkey.split('+');
        let (Some(name), Some(id), Some(key), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(NoteError::VerifierKey);
        };
        if id.len() != 8 || !id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(NoteError::VerifierKey);
        }
        let id = u32::from_str_radix(id, 16).map_err(|_| NoteError::VerifierKey)?;
        let raw = base64_decode(key).map_err(|_| NoteError::VerifierKey)?;
        let (kind, key) = raw.split_first().ok_or(NoteError::VerifierKey)?;
        let key: [u8; 32] = key.try_into().map_err(|_| NoteError::VerifierKey)?;
        let v = match *kind {
            ED25519 => Self::ed25519(name, key)?,
            COSIGNATURE => Self::cosigner(name, key)?,
            _ => return Err(NoteError::VerifierKey),
        };
        if v.id == id {
            Ok(v)
        } else {
            Err(NoteError::VerifierKey)
        }
    }

    /// The verifier key string.
    #[must_use]
    pub fn to_vkey(&self) -> String {
        let mut raw = Vec::with_capacity(33);
        raw.push(self.kind);
        raw.extend_from_slice(&self.key);
        format!("{}+{:08x}+{}", self.name, self.id, base64_encode(&raw))
    }

    /// Key name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Key ID.
    #[must_use]
    pub const fn id(&self) -> u32 {
        self.id
    }

    /// Whether this is a checkpoint cosigner.
    #[must_use]
    pub const fn is_cosigner(&self) -> bool {
        self.kind == COSIGNATURE
    }
}

/// One signature line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteSignature {
    /// Key name.
    pub name: String,
    /// Key ID.
    pub id: u32,
    /// The bytes after the key ID.
    pub signature: Vec<u8>,
}

/// A note split into its body and signature lines, not yet verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Note {
    /// The body, including its final newline.
    pub body: String,
    /// The signature lines in order.
    pub signatures: Vec<NoteSignature>,
}

/// Splits a note into body and signatures and checks its syntax.
///
/// # Errors
/// [`NoteError`].
pub fn parse_note(text: &str) -> Result<Note, NoteError> {
    if text.len() > MAX_NOTE {
        return Err(NoteError::TooLarge);
    }
    let split = text.rfind("\n\n").ok_or(NoteError::Malformed)?;
    let (body, rest) = text.split_at(split.checked_add(1).ok_or(NoteError::Malformed)?);
    let sigs = rest.strip_prefix('\n').ok_or(NoteError::Malformed)?;
    if body.chars().any(|c| c.is_control() && c != '\n') {
        return Err(NoteError::Control);
    }
    if sigs.is_empty() || !sigs.ends_with('\n') {
        return Err(NoteError::Malformed);
    }
    let mut signatures: Vec<NoteSignature> = Vec::new();
    for line in sigs.trim_end_matches('\n').split('\n') {
        if signatures.len() == MAX_SIGNATURES {
            return Err(NoteError::TooLarge);
        }
        let line = line.strip_prefix(DASH).ok_or(NoteError::Malformed)?;
        let (name, b64) = line.split_once(' ').ok_or(NoteError::Malformed)?;
        check_name(name)?;
        let raw = base64_decode(b64)?;
        if raw.len() < 5 {
            return Err(NoteError::Malformed);
        }
        let (id, signature) = raw.split_first_chunk::<4>().ok_or(NoteError::Malformed)?;
        let id = u32::from_be_bytes(*id);
        if signatures.iter().any(|s| s.name == name && s.id == id) {
            return Err(NoteError::Duplicate);
        }
        signatures.push(NoteSignature {
            name: name.to_string(),
            id,
            signature: signature.to_vec(),
        });
    }
    Ok(Note {
        body: body.to_string(),
        signatures,
    })
}

/// A signature that verified, with the cosignature timestamp when there is one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accepted {
    /// Key name.
    pub name: String,
    /// Key ID.
    pub id: u32,
    /// Seconds since the epoch, for a cosignature.
    pub timestamp: Option<u64>,
}

/// The message an Ed25519 cosigner signs: `cosignature/v1`, `time <t>`, then the checkpoint
/// body including extension lines.
#[must_use]
pub fn cosigned_message(timestamp: u64, body: &str) -> Vec<u8> {
    format!("cosignature/v1\ntime {timestamp}\n{body}").into_bytes()
}

/// Verifies a note against known keys. Signatures from unknown keys are ignored; a failing
/// signature from a known key rejects the note; at least one must verify.
///
/// # Errors
/// [`NoteError`].
pub fn verify_note(
    backend: &impl Backend,
    text: &str,
    known: &[Verifier],
) -> Result<(Note, Vec<Accepted>), NoteError> {
    let note = parse_note(text)?;
    let mut accepted = Vec::new();
    for s in &note.signatures {
        let Some(v) = known.iter().find(|v| v.name == s.name && v.id == s.id) else {
            continue;
        };
        let timestamp = if v.kind == COSIGNATURE {
            let (ts, sig) = s
                .signature
                .split_at_checked(8)
                .ok_or(NoteError::Malformed)?;
            let ts = u64::from_be_bytes(ts.try_into().map_err(|_| NoteError::Malformed)?);
            ed25519(backend, &v.key, &cosigned_message(ts, &note.body), sig)
                .map_err(NoteError::Signature)?;
            Some(ts)
        } else {
            ed25519(backend, &v.key, note.body.as_bytes(), &s.signature)
                .map_err(NoteError::Signature)?;
            None
        };
        accepted.push(Accepted {
            name: s.name.clone(),
            id: s.id,
            timestamp,
        });
    }
    if accepted.is_empty() {
        return Err(NoteError::Unverified);
    }
    Ok((note, accepted))
}

/// A `tlog-checkpoint` body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    /// Log origin.
    pub origin: String,
    /// Tree size.
    pub size: u64,
    /// RFC 9162 root hash at that size.
    pub root: [u8; 32],
    /// Extension lines, each non-empty.
    pub extensions: Vec<String>,
}

impl Checkpoint {
    /// Parses a checkpoint body.
    ///
    /// # Errors
    /// [`NoteError::Checkpoint`] or [`NoteError::Name`].
    pub fn parse(body: &str) -> Result<Self, NoteError> {
        let lines = body.strip_suffix('\n').ok_or(NoteError::Checkpoint)?;
        let mut it = lines.split('\n');
        let (Some(origin), Some(size), Some(root)) = (it.next(), it.next(), it.next()) else {
            return Err(NoteError::Checkpoint);
        };
        check_name(origin)?;
        let canonical = !size.is_empty()
            && size.bytes().all(|b| b.is_ascii_digit())
            && (size == "0" || !size.starts_with('0'));
        if !canonical {
            return Err(NoteError::Checkpoint);
        }
        let size = size.parse::<u64>().map_err(|_| NoteError::Checkpoint)?;
        let root: [u8; 32] = base64_decode(root)
            .map_err(|_| NoteError::Checkpoint)?
            .try_into()
            .map_err(|_| NoteError::Checkpoint)?;
        let extensions: Vec<String> = it.map(ToString::to_string).collect();
        if extensions
            .iter()
            .any(|e| e.is_empty() || e.chars().any(char::is_control))
        {
            return Err(NoteError::Checkpoint);
        }
        Ok(Self {
            origin: origin.to_string(),
            size,
            root,
            extensions,
        })
    }

    /// The body a log signs.
    ///
    /// # Errors
    /// [`NoteError::Name`] or [`NoteError::Checkpoint`] for an origin or extension line that
    /// breaks the rules.
    pub fn to_body(&self) -> Result<String, NoteError> {
        check_name(&self.origin)?;
        let mut out = format!(
            "{}\n{}\n{}\n",
            self.origin,
            self.size,
            base64_encode(&self.root)
        );
        for e in &self.extensions {
            if e.is_empty() || e.chars().any(char::is_control) {
                return Err(NoteError::Checkpoint);
            }
            out.push_str(e);
            out.push('\n');
        }
        Ok(out)
    }
}

/// Verifies a signed checkpoint: the note verifies under `log` and `cosigners`, the body is a
/// checkpoint of `origin`, and the log's own signature is among those accepted.
///
/// # Errors
/// [`NoteError`].
pub fn verify_checkpoint(
    backend: &impl Backend,
    text: &str,
    origin: &str,
    log: &Verifier,
    cosigners: &[Verifier],
) -> Result<(Checkpoint, Vec<Accepted>), NoteError> {
    let mut known = alloc::vec![log.clone()];
    known.extend(cosigners.iter().filter(|c| c.is_cosigner()).cloned());
    let (note, accepted) = verify_note(backend, text, &known)?;
    let cp = Checkpoint::parse(&note.body)?;
    if cp.origin != origin {
        return Err(NoteError::Checkpoint);
    }
    if !accepted
        .iter()
        .any(|a| a.name == log.name && a.id == log.id)
    {
        return Err(NoteError::Unverified);
    }
    Ok((cp, accepted))
}

#[cfg(test)]
mod tests;
