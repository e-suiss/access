//! How a signed PAP travels (CR-43, L2-BUD-1, OP-159 m.3 (p), (q), m.21 (f)): an offline PAP in
//! the smallest offline carrier that holds it, never by reference, and not at all when it fits
//! none; any other PAP inline while its text fits the header budget, else by reference.

use access_crypto::budget::Carrier;
use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_kernel::validity::ProfileClass;

/// How a signed PAP is carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Carried {
    /// Inline in the answer; for an offline PAP, the smallest offline carrier that holds it.
    Inline(Option<Carrier>),
    /// By reference: the SHA-256 of the artefact bytes and their length (`projection-ref.cddl`).
    Reference {
        /// SHA-256 of the artefact bytes.
        digest: [u8; 32],
        /// Their length.
        size: u64,
    },
    /// An offline PAP no offline carrier holds: it is not produced (`422
    /// projection-over-budget`).
    OverBudget,
}

/// Most expired projections one keep expires first.
pub const EXPIRE_BATCH: u32 = 64;

/// The additional data a kept projection is sealed under: its domain and digest.
#[must_use]
pub fn aad(domain: &Digest, digest: &[u8; 32]) -> Vec<u8> {
    [b"access/projection-blob/v1\0".as_slice(), &domain.0, digest].concat()
}

/// The offline carriers, smallest first.
const OFFLINE: [Carrier; 2] = [Carrier::Qr, Carrier::Nfc];

/// The length of `n` bytes as unpadded base64url text, as a header carries them.
const fn text_len(n: usize) -> usize {
    n.saturating_mul(4).div_ceil(3)
}

/// Whether the PAP `payload` is of the offline class.
#[must_use]
pub fn offline(payload: &[u8]) -> bool {
    access_kernel::pap::Pap::from_bytes(payload)
        .is_ok_and(|p| p.validity.class == ProfileClass::Offline)
}

/// How the PAP `payload`, signed as `sign1` (a `COSE_Sign1` or the hybrid carrier), is carried.
#[must_use]
pub fn plan(payload: &[u8], sign1: &[u8]) -> Carried {
    if offline(payload) {
        // L2-BUD-1, OP-159 m.3 (p)
        return OFFLINE
            .into_iter()
            .find(|c| c.check(sign1.len()).is_ok())
            .map_or(Carried::OverBudget, |c| Carried::Inline(Some(c)));
    }
    // OP-159 m.3 (q)
    if Carrier::Header.check(text_len(sign1.len())).is_ok() {
        return Carried::Inline(None);
    }
    Carried::Reference {
        digest: suiss_crypto::digest::sha256(sign1),
        size: u64::try_from(sign1.len()).unwrap_or(u64::MAX),
    }
}

/// The `fetch` path of a projection reference (`projection-ref.cddl`).
#[must_use]
pub fn fetch_path(domain: &Digest, digest: &[u8; 32]) -> String {
    format!(
        "/access/v1/domains/{}/projections/{}",
        access_kernel::json::b64url_encode(&domain.0),
        access_kernel::json::b64url_encode(digest)
    )
}

#[cfg(test)]
mod tests;
