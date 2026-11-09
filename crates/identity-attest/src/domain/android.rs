//! Android hardware key attestation (§12.2.1, L21, AG-31 model 1): the checklist of
//! <https://developer.android.com/privacy-and-security/security-key-attestation>.
//!
//! 1. The chain verifies to an embedded Google root ([`crate::domain::roots::ANDROID`]).
//! 2. Only the leaf carries the `KeyDescription` extension (1.3.6.1.4.1.11129.2.1.17).
//! 3. Its `attestationChallenge` is the challenge Access issued.
//! 4. Attestation and `KeyMint` security levels are hardware (TEE or `StrongBox`), `StrongBox` when
//!    the policy asks for it.
//! 5. The hardware-enforced list says the key was generated in hardware (`origin` 0) and holds
//!    a `RootOfTrust`; verified boot and a locked bootloader when the policy asks for them.
//!
//! The result is an attestation, a Claim input only (L21): it never names an Instance.

use crate::AttestError;
use crate::domain::der::{self, Reader};
use crate::domain::x509::{self, AnyUsage, Cert};

/// 1.3.6.1.4.1.11129.2.1.17, the key attestation extension.
pub(crate) const OID_KEY_DESCRIPTION: &[u8] =
    &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x01, 0x11];

const TAG_ORIGIN: u32 = 702;
const TAG_ROOT_OF_TRUST: u32 = 704;
const ORIGIN_GENERATED: u64 = 0;

/// Where the attested key lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecurityLevel {
    /// The Trusted Execution Environment.
    Tee,
    /// A `StrongBox` secure element.
    StrongBox,
}

/// What the policy asks of an Android attestation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy<'a> {
    /// The challenge Access issued.
    pub challenge: &'a [u8],
    /// Whether only `StrongBox` is accepted.
    pub strongbox: bool,
    /// Whether the device must have booted a verified image.
    pub verified_boot: bool,
    /// Whether the bootloader must be locked.
    pub locked: bool,
}

/// A verified Android key attestation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attested {
    /// Where the key lives.
    pub level: SecurityLevel,
    /// `attestationVersion`.
    pub version: u64,
    /// Whether the device booted a verified image.
    pub verified_boot: bool,
    /// Whether the bootloader is locked.
    pub locked: bool,
    /// The attested public key (the leaf's `subjectPublicKey`).
    pub public_key: Vec<u8>,
}

fn level(v: &[u8]) -> Result<Option<SecurityLevel>, der::DerError> {
    Ok(match der::uint(v)? {
        1 => Some(SecurityLevel::Tee),
        2 => Some(SecurityLevel::StrongBox),
        _ => None,
    })
}

struct RootOfTrust {
    locked: bool,
    verified: bool,
}

fn hardware_list(list: &[u8]) -> Result<(Option<u64>, Option<RootOfTrust>), der::DerError> {
    let mut r = Reader::new(list)?;
    let (mut origin, mut root) = (None, None);
    while !r.is_empty() {
        let t = r.next_tlv()?;
        if t.tag.context(TAG_ORIGIN) {
            origin = Some(der::uint(Reader::new(t.value)?.tagged(der::INTEGER)?)?);
        } else if t.tag.context(TAG_ROOT_OF_TRUST) {
            let mut seq = Reader::new(Reader::new(t.value)?.tagged(der::SEQUENCE)?)?;
            seq.tagged(der::OCTET_STRING)?;
            let locked = der::boolean(seq.tagged(der::BOOLEAN)?)?;
            let state = der::uint(seq.tagged(der::ENUMERATED)?)?;
            root = Some(RootOfTrust {
                locked,
                verified: state == 0,
            });
        }
    }
    Ok((origin, root))
}

/// Verifies the attestation certificate `chain` (leaf first, DER) to `roots` at `now_s`
/// (Unix seconds) under `policy`.
///
/// # Errors
/// [`AttestError`].
pub fn verify(
    chain: &[Vec<u8>],
    roots: &[&[u8]],
    policy: &Policy<'_>,
    now_s: u64,
) -> Result<Attested, AttestError> {
    let (leaf, rest) = chain.split_first().ok_or(AttestError::Format)?;
    let intermediates: Vec<Vec<u8>> = rest
        .iter()
        .filter(|c| !roots.contains(&c.as_slice()))
        .cloned()
        .collect();
    x509::verify_chain(leaf, &intermediates, roots, now_s, AnyUsage)
        .map_err(|_| AttestError::Chain)?;
    for c in rest {
        let cert = Cert::parse(c).map_err(|_| AttestError::Format)?;
        if cert
            .extension(OID_KEY_DESCRIPTION)
            .map_err(|_| AttestError::Format)?
            .is_some()
        {
            return Err(AttestError::Certificate);
        }
    }
    let cert = Cert::parse(leaf).map_err(|_| AttestError::Format)?;
    let ext = cert
        .extension(OID_KEY_DESCRIPTION)
        .map_err(|_| AttestError::Format)?
        .ok_or(AttestError::Certificate)?;
    let parse = || -> Result<_, der::DerError> {
        let mut kd = Reader::new(Reader::new(ext.value)?.tagged(der::SEQUENCE)?)?;
        let version = der::uint(kd.tagged(der::INTEGER)?)?;
        let attestation_level = level(kd.tagged(der::ENUMERATED)?)?;
        kd.tagged(der::INTEGER)?;
        let keymint_level = level(kd.tagged(der::ENUMERATED)?)?;
        let challenge = kd.tagged(der::OCTET_STRING)?;
        kd.tagged(der::OCTET_STRING)?;
        kd.tagged(der::SEQUENCE)?;
        let hardware = hardware_list(kd.tagged(der::SEQUENCE)?)?;
        Ok((
            version,
            attestation_level,
            keymint_level,
            challenge,
            hardware,
        ))
    };
    let (version, attestation_level, keymint_level, challenge, (origin, root)) =
        parse().map_err(|_| AttestError::Format)?;
    if challenge != policy.challenge {
        return Err(AttestError::Challenge);
    }
    let level = match (attestation_level, keymint_level) {
        (Some(a), Some(k)) if a == k => a,
        _ => return Err(AttestError::Policy),
    };
    if policy.strongbox && level != SecurityLevel::StrongBox {
        return Err(AttestError::Policy);
    }
    if origin != Some(ORIGIN_GENERATED) {
        return Err(AttestError::Policy);
    }
    let root = root.ok_or(AttestError::Policy)?;
    if (policy.verified_boot && !root.verified) || (policy.locked && !root.locked) {
        return Err(AttestError::Policy);
    }
    Ok(Attested {
        level,
        version,
        verified_boot: root.verified,
        locked: root.locked,
        public_key: cert.public_key.to_vec(),
    })
}

#[cfg(test)]
mod tests;
