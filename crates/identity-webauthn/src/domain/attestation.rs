//! Attestation objects and the realm's attestation policy (§10.2.4, OP-146 m.4 (d), OP-159 m.3
//! (ll)). Under `none` attestation is never a trust input. Under `direct`, a `packed`, `tpm`,
//! `android-key`, `apple` or `fido-u2f` statement (WebAuthn L3 §8) is verified, its chain must
//! end in a root fresh FIDO metadata lists for the model, and every certificate that names CRL
//! distribution points must be covered by a readable, current CRL that does not revoke it.

mod android;
mod apple;
mod packed;
mod tpm;
mod u2f;

use access_parse::cbor::{Item, Limits, decode};
use rustls_pki_types::{CertificateDer, SignatureVerificationAlgorithm};
use webpki::{
    BorrowedCertRevocationList, CertRevocationList, ExpirationPolicy, RevocationCheckDepth,
    RevocationOptionsBuilder, UnknownStatusPolicy,
};

use super::Rejection;
use super::authenticator_data::{AttestedCredential, AuthenticatorData};
use super::cose::CoseAlgorithm;
use super::credential::AttestationKind;
use super::crl::Crls;
use super::mds::{AnyUsage, MdsBlob, verify_chain};
use super::policy::AttestationPolicy;
use super::x509::{self, Cert, Reader};

/// Most certificates in one `x5c` (PD).
pub(crate) const MAX_CHAIN: usize = 8;

/// Most CRL distribution points one registration fetches (PD); a chain naming more cannot be
/// read as unrevoked.
pub const MAX_FETCHES: usize = 8;

/// The formats a `direct` realm verifies (WebAuthn L3 §8). `android-safetynet` was withdrawn
/// and is not among them.
pub const FORMATS: [&str; 5] = ["packed", "tpm", "android-key", "apple", "fido-u2f"];

/// A decoded attestation object.
pub struct AttestationObject<'a> {
    /// `fmt`.
    pub fmt: &'a str,
    /// `attStmt`.
    pub statement: Item<'a>,
    /// `authData` bytes.
    pub auth_data: &'a [u8],
}

impl<'a> AttestationObject<'a> {
    /// Decodes within the WebAuthn CBOR limits (CR-10).
    ///
    /// # Errors
    /// [`Rejection`].
    pub fn parse(raw: &'a [u8]) -> Result<Self, Rejection> {
        let item = decode(raw, Limits::CEILING)?;
        let fmt = item
            .get_text("fmt")
            .and_then(Item::as_text)
            .ok_or(Rejection::AttestationFormat)?;
        let statement = item
            .get_text("attStmt")
            .filter(|s| s.as_map().is_some())
            .ok_or(Rejection::AttestationFormat)?
            .clone();
        let auth_data = item
            .get_text("authData")
            .and_then(Item::as_bytes)
            .ok_or(Rejection::AuthenticatorData)?;
        Ok(Self {
            fmt,
            statement,
            auth_data,
        })
    }
}

/// What a `direct` realm verifies a registration against: the metadata held now and what each
/// CRL distribution point of the statement's chain gave.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Evidence {
    /// The metadata blob held now, fresh or not.
    pub metadata: Option<MdsBlob>,
    /// The CRLs fetched for [`revocation_points`].
    pub crls: Crls,
}

impl Evidence {
    /// Metadata and no CRLs.
    #[must_use]
    pub fn metadata(metadata: Option<MdsBlob>) -> Self {
        Self {
            metadata,
            crls: Crls::default(),
        }
    }
}

/// The CRL distribution point URIs of every certificate in the statement's `x5c`, deduplicated;
/// what a registration fetches before it verifies (OP-159 m.3 (ll)).
#[must_use]
pub fn revocation_points(object: &AttestationObject<'_>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let Some(chain) = object.statement.get_text("x5c").and_then(Item::as_array) else {
        return out;
    };
    for cert in chain.iter().take(MAX_CHAIN).filter_map(Item::as_bytes) {
        let Ok(points) = Cert::parse(cert).and_then(|c| c.crl_points()) else {
            continue;
        };
        for p in points {
            if out.len() < MAX_FETCHES && !out.iter().any(|o| o == p) {
                out.push(p.to_owned());
            }
        }
    }
    out
}

pub(crate) fn signature_alg(alg: i64) -> Option<&'static dyn SignatureVerificationAlgorithm> {
    match CoseAlgorithm::from_id(alg)? {
        CoseAlgorithm::Es256 | CoseAlgorithm::Esp256 => Some(webpki::aws_lc_rs::ECDSA_P256_SHA256),
        CoseAlgorithm::Rs256 => Some(webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA256),
        CoseAlgorithm::Ed25519 | CoseAlgorithm::EdDsa => Some(webpki::aws_lc_rs::ED25519),
    }
}

/// The `x5c` of a statement, leaf first.
pub(crate) fn chain<'a>(stmt: &Item<'a>) -> Result<Vec<&'a [u8]>, Rejection> {
    let x5c = stmt
        .get_text("x5c")
        .and_then(Item::as_array)
        .ok_or(Rejection::AttestationTrust)?;
    if x5c.is_empty() || x5c.len() > MAX_CHAIN {
        return Err(Rejection::AttestationStatement);
    }
    x5c.iter()
        .map(Item::as_bytes)
        .collect::<Option<Vec<_>>>()
        .ok_or(Rejection::AttestationStatement)
}

/// Verifies `signature` over `message` by the key of the certificate `der`.
pub(crate) fn verify_by(
    der: &[u8],
    alg: &dyn SignatureVerificationAlgorithm,
    message: &[u8],
    signature: &[u8],
) -> Result<(), Rejection> {
    let cert = CertificateDer::from(der);
    webpki::EndEntityCert::try_from(&cert)
        .and_then(|ee| ee.verify_signature(alg, message, signature))
        .map_err(|_| Rejection::AttestationStatement)
}

/// The non-critical AAGUID extension, when present, must name the credential's model (WebAuthn
/// L3 §8.2.1, §8.3.1).
pub(crate) fn aaguid_matches(cert: &Cert<'_>, credential: &AttestedCredential<'_>) -> bool {
    const OID_AAGUID: &[u8] = &[
        0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xe5, 0x1c, 0x01, 0x01, 0x04,
    ];
    match cert.extension(OID_AAGUID) {
        Err(_) => false,
        Ok(None) => true,
        Ok(Some(e)) => {
            !e.critical
                && Reader::new(e.value)
                    .and_then(|mut r| r.tagged(x509::OCTET_STRING))
                    .is_ok_and(|inner| inner == credential.aaguid.0)
        }
    }
}

/// How the statement's model is found in the metadata.
pub(crate) enum Lookup<'a> {
    /// By the credential's AAGUID.
    Aaguid,
    /// By the attestation certificate's key identifier (U2F, which has no AAGUID).
    KeyId(&'a [u8]),
}

/// A verified statement: its chain, leaf first, and how its model is found.
pub(crate) struct Statement<'a> {
    pub(crate) chain: Vec<&'a [u8]>,
    pub(crate) lookup: Lookup<'a>,
}

/// The input every format reads.
pub(crate) struct Input<'s, 'a> {
    pub(crate) stmt: &'s Item<'a>,
    pub(crate) auth_data: &'s AuthenticatorData<'s>,
    pub(crate) credential: &'s AttestedCredential<'s>,
    pub(crate) client_data_hash: &'s [u8; 32],
}

impl Input<'_, '_> {
    /// `authenticatorData ‖ clientDataHash`, the message most formats sign.
    pub(crate) fn signed(&self) -> Vec<u8> {
        let mut message = self.auth_data.raw.to_vec();
        message.extend_from_slice(self.client_data_hash);
        message
    }
}

/// Whether the CRL's issuing distribution point, when it has one, is the plain full name the
/// CRL was fetched from; a scoped, partitioned or indirect CRL is not read as covering the
/// certificate.
fn idp_names(idp: Option<&[u8]>, url: &str) -> bool {
    let Some(idp) = idp else {
        return true;
    };
    let read = || -> Result<bool, x509::DerError> {
        let mut outer = Reader::new(idp)?;
        let mut seq = Reader::new(outer.tagged(x509::SEQUENCE)?)?;
        let point = seq.next_tlv()?;
        if !outer.is_empty() || !seq.is_empty() || point.tag.first != 0xa0 {
            return Ok(false);
        }
        let mut name = Reader::new(point.value)?;
        let full = name.next_tlv()?;
        if !name.is_empty() || full.tag.first != 0xa0 {
            return Ok(false);
        }
        let mut names = Reader::new(full.value)?;
        while !names.is_empty() {
            let n = names.next_tlv()?;
            if n.tag.first == 0x86 && n.value == url.as_bytes() {
                return Ok(true);
            }
        }
        Ok(false)
    };
    read().unwrap_or(false)
}

/// The CRL of every certificate in `chain` that names distribution points (OP-159 m.3 (ll)):
/// one fetched from one of its points, issued by its issuer. A certificate without points
/// publishes no revocation and needs none.
///
/// # Errors
/// [`Rejection::AttestationRevocationUnknown`].
fn revocation_lists<'c>(
    chain: &[&[u8]],
    crls: &'c Crls,
) -> Result<Vec<CertRevocationList<'c>>, Rejection> {
    let mut out = Vec::new();
    for der in chain {
        let cert = Cert::parse(der).map_err(|_| Rejection::AttestationStatement)?;
        let points = cert
            .crl_points()
            .map_err(|_| Rejection::AttestationRevocationUnknown)?;
        if points.is_empty() {
            continue;
        }
        let found = points.iter().find_map(|url| {
            let list = CertRevocationList::from(
                BorrowedCertRevocationList::from_der(crls.get(url)?).ok()?,
            );
            (list.issuer() == cert.issuer && idp_names(list.issuing_distribution_point(), url))
                .then_some(list)
        });
        out.push(found.ok_or(Rejection::AttestationRevocationUnknown)?);
    }
    Ok(out)
}

fn chain_rejection(error: &webpki::Error) -> Rejection {
    use webpki::Error as E;
    match error {
        E::CertRevoked => Rejection::AttestationRevoked,
        E::CrlExpired { .. }
        | E::InvalidCrlSignatureForPublicKey
        | E::IssuerNotCrlSigner
        | E::UnknownRevocationStatus
        | E::UnsupportedCrlVersion
        | E::UnsupportedDeltaCrl
        | E::UnsupportedIndirectCrl
        | E::UnsupportedRevocationReason
        | E::UnsupportedRevocationReasonsPartitioning
        | E::UnsupportedCrlIssuingDistributionPoint
        | E::UnsupportedCrlSignatureAlgorithmContext(_)
        | E::UnsupportedCrlSignatureAlgorithmForPublicKeyContext(_)
        | E::InvalidCrlNumber => Rejection::AttestationRevocationUnknown,
        _ => Rejection::AttestationTrust,
    }
}

/// Applies the realm's attestation policy. `client_data_hash` completes the signed message;
/// the metadata in `evidence` must be fresh at `now` for `direct`.
///
/// # Errors
/// [`Rejection`].
pub fn verify_attestation(
    object: &AttestationObject<'_>,
    auth_data: &AuthenticatorData<'_>,
    client_data_hash: &[u8; 32],
    policy: &AttestationPolicy,
    evidence: &Evidence,
    now: u64,
) -> Result<AttestationKind, Rejection> {
    let credential = auth_data
        .attested
        .as_ref()
        .ok_or(Rejection::AttestedCredential)?;
    let aaguids = match policy {
        AttestationPolicy::None => {
            return if object.fmt == "none" {
                if object.statement.as_map().is_some_and(<[_]>::is_empty) {
                    Ok(AttestationKind::None)
                } else {
                    Err(Rejection::AttestationStatement)
                }
            } else {
                Ok(AttestationKind::Unverified(object.fmt.to_owned()))
            };
        }
        AttestationPolicy::Direct { aaguids, .. } => aaguids,
    };
    // OP-146 m.4 (d)
    let metadata = evidence
        .metadata
        .as_ref()
        .filter(|m| m.is_fresh(now))
        .ok_or(Rejection::MetadataUnavailable)?;
    if !aaguids.is_empty() && !aaguids.contains(&credential.aaguid) {
        return Err(Rejection::AaguidNotAllowed);
    }
    let input = Input {
        stmt: &object.statement,
        auth_data,
        credential,
        client_data_hash,
    };
    // OP-159 m.3 (ll)
    let statement = match object.fmt {
        "packed" => packed::verify(&input)?,
        "tpm" => tpm::verify(&input)?,
        "android-key" => android::verify(&input)?,
        "apple" => apple::verify(&input)?,
        "fido-u2f" => u2f::verify(&input)?,
        _ => return Err(Rejection::AttestationFormat),
    };
    let entry = match statement.lookup {
        Lookup::Aaguid => metadata.entry(credential.aaguid),
        Lookup::KeyId(id) => metadata.entry_for_key(id),
    }
    .ok_or(Rejection::AttestationTrust)?;
    if entry.compromised {
        return Err(Rejection::AuthenticatorStatus);
    }
    let lists = revocation_lists(&statement.chain, &evidence.crls)?;
    let refs: Vec<&CertRevocationList<'_>> = lists.iter().collect();
    let revocation = match RevocationOptionsBuilder::new(&refs) {
        Ok(b) => Some(
            b.with_depth(RevocationCheckDepth::Chain)
                .with_status_policy(UnknownStatusPolicy::Allow)
                .with_expiration_policy(ExpirationPolicy::Enforce)
                .build(),
        ),
        Err(_) => None,
    };
    let chain: Vec<CertificateDer<'_>> = statement
        .chain
        .iter()
        .map(|c| CertificateDer::from(*c))
        .collect();
    let (leaf, intermediates) = chain.split_first().ok_or(Rejection::AttestationStatement)?;
    let roots: Vec<CertificateDer<'_>> = entry
        .roots
        .iter()
        .map(|r| CertificateDer::from(r.as_slice()))
        .collect();
    verify_chain(leaf, intermediates, &roots, now, AnyUsage, revocation)
        .map_err(|e| chain_rejection(&e))?;
    Ok(AttestationKind::Verified(object.fmt.to_owned()))
}
