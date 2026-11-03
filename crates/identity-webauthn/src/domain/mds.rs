//! FIDO Metadata Service 3.x blob verification (§10.2.4, OP-146 m.4 (d)): the JWT's `x5c` chain
//! is verified with rustls-webpki to the operator-supplied root, the RS256 signature with
//! aws-lc-rs, and `nextUpdate` against trusted time. Time is an input; nothing here reads a
//! clock.

use core::time::Duration;

use access_kernel::json::{Json, b64url_decode, parse};
use rustls_pki_types::{CertificateDer, SignatureVerificationAlgorithm, UnixTime};
use serde::Deserialize;
use webpki::{
    EndEntityCert, ExtendedKeyUsageValidator, KeyPurposeIdIter, KeyUsage, anchor_from_trusted_cert,
};

use super::ids::Aaguid;

/// Ceiling for a blob (PD).
pub const MAX_BLOB: usize = 32 * 1024 * 1024;
const MAX_HEADER: usize = 64 * 1024;
const MAX_CHAIN: usize = 8;
const DAY: u64 = 86_400;

/// Certificate signature algorithms accepted on metadata and attestation chains.
pub(crate) const CHAIN_ALGS: &[&dyn SignatureVerificationAlgorithm] = &[
    webpki::aws_lc_rs::ECDSA_P256_SHA256,
    webpki::aws_lc_rs::ECDSA_P256_SHA384,
    webpki::aws_lc_rs::ECDSA_P384_SHA256,
    webpki::aws_lc_rs::ECDSA_P384_SHA384,
    webpki::aws_lc_rs::ED25519,
    webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA256,
    webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA384,
    webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA512,
];

/// Accepts any extended key usage: FIDO attestation certificates carry none or vendor ones.
pub(crate) struct AnyUsage;

impl ExtendedKeyUsageValidator for AnyUsage {
    fn validate(&self, _iter: KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        Ok(())
    }
}

/// Verifies `leaf` up to one of `roots` through `intermediates` at `now` (Unix seconds).
pub(crate) fn verify_chain(
    leaf: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    roots: &[CertificateDer<'_>],
    now: u64,
    usage: impl ExtendedKeyUsageValidator,
) -> Result<(), webpki::Error> {
    let anchors = roots
        .iter()
        .map(anchor_from_trusted_cert)
        .collect::<Result<Vec<_>, _>>()?;
    let ee = EndEntityCert::try_from(leaf)?;
    ee.verify_for_usage(
        CHAIN_ALGS,
        &anchors,
        intermediates,
        UnixTime::since_unix_epoch(Duration::from_secs(now)),
        usage,
        None,
        None,
    )
    .map(|_| ())
}

/// Why a blob is not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MdsError {
    /// Larger than [`MAX_BLOB`].
    #[error("blob too large")]
    Size,
    /// Not a compact JWS with the expected header.
    #[error("malformed blob")]
    Format,
    /// Header `alg` is not RS256.
    #[error("algorithm not accepted")]
    Algorithm,
    /// The `x5c` chain does not verify to the root.
    #[error("certificate chain invalid")]
    Certificate,
    /// The signature does not verify.
    #[error("signature invalid")]
    Signature,
    /// The payload is not the expected JSON.
    #[error("malformed payload")]
    Payload,
    /// `nextUpdate` has passed.
    #[error("blob stale")]
    Stale,
    /// The serial number is not above the cached blob's.
    #[error("blob rollback")]
    Rollback,
}

impl MdsError {
    /// Stable reason code for problem details (RFC 9457).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Size => "mds-size",
            Self::Format => "mds-format",
            Self::Algorithm => "mds-algorithm",
            Self::Certificate => "mds-certificate",
            Self::Signature => "mds-signature",
            Self::Payload => "mds-payload",
            Self::Stale => "mds-stale",
            Self::Rollback => "mds-rollback",
        }
    }
}

/// One authenticator model from the blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MdsEntry {
    /// The model.
    pub aaguid: Aaguid,
    /// Attestation root certificates (DER).
    pub roots: Vec<Vec<u8>>,
    /// Some status report marks the model revoked or a key or UV compromised.
    pub compromised: bool,
    /// Vendor description.
    pub description: Option<String>,
}

/// A verified blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MdsBlob {
    /// `no`, the serial number.
    pub serial: u64,
    /// `nextUpdate` as Unix seconds at the start of that day (UTC).
    pub next_update: u64,
    /// FIDO2 entries (those with an AAGUID).
    pub entries: Vec<MdsEntry>,
}

impl MdsBlob {
    /// Fresh until the end of the `nextUpdate` day.
    #[must_use]
    pub fn is_fresh(&self, now: u64) -> bool {
        now < self.next_update.saturating_add(DAY)
    }

    /// The entry for `aaguid`.
    #[must_use]
    pub fn entry(&self, aaguid: Aaguid) -> Option<&MdsEntry> {
        self.entries.iter().find(|e| e.aaguid == aaguid)
    }
}

const COMPROMISED: &[&str] = &[
    "REVOKED",
    "USER_VERIFICATION_BYPASS",
    "ATTESTATION_KEY_COMPROMISE",
    "USER_KEY_REMOTE_COMPROMISE",
    "USER_KEY_PHYSICAL_COMPROMISE",
];

#[derive(Deserialize)]
struct Payload {
    no: u64,
    #[serde(rename = "nextUpdate")]
    next_update: String,
    entries: Vec<RawEntry>,
}

#[derive(Deserialize)]
struct RawEntry {
    aaguid: Option<String>,
    #[serde(rename = "metadataStatement")]
    statement: Option<RawStatement>,
    #[serde(rename = "statusReports", default)]
    status_reports: Vec<RawStatus>,
}

#[derive(Deserialize)]
struct RawStatement {
    #[serde(rename = "attestationRootCertificates", default)]
    roots: Vec<String>,
    description: Option<String>,
}

#[derive(Deserialize)]
struct RawStatus {
    status: String,
}

/// Padded standard base64 (RFC 4648 §4), as `x5c` and metadata statements use it.
fn base64_standard(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(4) || text.contains(['-', '_']) {
        return None;
    }
    let body = text
        .strip_suffix("==")
        .or_else(|| text.strip_suffix('='))
        .unwrap_or(text);
    if body.contains('=') {
        return None;
    }
    let url: String = body
        .chars()
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            c => c,
        })
        .collect();
    b64url_decode(&url).ok()
}

/// Days since 1970-01-01 of a `YYYY-MM-DD` date (years 1970–9999).
fn epoch_day(date: &str) -> Option<u64> {
    let mut parts = date.split('-');
    let (y, m, d) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || y.len() != 4 || m.len() != 2 || d.len() != 2 {
        return None;
    }
    let (y, m, d): (u64, u64, u64) = (y.parse().ok()?, m.parse().ok()?, d.parse().ok()?);
    if !(1970..=9999).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y = if m <= 2 { y.checked_sub(1)? } else { y };
    let era = y.checked_div(400)?;
    let yoe = y.checked_sub(era.checked_mul(400)?)?;
    let mp = if m > 2 {
        m.checked_sub(3)?
    } else {
        m.checked_add(9)?
    };
    let doy = mp
        .checked_mul(153)?
        .checked_add(2)?
        .checked_div(5)?
        .checked_add(d)?
        .checked_sub(1)?;
    let doe = yoe
        .checked_mul(365)?
        .checked_add(yoe.checked_div(4)?)?
        .checked_sub(yoe.checked_div(100)?)?
        .checked_add(doy)?;
    era.checked_mul(146_097)?
        .checked_add(doe)?
        .checked_sub(719_468)
}

fn entry(raw: RawEntry) -> Result<Option<MdsEntry>, MdsError> {
    let Some(aaguid) = raw.aaguid else {
        return Ok(None);
    };
    let aaguid = Aaguid::parse(&aaguid).ok_or(MdsError::Payload)?;
    let (roots, description) = match raw.statement {
        Some(s) => (
            s.roots
                .iter()
                .map(|r| base64_standard(r).ok_or(MdsError::Payload))
                .collect::<Result<Vec<_>, _>>()?,
            s.description,
        ),
        None => (Vec::new(), None),
    };
    let compromised = raw
        .status_reports
        .iter()
        .any(|r| COMPROMISED.contains(&r.status.as_str()));
    Ok(Some(MdsEntry {
        aaguid,
        roots,
        compromised,
        description,
    }))
}

/// Verifies a metadata blob against `root` (DER) at `now` (Unix seconds). A stale blob is
/// rejected here, so no caller can cache one.
///
/// # Errors
/// [`MdsError`].
pub fn verify_blob(jwt: &[u8], root: &[u8], now: u64) -> Result<MdsBlob, MdsError> {
    if jwt.len() > MAX_BLOB {
        return Err(MdsError::Size);
    }
    let text = core::str::from_utf8(jwt).map_err(|_| MdsError::Format)?;
    let text = text.trim_end();
    let mut parts = text.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(MdsError::Format);
    };
    let header_bytes = b64url_decode(h).map_err(|_| MdsError::Format)?;
    let header = parse(&header_bytes, MAX_HEADER).map_err(|_| MdsError::Format)?;
    if header.get("alg").and_then(Json::as_str) != Some("RS256") {
        return Err(MdsError::Algorithm);
    }
    let Some(Json::Array(x5c)) = header.get("x5c") else {
        return Err(MdsError::Format);
    };
    if x5c.is_empty() || x5c.len() > MAX_CHAIN {
        return Err(MdsError::Format);
    }
    let chain = x5c
        .iter()
        .map(|c| {
            c.as_str()
                .and_then(base64_standard)
                .map(CertificateDer::from)
                .ok_or(MdsError::Format)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (leaf, intermediates) = chain.split_first().ok_or(MdsError::Format)?;
    let root = CertificateDer::from(root);
    verify_chain(
        leaf,
        intermediates,
        core::slice::from_ref(&root),
        now,
        KeyUsage::server_auth(),
    )
    .map_err(|_| MdsError::Certificate)?;
    let signature = b64url_decode(s).map_err(|_| MdsError::Format)?;
    let signing_input = text
        .get(..h.len().saturating_add(1).saturating_add(p.len()))
        .ok_or(MdsError::Format)?;
    EndEntityCert::try_from(leaf)
        .and_then(|ee| {
            ee.verify_signature(
                webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA256,
                signing_input.as_bytes(),
                &signature,
            )
        })
        .map_err(|_| MdsError::Signature)?;
    let payload = b64url_decode(p).map_err(|_| MdsError::Format)?;
    access_parse::json::check(&payload, MAX_BLOB, access_parse::json::MAX_DEPTH)
        .map_err(|_| MdsError::Payload)?;
    let payload: Payload = serde_json::from_slice(&payload).map_err(|_| MdsError::Payload)?;
    let next_update = epoch_day(&payload.next_update)
        .and_then(|d| d.checked_mul(DAY))
        .ok_or(MdsError::Payload)?;
    let mut entries = Vec::new();
    for raw in payload.entries {
        if let Some(e) = entry(raw)? {
            entries.push(e);
        }
    }
    let blob = MdsBlob {
        serial: payload.no,
        next_update,
        entries,
    };
    if blob.is_fresh(now) {
        Ok(blob)
    } else {
        Err(MdsError::Stale)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-146 m.4 (d)
    #[test]
    fn epoch_days() {
        assert_eq!(epoch_day("1970-01-01"), Some(0));
        assert_eq!(epoch_day("2000-03-01"), Some(11_017));
        assert_eq!(epoch_day("2026-11-03"), Some(20_760));
        assert_eq!(epoch_day("2026-13-01"), None);
        assert_eq!(epoch_day("26-11-03"), None);
        assert_eq!(epoch_day("2026-11-03-1"), None);
    }

    // OP-146 m.4 (d)
    #[test]
    fn standard_base64() {
        assert_eq!(base64_standard("+/8="), Some(vec![0xfb, 0xff]));
        assert_eq!(base64_standard("AA=="), Some(vec![0]));
        assert_eq!(base64_standard("AAAA"), Some(vec![0, 0, 0]));
        assert_eq!(base64_standard("AA"), None);
        assert_eq!(base64_standard("-_8="), None);
        assert_eq!(base64_standard("A=AA"), None);
        assert_eq!(base64_standard("AB=="), None);
    }
}
