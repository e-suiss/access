//! The X.509 fields path validation does not expose, and path validation itself with
//! rustls-webpki (RFC 5280): extensions, the subject, the key usage and the public key.

use core::time::Duration;

use rustls_pki_types::{CertificateDer, SignatureVerificationAlgorithm, UnixTime};
use webpki::{
    EndEntityCert, ExtendedKeyUsageValidator, KeyPurposeIdIter, KeyUsage, anchor_from_trusted_cert,
};

use crate::domain::der::{self, Reader};

/// 2.5.29.17, subjectAltName.
pub(crate) const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11];
/// 2.5.29.19, basicConstraints.
pub(crate) const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
/// 2.5.29.15, keyUsage.
pub(crate) const OID_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
/// 2.5.29.37, extKeyUsage.
pub(crate) const OID_EXT_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];

/// Most certificates in one chain (PD).
pub(crate) const MAX_CHAIN: usize = 8;

/// Certificate signature algorithms accepted on every chain.
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

/// One extension.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Extension<'a> {
    pub(crate) oid: &'a [u8],
    pub(crate) critical: bool,
    pub(crate) value: &'a [u8],
}

/// The fields of a certificate this crate reads.
#[derive(Clone, Debug)]
pub(crate) struct Cert<'a> {
    pub(crate) version: u64,
    pub(crate) subject: &'a [u8],
    pub(crate) public_key: &'a [u8],
    pub(crate) extensions: Vec<Extension<'a>>,
}

impl<'a> Cert<'a> {
    /// Reads the `TBSCertificate` of `der`.
    pub(crate) fn parse(der: &'a [u8]) -> Result<Self, der::DerError> {
        let mut outer = Reader::new(der)?;
        let cert = outer.tagged(der::SEQUENCE)?;
        if !outer.is_empty() {
            return Err(der::DerError);
        }
        let mut c = Reader::new(cert)?;
        let mut tbs = Reader::new(c.tagged(der::SEQUENCE)?)?;
        let mut version = 0;
        let mut first = tbs.next_tlv()?;
        if first.tag.first == 0xa0 {
            version = der::uint(Reader::new(first.value)?.tagged(der::INTEGER)?)?;
            first = tbs.next_tlv()?;
        }
        if !first.tag.is(der::INTEGER) {
            return Err(der::DerError);
        }
        tbs.tagged(der::SEQUENCE)?;
        tbs.tagged(der::SEQUENCE)?;
        tbs.tagged(der::SEQUENCE)?;
        let subject = tbs.tagged(der::SEQUENCE)?;
        let mut spki = Reader::new(tbs.tagged(der::SEQUENCE)?)?;
        spki.tagged(der::SEQUENCE)?;
        let bits = spki.tagged(der::BIT_STRING)?;
        let [0, public_key @ ..] = bits else {
            return Err(der::DerError);
        };
        let mut extensions = Vec::new();
        while !tbs.is_empty() {
            let t = tbs.next_tlv()?;
            if t.tag.first != 0xa3 {
                continue;
            }
            let mut list = Reader::new(Reader::new(t.value)?.tagged(der::SEQUENCE)?)?;
            while !list.is_empty() {
                let mut e = Reader::new(list.tagged(der::SEQUENCE)?)?;
                let oid = e.tagged(der::OID)?;
                let critical = e.optional(der::BOOLEAN)?.map(der::boolean).transpose()?;
                let value = e.tagged(der::OCTET_STRING)?;
                if !e.is_empty() {
                    return Err(der::DerError);
                }
                extensions.push(Extension {
                    oid,
                    critical: critical.unwrap_or(false),
                    value,
                });
            }
        }
        Ok(Self {
            version,
            subject,
            public_key,
            extensions,
        })
    }

    /// The extension `oid`; `Err` when it appears more than once (RFC 5280 §4.2).
    pub(crate) fn extension(&self, oid: &[u8]) -> Result<Option<Extension<'a>>, der::DerError> {
        let mut found = self.extensions.iter().filter(|e| e.oid == oid);
        let first = found.next().copied();
        if found.next().is_some() {
            return Err(der::DerError);
        }
        Ok(first)
    }

    /// The `uniformResourceIdentifier` names of the subjectAltName extension.
    pub(crate) fn san_uris(&self) -> Result<Vec<&'a str>, der::DerError> {
        let Some(e) = self.extension(OID_SAN)? else {
            return Ok(Vec::new());
        };
        let mut names = Reader::new(Reader::new(e.value)?.tagged(der::SEQUENCE)?)?;
        let mut out = Vec::new();
        while !names.is_empty() {
            let n = names.next_tlv()?;
            if n.tag.first == 0x86 {
                out.push(core::str::from_utf8(n.value).map_err(|_| der::DerError)?);
            }
        }
        Ok(out)
    }

    /// `cA` of the basicConstraints extension; `None` when the extension is absent.
    pub(crate) fn is_ca(&self) -> Result<Option<bool>, der::DerError> {
        let Some(e) = self.extension(OID_BASIC_CONSTRAINTS)? else {
            return Ok(None);
        };
        let mut seq = Reader::new(Reader::new(e.value)?.tagged(der::SEQUENCE)?)?;
        let ca = seq.optional(der::BOOLEAN)?.map(der::boolean).transpose()?;
        Ok(Some(ca.unwrap_or(false)))
    }

    /// The keyUsage bits, bit 0 (`digitalSignature`) first; `None` when absent.
    pub(crate) fn key_usage(&self) -> Result<Option<u16>, der::DerError> {
        let Some(e) = self.extension(OID_KEY_USAGE)? else {
            return Ok(None);
        };
        let bits = Reader::new(e.value)?.tagged(der::BIT_STRING)?;
        let (unused, body) = bits.split_first().ok_or(der::DerError)?;
        if *unused > 7 || body.is_empty() || body.len() > 2 {
            return Err(der::DerError);
        }
        let hi = u16::from(*body.first().ok_or(der::DerError)?);
        let lo = u16::from(body.get(1).copied().unwrap_or(0));
        Ok(Some((hi << 8) | lo))
    }

    /// The key purposes of the extKeyUsage extension.
    pub(crate) fn ext_key_usage(&self) -> Result<Vec<&'a [u8]>, der::DerError> {
        let Some(e) = self.extension(OID_EXT_KEY_USAGE)? else {
            return Ok(Vec::new());
        };
        let mut list = Reader::new(Reader::new(e.value)?.tagged(der::SEQUENCE)?)?;
        let mut out = Vec::new();
        while !list.is_empty() {
            out.push(list.tagged(der::OID)?);
        }
        Ok(out)
    }
}

/// `digitalSignature`, the first keyUsage bit.
pub(crate) const DIGITAL_SIGNATURE: u16 = 0x8000;
/// `keyCertSign`.
pub(crate) const KEY_CERT_SIGN: u16 = 0x0400;
/// `cRLSign`.
pub(crate) const CRL_SIGN: u16 = 0x0200;

/// Accepts any extended key usage: attestation certificates carry none or vendor ones.
pub(crate) struct AnyUsage;

impl ExtendedKeyUsageValidator for AnyUsage {
    fn validate(&self, _iter: KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        Ok(())
    }
}

/// Verifies `leaf` to one of `roots` through `intermediates` at `now_s` (Unix seconds).
pub(crate) fn verify_chain(
    leaf: &[u8],
    intermediates: &[Vec<u8>],
    roots: &[&[u8]],
    now_s: u64,
    usage: impl ExtendedKeyUsageValidator,
) -> Result<(), webpki::Error> {
    if intermediates.len() >= MAX_CHAIN {
        return Err(webpki::Error::MaximumPathDepthExceeded);
    }
    let roots: Vec<CertificateDer<'_>> = roots.iter().map(|r| CertificateDer::from(*r)).collect();
    let anchors = roots
        .iter()
        .map(anchor_from_trusted_cert)
        .collect::<Result<Vec<_>, _>>()?;
    let leaf = CertificateDer::from(leaf);
    let inter: Vec<CertificateDer<'_>> = intermediates
        .iter()
        .filter(|c| !roots.iter().any(|r| r.as_ref() == c.as_slice()))
        .map(|c| CertificateDer::from(c.as_slice()))
        .collect();
    let ee = EndEntityCert::try_from(&leaf)?;
    ee.verify_for_usage(
        CHAIN_ALGS,
        &anchors,
        &inter,
        UnixTime::since_unix_epoch(Duration::from_secs(now_s)),
        usage,
        None,
        None,
    )
    .map(|_| ())
}

/// The client-authentication purpose, for X.509-SVIDs presented over mutual TLS.
pub(crate) fn client_auth() -> KeyUsage {
    KeyUsage::client_auth()
}

/// Verifies `signature` over `message` by the key of the certificate `der`.
pub(crate) fn verify_signature(
    der: &[u8],
    alg: &dyn SignatureVerificationAlgorithm,
    message: &[u8],
    signature: &[u8],
) -> Result<(), webpki::Error> {
    let cert = CertificateDer::from(der);
    EndEntityCert::try_from(&cert)?.verify_signature(alg, message, signature)
}
