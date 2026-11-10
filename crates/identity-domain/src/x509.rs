//! The certificates a custom domain needs (RFC 2986, RFC 5280, RFC 8737, OP-156 m.3 (i)): the
//! certificate signing request of a domain's own key, the self-signed TLS-ALPN-01 challenge
//! certificate, and the few fields of an issued leaf Access checks before it serves it. ECDSA
//! P-256 only; the keys sign behind [`suiss_crypto::signer::Signer`].

use access_parse::der::{Reader, SEQUENCE};
use suiss_crypto::cose::PublicKey;
use suiss_crypto::signer::Signer;

use crate::der::{
    self, ACME_IDENTIFIER, BASIC_CONSTRAINTS, DerWriteError, EXT_KEY_USAGE, EXTENSION_REQUEST,
    KEY_USAGE, SERVER_AUTH, SUBJECT_ALT_NAME, bits, ecdsa_sha256, ecdsa_sig_value, explicit, name,
    octets, oid, p256_spki, seq, set, true_, uint,
};

/// The ALPN protocol of a TLS-ALPN-01 validation (RFC 8737 §6.2).
pub const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";

/// Longest common name written: RFC 5280's `ub-common-name`.
const MAX_CN: usize = 64;

/// Why a certificate or request could not be made or read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CertError {
    /// The key is not ECDSA P-256 or did not sign.
    #[error("key")]
    Key,
    /// The DER could not be written.
    #[error("encode")]
    Encode,
    /// The certificate is not one Access reads.
    #[error("malformed certificate")]
    Malformed,
}

impl From<DerWriteError> for CertError {
    fn from(_: DerWriteError) -> Self {
        Self::Encode
    }
}

impl CertError {
    /// Stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Key => "certificate-key",
            Self::Encode => "certificate-encode",
            Self::Malformed => "certificate-malformed",
        }
    }
}

fn sec1(key: &dyn Signer) -> Result<Vec<u8>, CertError> {
    match key.public_key() {
        PublicKey::P256(point) if point.len() == 65 => Ok(point),
        _ => Err(CertError::Key),
    }
}

fn signed(key: &dyn Signer, body: &[u8]) -> Result<Vec<u8>, CertError> {
    let raw = key.sign(body).map_err(|_| CertError::Key)?;
    let value = ecdsa_sig_value(&raw)?;
    Ok(seq(&[body, &ecdsa_sha256(), &bits(&value)]))
}

fn dns_names(hosts: &[&str]) -> Vec<u8> {
    let names: Vec<Vec<u8>> = hosts.iter().map(|h| der::tlv(0x82, h.as_bytes())).collect();
    let refs: Vec<&[u8]> = names.iter().map(Vec::as_slice).collect();
    seq(&refs)
}

fn extension(id: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    if critical {
        seq(&[&oid(id), &true_(), &octets(value)])
    } else {
        seq(&[&oid(id), &octets(value)])
    }
}

fn cn(host: &str) -> Option<&str> {
    (host.len() <= MAX_CN).then_some(host)
}

/// The PKCS#10 request for `host` signed by the domain's key `key` (RFC 2986, RFC 8555 §7.4):
/// the host as its only subjectAltName, and as common name when it fits.
///
/// # Errors
/// [`CertError`].
pub fn csr(key: &dyn Signer, host: &str) -> Result<Vec<u8>, CertError> {
    let ext = seq(&[&extension(SUBJECT_ALT_NAME, false, &dns_names(&[host]))]);
    let attribute = seq(&[&oid(EXTENSION_REQUEST), &set(&[&ext])]);
    let info = seq(&[
        &uint(&[0]),
        &name(cn(host)),
        &p256_spki(&sec1(key)?),
        &explicit(0, &attribute),
    ]);
    signed(key, &info)
}

/// What a certificate Access makes says.
pub struct Profile<'a> {
    /// Serial number magnitude, at most 20 bytes.
    pub serial: &'a [u8],
    /// Common name of the subject; `None` for an empty subject.
    pub subject: Option<&'a str>,
    /// Common name of the issuer; `None` for an empty issuer.
    pub issuer: Option<&'a str>,
    /// Validity, Unix seconds.
    pub not_before: i64,
    /// Validity, Unix seconds.
    pub not_after: i64,
    /// The extensions, each a DER `Extension`.
    pub extensions: Vec<Vec<u8>>,
}

/// A certificate of `profile` for the public point `subject_key`, signed by `issuer_key`.
///
/// # Errors
/// [`CertError`].
pub fn certificate(
    profile: &Profile<'_>,
    subject_key: &[u8],
    issuer_key: &dyn Signer,
) -> Result<Vec<u8>, CertError> {
    if profile.serial.is_empty() || profile.serial.len() > 20 {
        return Err(CertError::Encode);
    }
    let refs: Vec<&[u8]> = profile.extensions.iter().map(Vec::as_slice).collect();
    let tbs = seq(&[
        &explicit(0, &uint(&[2])),
        &uint(profile.serial),
        &ecdsa_sha256(),
        &name(profile.issuer),
        &seq(&[
            &der::time(profile.not_before)?,
            &der::time(profile.not_after)?,
        ]),
        &name(profile.subject),
        &p256_spki(subject_key),
        &explicit(3, &seq(&refs)),
    ]);
    signed(issuer_key, &tbs)
}

/// The subjectAltName extension naming `hosts`.
#[must_use]
pub fn san(hosts: &[&str]) -> Vec<u8> {
    extension(SUBJECT_ALT_NAME, false, &dns_names(hosts))
}

/// The critical `acmeIdentifier` extension over the SHA-256 of a key authorization (RFC 8737
/// §3).
#[must_use]
pub fn acme_identifier(digest: &[u8; 32]) -> Vec<u8> {
    extension(ACME_IDENTIFIER, true, &octets(digest))
}

/// The critical basicConstraints extension: CA or end entity.
#[must_use]
pub fn basic_constraints(ca: bool) -> Vec<u8> {
    if ca {
        extension(BASIC_CONSTRAINTS, true, &seq(&[&true_()]))
    } else {
        extension(BASIC_CONSTRAINTS, true, &seq(&[]))
    }
}

/// The critical keyUsage extension: `keyCertSign` for a CA, `digitalSignature` otherwise.
#[must_use]
pub fn key_usage(ca: bool) -> Vec<u8> {
    let value = if ca {
        der::tlv(der::BIT_STRING, &[0x02, 0x04])
    } else {
        der::tlv(der::BIT_STRING, &[0x07, 0x80])
    };
    extension(KEY_USAGE, true, &value)
}

/// The extKeyUsage extension for a TLS server.
#[must_use]
pub fn server_auth() -> Vec<u8> {
    extension(EXT_KEY_USAGE, false, &seq(&[&oid(SERVER_AUTH)]))
}

/// The self-signed TLS-ALPN-01 challenge certificate for `host` (RFC 8737 §3): its one
/// subjectAltName is the host and its critical `acmeIdentifier` holds `digest`, the SHA-256 of
/// the key authorization. `key` is any throwaway key; the certificate proves only control of
/// the endpoint.
///
/// # Errors
/// [`CertError`].
pub fn alpn_challenge(
    key: &dyn Signer,
    host: &str,
    digest: &[u8; 32],
    serial: &[u8; 16],
    now_s: i64,
) -> Result<Vec<u8>, CertError> {
    let profile = Profile {
        serial,
        subject: cn(host),
        issuer: cn(host),
        not_before: now_s.saturating_sub(3600),
        not_after: now_s.saturating_add(7 * 86_400),
        extensions: vec![san(&[host]), acme_identifier(digest)],
    };
    certificate(&profile, &sec1(key)?, key)
}

/// What Access reads from a leaf before serving it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leaf {
    /// Validity start, Unix seconds.
    pub not_before: i64,
    /// Validity end, Unix seconds.
    pub not_after: i64,
    /// The subject public key, uncompressed SEC1 for P-256; empty for another key.
    pub public_point: Vec<u8>,
    /// The `dNSName` entries of the subjectAltName.
    pub dns_names: Vec<String>,
    /// The `acmeIdentifier` digest, when the extension is present.
    pub acme_identifier: Option<[u8; 32]>,
}

fn tagged<'a>(r: &mut Reader<'a>, tag: u8) -> Result<&'a [u8], CertError> {
    r.tagged(tag).map_err(|_| CertError::Malformed)
}

fn reader(input: &[u8]) -> Result<Reader<'_>, CertError> {
    Reader::new(input).map_err(|_| CertError::Malformed)
}

/// Reads the validity, key and names of a DER certificate (RFC 5280 §4.1), every length
/// bounded (CR-10).
///
/// # Errors
/// [`CertError::Malformed`].
pub fn read_leaf(cert: &[u8]) -> Result<Leaf, CertError> {
    let mut outer = reader(cert)?;
    let mut parts = reader(tagged(&mut outer, SEQUENCE)?)?;
    let mut tbs = reader(tagged(&mut parts, SEQUENCE)?)?;
    let mut first = tbs.next_tlv().map_err(|_| CertError::Malformed)?;
    if first.tag == 0xa0 {
        first = tbs.next_tlv().map_err(|_| CertError::Malformed)?;
    }
    if first.tag != der::INTEGER {
        return Err(CertError::Malformed);
    }
    tagged(&mut tbs, SEQUENCE)?;
    tagged(&mut tbs, SEQUENCE)?;
    let mut validity = reader(tagged(&mut tbs, SEQUENCE)?)?;
    let mut time = || -> Result<i64, CertError> {
        let t = validity.next_tlv().map_err(|_| CertError::Malformed)?;
        der::parse_time(t.tag, t.value).ok_or(CertError::Malformed)
    };
    let (not_before, not_after) = (time()?, time()?);
    tagged(&mut tbs, SEQUENCE)?;
    let mut spki = reader(tagged(&mut tbs, SEQUENCE)?)?;
    let algorithm = tagged(&mut spki, SEQUENCE)?;
    let key = tagged(&mut spki, der::BIT_STRING)?;
    let expected = seq(&[&oid(der::EC_PUBLIC_KEY), &oid(der::P256)]);
    let public_point = match key.split_first() {
        Some((0, point)) if expected.get(2..) == Some(algorithm) => point.to_vec(),
        _ => Vec::new(),
    };
    let mut dns_names = Vec::new();
    let mut acme = None;
    while !tbs.is_empty() {
        let t = tbs.next_tlv().map_err(|_| CertError::Malformed)?;
        if t.tag != 0xa3 {
            continue;
        }
        let mut exts = reader(tagged(&mut reader(t.value)?, SEQUENCE)?)?;
        while !exts.is_empty() {
            let mut ext = reader(tagged(&mut exts, SEQUENCE)?)?;
            let id = tagged(&mut ext, der::OID)?;
            let mut value = ext.next_tlv().map_err(|_| CertError::Malformed)?;
            if value.tag == der::BOOLEAN {
                value = ext.next_tlv().map_err(|_| CertError::Malformed)?;
            }
            if value.tag != der::OCTET_STRING {
                return Err(CertError::Malformed);
            }
            if id == SUBJECT_ALT_NAME {
                let mut names = reader(tagged(&mut reader(value.value)?, SEQUENCE)?)?;
                while !names.is_empty() {
                    let n = names.next_tlv().map_err(|_| CertError::Malformed)?;
                    if n.tag == 0x82 {
                        let host = core::str::from_utf8(n.value)
                            .map_err(|_| CertError::Malformed)?
                            .to_ascii_lowercase();
                        dns_names.push(host);
                    }
                }
            } else if id == ACME_IDENTIFIER {
                let inner = tagged(&mut reader(value.value)?, der::OCTET_STRING)?;
                acme = Some(<[u8; 32]>::try_from(inner).map_err(|_| CertError::Malformed)?);
            }
        }
    }
    Ok(Leaf {
        not_before,
        not_after,
        public_point,
        dns_names,
        acme_identifier: acme,
    })
}

/// PEM of one `CERTIFICATE`.
#[must_use]
pub fn pem(der: &[u8]) -> String {
    let b64 = suiss_crypto::note::base64_encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(core::str::from_utf8(line).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

/// The DER certificates of a PEM chain, in order; at most `max` of them.
///
/// # Errors
/// [`CertError::Malformed`] for anything but `CERTIFICATE` blocks or more than `max`.
pub fn pem_chain(text: &str, max: usize) -> Result<Vec<Vec<u8>>, CertError> {
    let mut out = Vec::new();
    let mut body: Option<String> = None;
    for line in text.lines().map(str::trim) {
        match (line, body.as_mut()) {
            ("", _) => {}
            ("-----BEGIN CERTIFICATE-----", None) => body = Some(String::new()),
            ("-----END CERTIFICATE-----", Some(b)) => {
                let der = suiss_crypto::note::base64_decode(b).map_err(|_| CertError::Malformed)?;
                out.push(der);
                body = None;
                if out.len() > max {
                    return Err(CertError::Malformed);
                }
            }
            (l, Some(b)) if !l.starts_with("-----") => b.push_str(l),
            _ => return Err(CertError::Malformed),
        }
    }
    if body.is_some() || out.is_empty() {
        return Err(CertError::Malformed);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use suiss_crypto::signer::SoftSigner;

    // RFC 8737 §3
    #[test]
    fn the_challenge_certificate_names_the_host_and_the_key_authorization() {
        let (key, _) = SoftSigner::generate_p256().unwrap();
        let digest = [7_u8; 32];
        let cert =
            alpn_challenge(&key, "login.acme.example", &digest, &[1; 16], 1_800_000_000).unwrap();
        let leaf = read_leaf(&cert).unwrap();
        assert_eq!(leaf.dns_names, ["login.acme.example"]);
        assert_eq!(leaf.acme_identifier, Some(digest));
        assert_eq!(leaf.public_point, sec1(&key).unwrap());
        assert!(leaf.not_before < 1_800_000_000 && leaf.not_after > 1_800_000_000);
    }

    // RFC 5280 §4.1
    #[test]
    fn a_server_certificate_parses_for_webpki() {
        let (key, _) = SoftSigner::generate_p256().unwrap();
        let profile = Profile {
            serial: &[3; 16],
            subject: Some("login.acme.example"),
            issuer: Some("ca"),
            not_before: 1_800_000_000,
            not_after: 1_807_776_000,
            extensions: vec![
                san(&["login.acme.example"]),
                server_auth(),
                basic_constraints(false),
                key_usage(false),
            ],
        };
        let cert = certificate(&profile, &sec1(&key).unwrap(), &key).unwrap();
        let der = rustls_pki_types::CertificateDer::from(cert.clone());
        assert!(webpki::EndEntityCert::try_from(&der).is_ok());
        assert_eq!(read_leaf(&cert).unwrap().not_after, 1_807_776_000);
    }

    #[test]
    fn pem_round_trips() {
        let (key, _) = SoftSigner::generate_p256().unwrap();
        let cert = alpn_challenge(&key, "a.example", &[0; 32], &[2; 16], 1_800_000_000).unwrap();
        let text = format!("{}{}", pem(&cert), pem(&cert));
        assert_eq!(pem_chain(&text, 4).unwrap(), vec![cert.clone(), cert]);
        assert!(pem_chain("-----BEGIN X-----\n-----END X-----\n", 4).is_err());
    }
}
