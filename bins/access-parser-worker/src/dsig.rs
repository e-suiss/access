//! XML Signature verification of one enveloped signature (XML Signature 1.1 subset, §10.6.1, §14.6,
//! IDI-8, TI-9): exactly one `ds:Signature`, a direct child of the message element, one
//! `Reference` to that element's own identifier, the enveloped-signature and exclusive
//! canonicalization transforms and nothing else, SHA-2 digests, and RSA or ECDSA with SHA-2.
//! The key is one of the service provider's pinned certificates; `KeyInfo` is never read
//! (rule 8). SHA-1, DSA, HMAC and every other transform are refused.

use access_crypto::xmlsec::{self, Verify};

use crate::c14n::{self, DEFAULT_TOKEN};
use crate::dom::Doc;

/// The XML Signature namespace.
pub(crate) const DS: &str = "http://www.w3.org/2000/09/xmldsig#";

/// Exclusive canonicalization without comments.
pub(crate) const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

/// The enveloped-signature transform.
pub(crate) const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

/// RSA PKCS#1 v1.5 with SHA-256.
pub(crate) const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
/// RSA PKCS#1 v1.5 with SHA-384.
pub(crate) const RSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
/// RSA PKCS#1 v1.5 with SHA-512.
pub(crate) const RSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
/// ECDSA with SHA-256.
pub(crate) const ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
/// ECDSA with SHA-384.
pub(crate) const ECDSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";

const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
const SHA512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";

/// A public key from a pinned certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Key {
    /// RSA, PKCS#1 `RSAPublicKey`.
    Rsa(Vec<u8>),
    /// ECDSA P-256, uncompressed point.
    P256(Vec<u8>),
    /// ECDSA P-384, uncompressed point.
    P384(Vec<u8>),
}

const RSA_OID: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const EC_OID: [u8; 7] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const P256_OID: [u8; 8] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const P384_OID: [u8; 5] = [0x2b, 0x81, 0x04, 0x00, 0x22];

fn der(e: access_parse::der::DerError) -> &'static str {
    let _ = e;
    "cert-malformed"
}

/// The public key of an X.509 certificate (RFC 5280 §4.1): `tbsCertificate`'s
/// `subjectPublicKeyInfo`, RSA or EC P-256/P-384.
///
/// # Errors
/// `cert-malformed`, `cert-key-unsupported`.
pub(crate) fn key_of(cert: &[u8]) -> Result<Key, &'static str> {
    use access_parse::der::{OID, Reader, SEQUENCE};
    let mut outer = Reader::new(cert).map_err(der)?;
    let certificate = outer.tagged(SEQUENCE).map_err(der)?;
    if !outer.is_empty() {
        return Err("cert-malformed");
    }
    let mut c = Reader::new(certificate).map_err(der)?;
    let tbs = c.tagged(SEQUENCE).map_err(der)?;
    let mut t = Reader::new(tbs).map_err(der)?;
    let mut first = t.next_tlv().map_err(der)?;
    if first.tag == 0xa0 {
        first = t.next_tlv().map_err(der)?;
    }
    if first.tag != 0x02 {
        return Err("cert-malformed");
    }
    for _ in 0..4 {
        t.next_tlv().map_err(der)?;
    }
    let spki = t.tagged(SEQUENCE).map_err(der)?;
    let mut s = Reader::new(spki).map_err(der)?;
    let alg = s.tagged(SEQUENCE).map_err(der)?;
    let bits = s.tagged(0x03).map_err(der)?;
    let (&unused, point) = bits.split_first().ok_or("cert-malformed")?;
    if unused != 0 || !s.is_empty() {
        return Err("cert-malformed");
    }
    let mut a = Reader::new(alg).map_err(der)?;
    let oid = a.tagged(OID).map_err(der)?;
    if oid == RSA_OID {
        return Ok(Key::Rsa(point.to_vec()));
    }
    if oid == EC_OID {
        let curve = a.tagged(OID).map_err(der)?;
        if curve == P256_OID {
            return Ok(Key::P256(point.to_vec()));
        }
        if curve == P384_OID {
            return Ok(Key::P384(point.to_vec()));
        }
    }
    Err("cert-key-unsupported")
}

/// The verification algorithm for `sig_alg` over `key`; SHA-1 and anything unlisted refuse
/// (TI-9, OP-155 m.3 (e)).
fn algorithm(sig_alg: &str, key: &Key) -> Option<Verify> {
    Some(match (sig_alg, key) {
        (RSA_SHA256, Key::Rsa(_)) => Verify::RsaSha256,
        (RSA_SHA384, Key::Rsa(_)) => Verify::RsaSha384,
        (RSA_SHA512, Key::Rsa(_)) => Verify::RsaSha512,
        (ECDSA_SHA256, Key::P256(_)) => Verify::P256Sha256,
        (ECDSA_SHA384, Key::P384(_)) => Verify::P384Sha384,
        _ => return None,
    })
}

/// Whether `sig_alg` is a signature method Access accepts at all.
pub(crate) fn accepted(sig_alg: &str) -> bool {
    [
        RSA_SHA256,
        RSA_SHA384,
        RSA_SHA512,
        ECDSA_SHA256,
        ECDSA_SHA384,
    ]
    .contains(&sig_alg)
}

fn bytes(key: &Key) -> &[u8] {
    match key {
        Key::Rsa(b) | Key::P256(b) | Key::P384(b) => b,
    }
}

/// Verifies `sig` over `signed` with `sig_alg` and one of `certs`.
///
/// # Errors
/// `signature-alg`, `signature-invalid`, or a certificate refusal.
pub(crate) fn verify_with(
    certs: &[Vec<u8>],
    sig_alg: &str,
    signed: &[u8],
    sig: &[u8],
) -> Result<(), &'static str> {
    if !accepted(sig_alg) {
        return Err("signature-alg");
    }
    if certs.is_empty() {
        return Err("signature-no-key");
    }
    for cert in certs {
        let key = key_of(cert)?;
        let Some(alg) = algorithm(sig_alg, &key) else {
            continue;
        };
        if xmlsec::verify(alg, bytes(&key), signed, sig) {
            return Ok(());
        }
    }
    Err("signature-invalid")
}

fn b64(s: &str) -> Result<Vec<u8>, &'static str> {
    let compact: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    b64std::decode(&compact).ok_or("signature-malformed")
}

/// Standard base64 (RFC 4648 §4) with padding, the encoding of XML Signature values.
pub(crate) mod b64std {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn value(c: u8) -> Option<u32> {
        ALPHABET
            .iter()
            .position(|a| *a == c)
            .and_then(|p| u32::try_from(p).ok())
    }

    /// Decodes padded standard base64; `None` for anything else.
    pub(crate) fn decode(s: &str) -> Option<Vec<u8>> {
        let b = s.as_bytes();
        if !b.len().is_multiple_of(4) {
            return None;
        }
        let mut out = Vec::new();
        let (chunks, _) = b.as_chunks::<4>();
        let last = chunks.len().checked_sub(1);
        for (n, chunk) in chunks.iter().enumerate() {
            let pad = chunk.iter().rev().take_while(|c| **c == b'=').count();
            if pad > 2 || (pad > 0 && Some(n) != last) {
                return None;
            }
            let keep = 4_usize.checked_sub(pad)?;
            let mut acc: u32 = 0;
            for (i, c) in chunk.iter().enumerate() {
                let v = if i < keep { value(*c)? } else { 0 };
                acc = (acc << 6) | v;
            }
            let bytes = acc.to_be_bytes();
            out.extend_from_slice(bytes.get(1..keep)?);
        }
        Some(out)
    }
}

fn digest_of(alg: &str, data: &[u8]) -> Result<Vec<u8>, &'static str> {
    let d = match alg {
        SHA256 => xmlsec::Digest::Sha256,
        SHA384 => xmlsec::Digest::Sha384,
        SHA512 => xmlsec::Digest::Sha512,
        _ => return Err("signature-digest-alg"),
    };
    Ok(xmlsec::digest(d, data))
}

fn prefix_list(doc: &Doc, transform: usize) -> Result<Vec<String>, &'static str> {
    let kids = doc.kids(transform)?;
    match kids.as_slice() {
        [] => Ok(Vec::new()),
        [one] => {
            let e = doc.get(*one)?;
            if e.is(EXC_C14N, "InclusiveNamespaces") && doc.kids(*one)?.is_empty() {
                let list = e.attr("PrefixList").unwrap_or_default();
                Ok(list.split_ascii_whitespace().map(String::from).collect())
            } else {
                Err("signature-transform")
            }
        }
        _ => Err("signature-transform"),
    }
}

fn method(doc: &Doc, parent: usize, local: &str) -> Result<(usize, String), &'static str> {
    let i = doc.one(parent, DS, local)?.ok_or("signature-malformed")?;
    let alg = doc
        .get(i)?
        .attr("Algorithm")
        .ok_or("signature-malformed")?
        .to_owned();
    Ok((i, alg))
}

/// The one enveloped signature of the message element `message`, verified with one of `certs`;
/// `Ok(None)` when the element carries none. Every `ds:Signature` elsewhere in the document is
/// refused, so the verified element and the element read are the same arena index (IDI-8).
///
/// # Errors
/// A stable refusal code.
pub(crate) fn enveloped(
    doc: &Doc,
    message: usize,
    certs: &[Vec<u8>],
) -> Result<Option<String>, &'static str> {
    let mut found = Vec::new();
    for i in doc.subtree(0)? {
        if doc.get(i)?.is(DS, "Signature") {
            found.push(i);
        }
    }
    let sig = match found.as_slice() {
        [] => return Ok(None),
        [one] => *one,
        _ => return Err("signature-multiple"),
    };
    // IDI-8
    if doc.get(sig)?.parent != Some(message) {
        return Err("signature-not-enveloped");
    }
    let kids = doc.kids(sig)?;
    let signed_info = *kids.first().ok_or("signature-malformed")?;
    let value = *kids.get(1).ok_or("signature-malformed")?;
    if !doc.get(signed_info)?.is(DS, "SignedInfo") || !doc.get(value)?.is(DS, "SignatureValue") {
        return Err("signature-malformed");
    }
    for extra in kids.iter().skip(2) {
        if !doc.get(*extra)?.is(DS, "KeyInfo") {
            return Err("signature-malformed");
        }
    }
    let si = doc.kids(signed_info)?;
    let (c14n_el, c14n_alg) = method(doc, signed_info, "CanonicalizationMethod")?;
    let (_, sig_alg) = method(doc, signed_info, "SignatureMethod")?;
    let references = doc.named(signed_info, DS, "Reference")?;
    if si.len() != 3 || references.len() != 1 {
        return Err("signature-reference-count");
    }
    if c14n_alg != EXC_C14N {
        return Err("signature-c14n");
    }
    let si_inclusive = prefix_list(doc, c14n_el)?;
    let reference = *references.first().ok_or("signature-malformed")?;
    let uri = doc
        .get(reference)?
        .attr("URI")
        .ok_or("signature-reference")?;
    let target = uri.strip_prefix('#').ok_or("signature-reference")?;
    // IDI-8
    let target_at = *doc.ids.get(target).ok_or("signature-reference")?;
    if target_at != message || doc.get(message)?.attr("ID") != Some(target) {
        return Err("signature-reference");
    }
    let rk = doc.kids(reference)?;
    let [transforms, dm, dv] = rk.as_slice() else {
        return Err("signature-malformed");
    };
    if !doc.get(*transforms)?.is(DS, "Transforms")
        || !doc.get(*dm)?.is(DS, "DigestMethod")
        || !doc.get(*dv)?.is(DS, "DigestValue")
    {
        return Err("signature-malformed");
    }
    let ts = doc.named(*transforms, DS, "Transform")?;
    if ts.len() != doc.kids(*transforms)?.len() {
        return Err("signature-transform");
    }
    let algs = ts
        .iter()
        .map(|t| {
            doc.get(*t)
                .map(|e| e.attr("Algorithm").unwrap_or_default().to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if algs != [ENVELOPED, EXC_C14N] {
        return Err("signature-transform");
    }
    let enveloped = *ts.first().ok_or("signature-transform")?;
    if !doc.kids(enveloped)?.is_empty() {
        return Err("signature-transform");
    }
    let inclusive = prefix_list(doc, *ts.get(1).ok_or("signature-transform")?)?;
    if inclusive
        .iter()
        .any(|p| p != DEFAULT_TOKEN && p.contains(':'))
    {
        return Err("signature-transform");
    }
    let digest_alg = doc
        .get(*dm)?
        .attr("Algorithm")
        .ok_or("signature-malformed")?;
    let canonical = c14n::canonical(doc, message, Some(sig), &inclusive)?;
    let digest = digest_of(digest_alg, canonical.as_bytes())?;
    let expected = b64(&doc.text(*dv)?)?;
    if digest != expected {
        return Err("signature-digest");
    }
    let signed = c14n::canonical(doc, signed_info, None, &si_inclusive)?;
    let value = b64(&doc.text(value)?)?;
    verify_with(certs, &sig_alg, signed.as_bytes(), &value)?;
    Ok(Some(sig_alg))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::b64std::decode;

    #[test]
    fn base64_is_strict() {
        assert_eq!(decode("YWJj").unwrap(), b"abc");
        assert_eq!(decode("YWI=").unwrap(), b"ab");
        assert_eq!(decode("YQ==").unwrap(), b"a");
        assert!(decode("YQ=").is_none());
        assert!(decode("Y=Q=").is_none());
        assert!(decode("YW*j").is_none());
    }
}
