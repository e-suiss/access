//! `EncryptedAssertion` (§10.6.1 rule 7, §13.2, §15.3.3 CR-4, RR-36): the signed assertion is
//! encrypted with AES-256-GCM under a fresh key, and the key with RSA-OAEP (SHA-256, MGF1
//! SHA-256) for the registration's pinned encryption certificate, placed inline. `rsa-1_5` and
//! `EncryptedAttribute` are never produced.

use access_crypto::xmlsec;

use crate::assertion::{Encrypter, Random};
use crate::dsig::SignError;
use crate::sp::b64;
use crate::uri;
use crate::xml::El;

/// AES-256-GCM (XML Encryption 1.1).
pub const AES256_GCM: &str = "http://www.w3.org/2009/xmlenc11#aes256-gcm";
/// RSA-OAEP (XML Encryption 1.1).
pub const RSA_OAEP: &str = "http://www.w3.org/2009/xmlenc11#rsa-oaep";
/// MGF1 with SHA-256.
pub const MGF1_SHA256: &str = "http://www.w3.org/2009/xmlenc11#mgf1sha256";
/// The `Type` of encrypted element content.
pub const TYPE_ELEMENT: &str = "http://www.w3.org/2001/04/xmlenc#Element";

fn err(what: &str) -> SignError {
    SignError(String::from(what))
}

/// The `subjectPublicKeyInfo` of an X.509 certificate, as DER (RFC 5280 §4.1).
///
/// # Errors
/// [`SignError`] for anything that is not a certificate.
pub fn spki(cert: &[u8]) -> Result<Vec<u8>, SignError> {
    use access_parse::der::{Reader, SEQUENCE};
    let bad = |_| err("certificate");
    let mut outer = Reader::new(cert).map_err(bad)?;
    let certificate = outer.tagged(SEQUENCE).map_err(bad)?;
    let mut c = Reader::new(certificate).map_err(bad)?;
    let tbs = c.tagged(SEQUENCE).map_err(bad)?;
    let mut t = Reader::new(tbs).map_err(bad)?;
    let mut first = t.next_tlv().map_err(bad)?;
    if first.tag == 0xa0 {
        first = t.next_tlv().map_err(bad)?;
    }
    if first.tag != 0x02 {
        return Err(err("certificate"));
    }
    for _ in 0..4 {
        t.next_tlv().map_err(bad)?;
    }
    let spki = t.tagged(SEQUENCE).map_err(bad)?;
    let mut out = vec![SEQUENCE];
    let len = spki.len();
    if len < 0x80 {
        out.push(u8::try_from(len).map_err(|_| err("certificate"))?);
    } else if len <= 0xff {
        out.push(0x81);
        out.push(u8::try_from(len).map_err(|_| err("certificate"))?);
    } else {
        out.push(0x82);
        out.extend_from_slice(
            &u16::try_from(len)
                .map_err(|_| err("certificate"))?
                .to_be_bytes(),
        );
    }
    out.extend_from_slice(spki);
    Ok(out)
}

/// The encrypter over the process's random source.
pub struct XmlEnc<'a, R: ?Sized>(pub &'a R);

fn xenc(local: &'static str) -> El {
    El::new("xenc", uri::XENC, local)
}

fn cipher(value: &[u8]) -> El {
    xenc("CipherData").child(xenc("CipherValue").text(b64::encode(value)))
}

impl<R: Random + ?Sized> Encrypter for XmlEnc<'_, R> {
    fn encrypt(&self, assertion: &El, cert: &[u8]) -> Result<El, SignError> {
        let mut key = <[u8; 32]>::default();
        self.0.fill(&mut key)?;
        let mut nonce = <[u8; 12]>::default();
        self.0.fill(&mut nonce)?;
        let wrapped = xmlsec::rsa_oaep_encrypt(&spki(cert)?, &key).map_err(|_| err("key wrap"))?;
        let mut data = assertion.canonical().into_bytes();
        xmlsec::aes256_gcm_seal(&key, nonce, &mut data).map_err(|_| err("aead"))?;
        let mut body = nonce.to_vec();
        body.extend_from_slice(&data);
        let encrypted_key = xenc("EncryptedKey")
            .child(
                xenc("EncryptionMethod")
                    .attr("Algorithm", RSA_OAEP)
                    .child(
                        El::new("ds", uri::DS, "DigestMethod")
                            .attr("Algorithm", crate::alg::DigestAlg::Sha256.uri()),
                    )
                    .child(El::new("xenc11", uri::XENC11, "MGF").attr("Algorithm", MGF1_SHA256)),
            )
            .child(cipher(&wrapped));
        Ok(El::new("saml", uri::SAML, "EncryptedAssertion").child(
            xenc("EncryptedData")
                .attr("Type", TYPE_ELEMENT)
                .child(xenc("EncryptionMethod").attr("Algorithm", AES256_GCM))
                .child(El::new("ds", uri::DS, "KeyInfo").child(encrypted_key))
                .child(cipher(&body)),
        ))
    }
}
