//! The caller's Instance key (OP-151 m.3 (h), TN-130, PI-11): a PKCS#8 file or a PKCS#11 token
//! object. It signs the AIS of every write, the DPoP proofs that bind the read token, and the
//! client assertion that obtains it. There is no other credential: the command line has no
//! bearer token option and never reads a token from an argument or the environment (TN-130,
//! MD-14).

use std::path::{Path, PathBuf};

use access_kernel::ais::CONTENT_TYPE;
use access_kernel::json::b64url_encode;
use access_kernel::verify::cose::PublicKey;
use access_kernel::verify::key_scope::thumbprint;
use access_sdk::auth::dpop::{ProofKey, jwk};
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::pem::PemObject as _;
use suiss_crypto::pkcs11::KeyStore;
use suiss_crypto::secret::Secret;
use suiss_crypto::signer::{Signer, SoftSigner, sign_sign1};

/// Why the key cannot be used.
#[derive(Debug, thiserror::Error)]
pub(crate) enum KeyError {
    /// The key file cannot be read or is not a PKCS#8 P-256 or Ed25519 key.
    #[error("key file: {0}")]
    File(String),
    /// The PKCS#11 URI is not `pkcs11:token=…;object=…?module-path=…&pin-source=file:…`.
    #[error("PKCS#11 URI: {0}")]
    Uri(String),
    /// The token or the object cannot be used.
    #[error("PKCS#11: {0}")]
    Token(String),
    /// Signing failed.
    #[error("signing failed")]
    Sign,
}

/// Where the key is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum KeySource {
    /// A PKCS#8 PEM file.
    File(PathBuf),
    /// A PKCS#11 object (RFC 7512).
    Pkcs11(Pkcs11Uri),
}

/// The parts of an RFC 7512 URI the command line uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Pkcs11Uri {
    pub(crate) token: String,
    pub(crate) object: String,
    pub(crate) module: PathBuf,
    pub(crate) pin_file: PathBuf,
}

fn pct_decode(s: &str) -> Option<String> {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0usize;
    while let Some(&c) = b.get(i) {
        if c == b'%' {
            let h = std::str::from_utf8(b.get(i.checked_add(1)?..i.checked_add(3)?)?).ok()?;
            out.push(u8::from_str_radix(h, 16).ok()?);
            i = i.checked_add(3)?;
        } else {
            out.push(c);
            i = i.checked_add(1)?;
        }
    }
    String::from_utf8(out).ok()
}

impl Pkcs11Uri {
    /// Parses `pkcs11:token=<label>;object=<label>?module-path=<path>&pin-source=file:<path>`.
    /// The PIN comes from a file only, never from the URI (`pin-value` is refused).
    pub(crate) fn parse(uri: &str) -> Result<Self, KeyError> {
        let bad = |what: &str| KeyError::Uri(what.to_owned());
        let rest = uri.strip_prefix("pkcs11:").ok_or_else(|| bad("scheme"))?;
        let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
        let mut token = None;
        let mut object = None;
        for attr in path.split(';').filter(|a| !a.is_empty()) {
            let (k, v) = attr.split_once('=').ok_or_else(|| bad(attr))?;
            let v = pct_decode(v).ok_or_else(|| bad(attr))?;
            match k {
                "token" => token = Some(v),
                "object" => object = Some(v),
                _ => {}
            }
        }
        let mut module = None;
        let mut pin_file = None;
        for attr in query.split('&').filter(|a| !a.is_empty()) {
            let (k, v) = attr.split_once('=').ok_or_else(|| bad(attr))?;
            let v = pct_decode(v).ok_or_else(|| bad(attr))?;
            match k {
                "module-path" => module = Some(PathBuf::from(v)),
                "pin-source" => {
                    pin_file = Some(PathBuf::from(
                        v.strip_prefix("file:").ok_or_else(|| bad("pin-source"))?,
                    ));
                }
                "pin-value" => return Err(bad("pin-value: the PIN comes from a file")),
                _ => {}
            }
        }
        Ok(Self {
            token: token.ok_or_else(|| bad("token"))?,
            object: object.ok_or_else(|| bad("object"))?,
            module: module.ok_or_else(|| bad("module-path"))?,
            pin_file: pin_file.ok_or_else(|| bad("pin-source"))?,
        })
    }
}

/// The Instance key, loaded.
pub(crate) struct InstanceKey {
    signer: Box<dyn Signer>,
    public: PublicKey,
    kid: [u8; 32],
}

impl core::fmt::Debug for InstanceKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InstanceKey")
            .field("kid", &b64url_encode(&self.kid))
            .finish_non_exhaustive()
    }
}

fn read_pkcs8(path: &Path) -> Result<SoftSigner, KeyError> {
    let pem = std::fs::read(path).map_err(|e| KeyError::File(e.to_string()))?;
    let der = PrivateKeyDer::from_pem_slice(&pem).map_err(|e| KeyError::File(e.to_string()))?;
    let PrivateKeyDer::Pkcs8(doc) = der else {
        return Err(KeyError::File(String::from("not a PKCS#8 key")));
    };
    let doc = Secret::new(doc.secret_pkcs8_der().to_vec());
    SoftSigner::p256_from_pkcs8(&doc)
        .or_else(|_| SoftSigner::ed25519_from_pkcs8(&doc))
        .map_err(|_| KeyError::File(String::from("not a P-256 or Ed25519 key")))
}

impl InstanceKey {
    /// Loads the key.
    pub(crate) fn load(source: &KeySource) -> Result<Self, KeyError> {
        let signer: Box<dyn Signer> = match source {
            KeySource::File(path) => Box::new(read_pkcs8(path)?),
            KeySource::Pkcs11(uri) => {
                let pin = std::fs::read_to_string(&uri.pin_file)
                    .map_err(|e| KeyError::Token(format!("PIN file: {e}")))?;
                let pin = Secret::new(pin.trim_end_matches(['\r', '\n']).to_owned());
                let store = KeyStore::open(&uri.module, &uri.token, &pin)
                    .map_err(|e| KeyError::Token(e.to_string()))?;
                Box::new(
                    store
                        .signer(&uri.object)
                        .map_err(|e| KeyError::Token(e.to_string()))?,
                )
            }
        };
        Ok(Self::from_signer(signer))
    }

    /// A key over any signer.
    pub(crate) fn from_signer(signer: Box<dyn Signer>) -> Self {
        let public = signer.public_key();
        let kid = thumbprint(&public);
        Self {
            signer,
            public,
            kid,
        }
    }

    /// The RFC 7638 thumbprint: the AIS `kid` and the read token's `cnf.jkt`.
    pub(crate) const fn kid(&self) -> &[u8; 32] {
        &self.kid
    }

    /// Signs `statement` (canonical CBOR) as the tagged `COSE_Sign1` AIS.
    pub(crate) fn sign_ais(&self, statement: &[u8]) -> Result<Vec<u8>, KeyError> {
        sign_sign1(self.signer.as_ref(), self.kid, CONTENT_TYPE, statement)
            .map_err(|_| KeyError::Sign)
    }

    /// A compact JWS with `typ` over `claims` (JSON text), `kid` the thumbprint.
    pub(crate) fn jws(&self, typ: &str, claims: &str) -> Result<String, KeyError> {
        let (_, alg) = jwk(&self.public).map_err(|_| KeyError::Sign)?;
        let header = format!(
            r#"{{"alg":"{alg}","kid":"{}","typ":"{typ}"}}"#,
            b64url_encode(&self.kid)
        );
        let mut out = b64url_encode(header.as_bytes());
        out.push('.');
        out.push_str(&b64url_encode(claims.as_bytes()));
        let sig = self
            .signer
            .sign(out.as_bytes())
            .map_err(|_| KeyError::Sign)?;
        out.push('.');
        out.push_str(&b64url_encode(&sig));
        Ok(out)
    }
}

impl ProofKey for InstanceKey {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }

    fn sign(&self, input: &[u8]) -> Option<Vec<u8>> {
        self.signer.sign(input).ok()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    #[test]
    fn a_pkcs11_uri_names_token_object_module_and_a_pin_file() {
        let u = Pkcs11Uri::parse(
            "pkcs11:token=ops;object=reconciler%201?module-path=/usr/lib/softhsm/libsofthsm2.so&pin-source=file:/run/pin",
        )
        .unwrap();
        assert_eq!(u.object, "reconciler 1");
        assert_eq!(u.pin_file, PathBuf::from("/run/pin"));
        assert!(Pkcs11Uri::parse("pkcs11:token=a;object=b?module-path=/m&pin-value=1234").is_err());
        assert!(Pkcs11Uri::parse("pkcs11:token=a?module-path=/m&pin-source=file:/p").is_err());
    }
}
