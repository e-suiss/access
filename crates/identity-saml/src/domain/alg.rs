//! SAML signature and digest algorithms (§10.4.5, §10.6.1, §13.2, RFC 9231, MD-3, CR-2, TI-9,
//! OP-155 m.3 (e)): RSA-SHA256 by default with RSA-3072, RSA-SHA384/512 by configuration and
//! ECDSA-SHA256 when the service provider's template supports it. SHA-1, PSS and Ed25519 are
//! named only to be refused.

use serde::{Deserialize, Serialize};

/// A signature algorithm Access produces.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SigAlg {
    /// `xmldsig-more#rsa-sha256`, the default (ecosystem exception, MD-3).
    RsaSha256,
    /// `xmldsig-more#rsa-sha384` (the correct URI, §10.6.1).
    RsaSha384,
    /// `xmldsig-more#rsa-sha512`.
    RsaSha512,
    /// `xmldsig-more#ecdsa-sha256`, with the realm's P-256 SAML key.
    EcdsaSha256,
}

/// A digest algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DigestAlg {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

/// Algorithm URIs that are never produced or accepted (TI-9 wins over the §10.6.1 compatibility
/// flag, OP-155 m.3 (e)); kept so a request naming one is refused by name.
pub const REFUSED: [&str; 8] = [
    "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
    "http://www.w3.org/2000/09/xmldsig#dsa-sha1",
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1",
    "http://www.w3.org/2000/09/xmldsig#hmac-sha1",
    "http://www.w3.org/2000/09/xmldsig#sha1",
    "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1",
    "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519",
    "http://www.w3.org/2001/04/xmlenc#rsa-1_5",
];

impl SigAlg {
    /// Every algorithm.
    pub const ALL: [Self; 4] = [
        Self::RsaSha256,
        Self::RsaSha384,
        Self::RsaSha512,
        Self::EcdsaSha256,
    ];

    /// The `SignatureMethod` URI.
    #[must_use]
    pub const fn uri(self) -> &'static str {
        match self {
            Self::RsaSha256 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            Self::RsaSha384 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
            Self::RsaSha512 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
            Self::EcdsaSha256 => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
        }
    }

    /// The algorithm of a URI; `None` for anything else, SHA-1 included.
    #[must_use]
    pub fn of_uri(uri: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.uri() == uri)
    }

    /// Its name in a registration.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RsaSha256 => "rsa-sha256",
            Self::RsaSha384 => "rsa-sha384",
            Self::RsaSha512 => "rsa-sha512",
            Self::EcdsaSha256 => "ecdsa-sha256",
        }
    }

    /// The algorithm a registration names.
    #[must_use]
    pub fn of_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.name() == name)
    }

    /// The digest the signature's reference uses.
    #[must_use]
    pub const fn digest(self) -> DigestAlg {
        match self {
            Self::RsaSha256 | Self::EcdsaSha256 => DigestAlg::Sha256,
            Self::RsaSha384 => DigestAlg::Sha384,
            Self::RsaSha512 => DigestAlg::Sha512,
        }
    }

    /// Whether the realm's ECDSA key signs it, rather than its RSA key.
    #[must_use]
    pub const fn ecdsa(self) -> bool {
        matches!(self, Self::EcdsaSha256)
    }
}

impl DigestAlg {
    /// The `DigestMethod` URI.
    #[must_use]
    pub const fn uri(self) -> &'static str {
        match self {
            Self::Sha256 => "http://www.w3.org/2001/04/xmlenc#sha256",
            Self::Sha384 => "http://www.w3.org/2001/04/xmldsig-more#sha384",
            Self::Sha512 => "http://www.w3.org/2001/04/xmlenc#sha512",
        }
    }

    /// The digest of `data`.
    #[must_use]
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        let d = match self {
            Self::Sha256 => access_crypto::xmlsec::Digest::Sha256,
            Self::Sha384 => access_crypto::xmlsec::Digest::Sha384,
            Self::Sha512 => access_crypto::xmlsec::Digest::Sha512,
        };
        access_crypto::xmlsec::digest(d, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TI-9, OP-155 m.3 (e), §10.6.1, SHA-1, SHA-384
    #[test]
    fn sha1_is_never_an_algorithm_and_sha384_has_the_right_uri() {
        for r in REFUSED {
            assert_eq!(SigAlg::of_uri(r), None, "{r}");
        }
        assert_eq!(
            SigAlg::RsaSha384.uri(),
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
        );
        assert_eq!(SigAlg::of_name("rsa-sha1"), None);
        assert_eq!(
            SigAlg::RsaSha512.digest().uri(),
            "http://www.w3.org/2001/04/xmlenc#sha512"
        );
    }
}
