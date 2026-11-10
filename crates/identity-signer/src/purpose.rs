//! The purposes of the identity signer's keys (§9.13.8, §10.7.1, MD-6, OP-144, OP-155 m.3 (c),
//! (d), (j), (k), OP-156 m.3 (i), (o), (z)): every key it holds serves exactly one purpose, signs only that purpose's
//! artefacts, and is kept under its purpose's label apart from the others. None of them is ever
//! held by the authority signer (CMP-22a), whose keys sign authority artefacts only.

use access_crypto::jose::JwsAlg;

/// One purpose. A key is made for one purpose and is never used for another.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyPurpose {
    /// The realm JOSE key set: identity tokens and identity plane `COSE_Sign1` artefacts
    /// (CR-18 to CR-27).
    Jose,
    /// The cell key that signs the identity audit log's checkpoints (OP-150 m.3 (h)).
    AuditCheckpoint,
    /// The realm's Claim issuer key (§10.1.7).
    ClaimIssuer,
    /// SAML assertions, responses and metadata, and WS-Federation tokens: RSA-3072, or P-256
    /// for a service provider whose template supports it (OP-155 m.3 (d), (e)).
    Saml,
    /// OpenID Federation entity statements and trust marks, P-256; never the Domain Metadata
    /// inside them (OP-155 m.3 (j)).
    Federation,
    /// ECDH-ES P-256 decryption of encrypted request objects and registration requests; it
    /// signs nothing (OP-155 m.3 (k)).
    JweEnc,
    /// RS256 identity assertions for clients that opted in, RSA-3072, made on the first opt-in
    /// (MD-6, OP-155 m.3 (k)).
    RsaId,
    /// The realm's OpenSSH user certificate authority, Ed25519 (OP-156 m.3 (o), IDP-32).
    SshCa,
    /// The Privacy Pass issuer key of RFC 9578 token type `0x0002`, RSA-2048: only the raw
    /// blind private operation, never a PKCS#1 or PSS signature over a message (OP-156 m.3 (z)).
    PrivacyPass,
    /// The ACME account key that signs RFC 8555 requests, P-256 (OP-156 m.3 (i)).
    Acme,
}

/// A key algorithm a purpose may hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyAlg {
    /// ECDSA P-256 signatures.
    Es256,
    /// Ed25519 signatures.
    Ed25519,
    /// RSA-3072 signatures (PKCS#1 v1.5 with SHA-256 for RS256 and SAML).
    Rsa3072,
    /// ECDH-ES key agreement on P-256.
    EcdhEsP256,
    /// RSA-2048 used only for the raw blind private operation of RFC 9474 (OP-156 m.3 (z)).
    Rsa2048Blind,
}

impl KeyAlg {
    /// The JOSE signature algorithm, for the algorithms the realm JOSE key set uses.
    #[must_use]
    pub const fn jws(self) -> Option<JwsAlg> {
        match self {
            Self::Es256 => Some(JwsAlg::Es256),
            Self::Ed25519 => Some(JwsAlg::Ed25519),
            Self::Rsa3072 | Self::EcdhEsP256 | Self::Rsa2048Blind => None,
        }
    }
}

/// What a key produces or opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Artefact {
    /// A compact JWS identity token: ID token, access token without authority, logout token.
    IdentityToken,
    /// An identity plane `COSE_Sign1` such as `auth_context`.
    IdentityCose,
    /// A C2SP signed note of the identity audit log.
    AuditCheckpoint,
    /// A Claim of the identity issuer's classes, and the two self-signed Exercises that open
    /// its Party.
    Claim,
    /// An XML signature over a SAML message, SAML metadata or a WS-Federation token.
    SamlXml,
    /// An OpenID Federation entity statement or trust mark.
    EntityStatement,
    /// The unwrapping of a JWE content key addressed to the realm.
    JweDecrypt,
    /// An RS256 identity assertion: ID token, userinfo or introspection answer.
    Rs256Assertion,
    /// An OpenSSH user certificate (`ssh-ed25519-cert-v01@openssh.com`) or the realm's KRL.
    SshCertificate,
    /// A blind signature over a blinded Privacy Pass token request.
    BlindSignature,
    /// A JWS of an ACME request (RFC 8555 §6.2).
    AcmeRequest,
}

impl KeyPurpose {
    /// Every purpose.
    pub const ALL: [Self; 10] = [
        Self::Jose,
        Self::AuditCheckpoint,
        Self::ClaimIssuer,
        Self::Saml,
        Self::Federation,
        Self::JweEnc,
        Self::RsaId,
        Self::SshCa,
        Self::PrivacyPass,
        Self::Acme,
    ];

    /// The purpose's label in the vault and in the protocol.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Jose => "jose",
            Self::AuditCheckpoint => crate::cell::LABEL,
            Self::ClaimIssuer => crate::issuer::LABEL,
            Self::Saml => "saml",
            Self::Federation => "federation",
            Self::JweEnc => "jwe-enc",
            Self::RsaId => "rsa-id",
            Self::SshCa => "ssh-ca",
            Self::PrivacyPass => "privacy-pass",
            Self::Acme => "acme",
        }
    }

    /// The purpose of a label.
    #[must_use]
    pub fn of_label(label: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.label() == label)
    }

    /// The algorithms a key of this purpose may have.
    #[must_use]
    pub const fn algs(self) -> &'static [KeyAlg] {
        match self {
            Self::Jose => &[KeyAlg::Es256, KeyAlg::Ed25519],
            Self::AuditCheckpoint | Self::ClaimIssuer | Self::SshCa => &[KeyAlg::Ed25519],
            Self::Saml => &[KeyAlg::Rsa3072, KeyAlg::Es256],
            Self::Federation | Self::Acme => &[KeyAlg::Es256],
            Self::PrivacyPass => &[KeyAlg::Rsa2048Blind],
            Self::JweEnc => &[KeyAlg::EcdhEsP256],
            Self::RsaId => &[KeyAlg::Rsa3072],
        }
    }

    /// The one artefact kind its key produces or opens.
    #[must_use]
    pub const fn artefacts(self) -> &'static [Artefact] {
        match self {
            Self::Jose => &[Artefact::IdentityToken, Artefact::IdentityCose],
            Self::AuditCheckpoint => &[Artefact::AuditCheckpoint],
            Self::ClaimIssuer => &[Artefact::Claim],
            Self::Saml => &[Artefact::SamlXml],
            Self::Federation => &[Artefact::EntityStatement],
            Self::JweEnc => &[Artefact::JweDecrypt],
            Self::RsaId => &[Artefact::Rs256Assertion],
            Self::SshCa => &[Artefact::SshCertificate],
            Self::PrivacyPass => &[Artefact::BlindSignature],
            Self::Acme => &[Artefact::AcmeRequest],
        }
    }

    /// Whether a key of this purpose may produce or open `artefact`.
    #[must_use]
    pub fn serves(self, artefact: Artefact) -> bool {
        self.artefacts().contains(&artefact)
    }

    /// Whether a key of this purpose may have `alg`.
    #[must_use]
    pub fn allows(self, alg: KeyAlg) -> bool {
        self.algs().contains(&alg)
    }

    /// Whether the key is made only when a realm or client first opts in, rather than when the
    /// realm opens (MD-6).
    #[must_use]
    pub const fn on_first_opt_in(self) -> bool {
        matches!(
            self,
            Self::Saml
                | Self::Federation
                | Self::JweEnc
                | Self::RsaId
                | Self::SshCa
                | Self::PrivacyPass
                | Self::Acme
        )
    }
}

/// The purposes Stages 10 and 11 add; the authority signer never holds one (OP-155 m.1 (b),
/// OP-156 m.1 (b)).
pub const IDENTITY_ONLY: [KeyPurpose; 7] = [
    KeyPurpose::Saml,
    KeyPurpose::Federation,
    KeyPurpose::JweEnc,
    KeyPurpose::RsaId,
    KeyPurpose::SshCa,
    KeyPurpose::PrivacyPass,
    KeyPurpose::Acme,
];

#[cfg(test)]
mod tests;
