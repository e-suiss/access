#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use super::*;

const ARTEFACTS: [Artefact; 12] = [
    Artefact::IdentityToken,
    Artefact::IdentityCose,
    Artefact::AuditCheckpoint,
    Artefact::Claim,
    Artefact::SamlXml,
    Artefact::EntityStatement,
    Artefact::JweDecrypt,
    Artefact::Rs256Assertion,
    Artefact::SshCertificate,
    Artefact::BlindSignature,
    Artefact::AcmeRequest,
    Artefact::PqIdentityToken,
];

// OP-155 m.1 (b), OP-144, §9.13.8, Ek B 5083
#[test]
fn a_purpose_key_never_signs_another_purposes_artefacts() {
    for artefact in ARTEFACTS {
        let serving: Vec<_> = KeyPurpose::ALL
            .into_iter()
            .filter(|p| p.serves(artefact))
            .collect();
        assert_eq!(serving.len(), 1, "{artefact:?} {serving:?}");
    }
    for a in KeyPurpose::ALL {
        for b in KeyPurpose::ALL.into_iter().filter(|b| *b != a) {
            for artefact in b.artefacts() {
                assert!(!a.serves(*artefact), "{a:?} serves {artefact:?} of {b:?}");
            }
        }
    }
    assert!(!KeyPurpose::Federation.serves(Artefact::IdentityToken));
    assert!(!KeyPurpose::Saml.serves(Artefact::EntityStatement));
    assert!(!KeyPurpose::JweEnc.serves(Artefact::IdentityToken));
    assert!(!KeyPurpose::RsaId.serves(Artefact::SamlXml));
}

// OP-156 m.3 (i), (o), (z), m.1 (b)
#[test]
fn the_stage_11_purposes_sign_only_their_own_artefacts() {
    assert_eq!(KeyPurpose::SshCa.algs(), &[KeyAlg::Ed25519]);
    assert_eq!(KeyPurpose::PrivacyPass.algs(), &[KeyAlg::Rsa2048Blind]);
    assert_eq!(KeyPurpose::Acme.algs(), &[KeyAlg::Es256]);
    for p in KeyPurpose::ALL {
        assert_eq!(
            p.allows(KeyAlg::Rsa2048Blind),
            p == KeyPurpose::PrivacyPass,
            "{p:?}"
        );
    }
    assert_eq!(KeyAlg::Rsa2048Blind.jws(), None);
    for (p, own) in [
        (KeyPurpose::SshCa, Artefact::SshCertificate),
        (KeyPurpose::PrivacyPass, Artefact::BlindSignature),
        (KeyPurpose::Acme, Artefact::AcmeRequest),
    ] {
        assert_eq!(p.artefacts(), &[own]);
        assert!(IDENTITY_ONLY.contains(&p));
        for other in ARTEFACTS.into_iter().filter(|a| *a != own) {
            assert!(!p.serves(other), "{p:?} serves {other:?}");
        }
    }
    assert!(!KeyPurpose::Jose.serves(Artefact::SshCertificate));
    assert!(!KeyPurpose::ClaimIssuer.serves(Artefact::SshCertificate));
    assert!(!KeyPurpose::Federation.serves(Artefact::AcmeRequest));
    assert!(!KeyPurpose::RsaId.serves(Artefact::BlindSignature));
}

// OP-155 m.3 (d), (e), (j), (k), MD-6
#[test]
fn each_purpose_holds_only_its_algorithms() {
    assert_eq!(KeyPurpose::Saml.algs(), &[KeyAlg::Rsa3072, KeyAlg::Es256]);
    assert_eq!(KeyPurpose::Federation.algs(), &[KeyAlg::Es256]);
    assert_eq!(KeyPurpose::JweEnc.algs(), &[KeyAlg::EcdhEsP256]);
    assert_eq!(KeyPurpose::RsaId.algs(), &[KeyAlg::Rsa3072]);
    for p in KeyPurpose::ALL {
        assert_eq!(
            p.allows(KeyAlg::EcdhEsP256),
            p == KeyPurpose::JweEnc,
            "{p:?}"
        );
        assert_eq!(
            p.allows(KeyAlg::Rsa3072),
            matches!(p, KeyPurpose::Saml | KeyPurpose::RsaId),
            "{p:?}"
        );
        assert_eq!(p.on_first_opt_in(), IDENTITY_ONLY.contains(&p), "{p:?}");
    }
    assert_eq!(KeyAlg::Rsa3072.jws(), None);
    assert_eq!(KeyAlg::Es256.jws(), Some(JwsAlg::Es256));
}

// OP-155 m.1 (b)
#[test]
fn labels_are_distinct_and_read_back() {
    let labels: BTreeSet<_> = KeyPurpose::ALL.into_iter().map(KeyPurpose::label).collect();
    assert_eq!(labels.len(), KeyPurpose::ALL.len());
    for p in KeyPurpose::ALL {
        assert_eq!(KeyPurpose::of_label(p.label()), Some(p));
    }
    assert_eq!(KeyPurpose::of_label("operational"), None);
}

fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs" || e == "toml") {
            out.push(path);
        }
    }
}

// OP-155 m.1 (b), CMP-22a, CMP-22b, OP-143 m.9 (e)
#[test]
fn the_authority_signer_never_holds_an_identity_purpose() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    for dir in ["crates/authority-signer", "bins/access-signer"] {
        sources(&root.join(dir), &mut files);
    }
    assert!(files.len() > 4, "{files:?}");
    for file in files {
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(
            !text.contains("access-identity-signer") && !text.contains("access_identity_signer"),
            "{} reaches the identity signer",
            file.display()
        );
        for p in KeyPurpose::ALL {
            let quoted = format!("\"{}\"", p.label());
            assert!(
                !text.contains(&quoted),
                "{} names the {:?} purpose",
                file.display(),
                p
            );
        }
    }
}

// CR-41, OP-159 m.3 (o)
#[test]
fn the_post_quantum_purpose_holds_only_ml_dsa_and_signs_only_its_tokens() {
    assert_eq!(
        KeyPurpose::Pq.algs(),
        &[KeyAlg::MlDsa44, KeyAlg::MlDsa65, KeyAlg::MlDsa87]
    );
    assert_eq!(KeyPurpose::Pq.artefacts(), &[Artefact::PqIdentityToken]);
    assert!(!KeyPurpose::Jose.serves(Artefact::PqIdentityToken));
    assert!(!KeyPurpose::Pq.serves(Artefact::IdentityToken));
    for p in KeyPurpose::ALL {
        assert_eq!(p.allows(KeyAlg::MlDsa65), p == KeyPurpose::Pq, "{p:?}");
    }
    assert_eq!(KeyAlg::MlDsa65.jws(), Some(JwsAlg::MlDsa65));
    assert!(IDENTITY_ONLY.contains(&KeyPurpose::Pq));
}
