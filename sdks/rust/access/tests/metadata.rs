//! Domain Metadata verified against the domain root (CR-58, OP-157 m.3 (s)).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

mod support;

use std::collections::BTreeSet;

use access_kernel::verify::cose::Algorithm;
use access_sdk::metadata::{MAX_METADATA, MetadataError, root, verify};
use support::{BINDING_SEED, OTHER_SEED, d, domain, ed_pub, metadata, signed_metadata_by};

fn ed25519() -> BTreeSet<Algorithm> {
    BTreeSet::from([Algorithm::Ed25519])
}

// CR-58, P2, OP-157 m.3 (s), Ek B 5671
#[test]
fn metadata_verifies_only_under_the_domain_root_for_its_own_domain() {
    let keys = root(&[ed_pub(BINDING_SEED)], &ed25519());
    let signed = signed_metadata_by(BINDING_SEED, &metadata());
    let held = verify(&signed, &domain(), &keys).unwrap();
    assert_eq!(held.domain, domain());
    assert_eq!(held.binding, metadata().binding);

    let forged = signed_metadata_by(OTHER_SEED, &metadata());
    assert!(matches!(
        verify(&forged, &domain(), &keys),
        Err(MetadataError::Signature(_))
    ));
    assert_eq!(
        verify(&signed, &d(2), &keys),
        Err(MetadataError::OtherDomain)
    );
    let other_root = root(&[ed_pub(OTHER_SEED)], &ed25519());
    assert!(matches!(
        verify(&signed, &domain(), &other_root),
        Err(MetadataError::Signature(_))
    ));
    assert_eq!(
        verify(&signed, &domain(), &root(&[], &ed25519())),
        Err(MetadataError::NoRoot)
    );
    assert_eq!(
        verify(
            &signed,
            &domain(),
            &root(&[ed_pub(BINDING_SEED)], &BTreeSet::new())
        ),
        Err(MetadataError::NoRoot)
    );
    let big = vec![0_u8; MAX_METADATA + 1];
    assert_eq!(verify(&big, &domain(), &keys), Err(MetadataError::TooLarge));
}
