#![allow(clippy::unwrap_used, clippy::too_many_lines, reason = "test code")]

use rcgen::{CustomExtension, PKCS_ECDSA_P256_SHA256};

use super::*;
use crate::domain::testing::{Ca, seq, tlv};

const NOW_S: u64 = 1_800_000_000;
const CHALLENGE: &[u8] = b"access-challenge-0123456789abcdef";

struct Desc {
    attestation: u8,
    keymint: u8,
    challenge: &'static [u8],
    origin: Option<u8>,
    root: Option<(bool, u8)>,
}

const GOOD: Desc = Desc {
    attestation: 2,
    keymint: 2,
    challenge: CHALLENGE,
    origin: Some(0),
    root: Some((true, 0)),
};

fn key_description(d: &Desc) -> Vec<u8> {
    let mut hw = Vec::new();
    if let Some(o) = d.origin {
        hw.push(tlv(&[0xbf, 0x85, 0x3e], &tlv(&[0x02], &[o])));
    }
    if let Some((locked, state)) = d.root {
        let rot = seq(&[
            tlv(&[0x04], &[7; 32]),
            tlv(&[0x01], &[if locked { 0xff } else { 0x00 }]),
            tlv(&[0x0a], &[state]),
            tlv(&[0x04], &[8; 32]),
        ]);
        hw.push(tlv(&[0xbf, 0x85, 0x40], &rot));
    }
    seq(&[
        tlv(&[0x02], &[0, 200]),
        tlv(&[0x0a], &[d.attestation]),
        tlv(&[0x02], &[0, 200]),
        tlv(&[0x0a], &[d.keymint]),
        tlv(&[0x04], d.challenge),
        tlv(&[0x04], &[]),
        seq(&[]),
        seq(&hw),
    ])
}

fn chain(ca: &Ca, d: &Desc) -> Vec<Vec<u8>> {
    let leaf = ca.leaf(|p| {
        p.custom_extensions.push(CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
            key_description(d),
        ));
    });
    vec![leaf, ca.root.clone()]
}

const STRICT: Policy<'static> = Policy {
    challenge: CHALLENGE,
    strongbox: true,
    verified_boot: true,
    locked: true,
};

// §12.2.1, L21, AG-31, Ek B 4125
#[test]
fn android_key_attestation_follows_its_checklist() {
    let ca = Ca::new(&PKCS_ECDSA_P256_SHA256);
    let roots = [ca.root.as_slice()];
    let ok = verify(&chain(&ca, &GOOD), &roots, &STRICT, NOW_S).unwrap();
    assert_eq!(ok.level, SecurityLevel::StrongBox);
    assert!(ok.verified_boot && ok.locked);
    assert_eq!(ok.public_key.len(), 65);
    let tee = Desc {
        attestation: 1,
        keymint: 1,
        ..GOOD
    };
    let relaxed = Policy {
        strongbox: false,
        ..STRICT
    };
    assert_eq!(
        verify(&chain(&ca, &tee), &roots, &relaxed, NOW_S)
            .unwrap()
            .level,
        SecurityLevel::Tee
    );
    let refused = [
        (
            Desc {
                attestation: 1,
                keymint: 1,
                ..GOOD
            },
            AttestError::Policy,
        ),
        (
            Desc {
                attestation: 0,
                keymint: 0,
                ..GOOD
            },
            AttestError::Policy,
        ),
        (
            Desc {
                attestation: 2,
                keymint: 1,
                ..GOOD
            },
            AttestError::Policy,
        ),
        (
            Desc {
                challenge: b"other",
                ..GOOD
            },
            AttestError::Challenge,
        ),
        (
            Desc {
                origin: Some(2),
                ..GOOD
            },
            AttestError::Policy,
        ),
        (
            Desc {
                origin: None,
                ..GOOD
            },
            AttestError::Policy,
        ),
        (Desc { root: None, ..GOOD }, AttestError::Policy),
        (
            Desc {
                root: Some((false, 0)),
                ..GOOD
            },
            AttestError::Policy,
        ),
        (
            Desc {
                root: Some((true, 2)),
                ..GOOD
            },
            AttestError::Policy,
        ),
    ];
    for (d, want) in refused {
        assert_eq!(verify(&chain(&ca, &d), &roots, &STRICT, NOW_S), Err(want));
    }
    let foreign = Ca::new(&PKCS_ECDSA_P256_SHA256);
    assert_eq!(
        verify(&chain(&foreign, &GOOD), &roots, &STRICT, NOW_S),
        Err(AttestError::Chain)
    );
    assert_eq!(
        verify(
            &chain(&ca, &GOOD),
            &crate::domain::roots::ANDROID,
            &STRICT,
            NOW_S
        ),
        Err(AttestError::Chain)
    );
    let plain = vec![ca.leaf(|_| {}), ca.root.clone()];
    assert_eq!(
        verify(&plain, &roots, &STRICT, NOW_S),
        Err(AttestError::Certificate)
    );
}
