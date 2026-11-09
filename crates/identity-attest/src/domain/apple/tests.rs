#![allow(clippy::unwrap_used, reason = "test code")]

use rcgen::{CustomExtension, PKCS_ECDSA_P256_SHA256};

use super::*;
use crate::domain::testing::{Ca, seq, tlv};

const NOW_S: u64 = 1_800_000_000;
const APP: &str = "TEAM123456.example.agent";

fn head(major: u8, n: usize) -> Vec<u8> {
    let m = major << 5;
    if n < 24 {
        vec![m | u8::try_from(n).unwrap()]
    } else if n < 0x100 {
        vec![m | 0x18, u8::try_from(n).unwrap()]
    } else {
        let [a, b] = u16::try_from(n).unwrap().to_be_bytes();
        vec![m | 0x19, a, b]
    }
}

fn text(s: &str) -> Vec<u8> {
    [head(3, s.len()), s.as_bytes().to_vec()].concat()
}

fn bytes(b: &[u8]) -> Vec<u8> {
    [head(2, b.len()), b.to_vec()].concat()
}

fn map(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut out = head(5, entries.len());
    for (k, v) in entries {
        out.extend(text(k));
        out.extend_from_slice(v);
    }
    out
}

struct Case {
    aaguid: [u8; 16],
    counter: u32,
    app: &'static str,
    nonce_ok: bool,
    id_ok: bool,
}

const GOOD: Case = Case {
    aaguid: AAGUID_PRODUCTION,
    counter: 0,
    app: APP,
    nonce_ok: true,
    id_ok: true,
};

fn object(ca: &Ca, c: &Case, client_data_hash: &[u8; 32]) -> (Vec<u8>, [u8; 32]) {
    let key = rcgen::KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let key_id = sha256(key.public_key_raw());
    let mut auth = sha256(c.app.as_bytes()).to_vec();
    auth.push(0x41);
    auth.extend(c.counter.to_be_bytes());
    auth.extend(c.aaguid);
    auth.extend([0, 32]);
    auth.extend(if c.id_ok { key_id } else { [9; 32] });
    let mut msg = auth.clone();
    msg.extend_from_slice(client_data_hash);
    let nonce = if c.nonce_ok { sha256(&msg) } else { [0; 32] };
    let ext = seq(&[tlv(&[0xa1], &tlv(&[0x04], &nonce))]);
    let leaf = ca.leaf_for(&key, |p| {
        p.custom_extensions.push(CustomExtension::from_oid_content(
            &[1, 2, 840, 113_635, 100, 8, 2],
            ext,
        ));
    });
    let stmt = [
        head(5, 2),
        text("x5c"),
        head(4, 1),
        bytes(&leaf),
        text("receipt"),
        bytes(b"receipt"),
    ]
    .concat();
    let obj = map(&[
        ("fmt", text("apple-appattest")),
        ("attStmt", stmt),
        ("authData", bytes(&auth)),
    ]);
    (obj, key_id)
}

// §12.2.1, §10.1.2, L21, AG-31, Ek B 4125, 4524
#[test]
fn app_attest_follows_its_checklist() {
    let ca = Ca::new(&PKCS_ECDSA_P256_SHA256);
    let roots = [ca.root.as_slice()];
    let cdh = [5; 32];
    let (obj, key_id) = object(&ca, &GOOD, &cdh);
    let policy = Policy {
        app_id: APP,
        key_id: &key_id,
        client_data_hash: &cdh,
        production: true,
    };
    let ok = verify(&obj, &roots, &policy, NOW_S).unwrap();
    assert!(ok.production);
    assert_eq!(ok.receipt, b"receipt");
    assert_eq!(sha256(&ok.public_key), key_id);
    let refused = [
        (
            Case {
                nonce_ok: false,
                ..GOOD
            },
            AttestError::Challenge,
        ),
        (
            Case {
                id_ok: false,
                ..GOOD
            },
            AttestError::Key,
        ),
        (Case { counter: 1, ..GOOD }, AttestError::Format),
        (
            Case {
                app: "OTHER.example.app",
                ..GOOD
            },
            AttestError::Policy,
        ),
        (
            Case {
                aaguid: AAGUID_DEVELOPMENT,
                ..GOOD
            },
            AttestError::Policy,
        ),
        (
            Case {
                aaguid: [0; 16],
                ..GOOD
            },
            AttestError::Policy,
        ),
    ];
    for (c, want) in refused {
        let (obj, key_id) = object(&ca, &c, &cdh);
        let p = Policy {
            key_id: &key_id,
            ..policy
        };
        assert_eq!(verify(&obj, &roots, &p, NOW_S), Err(want));
    }
    let (dev, dev_id) = object(
        &ca,
        &Case {
            aaguid: AAGUID_DEVELOPMENT,
            ..GOOD
        },
        &cdh,
    );
    let p = Policy {
        key_id: &dev_id,
        production: false,
        ..policy
    };
    assert!(!verify(&dev, &roots, &p, NOW_S).unwrap().production);
    let (obj, key_id) = object(&ca, &GOOD, &cdh);
    let wrong_key = [1; 32];
    let p = Policy {
        key_id: &wrong_key,
        ..policy
    };
    assert_eq!(verify(&obj, &roots, &p, NOW_S), Err(AttestError::Key));
    let p = Policy {
        key_id: &key_id,
        ..policy
    };
    assert_eq!(
        verify(&obj, &crate::domain::roots::APPLE_APP_ATTEST, &p, NOW_S),
        Err(AttestError::Chain)
    );
}
