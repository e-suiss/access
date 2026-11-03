//! Crypto vector V3 (CR-51 m.2, OP-125, OP-142): X25519 never yields an all-zero shared secret.
//! Access uses X25519 only in the TLS 1.3 key exchange (CR-12), so the vector runs against
//! the key exchange groups of the server's own TLS configuration and against aws-lc-rs over
//! the full Wycheproof X25519 file.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use aws_lc_rs::agreement::{self, PrivateKey, UnparsedPublicKey, X25519};
use rcgen::{CertificateParams, KeyPair};
use rustls::NamedGroup;
use serde_json::Value;

/// Points of small order and their non-canonical encodings (RFC 7748 §6.1; Wycheproof
/// `LowOrderPublic`): every scalar multiplies them to zero.
const LOW_ORDER: [&str; 7] = [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
];

fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}

fn server_config() -> std::sync::Arc<access_http::tls::ServerConfig> {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec![String::from("acme.id.test")])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    access_http::tls::server_config(cert.pem().as_bytes(), key.serialize_pem().as_bytes(), None)
        .unwrap()
}

// CR-51, CR-12, OP-125, OP-142, RFC 7748 §6.1, RFC 8446 §7.4.2: the server's X25519 and
// X25519MLKEM768 groups refuse a client share whose X25519 part has small order, as the server
// would receive it in a ClientHello; a normal share still completes
#[test]
fn v3_tls_key_exchange_refuses_a_zero_shared_secret() {
    let config = server_config();
    let groups = &config.crypto_provider().kx_groups;
    let mut seen = Vec::new();
    for group in groups {
        let name = group.name();
        let honest = group.start().unwrap().pub_key().to_vec();
        match name {
            NamedGroup::X25519 => {
                assert!(group.start_and_complete(&honest).is_ok());
                for point in LOW_ORDER {
                    assert!(group.start_and_complete(&hex(point)).is_err(), "{point}");
                }
            }
            NamedGroup::X25519MLKEM768 => {
                assert!(group.start_and_complete(&honest).is_ok());
                let split = honest.len() - 32;
                for point in LOW_ORDER {
                    let mut share = honest[..split].to_vec();
                    share.extend(hex(point));
                    assert!(group.start_and_complete(&share).is_err(), "{point}");
                }
            }
            _ => continue,
        }
        seen.push(name);
    }
    assert!(seen.contains(&NamedGroup::X25519MLKEM768), "{seen:?}");
    assert!(seen.contains(&NamedGroup::X25519), "{seen:?}");
}

// CR-51, CR-53, RFC 7748 §6.1: aws-lc-rs agrees with every Wycheproof X25519 vector and
// refuses every case whose shared secret would be zero
#[test]
fn v3_wycheproof_x25519() {
    let path = format!(
        "{}/../../conformance/vectors/external/wycheproof-x25519_test.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let file: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let (mut zero, mut agreed) = (0_u32, 0_u32);
    for g in file["testGroups"].as_array().unwrap() {
        for t in g["tests"].as_array().unwrap() {
            let id = &t["tcId"];
            let flags: Vec<&str> = t["flags"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| f.as_str().unwrap())
                .collect();
            let private =
                PrivateKey::from_private_key(&X25519, &hex(t["private"].as_str().unwrap()))
                    .unwrap();
            let public = hex(t["public"].as_str().unwrap());
            let shared = hex(t["shared"].as_str().unwrap());
            let out = agreement::agree(
                &private,
                UnparsedPublicKey::new(&X25519, &public),
                aws_lc_rs::error::Unspecified,
                |k| Ok(k.to_vec()),
            );
            if flags.contains(&"ZeroSharedSecret") {
                assert!(out.is_err(), "tcId {id}: a zero shared secret was accepted");
                zero += 1;
                continue;
            }
            match (t["result"].as_str().unwrap(), out) {
                ("valid", Ok(k)) => {
                    assert_eq!(k, shared, "tcId {id}");
                    agreed += 1;
                }
                ("valid", Err(_)) => panic!("tcId {id}: a valid case was refused"),
                (_, Ok(k)) => {
                    assert_eq!(k, shared, "tcId {id}");
                    assert!(k.iter().any(|b| *b != 0), "tcId {id}");
                }
                (_, Err(_)) => {}
            }
        }
    }
    assert!(zero >= 30, "{zero}");
    assert!(agreed >= 200, "{agreed}");
}
