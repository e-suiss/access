//! A test issuer and wallet for the verifier's tests and other crates' tests: certificates,
//! keys and credentials are made at run time, nothing secret is committed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::arithmetic_side_effects,
    clippy::must_use_candidate,
    missing_docs,
    reason = "test support behind the testing feature"
)]

use std::collections::BTreeMap;

use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::verify::cose::PublicKey;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};
use serde_json::{Value, json};
use suiss_crypto::ecdh_es::Enc;
use suiss_crypto::secret::Secret;
use suiss_crypto::signer::{Signer, SoftSigner};

use crate::domain::jwe;
use crate::domain::request::base64;
use crate::domain::sd_jwt_vc::digest_of;

pub fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

/// A certificate authority and one issuer certificate under it, with the issuer's signer.
pub struct Pki {
    pub root: Vec<u8>,
    pub leaf: Vec<u8>,
    pub signer: SoftSigner,
}

pub fn pki(san: &str) -> Pki {
    let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let root = CertifiedIssuer::self_signed(root_params, root_key).unwrap();
    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut leaf_params = CertificateParams::new(vec![san.to_owned()]).unwrap();
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let leaf = leaf_params.signed_by(&leaf_key, &root).unwrap();
    let signer = SoftSigner::p256_from_pkcs8(&Secret::new(leaf_key.serialize_der())).unwrap();
    Pki {
        root: root.der().to_vec(),
        leaf: leaf.der().to_vec(),
        signer,
    }
}

pub fn sign_jwt(signer: &dyn Signer, header: &Value, payload: &Value) -> String {
    let input = format!(
        "{}.{}",
        b64url_encode(header.to_string().as_bytes()),
        b64url_encode(payload.to_string().as_bytes())
    );
    let sig = signer.sign(input.as_bytes()).unwrap();
    format!("{input}.{}", b64url_encode(&sig))
}

pub fn jwk_of(signer: &dyn Signer) -> Value {
    let PublicKey::P256(sec1) = signer.public_key() else {
        panic!("p256")
    };
    json!({
        "kty": "EC", "crv": "P-256",
        "x": b64url_encode(&sec1[1..33]),
        "y": b64url_encode(&sec1[33..65]),
    })
}

pub fn disclosure(name: &str, value: &Value) -> String {
    let salt = b64url_encode(&access_crypto_salt());
    b64url_encode(json!([salt, name, value]).to_string().as_bytes())
}

pub fn access_crypto_salt() -> [u8; 16] {
    let (k, _) = SoftSigner::generate_ed25519().unwrap();
    let PublicKey::Ed25519(pk) = k.public_key() else {
        panic!("ed25519")
    };
    let mut s = [0u8; 16];
    s.copy_from_slice(&suiss_crypto::digest::sha256(&pk)[..16]);
    s
}

/// An SD-JWT VC: the issuer-signed JWT and one disclosure per selectively disclosable claim.
pub struct Credential {
    pub jwt: String,
    pub disclosures: BTreeMap<String, String>,
}

pub enum IssuerKey<'a> {
    X5c(&'a Pki, bool),
    Kid(&'a dyn Signer, &'a str),
}

pub fn sd_jwt_vc(
    key: &IssuerKey<'_>,
    iss: &str,
    vct: &str,
    holder: &dyn Signer,
    claims: &[(&str, Value)],
    extra: &Value,
) -> Credential {
    let mut disclosures = BTreeMap::new();
    let mut sd = Vec::new();
    for (name, value) in claims {
        let d = disclosure(name, value);
        sd.push(Value::from(digest_of(&d)));
        disclosures.insert((*name).to_owned(), d);
    }
    sd.push(Value::from(b64url_encode(&access_crypto_salt())));
    let now = now_ms() / 1000;
    let mut payload = json!({
        "iss": iss,
        "vct": vct,
        "iat": now,
        "exp": now + 3600,
        "cnf": { "jwk": jwk_of(holder) },
        "_sd": sd,
        "_sd_alg": "sha-256",
    });
    if let (Some(p), Some(e)) = (payload.as_object_mut(), extra.as_object()) {
        p.extend(e.clone());
    }
    let (signer, header): (&dyn Signer, Value) = match key {
        IssuerKey::X5c(pki, with_root) => {
            let mut chain = vec![base64(&pki.leaf)];
            if *with_root {
                chain.push(base64(&pki.root));
            }
            (
                &pki.signer,
                json!({ "alg": "ES256", "typ": "dc+sd-jwt", "x5c": chain }),
            )
        }
        IssuerKey::Kid(s, kid) => (
            *s,
            json!({ "alg": "ES256", "typ": "dc+sd-jwt", "kid": kid }),
        ),
    };
    Credential {
        jwt: sign_jwt(signer, &header, &payload),
        disclosures,
    }
}

pub fn present(
    c: &Credential,
    names: &[&str],
    holder: &dyn Signer,
    aud: &str,
    nonce: &str,
) -> String {
    let mut prefix = format!("{}~", c.jwt);
    for n in names {
        prefix.push_str(&c.disclosures[*n]);
        prefix.push('~');
    }
    let kb = sign_jwt(
        holder,
        &json!({ "alg": "ES256", "typ": "kb+jwt" }),
        &json!({
            "aud": aud,
            "nonce": nonce,
            "iat": now_ms() / 1000,
            "sd_hash": digest_of(&prefix),
        }),
    );
    format!("{prefix}{kb}")
}

/// The wallet's encrypted `direct_post.jwt` answer to the request object `object`.
pub fn seal_response(object: &Value, vp_token: &Value) -> String {
    let k = &object["client_metadata"]["jwks"]["keys"][0];
    let x = b64url_decode(k["x"].as_str().unwrap()).unwrap();
    let y = b64url_decode(k["y"].as_str().unwrap()).unwrap();
    let point = [&[0x04][..], &x, &y].concat();
    let params = json!({ "vp_token": vp_token, "state": object["state"] });
    jwe::encrypt(
        params.to_string().as_bytes(),
        &point,
        k["kid"].as_str().unwrap(),
        Enc::A128Gcm,
    )
    .unwrap()
}

/// The payload of a compact JWS, unverified.
pub fn payload_of(jwt: &str) -> Value {
    serde_json::from_slice(&b64url_decode(jwt.split('.').nth(1).unwrap()).unwrap()).unwrap()
}
