#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]

use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, PKCS_ECDSA_P256_SHA256,
    SignatureAlgorithm,
};

pub(crate) struct Ca {
    pub(crate) root: Vec<u8>,
    issuer: rcgen::Issuer<'static, KeyPair>,
}

impl Ca {
    pub(crate) fn new(alg: &'static SignatureAlgorithm) -> Self {
        let key = KeyPair::generate_for(alg).unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "Test Root");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let root = params.self_signed(&key).unwrap();
        Self {
            root: root.der().to_vec(),
            issuer: rcgen::Issuer::new(params, key),
        }
    }

    pub(crate) fn leaf(&self, f: impl FnOnce(&mut CertificateParams)) -> Vec<u8> {
        self.leaf_with_key(&PKCS_ECDSA_P256_SHA256, f).0
    }

    pub(crate) fn leaf_with_key(
        &self,
        alg: &'static SignatureAlgorithm,
        f: impl FnOnce(&mut CertificateParams),
    ) -> (Vec<u8>, KeyPair) {
        let key = KeyPair::generate_for(alg).unwrap();
        (self.leaf_for(&key, f), key)
    }

    pub(crate) fn leaf_for(
        &self,
        key: &KeyPair,
        f: impl FnOnce(&mut CertificateParams),
    ) -> Vec<u8> {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "Test Leaf");
        f(&mut params);
        params.signed_by(key, &self.issuer).unwrap().der().to_vec()
    }
}

pub(crate) fn b64_std(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk.first().copied().unwrap_or(0),
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                let idx = usize::try_from((n >> (18 - 6 * i)) & 0x3f).unwrap();
                out.push(char::from(ALPHABET[idx]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

pub(crate) fn tlv(tag: &[u8], content: &[u8]) -> Vec<u8> {
    let mut out = tag.to_vec();
    let n = content.len();
    if n < 0x80 {
        out.push(u8::try_from(n).unwrap());
    } else if n < 0x100 {
        out.extend([0x81, u8::try_from(n).unwrap()]);
    } else {
        out.extend([
            0x82,
            u8::try_from(n >> 8).unwrap(),
            u8::try_from(n & 0xff).unwrap(),
        ]);
    }
    out.extend_from_slice(content);
    out
}

pub(crate) fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(&[0x30], &parts.concat())
}
