//! Federations built at run time for other crates' tests: P-256 keys generated, statements
//! signed, nothing committed (gitleaks-clean fixtures).

use access_kernel::json::{Json, b64url_encode};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

use crate::build::{self, Configuration, Subordinate};
use crate::chain::TrustAnchor;
use crate::statement::{ENTITY_TYP, Jwk, parse_jwks};

/// A generated P-256 signing key with its `kid`.
pub struct Key {
    pair: EcdsaKeyPair,
    /// Its `kid`.
    pub kid: String,
}

impl Key {
    /// A new key; `None` when the generator fails.
    #[must_use]
    pub fn new(kid: &str) -> Option<Self> {
        Some(Self {
            pair: EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).ok()?,
            kid: String::from(kid),
        })
    }

    /// Its public JWKS.
    #[must_use]
    pub fn jwks(&self) -> Json {
        build::jwks_json(&[(self.kid.clone(), self.pair.public_key().as_ref().to_vec())])
            .unwrap_or(Json::Null)
    }

    /// Its public keys.
    #[must_use]
    pub fn keys(&self) -> Vec<Jwk> {
        parse_jwks(&self.jwks()).unwrap_or_default()
    }

    /// A compact ES256 JWS of `payload` with the protected header `{"alg","kid","typ"}`.
    #[must_use]
    pub fn sign(&self, typ: &str, payload: &str) -> String {
        let header = format!(r#"{{"alg":"ES256","kid":"{}","typ":"{typ}"}}"#, self.kid);
        let input = format!(
            "{}.{}",
            b64url_encode(header.as_bytes()),
            b64url_encode(payload.as_bytes())
        );
        let sig = self
            .pair
            .sign(&SystemRandom::new(), input.as_bytes())
            .map(|s| b64url_encode(s.as_ref()))
            .unwrap_or_default();
        format!("{input}.{sig}")
    }
}

/// A federation entity with its key.
pub struct Entity {
    /// Its entity identifier.
    pub id: String,
    /// Its federation key.
    pub key: Key,
}

impl Entity {
    /// A new entity; `None` when the key generator fails.
    #[must_use]
    pub fn new(id: &str) -> Option<Self> {
        Some(Self {
            id: String::from(id),
            key: Key::new(&format!("k-{}", id.trim_start_matches("https://")))?,
        })
    }

    /// Its signed entity configuration valid over `[iat_ms, exp_ms]`.
    #[must_use]
    pub fn config(&self, hints: &[&str], metadata: &Json, iat_ms: u64, exp_ms: u64) -> String {
        let hints: Vec<String> = hints.iter().map(|h| String::from(*h)).collect();
        build::configuration(&Configuration {
            entity_id: &self.id,
            iat_ms,
            exp_ms,
            jwks: &self.key.jwks(),
            authority_hints: &hints,
            metadata,
            trust_marks: &[],
            trust_mark_issuers: None,
        })
        .map(|p| self.key.sign(ENTITY_TYP, &p))
        .unwrap_or_default()
    }

    /// Its signed subordinate statement about `sub` with `policy`.
    #[must_use]
    pub fn about(&self, sub: &Self, policy: Option<&Json>, iat_ms: u64, exp_ms: u64) -> String {
        build::subordinate(&Subordinate {
            iss: &self.id,
            sub: &sub.id,
            iat_ms,
            exp_ms,
            jwks: &sub.key.jwks(),
            metadata_policy: policy,
            metadata: None,
            max_path_length: None,
        })
        .map(|p| self.key.sign(ENTITY_TYP, &p))
        .unwrap_or_default()
    }

    /// It as a trust anchor with pinned keys.
    #[must_use]
    pub fn anchor(&self) -> TrustAnchor {
        TrustAnchor {
            entity_id: self.id.clone(),
            jwks: self.key.keys(),
        }
    }

    /// Its `federation_fetch_endpoint`.
    #[must_use]
    pub fn fetch_endpoint(&self) -> String {
        format!("{}/fetch", self.id)
    }
}
