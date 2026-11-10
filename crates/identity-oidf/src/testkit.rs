//! Test federations built at run time: keys generated, statements signed, nothing committed.

use access_kernel::json::{self, Json, b64url_encode};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

use crate::build::{self, Configuration, Subordinate};
use crate::chain::TrustAnchor;
use crate::statement::{ENTITY_TYP, Jwk, MarkRef, parse_jwks};

pub(crate) const NOW: u64 = 1_800_000_000_000;
pub(crate) const HOUR: u64 = 3_600_000;
pub(crate) const TA: &str = "https://ta.example";
pub(crate) const INT: &str = "https://int.example";
pub(crate) const LEAF: &str = "https://rp.example";

pub(crate) fn j(s: &str) -> Json {
    json::parse(s.as_bytes(), 1 << 20).unwrap()
}

pub(crate) struct Key {
    pair: EcdsaKeyPair,
    pub(crate) kid: String,
}

impl Key {
    pub(crate) fn new(kid: &str) -> Self {
        Self {
            pair: EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap(),
            kid: String::from(kid),
        }
    }

    pub(crate) fn jwks(&self) -> Json {
        build::jwks_json(&[(self.kid.clone(), self.pair.public_key().as_ref().to_vec())]).unwrap()
    }

    pub(crate) fn keys(&self) -> Vec<Jwk> {
        parse_jwks(&self.jwks()).unwrap()
    }

    pub(crate) fn sign_header(&self, header: &str, payload: &str) -> String {
        let input = format!(
            "{}.{}",
            b64url_encode(header.as_bytes()),
            b64url_encode(payload.as_bytes())
        );
        let sig = self
            .pair
            .sign(&SystemRandom::new(), input.as_bytes())
            .unwrap();
        format!("{input}.{}", b64url_encode(sig.as_ref()))
    }

    pub(crate) fn sign(&self, typ: &str, payload: &str) -> String {
        self.sign_header(
            &format!(r#"{{"alg":"ES256","kid":"{}","typ":"{typ}"}}"#, self.kid),
            payload,
        )
    }
}

pub(crate) struct Entity {
    pub(crate) id: String,
    pub(crate) key: Key,
}

impl Entity {
    pub(crate) fn new(id: &str) -> Self {
        Self {
            id: String::from(id),
            key: Key::new(&format!("k-{}", id.trim_start_matches("https://"))),
        }
    }

    pub(crate) fn fetch_endpoint(&self) -> String {
        format!("{}/fetch", self.id)
    }

    pub(crate) fn config(&self, hints: &[&str], metadata: &Json, marks: &[MarkRef]) -> String {
        self.config_until(hints, metadata, marks, NOW.saturating_add(HOUR), None)
    }

    pub(crate) fn config_until(
        &self,
        hints: &[&str],
        metadata: &Json,
        marks: &[MarkRef],
        exp_ms: u64,
        issuers: Option<&Json>,
    ) -> String {
        let hints: Vec<String> = hints.iter().map(|h| String::from(*h)).collect();
        let payload = build::configuration(&Configuration {
            entity_id: &self.id,
            iat_ms: NOW.saturating_sub(1000),
            exp_ms,
            jwks: &self.key.jwks(),
            authority_hints: &hints,
            metadata,
            trust_marks: marks,
            trust_mark_issuers: issuers,
        })
        .unwrap();
        self.key.sign(ENTITY_TYP, &payload)
    }

    pub(crate) fn about(&self, sub: &Entity, policy: Option<&Json>, exp_ms: u64) -> String {
        let payload = build::subordinate(&Subordinate {
            iss: &self.id,
            sub: &sub.id,
            iat_ms: NOW.saturating_sub(1000).min(exp_ms.saturating_sub(1000)),
            exp_ms,
            jwks: &sub.key.jwks(),
            metadata_policy: policy,
            metadata: None,
            max_path_length: None,
        })
        .unwrap();
        self.key.sign(ENTITY_TYP, &payload)
    }

    pub(crate) fn anchor(&self) -> TrustAnchor {
        TrustAnchor {
            entity_id: self.id.clone(),
            jwks: self.key.keys(),
        }
    }

    pub(crate) fn federation_metadata(&self) -> Json {
        j(&format!(
            r#"{{"federation_entity":{{"federation_fetch_endpoint":"{}"}}}}"#,
            self.fetch_endpoint()
        ))
    }
}

pub(crate) fn rp_metadata() -> Json {
    j(
        r#"{"openid_relying_party":{"client_name":"RP","redirect_uris":["https://rp.example/cb"],"grant_types":["authorization_code","refresh_token"],"token_endpoint_auth_method":"private_key_jwt"}}"#,
    )
}

/// TA → intermediate → leaf.
pub(crate) struct Fed {
    pub(crate) ta: Entity,
    pub(crate) int: Entity,
    pub(crate) leaf: Entity,
}

impl Fed {
    pub(crate) fn new() -> Self {
        Self {
            ta: Entity::new(TA),
            int: Entity::new(INT),
            leaf: Entity::new(LEAF),
        }
    }

    pub(crate) fn anchors(&self) -> Vec<TrustAnchor> {
        vec![self.ta.anchor()]
    }

    pub(crate) fn leaf_ec(&self) -> String {
        self.leaf.config(&[INT], &rp_metadata(), &[])
    }

    pub(crate) fn ta_ec(&self) -> String {
        self.ta.config(&[], &self.ta.federation_metadata(), &[])
    }

    pub(crate) fn chain_with(
        &self,
        ta_policy: Option<&Json>,
        int_policy: Option<&Json>,
    ) -> Vec<String> {
        let exp = NOW.saturating_add(HOUR);
        vec![
            self.leaf_ec(),
            self.int.about(&self.leaf, int_policy, exp),
            self.ta.about(&self.int, ta_policy, exp),
            self.ta_ec(),
        ]
    }

    pub(crate) fn chain(&self) -> Vec<String> {
        self.chain_with(None, None)
    }
}

pub(crate) fn refs(v: &[String]) -> Vec<&str> {
    v.iter().map(String::as_str).collect()
}
