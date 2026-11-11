//! The realm issuer as an OpenID Federation leaf (OP-155 m.3 (j), IDP-19, §10.7.1 rule 1): its
//! entity configuration at `/.well-known/openid-federation`, signed with the realm's
//! `federation` key and never with its token key. A leaf serves no fetch or list; the
//! intermediate or trust anchor endpoints are announced only while that role is on.

use access_identity_oidf::build::{self, Configuration};
use access_kernel::json::{self, Json};

use super::Discovery;
use crate::domain::metadata;
use crate::ports::{Directory, Keys, RealmEntry, Unavailable};

/// How long an entity configuration is valid (PD, 24 hours).
pub const CONFIGURATION_TTL_MS: u64 = 24 * 3_600_000;

/// The endpoints of the intermediate or trust anchor role, below the issuer.
pub const AUTHORITY_ENDPOINTS: [(&str, &str); 4] = [
    ("federation_fetch_endpoint", "/federation/fetch"),
    ("federation_list_endpoint", "/federation/list"),
    ("federation_resolve_endpoint", "/federation/resolve"),
    (
        "federation_trust_mark_status_endpoint",
        "/federation/trust_mark_status",
    ),
];

/// The explicit registration endpoint, below the issuer.
pub const REGISTRATION_PATH: &str = "/federation/register";

/// Largest JSON document read back from the signer or the metadata builder.
const MAX_DOC: usize = 1 << 20;

/// What a request for the entity configuration gets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OidfReply {
    /// The signed entity configuration, `application/entity-statement+jwt`.
    Statement(String),
    /// A JSON list of entity identifiers, `application/json`.
    List(String),
    /// No realm here, or the realm is not a federation leaf.
    NotFound,
    /// A fetch about the issuer itself (OIDF §8.1.1): `invalid_request`.
    InvalidRequest,
    /// The directory or the signer did not answer (fail-closed).
    Unavailable,
}

fn member(m: &mut Vec<(String, Json)>, k: &str, v: Json) {
    m.retain(|(n, _)| n != k);
    m.push((String::from(k), v));
}

impl<D: Directory, K: Keys> Discovery<D, K> {
    /// The realm issuer's entity configuration at `now_ms` for a request to `authority`, with
    /// `slug` from a path-issuer route.
    pub async fn entity_configuration(
        &self,
        authority: &str,
        slug: Option<&str>,
        now_ms: u64,
    ) -> OidfReply {
        match self.configuration(authority, slug, now_ms).await {
            Ok(Some(s)) => OidfReply::Statement(s),
            Ok(None) => OidfReply::NotFound,
            Err(Unavailable) => OidfReply::Unavailable,
        }
    }

    async fn configuration(
        &self,
        authority: &str,
        slug: Option<&str>,
        now_ms: u64,
    ) -> Result<Option<String>, Unavailable> {
        let Some(realm) = self.resolve(authority, slug).await? else {
            return Ok(None);
        };
        // OP-155 m.3 (j)
        let Some(fed) = self
            .directory
            .federation(&realm)
            .await?
            .filter(|f| f.enabled)
        else {
            return Ok(None);
        };
        let facts = self.directory.facts(&realm).await?;
        let op = metadata::authorization_server_of(
            &realm.issuer,
            &self.served,
            &metadata::RealmFacts {
                public_sub: facts.public_sub_clients > 0,
                domain_metadata: None,
                cimd: facts.cimd,
                dcr: facts.dcr,
                device_code: facts.device_code,
                ciba: facts.ciba,
                mtls_port: self.mtls_port.filter(|_| facts.mtls_aliases),
                frontchannel: facts.frontchannel,
                secret_post: facts.secret_post,
                secret_jwt: facts.secret_jwt,
            },
        );
        let Ok(Json::Object(mut op)) = json::parse(op.as_bytes(), MAX_DOC) else {
            return Err(Unavailable);
        };
        if fed.registration_open {
            member(
                &mut op,
                "client_registration_types_supported",
                Json::Array(vec![
                    Json::Str(String::from("automatic")),
                    Json::Str(String::from("explicit")),
                ]),
            );
            member(
                &mut op,
                "federation_registration_endpoint",
                Json::Str(realm.issuer.endpoint(REGISTRATION_PATH)),
            );
        }
        let mut entity = Vec::new();
        if fed.ta_enabled {
            for (name, path) in AUTHORITY_ENDPOINTS {
                entity.push((String::from(name), Json::Str(realm.issuer.endpoint(path))));
            }
        }
        let metadata = Json::Object(vec![
            (String::from("federation_entity"), Json::Object(entity)),
            (String::from("openid_provider"), Json::Object(op)),
        ]);
        let jwks_doc = self.keys.federation_jwks(realm.realm).await?;
        let jwks = json::parse(jwks_doc.as_bytes(), MAX_DOC).map_err(|_| Unavailable)?;
        let payload = build::configuration(&Configuration {
            entity_id: realm.issuer.as_str(),
            iat_ms: now_ms,
            exp_ms: now_ms.saturating_add(CONFIGURATION_TTL_MS),
            jwks: &jwks,
            authority_hints: &fed.authority_hints,
            metadata: &metadata,
            trust_marks: &[],
            trust_mark_issuers: None,
        })
        .map_err(|_| Unavailable)?;
        let token = self
            .keys
            .sign_federation(
                realm.realm,
                access_identity_oidf::statement::ENTITY_TYP,
                payload.as_bytes(),
                now_ms,
            )
            .await?;
        Ok(Some(token))
    }

    /// The subordinates the realm's intermediate or trust anchor role vouches for; `None` while
    /// the role is off (a leaf serves no fetch or list, §10.7.1 rule 1).
    async fn subordinates(
        &self,
        authority: &str,
        slug: Option<&str>,
    ) -> Result<Option<(RealmEntry, Vec<(String, Json, Option<Json>)>)>, Unavailable> {
        let Some(realm) = self.resolve(authority, slug).await? else {
            return Ok(None);
        };
        let Some(fed) = self
            .directory
            .federation(&realm)
            .await?
            .filter(|f| f.enabled && f.ta_enabled)
        else {
            return Ok(None);
        };
        let Ok(Json::Array(list)) = json::parse(&fed.subordinates, MAX_DOC) else {
            return Err(Unavailable);
        };
        let subs = list
            .into_iter()
            .filter_map(|s| {
                let id = s.get("entity_id")?.as_str()?.to_owned();
                let jwks = s.get("jwks")?.clone();
                Some((id, jwks, s.get("metadata_policy").cloned()))
            })
            .collect();
        Ok(Some((realm, subs)))
    }

    /// The list endpoint of the intermediate or trust anchor role (OIDF §8.2): the entity
    /// identifiers of its subordinates, as JSON.
    pub async fn federation_list(&self, authority: &str, slug: Option<&str>) -> OidfReply {
        match self.subordinates(authority, slug).await {
            Ok(Some((_, subs))) => {
                let ids: Vec<String> = subs.into_iter().map(|(id, _, _)| id).collect();
                OidfReply::List(build::list_response(&ids))
            }
            Ok(None) => OidfReply::NotFound,
            Err(Unavailable) => OidfReply::Unavailable,
        }
    }

    /// The fetch endpoint of the intermediate or trust anchor role (OIDF §8.1): its subordinate
    /// statement about `sub`, signed with the realm's `federation` key at `now_ms`.
    pub async fn federation_fetch(
        &self,
        authority: &str,
        slug: Option<&str>,
        sub: &str,
        now_ms: u64,
    ) -> OidfReply {
        let found = match self.subordinates(authority, slug).await {
            Ok(Some((realm, _))) if realm.issuer.as_str() == sub => {
                return OidfReply::InvalidRequest;
            }
            Ok(Some((realm, subs))) => subs
                .into_iter()
                .find(|(id, _, _)| id == sub)
                .map(|s| (realm, s)),
            Ok(None) => None,
            Err(Unavailable) => return OidfReply::Unavailable,
        };
        let Some((realm, (id, jwks, policy))) = found else {
            return OidfReply::NotFound;
        };
        let Ok(payload) = build::subordinate(&build::Subordinate {
            iss: realm.issuer.as_str(),
            sub: &id,
            iat_ms: now_ms,
            exp_ms: now_ms.saturating_add(CONFIGURATION_TTL_MS),
            jwks: &jwks,
            metadata_policy: policy.as_ref(),
            metadata: None,
            max_path_length: None,
        }) else {
            return OidfReply::Unavailable;
        };
        self.keys
            .sign_federation(
                realm.realm,
                access_identity_oidf::statement::ENTITY_TYP,
                payload.as_bytes(),
                now_ms,
            )
            .await
            .map_or(OidfReply::Unavailable, OidfReply::Statement)
    }
}
