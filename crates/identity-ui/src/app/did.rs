//! The `did:web` document of a person or an agent (OP-154 m.3 (aa), E56, MD-10): the keys of
//! the Party's live Instances in the realm's governing domain as verification methods. The DID
//! is an identifier, never authority; an RP's `sub` stays pairwise. Only a Party this realm
//! binds is served: an active person's account or a registered agent that is not retired.

use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::verify::cose::PublicKey;
use access_kernel::verify::key_scope::thumbprint;
use access_store::identity::TenantTx;
use serde_json::{Value, json};

use super::me::{governing, unavailable};
use super::{Hosted, Reply};
use crate::ports::{Clock, Kits, Messages, PartyKeys};

/// The DID of `party` under `issuer` (`did:web:<host>[:<path>]:u:<party>`): the host's port is
/// percent-encoded and each path segment is one DID segment, so the DID resolves to
/// `<issuer>/u/<party>/did.json`. `None` for an issuer that is not `https`.
#[must_use]
pub fn did_of(issuer: &str, party: &[u8; 16]) -> Option<String> {
    let rest = issuer.strip_prefix("https://")?.trim_end_matches('/');
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    if host.is_empty() {
        return None;
    }
    let mut did = format!("did:web:{}", host.replace(':', "%3A"));
    for seg in path.split('/').filter(|s| !s.is_empty()) {
        did.push(':');
        did.push_str(seg);
    }
    did.push_str(":u:");
    did.push_str(&b64url_encode(party));
    Some(did)
}

/// The document of `did` with `keys` as its verification methods: `JsonWebKey2020`, each
/// named by its RFC 7638 thumbprint, for authentication and assertion. No service endpoint is
/// published.
#[must_use]
pub fn document(did: &str, keys: &[PublicKey]) -> Value {
    let mut methods = Vec::with_capacity(keys.len());
    let mut refs = Vec::with_capacity(keys.len());
    for k in keys {
        let kid = thumbprint(k);
        let Ok(jwk) = access_crypto::jose::public_jwk(&kid, k) else {
            continue;
        };
        let Ok(mut jwk) = serde_json::from_str::<Value>(&jwk) else {
            continue;
        };
        if let Some(o) = jwk.as_object_mut() {
            o.remove("use");
        }
        let id = format!("{did}#{}", b64url_encode(&kid));
        if refs.contains(&Value::String(id.clone())) {
            continue;
        }
        methods.push(json!({
            "id": id,
            "type": "JsonWebKey2020",
            "controller": did,
            "publicKeyJwk": jwk,
        }));
        refs.push(Value::String(id));
    }
    json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ],
        "id": did,
        "verificationMethod": methods,
        "authentication": refs,
        "assertionMethod": refs,
    })
}

fn not_found() -> Reply {
    Reply::problem(access_identity_account::domain::login::Problem {
        status: 404,
        code: "not-found",
        title: "Not Found",
        retry_after_s: None,
    })
}

impl<K: Kits, C: Clock + Sync, M: Messages> Hosted<K, C, M> {
    /// `GET /u/{party}/did.json` (OP-154 m.3 (aa)): the document of a Party this realm binds;
    /// any other Party is `404`, the same for one that never existed.
    pub async fn did_document<P: PartyKeys>(
        &self,
        entry: &access_identity_oauth::ports::RealmEntry,
        party: &str,
        keys: &P,
    ) -> Reply {
        let Some(party) = b64url_decode(party)
            .ok()
            .and_then(|b| <[u8; 16]>::try_from(b).ok())
        else {
            return not_found();
        };
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let Some(did) = did_of(&kit.issuer, &party) else {
            return not_found();
        };
        let Ok(mut t) = TenantTx::begin(&self.db, kit.tenant, kit.realm).await else {
            return unavailable();
        };
        let bound = match t.agent(party).await {
            Ok(Some(a)) => a.status != "retired",
            Ok(None) => match access_store::idp::party_subject(&mut t, &party).await {
                Ok(Some(s)) => match t.subject(s, false).await {
                    Ok(row) => row.is_some_and(|r| r.status == "active"),
                    Err(_) => return unavailable(),
                },
                Ok(None) => false,
                Err(_) => return unavailable(),
            },
            Err(_) => return unavailable(),
        };
        if t.commit().await.is_err() {
            return unavailable();
        }
        if !bound {
            return not_found();
        }
        let domain = match governing(&self.db, &kit).await {
            Ok(d) => d,
            Err(r) => return r,
        };
        let mut doc = match keys.live_keys(domain, party).await {
            Ok(list) => document(&did, &list),
            Err(_) => return unavailable(),
        };
        // E56 (2), OP-156 m.4 Q20
        let handles = match self.shown_handles(&kit, party).await {
            Ok(h) => h,
            Err(r) => return r,
        };
        if let (false, Some(m)) = (handles.is_empty(), doc.as_object_mut()) {
            m.insert(String::from("alsoKnownAs"), json!(handles));
        }
        Reply::json(200, doc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_did_resolves_to_the_route_under_the_issuer() {
        let p = [7; 16];
        let id = b64url_encode(&p);
        assert_eq!(
            did_of("https://access.test/realms/acme", &p).unwrap(),
            format!("did:web:access.test:realms:acme:u:{id}")
        );
        assert_eq!(
            did_of("https://acme.example:8443/", &p).unwrap(),
            format!("did:web:acme.example%3A8443:u:{id}")
        );
        assert!(did_of("http://acme.example", &p).is_none());
    }

    #[test]
    fn a_document_names_each_key_once_and_grants_nothing() {
        let key = PublicKey::Ed25519([3; 32]);
        let d = document("did:web:a.test:u:x", &[key.clone(), key]);
        assert_eq!(d["verificationMethod"].as_array().unwrap().len(), 1);
        assert_eq!(d["authentication"], d["assertionMethod"]);
        assert!(d.get("service").is_none());
        assert!(
            d["verificationMethod"][0]["publicKeyJwk"]
                .get("d")
                .is_none()
        );
    }
}
