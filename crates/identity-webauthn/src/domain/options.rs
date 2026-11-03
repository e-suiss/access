//! `PublicKeyCredentialCreationOptions` and `PublicKeyCredentialRequestOptions` in their JSON
//! form (WebAuthn L3 `parseCreationOptionsFromJSON` / `parseRequestOptionsFromJSON`).

use access_kernel::json::b64url_encode;
use serde_json::{Value, json};

use super::ids::{CredentialId, UserHandle};
use super::policy::RealmPolicy;
use super::prf::PrfConfig;
use super::rp::RelyingParty;

/// A credential reference for `excludeCredentials` / `allowCredentials`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialDescriptor {
    /// Credential ID.
    pub id: CredentialId,
    /// Transport hints.
    pub transports: Vec<String>,
}

fn descriptors(list: &[CredentialDescriptor]) -> Value {
    Value::Array(
        list.iter()
            .map(|d| {
                json!({
                    "type": "public-key",
                    "id": b64url_encode(d.id.as_bytes()),
                    "transports": d.transports,
                })
            })
            .collect(),
    )
}

/// The account the credential is created for.
pub struct UserEntity<'a> {
    /// `user.id`.
    pub handle: &'a UserHandle,
    /// `user.name`.
    pub name: &'a str,
    /// `user.displayName`.
    pub display_name: &'a str,
}

/// Creation options. A conditional create requests no attestation (§10.2.4); `credProps` and
/// `credProtect` level 2 are always requested; `prf` evaluates the salt when one is given.
#[must_use]
pub fn creation_options(
    rp: &RelyingParty,
    policy: &RealmPolicy,
    user: &UserEntity<'_>,
    challenge: &[u8],
    exclude: &[CredentialDescriptor],
    conditional: bool,
    prf: Option<&PrfConfig>,
) -> Value {
    let params: Vec<Value> = policy
        .algorithms()
        .into_iter()
        .map(|a| json!({ "type": "public-key", "alg": a.id() }))
        .collect();
    let attestation = if conditional {
        "none"
    } else {
        policy.attestation.conveyance()
    };
    let mut extensions = json!({
        "credProps": true,
        "credentialProtectionPolicy": "userVerificationOptionalWithCredentialIDList",
        "enforceCredentialProtectionPolicy": false,
    });
    if let (Some(prf), Some(map)) = (prf, extensions.as_object_mut()) {
        map.insert(
            "prf".into(),
            json!({ "eval": { "first": b64url_encode(&prf.first.0) } }),
        );
    }
    let ttl_ms = policy.ceremony_ttl.saturating_mul(1000);
    json!({
        "rp": { "id": rp.rp_id.as_str(), "name": rp.name },
        "user": {
            "id": b64url_encode(user.handle.as_bytes()),
            "name": user.name,
            "displayName": user.display_name,
        },
        "challenge": b64url_encode(challenge),
        "pubKeyCredParams": params,
        "timeout": ttl_ms,
        "excludeCredentials": descriptors(exclude),
        "authenticatorSelection": {
            "residentKey": "preferred",
            "userVerification": policy.user_verification.as_str(),
        },
        "attestation": attestation,
        "extensions": extensions,
    })
}

/// Request options. An empty `allow` is the discoverable-credential path that reveals no
/// identifier (TN-96, TN-97).
#[must_use]
pub fn request_options(
    rp: &RelyingParty,
    policy: &RealmPolicy,
    challenge: &[u8],
    allow: &[CredentialDescriptor],
) -> Value {
    json!({
        "challenge": b64url_encode(challenge),
        "rpId": rp.rp_id.as_str(),
        "allowCredentials": descriptors(allow),
        "userVerification": policy.user_verification.as_str(),
        "timeout": policy.ceremony_ttl.saturating_mul(1000),
    })
}
