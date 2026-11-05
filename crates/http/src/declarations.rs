//! The provider's declarations about its keys (SI-13, CR-18, CR-22, CR-30, RT12, T31,
//! OP-150 m.3 (e)), served as `/.well-known/access-provider-declarations`: custody, the binding
//! key's scope, the KMS/HSM quota and its sharing, HSM partition sharing and the identity plane's
//! own KMS. What the code fixes (custody, binding key scope, quota use, identity KMS) is not
//! configurable; what depends on the operator's infrastructure is the operator's statement, and
//! `null` while it has not made one.

use axum::Router;
use axum::http::{HeaderValue, header};
use axum::response::IntoResponse;
use axum::routing::get;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// The document's path.
pub const PATH: &str = "/.well-known/access-provider-declarations";

/// The document's version.
pub const VERSION: u8 = 1;

/// Whether keys are held for parties (SI-13, SEC17): Access has no custodial mode; Instance keys
/// are held by their parties (OP-149 m.16, OP-150 m.3 (e)).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Custody {
    /// No custodial key exists.
    #[default]
    None,
}

/// What one provider binding key covers (CR-18, MD-6): the authority signer makes one binding
/// key per domain in its token; a provider-wide binding key is not implemented.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BindingScope {
    /// One binding key per domain.
    #[default]
    Domain,
}

/// How the signers spend the KMS/HSM quota (CR-22).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum QuotaUse {
    /// The signer profile: key generation and unwrap only, never per signature.
    #[default]
    PerKeyOperation,
}

/// The KMS/HSM quota (CR-22, HL-20).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Kms {
    /// What a quota unit buys.
    pub quota_use: QuotaUse,
    /// Operations per second the KMS/HSM grants, as the operator declares it.
    pub quota_per_second: Option<u32>,
    /// Whether the quota is shared with other domains or tenants (HL-20).
    pub shared: Option<bool>,
}

/// Which key store the identity plane uses (T31, CR-32).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IdentityKms {
    /// Its own token and KEK, apart from the authority plane's.
    #[default]
    Separate,
}

/// The declarations document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Declarations {
    /// Document version.
    pub version: u8,
    /// Custodial key use.
    pub custody: Custody,
    /// The binding key's scope.
    pub binding_key_scope: BindingScope,
    /// The KMS/HSM quota.
    pub kms: Kms,
    /// Whether the HSM partition is shared with other domains or providers (CR-30, RT12).
    pub hsm_partition_shared: Option<bool>,
    /// The identity plane's key store.
    pub identity_kms: IdentityKms,
}

/// What the operator states about its infrastructure.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stated {
    /// KMS/HSM operations per second.
    pub kms_quota_per_second: Option<u32>,
    /// Whether the KMS quota is shared.
    pub kms_shared: Option<bool>,
    /// Whether the HSM partition is shared.
    pub hsm_partition_shared: Option<bool>,
}

impl Declarations {
    /// The document for what the operator `stated`; the rest is fixed by the code.
    #[must_use]
    pub fn of(stated: Stated) -> Self {
        Self {
            version: VERSION,
            custody: Custody::None,
            binding_key_scope: BindingScope::Domain,
            kms: Kms {
                quota_use: QuotaUse::PerKeyOperation,
                quota_per_second: stated.kms_quota_per_second,
                shared: stated.kms_shared,
            },
            hsm_partition_shared: stated.hsm_partition_shared,
            identity_kms: IdentityKms::Separate,
        }
    }
}

/// The route serving `declarations`.
pub fn router(declarations: &Declarations) -> Router {
    let body = serde_json::to_vec(declarations).unwrap_or_default();
    Router::new().route(
        PATH,
        get(move || {
            let body = body.clone();
            async move {
                (
                    [
                        (
                            header::CONTENT_TYPE,
                            HeaderValue::from_static("application/json"),
                        ),
                        (
                            header::CACHE_CONTROL,
                            HeaderValue::from_static("max-age=3600"),
                        ),
                    ],
                    body,
                )
                    .into_response()
            }
        }),
    )
}

/// The `OpenAPI` path entry of the document (OP-65).
#[must_use]
pub fn openapi_path() -> Value {
    json!({ "get": {
        "operationId": "getProviderDeclarations",
        "summary": "What the provider declares about its keys: no custody, the binding key's scope, the KMS/HSM quota and its sharing, HSM partition sharing and the identity plane's own KMS (SI-13, CR-18, CR-22, CR-30, T31, OP-150 m.3 (e)). `Cache-Control: max-age=3600`.",
        "security": [],
        "responses": { "200": {
            "description": "The declarations.",
            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ProviderDeclarations" } } },
        }},
    }})
}

/// The `OpenAPI` schemas of the document.
#[must_use]
pub fn openapi_components() -> Value {
    let flag = |d: &str| json!({ "type": ["boolean", "null"], "description": d });
    json!({
        "ProviderDeclarations": {
            "type": "object",
            "additionalProperties": false,
            "required": ["version", "custody", "binding_key_scope", "kms", "hsm_partition_shared", "identity_kms"],
            "properties": {
                "version": { "const": VERSION },
                "custody": { "enum": ["none"], "description": "No custodial key exists (SI-13, OP-150 m.3 (e))." },
                "binding_key_scope": { "enum": ["domain"], "description": "One binding key per domain (CR-18, MD-6)." },
                "kms": { "$ref": "#/components/schemas/ProviderKms" },
                "hsm_partition_shared": flag("Whether the HSM partition is shared (CR-30, RT12); null while undeclared."),
                "identity_kms": { "enum": ["separate"], "description": "The identity plane has its own token and KEK (T31)." },
            },
        },
        "ProviderKms": {
            "type": "object",
            "additionalProperties": false,
            "required": ["quota_use", "quota_per_second", "shared"],
            "properties": {
                "quota_use": { "enum": ["per-key-operation"], "description": "The signers spend the quota on key generation and unwrap, never per signature (CR-22)." },
                "quota_per_second": { "type": ["integer", "null"], "minimum": 0, "description": "Operations per second the KMS/HSM grants; null while undeclared." },
                "shared": flag("Whether the quota is shared with other domains or tenants (HL-20); null while undeclared."),
            },
        },
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // SI-13, OP-150, CR-22, CR-30, T31: custody is declared "none" and the identity plane's KMS
    // "separate" whatever the operator states; undeclared infrastructure facts stay null; the
    // document matches the committed example
    #[test]
    fn the_declarations_match_the_example() {
        let unstated = serde_json::to_value(Declarations::of(Stated::default())).unwrap();
        assert_eq!(unstated["custody"], "none");
        assert_eq!(unstated["identity_kms"], "separate");
        assert_eq!(unstated["kms"]["quota_use"], "per-key-operation");
        assert_eq!(unstated["binding_key_scope"], "domain");
        assert!(unstated["hsm_partition_shared"].is_null());
        let example: Declarations = serde_json::from_str(include_str!(
            "../../../sdks/openapi/examples/access-v1/provider-declarations.json"
        ))
        .unwrap();
        assert_eq!(
            example,
            Declarations::of(Stated {
                kms_quota_per_second: Some(100),
                kms_shared: Some(false),
                hsm_partition_shared: Some(false),
            })
        );
        assert!(
            serde_json::from_str::<Declarations>(
                &include_str!(
                    "../../../sdks/openapi/examples/access-v1/provider-declarations.json"
                )
                .replace("\"none\"", "\"user-gated\"")
            )
            .is_err()
        );
    }
}
