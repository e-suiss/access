//! W3C VC Data Model 2.0 (Ek B 4828; OP-155 m.3 (p)): a VC is only a carrier of Claim input,
//! and only one secured as VC-JOSE-COSE is read. An embedded `proof` (Data Integrity) is
//! refused without looking at it: there is no JSON-LD canonicalization here. A presentation
//! format the verifier does not profile (`ldp_vc`, `jwt_vc_json`) is refused by DCQL.

use access_kernel::json::Json;

/// The VC Data Model 2.0 base context.
pub const CONTEXT_V2: &str = "https://www.w3.org/ns/credentials/v2";

/// Why a W3C VC is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum W3cError {
    /// A Data Integrity `proof`: refused (no JSON-LD canonicalization).
    #[error("vc-data-integrity-refused")]
    DataIntegrity,
    /// Not a VC Data Model 2.0 credential.
    #[error("vc-malformed")]
    Malformed,
}

/// Whether `types` (a string or an array of strings) names `wanted`.
#[must_use]
pub fn has_type(types: &Json, wanted: &str) -> bool {
    match types {
        Json::Str(t) => t == wanted,
        Json::Array(items) => items.iter().any(|t| t.as_str() == Some(wanted)),
        _ => false,
    }
}

/// Checks that `vc`, the payload of a VC-JOSE `vc+jwt`, is a VC Data Model 2.0 credential with
/// no embedded proof.
///
/// # Errors
/// [`W3cError`].
pub fn secured_by_jose(vc: &Json) -> Result<(), W3cError> {
    if vc.get("proof").is_some() {
        return Err(W3cError::DataIntegrity);
    }
    let first = match vc.get("@context") {
        Some(Json::Array(items)) => items.first().and_then(Json::as_str),
        _ => None,
    };
    if first != Some(CONTEXT_V2)
        || !vc
            .get("type")
            .is_some_and(|t| has_type(t, "VerifiableCredential"))
    {
        return Err(W3cError::Malformed);
    }
    Ok(())
}
