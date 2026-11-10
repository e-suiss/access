//! The wallet response against its request (OID4VP 1.0 §8; Ek B 4833, 4982): the decrypted
//! parameters carry the request's `state` and a `vp_token` with exactly one presentation for
//! every credential query and nothing else; a presentation discloses only what its query asks
//! for, and every asked claim is there.

use access_kernel::json::Json;
use serde_json::Value;

use super::dcql::{CredentialQuery, Path, Query, Step, minimal};
use super::sd_jwt_vc::lookup;

/// Why a response does not answer its request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AnswerError {
    /// Not the parameters of an OID4VP response, or another request's `state`.
    #[error("response-malformed")]
    Malformed,
    /// The wallet answered with an error.
    #[error("wallet-declined")]
    Declined,
    /// A presentation for a query not asked, or a query without one.
    #[error("dcql-unanswered")]
    Unanswered,
    /// A disclosure nobody asked for (Ek B 4982).
    #[error("dcql-extra-disclosure")]
    Extra,
    /// An asked claim is missing.
    #[error("dcql-claim-missing")]
    Missing,
    /// The credential is not of an asked type.
    #[error("dcql-type")]
    Type,
}

impl AnswerError {
    /// Stable code.
    #[must_use]
    pub fn code(self) -> String {
        self.to_string()
    }
}

/// The presentation for each credential query, in query order.
///
/// # Errors
/// [`AnswerError`].
pub fn presentations(
    params: &[u8],
    query: &Query,
    state: &str,
) -> Result<Vec<String>, AnswerError> {
    let v: Value = serde_json::from_slice(params).map_err(|_| AnswerError::Malformed)?;
    let o = v.as_object().ok_or(AnswerError::Malformed)?;
    if o.get("state").and_then(Value::as_str) != Some(state) {
        return Err(AnswerError::Malformed);
    }
    if o.contains_key("error") {
        return Err(AnswerError::Declined);
    }
    let token = o
        .get("vp_token")
        .and_then(Value::as_object)
        .ok_or(AnswerError::Malformed)?;
    if token.len() != query.credentials.len() {
        return Err(AnswerError::Unanswered);
    }
    let mut out = Vec::with_capacity(query.credentials.len());
    for c in &query.credentials {
        let p = match token.get(&c.id).ok_or(AnswerError::Unanswered)? {
            Value::Array(items) => match items.as_slice() {
                [Value::String(s)] => s.clone(),
                _ => return Err(AnswerError::Unanswered),
            },
            _ => return Err(AnswerError::Malformed),
        };
        out.push(p);
    }
    Ok(out)
}

fn present(claims: &Json, path: &Path) -> bool {
    match path.iter().position(|s| *s == Step::Every) {
        None => lookup(claims, path).is_some(),
        Some(i) => {
            let head: Path = path.iter().take(i).cloned().collect();
            matches!(lookup(claims, &head), Some(Json::Array(items)) if !items.is_empty())
        }
    }
}

/// Checks one verified credential against its query and answers the values at the asked paths.
///
/// # Errors
/// [`AnswerError`].
pub fn check(
    query: &CredentialQuery,
    credential_type: &str,
    claims: &Json,
    disclosed: &[Path],
) -> Result<Vec<(Path, Json)>, AnswerError> {
    if !query.types.iter().any(|t| t == credential_type) {
        return Err(AnswerError::Type);
    }
    if !minimal(&query.claims, disclosed) {
        return Err(AnswerError::Extra);
    }
    let mut values = Vec::with_capacity(query.claims.len());
    for asked in &query.claims {
        if !present(claims, asked) {
            return Err(AnswerError::Missing);
        }
        let head: Path = asked
            .iter()
            .take_while(|s| **s != Step::Every)
            .cloned()
            .collect();
        if let Some(v) = lookup(claims, &head) {
            values.push((asked.clone(), v.clone()));
        }
    }
    Ok(values)
}
