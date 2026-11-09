//! Moving accounts in from another identity provider (§12.3.7, TN-84, TN-85): the
//! `import-accounts <realm> <file>` command over this process's pools and token, and the
//! previous provider's password check for the accounts that brought no hash.

use std::sync::Arc;

use access_identity_account::app::import::{Report, import_all};
use access_identity_account::app::{Actor, Realm};
use access_identity_account::ports::{LegacyIdp, LegacyIdpFuture, LegacyIdpUnavailable};
use access_identity_oauth::adapters::outbound::Outbound;
use access_store::Pool;

/// The largest answer read from the previous provider.
const MAX_ANSWER: usize = 4096;

/// The previous provider's check endpoint: `POST {identifier, password, reference}` as JSON,
/// `200 {"valid": true|false}`; any other answer is unavailable and fails the sign-in.
pub(crate) struct OutboundLegacyIdp {
    http: Outbound,
    url: String,
}

impl OutboundLegacyIdp {
    pub(crate) const fn new(http: Outbound, url: String) -> Self {
        Self { http, url }
    }
}

/// What the previous provider's answer says.
fn valid(status: u16, body: &[u8]) -> Result<bool, LegacyIdpUnavailable> {
    if status != 200 {
        return Err(LegacyIdpUnavailable);
    }
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("valid").and_then(serde_json::Value::as_bool))
        .ok_or(LegacyIdpUnavailable)
}

impl LegacyIdp for OutboundLegacyIdp {
    fn verify<'a>(
        &'a self,
        identifier: &'a str,
        password: &'a [u8],
        reference: &'a str,
    ) -> LegacyIdpFuture<'a> {
        Box::pin(async move {
            let password = core::str::from_utf8(password).map_err(|_| LegacyIdpUnavailable)?;
            let body = zeroize::Zeroizing::new(
                serde_json::json!({
                    "identifier": identifier,
                    "password": password,
                    "reference": reference,
                })
                .to_string(),
            );
            let a = self
                .http
                .post_reading(
                    &self.url,
                    "application/json",
                    &[],
                    body.as_bytes(),
                    MAX_ANSWER,
                )
                .await
                .map_err(|_| LegacyIdpUnavailable)?;
            valid(a.status, &a.body)
        })
    }
}

/// The previous provider for the hasher, when configured.
pub(crate) fn legacy_idp(url: Option<&str>, http: Outbound) -> Option<Arc<dyn LegacyIdp>> {
    url.map(|u| Arc::new(OutboundLegacyIdp::new(http, u.to_owned())) as Arc<dyn LegacyIdp>)
}

/// Imports every non-empty line of `text` into the realm.
///
/// # Errors
/// A storage or key failure stops the run; lines already imported stay.
pub(crate) async fn import(
    app: &Pool,
    vault: access_identity_account::app::vault::Vault,
    realm: &Realm<'_>,
    text: &str,
) -> Result<Report, String> {
    let db = access_identity_account::adapters::pg::PgAccounts::sealed(app.clone(), vault);
    let report = import_all(&db, realm, text, &IMPORTER)
        .await
        .map_err(|(n, e)| format!("line {n}: {e}"))?;
    tracing::info!(
        event = "accounts.imported",
        created = report.created,
        legacy = report.legacy,
        skipped = report.skipped.len(),
        "account import finished (TN-85)"
    );
    Ok(report)
}

/// The audit actor of an import.
pub(crate) const IMPORTER: Actor<'static> = Actor {
    actor: "operator:import-accounts",
    correlation: "import-accounts",
};

#[cfg(test)]
mod tests {
    use super::*;

    // TN-85, MD-8
    #[test]
    fn only_a_well_formed_200_answers_the_check() {
        assert_eq!(valid(200, br#"{"valid":true}"#), Ok(true));
        assert_eq!(valid(200, br#"{"valid":false}"#), Ok(false));
        assert_eq!(valid(200, br#"{"ok":true}"#), Err(LegacyIdpUnavailable));
        assert_eq!(valid(503, br#"{"valid":true}"#), Err(LegacyIdpUnavailable));
        assert_eq!(valid(200, b"yes"), Err(LegacyIdpUnavailable));
    }
}
