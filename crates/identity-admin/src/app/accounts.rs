//! The account changes of catalog 3 whose identity-plane work follows the bound decision
//! (OP-153 m.25 (b)): an administrator's account import over a file the change names by its
//! SHA-256 (TN-85, OP-153 m.19 (d)). The decision is bound and recorded first; the file's lines
//! are then imported one account at a time, as `access-server import-accounts` does, with the
//! Exercise as their audit correlation.

use access_identity_account::adapters::pg::PgAccounts;
use access_identity_account::app::import::{Report, file_of, import_all};
use access_kernel::json::b64url_encode;

use super::{Admin, Applied, DECIDED_BY, Proposal};
use crate::AdminError;
use crate::domain::{Change, Invalid};
use crate::ports::{Decider, Governance, Instances, RealmKeys};

impl<D: Decider, G: Governance + Instances, K: RealmKeys> Admin<'_, D, G, K> {
    /// Applies `idp.account.import` `p` with the actor's `ais`, then imports `content`, whose
    /// SHA-256 and line count the change names (TN-85, OP-153 m.19 (d)); a retry of a decision
    /// already written imports nothing again.
    ///
    /// # Errors
    /// [`AdminError`]: content the change does not name is [`Invalid::Body`].
    pub async fn import_accounts(
        &self,
        p: &Proposal,
        ais: Vec<u8>,
        content: &str,
    ) -> Result<(Applied, Option<Report>), AdminError> {
        let Change::AccountImport(named) = &p.change else {
            return Err(Invalid::Body.into());
        };
        let (file, lines) = file_of(content);
        if file != named.file || lines != u64::from(named.accounts) {
            return Err(Invalid::Body.into());
        }
        let vault = self
            .keys
            .vault(p.realm)
            .ok_or_else(|| AdminError::Unavailable(String::from("vault")))?;
        let applied = Box::pin(self.apply(p, ais)).await?;
        let Applied::Written { exercise, .. } = &applied else {
            return Ok((applied, None));
        };
        let realm = access_identity_account::app::Realm {
            tenant: p.tenant,
            realm: p.realm,
            kek: &*vault.kek,
            ids: self.ids,
        };
        let correlation = b64url_encode(&exercise.0);
        let who = access_identity_account::app::Actor {
            actor: DECIDED_BY,
            correlation: &correlation,
        };
        let db = PgAccounts::sealed(self.app.clone(), vault.clone());
        let report = import_all(&db, &realm, content, &who)
            .await
            .map_err(|(n, e)| AdminError::Unavailable(format!("import line {n}: {e}")))?;
        tracing::info!(
            event = "accounts.imported",
            created = report.created,
            legacy = report.legacy,
            skipped = report.skipped.len(),
            "account import finished (TN-85)"
        );
        Ok((applied, Some(report)))
    }
}
