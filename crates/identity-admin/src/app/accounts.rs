//! The account changes of catalog 3 whose identity-plane work follows the bound decision
//! (OP-153 m.25 (b)): an administrator's account import over a file the change names by its
//! SHA-256 (TN-85, OP-153 m.19 (d)), and the reserved migration export to the key the receiving
//! deployment bound to it (TN-86). The decision is bound and recorded first; the file's lines
//! are then imported one account at a time, as `access-server import-accounts` does, with the
//! Exercise as their audit correlation, and an export's bundle is sealed and answered once.

use access_identity_account::adapters::pg::PgAccounts;
use access_identity_account::app::import::{Report, file_of, import_all};
use access_kernel::json::b64url_encode;
use access_store::identity::TenantTx;
use suiss_crypto::dcbor::{self, Limits};

use super::{Admin, Applied, DECIDED_BY, Proposal};
use crate::AdminError;
use crate::domain::accounts::Bundle;
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

    /// Applies the reserved `idp.account.migration_export` `p` with the actor's `ais`, then
    /// seals every active account's import line to the change's recipient key (TN-86, OP-153
    /// m.19 (d), m.25 (i)); the bundle's dCBOR is answered once and never kept. A retry of a
    /// decision already written seals nothing.
    ///
    /// # Errors
    /// [`AdminError`].
    pub async fn export_accounts(
        &self,
        p: &Proposal,
        ais: Vec<u8>,
    ) -> Result<(Applied, Option<Vec<u8>>), AdminError> {
        let Change::MigrationExport(e) = &p.change else {
            return Err(Invalid::Body.into());
        };
        let vault = self
            .keys
            .vault(p.realm)
            .ok_or_else(|| AdminError::Unavailable(String::from("vault")))?;
        let applied = Box::pin(self.apply(p, ais)).await?;
        if !matches!(applied, Applied::Written { .. }) {
            return Ok((applied, None));
        }
        let mut t = TenantTx::begin(self.app, p.tenant, p.realm).await?;
        let issuer = access_store::idp::governance(&mut t)
            .await?
            .and_then(|g| g.issuer)
            .ok_or(AdminError::NoRealm)?;
        let mut subjects = Vec::new();
        let mut after = [0; 16];
        loop {
            let page = access_store::idp::realm::accounts(&mut t, after, 500).await?;
            let Some(last) = page.last().map(|a| a.subject) else {
                break;
            };
            subjects.extend(page.iter().map(|a| a.subject));
            if page.len() < 500 {
                break;
            }
            after = last;
        }
        let exported_at = t.server_time().await?;
        t.commit().await?;
        let realm = access_identity_account::app::Realm {
            tenant: p.tenant,
            realm: p.realm,
            kek: &*vault.kek,
            ids: self.ids,
        };
        let db = PgAccounts::sealed(self.app.clone(), vault.clone());
        let (lines, accounts) =
            access_identity_account::app::export::export_lines(&db, &realm, &subjects)
                .await
                .map_err(|e| AdminError::Unavailable(e.to_string()))?;
        let recipient = access_kernel::verify::key_scope::thumbprint(
            &access_kernel::verify::cose::PublicKey::P256(e.recipient.clone()),
        );
        let sealer = access_crypto::migration_bundle::Sealer::new(&e.recipient, &recipient)
            .map_err(|_| AdminError::Invalid(Invalid::Body))?;
        let mut bundle = Bundle {
            realm: issuer,
            exported_at,
            accounts,
            recipient,
            epk: sealer.epk().to_vec(),
            nonce: sealer.nonce(),
            ciphertext: Vec::new(),
        };
        let aad = dcbor::encode(&bundle.aad(), Limits::CEILING).map_err(|_| AdminError::Encode)?;
        bundle.ciphertext = sealer
            .seal(&aad, lines.as_bytes())
            .map_err(|_| AdminError::Encode)?;
        let bytes =
            dcbor::encode(&bundle.to_value(), Limits::CEILING).map_err(|_| AdminError::Encode)?;
        tracing::info!(
            event = "accounts.exported",
            accounts,
            "migration export sealed (TN-86)"
        );
        Ok((applied, Some(bytes)))
    }
}

/// Opens a migration bundle sealed to `key` (TN-86): its import lines, which the receiving
/// realm imports with its own `idp.account.import` (TN-85).
///
/// # Errors
/// [`AdminError`]: a bundle that does not open is [`Invalid::Body`].
pub fn open_bundle(
    bundle: &[u8],
    key: &access_crypto::migration_bundle::RecipientKey,
) -> Result<String, AdminError> {
    let value = dcbor::decode(bundle, Limits::CEILING).map_err(|_| Invalid::Body)?;
    let b = Bundle::from_value(&value).ok_or(Invalid::Body)?;
    let public = key.public().map_err(|_| Invalid::Body)?;
    let salt = access_kernel::verify::key_scope::thumbprint(
        &access_kernel::verify::cose::PublicKey::P256(public),
    );
    if salt != b.recipient {
        return Err(Invalid::Body.into());
    }
    let aad = dcbor::encode(&b.aad(), Limits::CEILING).map_err(|_| AdminError::Encode)?;
    let plain = key
        .open((&b.epk, &salt), b.nonce, &aad, &b.ciphertext)
        .map_err(|_| Invalid::Body)?;
    String::from_utf8(plain).map_err(|_| Invalid::Body.into())
}
