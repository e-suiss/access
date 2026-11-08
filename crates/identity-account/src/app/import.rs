//! Account import from another identity provider (§12.3.7, §18.1, TN-84, TN-85): one JSON line
//! per account, with its identifiers and either its password hash (and the hash's pre-hash or
//! pepper as data) or a reference the previous provider checks at the first sign-in. Nothing
//! else crosses: sessions, refresh tokens, consents and audit history stay with the previous
//! provider, and consents are given again as Grants here (TN-84). A line that cannot be imported
//! is reported and the rest go on.

use serde::Deserialize;

use crate::AccountError;
use crate::app::accounts::{change_status, create, store_password_as};
use crate::app::{Actor, Realm};
use crate::domain::identifier::{Identifier, IdentifierKind};
use crate::domain::legacy::{self, ImportRejected};
use crate::domain::status::AccountStatus;
use crate::ports::{AccountDb, AccountTx};

/// One import line.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Line {
    /// The e-mail address, if any.
    #[serde(default)]
    pub email: Option<String>,
    /// The user name, if any.
    #[serde(default)]
    pub username: Option<String>,
    /// The stored password hash: PHC, modular crypt or LDAP form.
    #[serde(default)]
    pub password_hash: Option<String>,
    /// The hash's pepper and pre-hash as data, e.g. `prehash=sha256-hex`.
    #[serde(default)]
    pub hash_transform: Option<String>,
    /// Without a hash: the previous provider checks the password at the first sign-in; this is
    /// its reference for the account (may be empty).
    #[serde(default)]
    pub legacy_idp_reference: Option<String>,
}

impl core::fmt::Debug for Line {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Line")
            .field("password_hash", &self.password_hash.is_some())
            .finish_non_exhaustive()
    }
}

/// Why a line was not imported. None names the password or the hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Skipped {
    /// Not one JSON object of the line format.
    #[error("not an import line")]
    Format,
    /// No identifier, or one outside its format.
    #[error("missing or malformed identifier")]
    Identifier,
    /// Both a hash and a previous-provider reference, or neither.
    #[error("exactly one of password_hash and legacy_idp_reference")]
    Credential,
    /// The hash is not importable.
    #[error(transparent)]
    Hash(#[from] ImportRejected),
    /// An identifier is already another account's.
    #[error("identifier already taken")]
    Taken,
}

/// What one line did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Imported {
    /// The new active account and its credential `algorithm`.
    Created {
        /// The account.
        subject: [u8; 16],
        /// Whether its password waits for a lazy migration.
        legacy: bool,
    },
    /// Not imported.
    Skipped(Skipped),
}

fn identifiers(line: &Line) -> Result<Vec<Identifier>, Skipped> {
    let mut out = Vec::new();
    if let Some(e) = &line.email {
        out.push(Identifier::new(IdentifierKind::Email, e).map_err(|_| Skipped::Identifier)?);
    }
    if let Some(u) = &line.username {
        out.push(Identifier::new(IdentifierKind::Username, u).map_err(|_| Skipped::Identifier)?);
    }
    if out.is_empty() {
        return Err(Skipped::Identifier);
    }
    Ok(out)
}

fn stored(line: &Line) -> Result<legacy::Stored, Skipped> {
    match (&line.password_hash, &line.legacy_idp_reference) {
        (Some(h), None) => Ok(legacy::classify(h, line.hash_transform.as_deref())?),
        (None, Some(r)) if line.hash_transform.is_none() => Ok(legacy::Stored {
            algorithm: legacy::IDP.to_owned(),
            text: r.clone(),
        }),
        _ => Err(Skipped::Credential),
    }
}

/// Imports one JSON line: an active account with its identifiers and its password credential.
///
/// # Errors
/// [`AccountError`] for storage or keys; a line that cannot be imported is
/// [`Imported::Skipped`].
pub async fn import_line<D: AccountDb>(
    db: &D,
    realm: &Realm<'_>,
    raw: &str,
    who: &Actor<'_>,
) -> Result<Imported, AccountError> {
    let Ok(line) = serde_json::from_str::<Line>(raw) else {
        return Ok(Imported::Skipped(Skipped::Format));
    };
    let ids = match identifiers(&line) {
        Ok(ids) => ids,
        Err(s) => return Ok(Imported::Skipped(s)),
    };
    let secret = match stored(&line) {
        Ok(s) => s,
        Err(s) => return Ok(Imported::Skipped(s)),
    };
    let subject = match create(db, realm, &ids, who).await {
        Ok(s) => s,
        Err(AccountError::IdentifierTaken) => return Ok(Imported::Skipped(Skipped::Taken)),
        Err(e) => return Err(e),
    };
    let mut tx = db.begin(realm.tenant, realm.realm).await?;
    store_password_as(
        &mut tx,
        realm,
        subject,
        &secret.text,
        &secret.algorithm,
        who,
    )
    .await?;
    tx.audit(&access_store::audit::AuditEvent {
        event_type: "account.imported",
        actor: who.actor,
        target: &realm.external(subject)?,
        correlation: who.correlation,
    })
    .await?;
    tx.commit().await?;
    for to in [AccountStatus::PendingUserAction, AccountStatus::Active] {
        change_status(db, realm, subject, to, who).await?;
    }
    Ok(Imported::Created {
        subject,
        legacy: legacy::is_legacy(&secret.algorithm),
    })
}
