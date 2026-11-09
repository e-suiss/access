//! An administrator's migration export (TN-86, OP-153 m.19 (d), m.25 (i)): each active account
//! as one line of the import format of [`crate::app::import`], so the receiving deployment
//! imports the opened bundle as it imports any file. A password hash leaves without the realm's
//! pepper, an imported one with its pre-hash, and an account the previous provider still checks
//! with its reference; an account without a password credential has no line. Passkeys stay bound
//! to their relying party ID and are not part of it.

use access_store::accounts::IdentifierRow;
use serde_json::{Map, Value};

use crate::AccountError;
use crate::adapters::pg::{PgAccounts, PgTx};
use crate::app::Realm;
use crate::app::sealing::{open_password, subject_key};
use crate::app::vault;
use crate::domain::legacy;
use crate::ports::{AccountDb, AccountTx as _};

/// The import line of `subject`, or `None` without a live identifier or a password credential.
async fn line(
    tx: &mut PgTx,
    realm: &Realm<'_>,
    subject: [u8; 16],
) -> Result<Option<String>, AccountError> {
    let Some(row) = tx.0.subject(subject, false).await? else {
        return Ok(None);
    };
    if row.status != "active" {
        return Ok(None);
    }
    let v = tx.vault()?.clone();
    let mut m = Map::new();
    let ids: Vec<IdentifierRow> = tx.0.identifiers(subject).await?;
    for id in ids.iter().filter(|i| i.live) {
        let key = match id.kind.as_str() {
            "email" => "email",
            "username" => "username",
            _ => continue,
        };
        if m.contains_key(key) {
            continue;
        }
        if let Some(value) = vault::reveal(&mut tx.0, &v, subject, &id.stored).await? {
            m.insert(String::from(key), Value::String(value));
        }
    }
    if m.is_empty() {
        return Ok(None);
    }
    let dek = subject_key(realm, &row)?;
    let Some(c) =
        tx.0.credentials(subject, "password")
            .await?
            .into_iter()
            .next()
    else {
        return Ok(None);
    };
    let (stored, _) = open_password(realm, &dek, &subject, &c.sealed)?;
    if c.algorithm == legacy::IDP {
        m.insert(
            String::from("legacy_idp_reference"),
            Value::String(stored.expose().clone()),
        );
    } else if legacy::is_legacy(&c.algorithm) && c.algorithm != legacy::ARGON2 {
        let (spec, hash) = stored
            .expose()
            .split_once('\n')
            .ok_or(AccountError::Corrupt)?;
        m.insert(
            String::from("password_hash"),
            Value::String(hash.to_owned()),
        );
        if !spec.is_empty() {
            m.insert(
                String::from("hash_transform"),
                Value::String(spec.to_owned()),
            );
        }
    } else {
        m.insert(
            String::from("password_hash"),
            Value::String(stored.expose().clone()),
        );
    }
    serde_json::to_string(&Value::Object(m))
        .map(Some)
        .map_err(|_| AccountError::Corrupt)
}

/// The import lines of `subjects`, newline-terminated, and how many there are (TN-86).
///
/// # Errors
/// [`AccountError`].
pub async fn export_lines(
    db: &PgAccounts,
    realm: &Realm<'_>,
    subjects: &[[u8; 16]],
) -> Result<(String, u64), AccountError> {
    let mut tx = db.begin(realm.tenant, realm.realm).await?;
    let mut out = String::new();
    let mut n = 0_u64;
    for s in subjects {
        if let Some(l) = line(&mut tx, realm, *s).await? {
            out.push_str(&l);
            out.push('\n');
            n = n.saturating_add(1);
        }
    }
    tx.commit().await?;
    Ok((out, n))
}
