//! First-contact tokens (E58, OP-156 m.3 (z), Ek B 4495): RFC 9578 type `0x0002` tokens a
//! person's agent spends on a first contact through Relay. Access issues them blind, so a token
//! names nobody and two tokens of one person cannot be told apart; Relay verifies them with a
//! standard RSASSA-PSS check and keeps the spent set. A token produces no authority: it is never
//! a Claim, a Grant or a decision input.
//!
//! - One issuer key per realm and 30-day period, made when its period first needs it and sealed
//!   under the realm KEK; the directory lists the current and the previous period's key.
//! - At most [`DAILY_LIMIT`] tokens per identity and day (POLICY DEFAULT); the count is one row
//!   per token, naming no blinded message.

use access_crypto::blind_rsa::{self, BlindError, IssuerKey, MODULUS_LEN};
use access_store::audit::AuditEvent;
use access_store::first_contact::FirstContactKey;
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::envelope::{Dek, Sealed, open_body, seal_body};

use crate::AccountError;
use crate::adapters::pg::PgTx;
use crate::app::{Actor, Realm};
use crate::domain::status::AccountStatus;
use crate::ports::AccountTx;

/// Tokens one identity may be issued per day (POLICY DEFAULT, OP-156 m.3 (z)).
pub const DAILY_LIMIT: i64 = 20;

/// How long one issuer key signs: 30 days (OP-156 m.3 (z)).
pub const PERIOD_MS: u64 = 30 * 86_400_000;

/// The RFC 9578 token type.
pub const TOKEN_TYPE: u16 = 0x0002;

const DAY_MS: u64 = 86_400_000;

const KEY_CONTEXT: &[u8] = b"access/first-contact/issuer-key/v1";

/// One blinded token request (`first-contact-request`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenRequest {
    /// Must be [`TOKEN_TYPE`].
    pub token_type: u16,
    /// The last byte of the issuer key's `token_key_id`.
    pub truncated_key_id: u8,
    /// The blinded message, 256 bytes.
    pub blinded_msg: Vec<u8>,
}

/// Why a request was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// Not a type `0x0002` request of 256 bytes below the modulus.
    Request,
    /// The truncated key id is not the current key's.
    Key,
    /// The identity had its tokens for today.
    Limit,
    /// The account cannot be issued tokens now.
    Inactive,
}

/// A key as the directory publishes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishedKey {
    /// The RFC 9578 token key.
    pub token_key: Vec<u8>,
    /// `token_key_id`.
    pub token_key_id: [u8; 32],
    /// When it starts signing, Unix ms.
    pub not_before_ms: u64,
}

fn period_of(ms: u64) -> Result<i64, AccountError> {
    i64::try_from(ms / PERIOD_MS).map_err(|_| AccountError::Corrupt)
}

fn seal(realm: &Realm<'_>, doc: &[u8]) -> Result<Vec<u8>, AccountError> {
    let dek = Dek::generate().map_err(|_| AccountError::Corrupt)?;
    let wrapped = realm.kek.wrap(&dek).map_err(|_| AccountError::Corrupt)?;
    let sealed = seal_body(dek, KEY_CONTEXT, doc).map_err(|_| AccountError::Corrupt)?;
    let v = Value::Map(vec![
        (Value::text("kek"), Value::text(realm.kek.id())),
        (Value::text("wrapped"), Value::Bytes(wrapped)),
        (Value::text("nonce"), Value::Bytes(sealed.nonce.to_vec())),
        (Value::text("ciphertext"), Value::Bytes(sealed.ciphertext)),
    ]);
    dcbor::encode(&v, Limits::CEILING).map_err(|_| AccountError::Corrupt)
}

fn open(realm: &Realm<'_>, sealed: &[u8]) -> Result<IssuerKey, AccountError> {
    let v = dcbor::decode(sealed, Limits::CEILING).map_err(|_| AccountError::Corrupt)?;
    let bytes = |k: &str| match v.get(k) {
        Some(Value::Bytes(b)) => Ok(b.clone()),
        _ => Err(AccountError::Corrupt),
    };
    let dek = realm
        .kek
        .unwrap(&bytes("wrapped")?)
        .map_err(|_| AccountError::Corrupt)?;
    let body = Sealed {
        nonce: bytes("nonce")?
            .try_into()
            .map_err(|_| AccountError::Corrupt)?,
        ciphertext: bytes("ciphertext")?,
    };
    let doc = open_body(&dek, KEY_CONTEXT, &body).map_err(|_| AccountError::Corrupt)?;
    IssuerKey::from_pkcs8(&doc).map_err(|_| AccountError::Corrupt)
}

/// The key of the period `now_ms` falls in, made and stored when it has none yet; a
/// concurrent maker's key wins.
async fn current(
    tx: &mut PgTx,
    realm: &Realm<'_>,
    now_ms: u64,
) -> Result<FirstContactKey, AccountError> {
    let period = period_of(now_ms)?;
    if let Some(k) =
        tx.0.first_contact_keys(period)
            .await?
            .into_iter()
            .find(|k| k.period == period)
    {
        return Ok(k);
    }
    let (key, der) = IssuerKey::generate().map_err(|_| AccountError::Corrupt)?;
    let token_key = key.token_key();
    let made = FirstContactKey {
        period,
        token_key_id: access_crypto::privacy_pass::token_key_id(&token_key),
        token_key,
        sealed_key: seal(realm, &der)?,
    };
    tx.0.insert_first_contact_key(&made).await?;
    tx.0.first_contact_keys(period)
        .await?
        .into_iter()
        .find(|k| k.period == period)
        .ok_or(AccountError::Corrupt)
}

/// The issuer directory (RFC 9578 §4): the current period's key, made if it is missing, and
/// the previous period's, whose tokens Relay may still be holding.
///
/// # Errors
/// [`AccountError`].
pub async fn directory(
    tx: &mut PgTx,
    realm: &Realm<'_>,
) -> Result<Vec<PublishedKey>, AccountError> {
    let now = tx.server_time().await?;
    current(tx, realm, now).await?;
    let from = period_of(now)?.saturating_sub(1);
    tx.0.first_contact_keys(from)
        .await?
        .into_iter()
        .map(|k| {
            Ok(PublishedKey {
                not_before_ms: u64::try_from(k.period)
                    .ok()
                    .and_then(|p| p.checked_mul(PERIOD_MS))
                    .ok_or(AccountError::Corrupt)?,
                token_key: k.token_key,
                token_key_id: k.token_key_id,
            })
        })
        .rev()
        .collect()
}

/// `BlindSign` of one request for `subject` (E58): the current key only, at most
/// [`DAILY_LIMIT`] a day. The issuance and a refusal at the limit are audited under the
/// account; the request itself is never kept.
///
/// # Errors
/// [`AccountError`].
pub async fn issue(
    tx: &mut PgTx,
    realm: &Realm<'_>,
    subject: [u8; 16],
    request: &TokenRequest,
    who: &Actor<'_>,
) -> Result<Result<[u8; MODULUS_LEN], Refused>, AccountError> {
    if request.token_type != TOKEN_TYPE || request.blinded_msg.len() != MODULUS_LEN {
        return Ok(Err(Refused::Request));
    }
    let Some(row) = tx.subject(subject, true).await? else {
        return Ok(Err(Refused::Inactive));
    };
    if AccountStatus::parse(&row.status) != Some(AccountStatus::Active) {
        return Ok(Err(Refused::Inactive));
    }
    let now = tx.server_time().await?;
    let day = i32::try_from(now / DAY_MS).map_err(|_| AccountError::Corrupt)?;
    let target = realm.external(subject)?;
    if tx.0.first_contact_issued(subject, day).await? >= DAILY_LIMIT {
        tx.audit(&AuditEvent {
            event_type: "first_contact.limit_reached",
            actor: who.actor,
            target: &target,
            correlation: who.correlation,
        })
        .await?;
        return Ok(Err(Refused::Limit));
    }
    let key = current(tx, realm, now).await?;
    if key.token_key_id.last() != Some(&request.truncated_key_id) {
        return Ok(Err(Refused::Key));
    }
    let sig = match open(realm, &key.sealed_key)?.blind_sign(&request.blinded_msg) {
        Ok(s) => s,
        Err(BlindError::Input) => return Ok(Err(Refused::Request)),
        Err(_) => return Err(AccountError::Corrupt),
    };
    tx.0.insert_first_contact_issued(subject, day, key.period)
        .await?;
    tx.audit(&AuditEvent {
        event_type: "first_contact.tokens_issued",
        actor: who.actor,
        target: &target,
        correlation: who.correlation,
    })
    .await?;
    Ok(Ok(sig))
}

/// The modulus of a published token key, for a client that blinds against it.
#[must_use]
pub fn modulus(token_key: &[u8]) -> Option<&[u8]> {
    blind_rsa::token_key_modulus(token_key)
}
