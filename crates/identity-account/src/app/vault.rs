//! The PII vault (OP-153 m.3 (aa), OP-42, OP-74, T31): identifiers and profile fields are sealed
//! under a DEK of their subject and vault class, wrapped by the realm KEK, and found by the realm's
//! keyed blind index. Shredding a class DEK makes its fields unreadable; the rows and the index stay
//! (U58, TN-76 m.5).

use std::sync::Arc;

use access_crypto::realm_index::RealmIndexKey;
use access_store::accounts::{SealedIdentifier, StoredValue};
use access_store::identity::TenantTx;
use suiss_crypto::envelope::{Dek, Kek, Sealed, open_body, seal_body};

use crate::AccountError;
use crate::domain::identifier::{IdentifierKind, normalize};

const CONTEXT: &[u8] = b"access/pii/v1\0";

/// A vault class (OP-153 m.3 (aa)); `credential` is the subject's own DEK.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PiiClass {
    /// Profile fields and user names.
    Profile,
    /// E-mail addresses and phone numbers.
    Contact,
    /// What the user's security history keeps beyond the audit row.
    SecurityHistory,
}

impl PiiClass {
    /// Every class with its own key row.
    pub const ALL: [Self; 3] = [Self::Profile, Self::Contact, Self::SecurityHistory];

    /// The stored name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Profile => "profile",
            Self::Contact => "contact",
            Self::SecurityHistory => "security_history",
        }
    }

    /// The class of a stored name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.name() == name)
    }

    /// The class an identifier of `kind` is sealed under.
    #[must_use]
    pub const fn of_identifier(kind: IdentifierKind) -> Self {
        match kind {
            IdentifierKind::Username => Self::Profile,
            IdentifierKind::Email | IdentifierKind::Phone => Self::Contact,
        }
    }

    /// The Ek C retention class whose rule decides when its key may go (OP-74 m.2).
    #[must_use]
    pub const fn retention(self) -> suiss_retention::Class {
        match self {
            Self::Profile | Self::Contact => suiss_retention::Class::Profile,
            Self::SecurityHistory => suiss_retention::Class::Audit,
        }
    }
}

/// One realm's vault keys: the realm KEK and the realm's index key.
#[derive(Clone)]
pub struct Vault {
    /// The realm KEK that wraps class DEKs (OP-42, OP-135).
    pub kek: Arc<dyn Kek + Send + Sync>,
    /// The realm's blind index key (OP-153 m.3 (aa)).
    pub index: Arc<RealmIndexKey>,
}

impl Vault {
    /// Vault keys in process memory, for tests: `kek` and an index key from `index`.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn in_memory(kek: Arc<dyn Kek + Send + Sync>, index: [u8; 32]) -> Self {
        Self {
            kek,
            index: Arc::new(RealmIndexKey::new(access_crypto::Secret::new(index))),
        }
    }
}

/// The folded form an identifier is indexed by: NFKC, trimmed, lower case.
#[must_use]
pub fn folded(value: &str) -> String {
    normalize(value).to_lowercase()
}

impl Vault {
    /// The realm's blind index of `value`.
    ///
    /// # Errors
    /// [`AccountError::Vault`] when the token refuses.
    pub fn index_of(
        &self,
        tenant: &[u8; 16],
        realm: &[u8; 16],
        value: &str,
    ) -> Result<[u8; 32], AccountError> {
        self.index
            .index(tenant, realm, &folded(value))
            .map_err(|_| AccountError::Vault)
    }
}

fn context(t: &TenantTx, subject: &[u8; 16], class: PiiClass, field: &str) -> Vec<u8> {
    let mut c = CONTEXT.to_vec();
    c.extend_from_slice(t.tenant().as_bytes());
    if let Some(r) = t.realm() {
        c.extend_from_slice(r.as_bytes());
    }
    c.extend_from_slice(subject);
    c.extend_from_slice(class.name().as_bytes());
    c.push(0);
    c.extend_from_slice(field.as_bytes());
    c
}

/// The subject's DEK of `class`, made and stored on first use when `create` is set; `None` when
/// it was shredded, or does not exist and `create` is not set.
///
/// # Errors
/// [`AccountError::Corrupt`] when another KEK wrapped it; [`AccountError`].
pub async fn class_key(
    t: &mut TenantTx,
    vault: &Vault,
    subject: [u8; 16],
    class: PiiClass,
    create: bool,
) -> Result<Option<Dek>, AccountError> {
    if let Some(row) = t.subject_key(subject, class.name()).await? {
        let Some(wrapped) = row.wrapped_dek else {
            return Ok(None);
        };
        if row.kek_id != vault.kek.id() {
            return Err(AccountError::Corrupt);
        }
        return Ok(Some(vault.kek.unwrap(&wrapped)?));
    }
    if !create {
        return Ok(None);
    }
    let dek = Dek::generate()?;
    let wrapped = vault.kek.wrap(&dek)?;
    if !t
        .insert_subject_key(subject, class.name(), vault.kek.id(), &wrapped)
        .await?
    {
        return Err(AccountError::Corrupt);
    }
    Ok(Some(dek))
}

fn copy(dek: &Dek) -> Dek {
    Dek::from_secret(access_crypto::Secret::new(*dek.secret().expose()))
}

/// Seals `plaintext` as field `field` of `subject` under the class DEK `dek`.
///
/// # Errors
/// [`AccountError::Envelope`].
pub fn seal(
    t: &TenantTx,
    dek: &Dek,
    subject: [u8; 16],
    class: PiiClass,
    field: &str,
    plaintext: &[u8],
) -> Result<Sealed, AccountError> {
    Ok(seal_body(
        copy(dek),
        &context(t, &subject, class, field),
        plaintext,
    )?)
}

/// Opens a field sealed by [`seal`].
///
/// # Errors
/// [`AccountError::Envelope`]; [`AccountError::Corrupt`] for non-UTF-8 content.
pub fn open(
    t: &TenantTx,
    dek: &Dek,
    subject: [u8; 16],
    class: PiiClass,
    field: &str,
    sealed: &Sealed,
) -> Result<String, AccountError> {
    let plain = open_body(dek, &context(t, &subject, class, field), sealed)?;
    String::from_utf8(plain.to_vec()).map_err(|_| AccountError::Corrupt)
}

/// The field name every identifier is sealed under.
pub const IDENTIFIER: &str = "identifier";

/// The sealed form of identifier `value` of `kind` for `subject`, with its blind index.
///
/// # Errors
/// [`AccountError`].
pub async fn seal_identifier(
    t: &mut TenantTx,
    vault: &Vault,
    subject: [u8; 16],
    kind: IdentifierKind,
    value: &str,
) -> Result<SealedIdentifier, AccountError> {
    let realm = t.realm().ok_or(AccountError::Corrupt)?;
    let index = vault.index_of(t.tenant().as_bytes(), realm.as_bytes(), value)?;
    let class = PiiClass::of_identifier(kind);
    let dek = class_key(t, vault, subject, class, true)
        .await?
        .ok_or(AccountError::Shredded)?;
    let sealed = seal(t, &dek, subject, class, IDENTIFIER, value.as_bytes())?;
    Ok(SealedIdentifier {
        index,
        class: class.name(),
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext,
    })
}

/// The readable value of a stored identifier; `None` once its class key is shredded (U58).
///
/// # Errors
/// [`AccountError`].
pub async fn reveal(
    t: &mut TenantTx,
    vault: &Vault,
    subject: [u8; 16],
    stored: &StoredValue,
) -> Result<Option<String>, AccountError> {
    match stored {
        StoredValue::Plain(v) => Ok(Some(v.clone())),
        StoredValue::Sealed {
            class,
            nonce,
            ciphertext,
        } => {
            let class = PiiClass::parse(class).ok_or(AccountError::Corrupt)?;
            let Some(dek) = class_key(t, vault, subject, class, false).await? else {
                return Ok(None);
            };
            let sealed = Sealed {
                nonce: *nonce,
                ciphertext: ciphertext.clone(),
            };
            open(t, &dek, subject, class, IDENTIFIER, &sealed).map(Some)
        }
    }
}

/// The readable value of a stored identifier with the realm KEK alone, as [`reveal`] does: a
/// management write reads the account's own address with it (TN-61). `None` once its class key
/// is shredded (U58).
///
/// # Errors
/// [`AccountError::Corrupt`] when another KEK wrapped the key; [`AccountError`].
pub async fn reveal_with_kek(
    t: &mut TenantTx,
    kek: &(dyn Kek + Send + Sync),
    subject: [u8; 16],
    stored: &StoredValue,
) -> Result<Option<String>, AccountError> {
    match stored {
        StoredValue::Plain(v) => Ok(Some(v.clone())),
        StoredValue::Sealed {
            class,
            nonce,
            ciphertext,
        } => {
            let class = PiiClass::parse(class).ok_or(AccountError::Corrupt)?;
            let Some(row) = t.subject_key(subject, class.name()).await? else {
                return Ok(None);
            };
            let Some(wrapped) = row.wrapped_dek else {
                return Ok(None);
            };
            if row.kek_id != kek.id() {
                return Err(AccountError::Corrupt);
            }
            let dek = kek.unwrap(&wrapped)?;
            let sealed = Sealed {
                nonce: *nonce,
                ciphertext: ciphertext.clone(),
            };
            open(t, &dek, subject, class, IDENTIFIER, &sealed).map(Some)
        }
    }
}

/// Seals up to `limit` identifiers of the realm still written in plaintext, each under its
/// subject's class key (OP-153 m.3 (aa)); returns how many were sealed.
///
/// # Errors
/// [`AccountError`].
pub async fn seal_plaintext(
    t: &mut TenantTx,
    vault: &Vault,
    limit: i64,
) -> Result<u64, AccountError> {
    let mut n = 0_u64;
    for (id, subject, kind, value) in t.plaintext_identifiers(limit).await? {
        let kind = match kind.as_str() {
            "username" => IdentifierKind::Username,
            "email" => IdentifierKind::Email,
            "phone" => IdentifierKind::Phone,
            _ => return Err(AccountError::Corrupt),
        };
        let sealed = match seal_identifier(t, vault, subject, kind, &value).await {
            Err(AccountError::Shredded) => continue,
            other => other?,
        };
        if t.seal_identifier(id, &sealed).await? {
            n = n.saturating_add(1);
        }
    }
    Ok(n)
}

/// A profile field the vault keeps (OP-153 m.3 (aa), (q)).
pub const PROFILE_FIELDS: [&str; 6] = [
    "name",
    "given_name",
    "family_name",
    "birthdate",
    "locale",
    "zoneinfo",
];

/// Longest profile value, in bytes.
pub const MAX_PROFILE_BYTES: usize = 1024;

/// Sets profile field `field` of `subject`, sealed under its `profile` key.
///
/// # Errors
/// [`AccountError::Invalid`] for an unknown field or an oversized value; [`AccountError`].
pub async fn set_profile(
    t: &mut TenantTx,
    vault: &Vault,
    subject: [u8; 16],
    field: &str,
    value: &str,
) -> Result<(), AccountError> {
    if !PROFILE_FIELDS.contains(&field) || value.len() > MAX_PROFILE_BYTES || value.is_empty() {
        return Err(AccountError::Invalid);
    }
    let dek = class_key(t, vault, subject, PiiClass::Profile, true)
        .await?
        .ok_or(AccountError::Shredded)?;
    let sealed = seal(t, &dek, subject, PiiClass::Profile, field, value.as_bytes())?;
    t.set_profile_field(subject, field, &sealed.nonce, &sealed.ciphertext)
        .await?;
    Ok(())
}

/// The subject's readable profile fields; empty once its `profile` key is shredded (U58).
///
/// # Errors
/// [`AccountError`].
pub async fn profile(
    t: &mut TenantTx,
    vault: &Vault,
    subject: [u8; 16],
) -> Result<Vec<(String, String)>, AccountError> {
    let rows = t.profile_fields(subject).await?;
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let Some(dek) = class_key(t, vault, subject, PiiClass::Profile, false).await? else {
        return Ok(Vec::new());
    };
    rows.into_iter()
        .map(|(field, nonce, ciphertext)| {
            let v = open(
                t,
                &dek,
                subject,
                PiiClass::Profile,
                &field,
                &Sealed { nonce, ciphertext },
            )?;
            Ok((field, v))
        })
        .collect()
}
