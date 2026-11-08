//! Use cases over the domain and its ports (OP-63).

pub mod accounts;
pub mod breach;
pub mod claims;
pub mod events;
pub mod external;
pub mod hasher;
pub mod local;
pub mod login;
pub mod privacy;
pub mod registration;
pub mod sealing;
pub mod signal;
pub mod vault;

use access_crypto::opaque_id::IdKey;
use access_store::identity::{RealmId, TenantId};
use suiss_crypto::envelope::Kek;

use crate::AccountError;

/// The realm an operation runs in, with its keys.
pub struct Realm<'a> {
    /// Tenant.
    pub tenant: TenantId,
    /// Realm.
    pub realm: RealmId,
    /// The realm KEK that wraps subject DEKs (OP-42, OP-135).
    pub kek: &'a (dyn Kek + Sync),
    /// The cell's id key for external subject ids (OP-137).
    pub ids: &'a IdKey,
}

/// A realm as events and audit rows name it: its id and the cell's id key (OP-137).
#[derive(Clone, Copy)]
pub struct Named<'a> {
    /// Realm.
    pub realm: RealmId,
    /// The cell's id key for external subject ids (OP-137).
    pub ids: &'a IdKey,
}

/// What names a realm and its subjects in events and audit rows (OP-137).
pub trait Naming: Sync {
    /// The realm.
    fn realm_id(&self) -> RealmId;

    /// The subject's external id, as audit rows and APIs name it.
    ///
    /// # Errors
    /// [`AccountError::OpaqueId`].
    fn external(&self, subject: [u8; 16]) -> Result<String, AccountError>;
}

impl Naming for Named<'_> {
    fn realm_id(&self) -> RealmId {
        self.realm
    }

    fn external(&self, subject: [u8; 16]) -> Result<String, AccountError> {
        Ok(self.ids.encode(SUBJECT_PREFIX, subject)?)
    }
}

impl Naming for Realm<'_> {
    fn realm_id(&self) -> RealmId {
        self.realm
    }

    fn external(&self, subject: [u8; 16]) -> Result<String, AccountError> {
        Realm::external(self, subject)
    }
}

/// Who acts and the request it belongs to, as the audit row records them (OP-10).
pub struct Actor<'a> {
    /// Actor reference.
    pub actor: &'a str,
    /// Request correlation id.
    pub correlation: &'a str,
}

/// External id prefix of identity subjects (OP-137 m.2).
pub const SUBJECT_PREFIX: &str = "usr";

impl Realm<'_> {
    /// The subject's external id, as audit rows and APIs name it.
    ///
    /// # Errors
    /// [`AccountError::OpaqueId`].
    pub fn external(&self, subject: [u8; 16]) -> Result<String, AccountError> {
        Ok(self.ids.encode(SUBJECT_PREFIX, subject)?)
    }
}
