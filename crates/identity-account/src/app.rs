//! Use cases over the domain and its ports (OP-63).

pub mod accounts;
pub mod administration;
pub mod approver;
pub mod artifacts;
pub mod binding;
pub mod breach;
pub mod breakglass;
pub mod claims;
pub mod events;
pub mod export;
pub mod external;
pub mod first_contact;
pub mod hasher;
pub mod hr;
pub mod import;
pub mod ldap;
pub mod local;
pub mod login;
pub mod national_id;
pub mod privacy;
pub mod registration;
pub mod sealing;
pub mod signal;
pub mod support;
pub mod vault;

use access_crypto::opaque_id::IdKey;
use access_store::identity::{EnvironmentId, TenantId};
use suiss_crypto::envelope::Kek;

use crate::AccountError;

/// The environment an operation runs in, with its keys.
pub struct Environment<'a> {
    /// Tenant.
    pub tenant: TenantId,
    /// Environment.
    pub environment: EnvironmentId,
    /// The environment KEK that wraps subject DEKs (OP-42, OP-135).
    pub kek: &'a (dyn Kek + Sync),
    /// The cell's id key for external subject ids (OP-137).
    pub ids: &'a IdKey,
}

/// An environment as events and audit rows name it: its id and the cell's id key (OP-137).
#[derive(Clone, Copy)]
pub struct Named<'a> {
    /// Environment.
    pub environment: EnvironmentId,
    /// The cell's id key for external subject ids (OP-137).
    pub ids: &'a IdKey,
}

/// What names an environment and its subjects in events and audit rows (OP-137).
pub trait Naming: Sync {
    /// The environment.
    fn environment_id(&self) -> EnvironmentId;

    /// The subject's external id, as audit rows and APIs name it.
    ///
    /// # Errors
    /// [`AccountError::OpaqueId`].
    fn external(&self, subject: [u8; 16]) -> Result<String, AccountError>;
}

impl Naming for Named<'_> {
    fn environment_id(&self) -> EnvironmentId {
        self.environment
    }

    fn external(&self, subject: [u8; 16]) -> Result<String, AccountError> {
        Ok(self.ids.encode(SUBJECT_PREFIX, subject)?)
    }
}

impl Naming for Environment<'_> {
    fn environment_id(&self) -> EnvironmentId {
        self.environment
    }

    fn external(&self, subject: [u8; 16]) -> Result<String, AccountError> {
        Environment::external(self, subject)
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

impl Environment<'_> {
    /// The subject's external id, as audit rows and APIs name it.
    ///
    /// # Errors
    /// [`AccountError::OpaqueId`].
    pub fn external(&self, subject: [u8; 16]) -> Result<String, AccountError> {
        Ok(self.ids.encode(SUBJECT_PREFIX, subject)?)
    }
}
