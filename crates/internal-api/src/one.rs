//! One's cloud key permission as the identity plane forwards it (OP-156 m.3 (w), E59, OP-62):
//! the person's device Instance's own `one.cloud_key/grant` or `one.cloud_key/revoke` Exercise,
//! committed with the identity plane as PEP, and where the Mandate a permission is bound to
//! stands. The record the identity plane keeps holds no key or data (OP-78).

use std::future::Future;

use access_kernel::combinator::Capacity;
use access_kernel::digest::Digest;
use access_kernel::intent::IntentEnvelope;
use access_kernel::meta::ExerciseBasis;
use access_kernel::model::Id;

use crate::idp::{Unavailable, Verdict};

/// The namespace of One's own work, which a permission's purpose names an action of.
pub const WORK_NAMESPACE: &str = "one";

/// The namespace of the cloud key actions.
pub const NAMESPACE: &str = "one.cloud_key";

/// The grant action's name.
pub const GRANT: &str = "grant";

/// The revoke action's name.
pub const REVOKE: &str = "revoke";

/// A device Instance's Exercise of a cloud key action.
#[derive(Clone, Debug)]
pub struct CloudKeyExercise {
    /// The realm's governing domain.
    pub domain: Digest,
    /// The Exercise nonce.
    pub nonce: Vec<u8>,
    /// The intent.
    pub intent: IntentEnvelope,
    /// Declared basis.
    pub basis: ExerciseBasis,
    /// Declared capacity.
    pub capacity: Capacity,
    /// The device Instance's AIS over the intent.
    pub ais: Vec<u8>,
    /// The identity plane as PEP.
    pub pep: String,
    /// The Party the session's subject is bound to: a live Instance of it must have signed.
    pub actor: Id,
}

/// Where a Mandate stands for the work a permission serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MandateStanding {
    /// Live and covering it until the given Unix ms.
    Covers(u64),
    /// Revoked, past its window, or narrowed so it no longer covers it.
    Ended,
    /// No such Mandate.
    Unknown,
}

/// The authority plane behind One's cloud key permissions.
pub trait CloudKeyAuthority: Send + Sync {
    /// Commits `exercise` as PEP after checking that a live Instance of its actor signed it.
    fn commit(
        &self,
        exercise: CloudKeyExercise,
    ) -> impl Future<Output = Result<Verdict, Unavailable>> + Send;

    /// Where `mandate` of `domain` stands now for the action `name` of `namespace`.
    fn mandate(
        &self,
        domain: Digest,
        mandate: Id,
        action: (&str, &str),
    ) -> impl Future<Output = Result<MandateStanding, Unavailable>> + Send;
}
