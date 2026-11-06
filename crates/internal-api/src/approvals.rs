//! The approval behind a `contribute` Exercise between the planes (OP-62, §9.14.1 A, OP-150
//! L6): what a `REQUIRE_ACTION` left for the Approval Surface, and the contribution the surface
//! commits once the approver's single act is done. The identity plane shows the render the
//! decision point produced, never one of its own (§9.14.5 WYSIWYS, XI-8). The contribute intent
//! itself is the Kernel's (`access_kernel::contribution`, OP-149 m.33 (b)), so an approver's
//! device pre-signs the same bytes the plane commits.

use access_kernel::combinator::Capacity;
pub use access_kernel::contribution::{
    NAMESPACE as CONTRIBUTION_NAMESPACE, contribute_intent, contribute_payload,
};
use access_kernel::digest::Digest;
use access_kernel::meta::ExerciseBasis;
use access_kernel::model::{Id, Window};

/// What the decision point recorded when it asked for an approval of an intent (§9.14.1 step
/// 1, §13.7.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opening {
    /// The render digest it computed from the accepted Action Schema (§9.13.3).
    pub render_digest: Digest,
    /// The render itself, dCBOR (`access_kernel::render`), when the decision point kept it.
    pub render: Option<Vec<u8>>,
    /// The intent's consequence tier, 0 to 3.
    pub tier: u8,
}

/// A contribution the Approval Surface commits as PEP (§9.14.1 A step 4): the approver
/// Instance's AIS over [`contribute_intent`], the Approval Act Statement and the
/// `authentication` Claim bound to its digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contribution {
    /// The domain of the target request.
    pub domain: Digest,
    /// The contribution's nonce: the AAS `exercise_ref`.
    pub nonce: Vec<u8>,
    /// The target intent digest.
    pub target: Digest,
    /// The `contribute` class.
    pub class: String,
    /// The approver's basis for the class.
    pub basis: ExerciseBasis,
    /// Capacity.
    pub capacity: Capacity,
    /// The intent's validity.
    pub validity: Window,
    /// The approver Instance's AIS (`COSE_Sign1`) over the contribute intent.
    pub ais: Vec<u8>,
    /// The Approval Act Statement, dCBOR.
    pub aas: Vec<u8>,
    /// The recorded `authentication` Claim bound to H(AAS).
    pub claim: Id,
    /// The identity plane as PEP.
    pub pep: String,
}
