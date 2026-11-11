//! The approval behind a `contribute` Exercise between the planes (OP-62, §9.14.1 A, OP-150
//! L6): what a `REQUIRE_ACTION` left for the Approval Surface, and the contribution the surface
//! commits once the approver's single act is done. The identity plane shows the render the
//! decision point produced, never one of its own (§9.14.5 WYSIWYS, XI-8). The contribute intent
//! itself is the Kernel's (`access_kernel::contribution`, OP-149 m.33 (b)), so an approver's
//! device pre-signs the same bytes the plane commits.

use access_kernel::combinator::{Capacity, Unmet};
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
    /// The requirement terms that decision left unmet, with how many proofs each still missed
    /// (§8.17.6.4, OP-157 m.3 (l)).
    pub unmet: Vec<Unmet>,
    /// The contributions to the intent recorded since that decision and not consumed yet.
    pub contributed: Vec<Contributed>,
    /// Whether every record since that decision was read; when not, `contributed` may miss
    /// some and the surface counts nothing.
    pub counted: bool,
}

/// A contribution recorded to an intent (§8.17.6.4): who made it, from which Instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contributed {
    /// The `contribute` class.
    pub class: String,
    /// The contributor's Party.
    pub party: Id,
    /// The contributor's Instance.
    pub instance: Id,
    /// Position of the contribution.
    pub since: u64,
}

/// Whether a viewer may contribute a class now, and how many named holders may (§8.17.6.1,
/// §7.9.5.3, E26, OP-157 m.3 (l)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Eligibility {
    /// The viewer's Party holds a live Grant that lets it contribute the class.
    pub eligible: bool,
    /// The number of named holders, only for a viewer the domain lets see the eligible set.
    pub named: Option<u32>,
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
