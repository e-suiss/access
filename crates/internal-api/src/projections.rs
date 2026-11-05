//! Authority token projections between the planes (§9.9, §11.4.5, OP-150 m.2): the realm's
//! authorization server asks the authority plane to decide a `projection.issue` Exercise, and
//! the answer is either the signed token or the decision that refused it. Every issuance, and
//! every refresh, is its own decision (§9.9.3); the identity plane never mints an authority
//! token itself, and its protocol-scoped tokens never carry authority (OP-146 contracts §5 (c)).

use std::future::Future;

use access_kernel::combinator::{Capacity, Decision};
use access_kernel::digest::Digest;
use access_kernel::intent::IntentEnvelope;
use access_kernel::meta::ExerciseBasis;
use access_kernel::status::StatusRef;

use crate::idp::Unavailable;

/// Stable code of [`Unavailable`] while no projection is served.
pub const UNAVAILABLE: &str = "projection-unavailable";

/// Largest token, in bytes, the authority plane issues (OP-150 m.3 (s)).
pub const MAX_TOKEN_BYTES: usize = 8192;

/// Stable code for a token that would exceed [`MAX_TOKEN_BYTES`] (OP-150 m.3 (s)).
pub const TOKEN_TOO_LARGE: &str = "token-too-large";

/// Stable code when the authority signer cannot be reached (K17): the AS answers 503.
pub const SIGNER_UNAVAILABLE: &str = "signer-unavailable";

/// The token class (§9.9): an exact-intent token for one intent, or a bounds token for a set of
/// actions within the contract's bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TokenKind {
    /// RAR `kind=intent`: one intent envelope, exact.
    Intent,
    /// RAR `kind=bounds`: an authority-set projection.
    Bounds,
}

/// The key the token is bound to (sender-constrained by default, PI-11).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confirmation {
    /// `cnf.jkt`: the RFC 7638 thumbprint of the DPoP key (RFC 9449).
    DpopJkt([u8; 32]),
    /// `cnf.x5t#S256`: the client certificate thumbprint (RFC 8705).
    MtlsX5t([u8; 32]),
}

/// A token projection the authorization server asks for: the signed `projection.issue`
/// Exercise of the actor and the OAuth facts the token must carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenProjectionRequest {
    /// The governing domain.
    pub domain: Digest,
    /// The Exercise nonce.
    pub nonce: Vec<u8>,
    /// The `projection_issue` intent; its `opaque["payload"]` is the payload digest.
    pub intent: IntentEnvelope,
    /// The `projection_issue` payload (CDDL `meta-payload`), deterministic CBOR.
    pub payload: Vec<u8>,
    /// Declared basis.
    pub basis: ExerciseBasis,
    /// Declared capacity; a principal becomes the token's `sub` and the actor its `act`.
    pub capacity: Capacity,
    /// The actor's AIS over the intent.
    pub ais: Vec<u8>,
    /// The identity plane as PEP.
    pub pep: String,
    /// The authorization server's issuer identifier, the token's `iss`.
    pub issuer: String,
    /// The OAuth client the token is for.
    pub client_id: String,
    /// The token class.
    pub kind: TokenKind,
    /// The one intent of an exact-intent token ([`TokenKind::Intent`]); `None` for bounds.
    pub target: Option<IntentEnvelope>,
    /// The key binding.
    pub confirmation: Confirmation,
    /// RFC 8707 resources, which become the audience; never empty (no default resource).
    pub resources: Vec<String>,
    /// Whether this is a refresh: a new decision for the same family (§9.9.3).
    pub family: Option<[u8; 16]>,
}

/// A token the authority plane signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedToken {
    /// The compact JWS, `typ` `at+jwt` (RFC 9068), with `authorization_details` (RFC 9396).
    pub token: String,
    /// The `projection.issue` `ExerciseID`.
    pub exercise: Digest,
    /// Position of its decision record.
    pub position: u64,
    /// Digest of the token's `ValidityContract`.
    pub contract: Digest,
    /// `exp`, trusted time in milliseconds; never past the contract's horizon.
    pub expires_at: u64,
    /// The token's Token Status List entry.
    pub status: Option<StatusRef>,
    /// The refresh family it belongs to.
    pub family: [u8; 16],
}

/// The authority plane's answer to a [`TokenProjectionRequest`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenProjection {
    /// Allowed, committed and signed.
    Issued(IssuedToken),
    /// Denied; the AS answers `access_denied` and issues nothing.
    Denied {
        /// The decision.
        decision: Decision,
        /// Position of its record.
        position: Option<u64>,
    },
    /// Waiting on an action (step-up, approval); the AS answers with what is required.
    RequireAction {
        /// The decision, with its unmet requirements.
        decision: Decision,
        /// Position of its record.
        position: Option<u64>,
    },
    /// No decision: malformed, too large ([`TOKEN_TOO_LARGE`]) or refused.
    Refused {
        /// Stable reason code.
        code: String,
    },
}

/// The authority plane's answer about one of its tokens (RFC 7662, MD-8, §9.9.3 rule 5): what
/// state it reflects, `at_least` the domain's head when it was asked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Introspection {
    /// Signed by the domain's operational key, within its horizon, its family not revoked.
    pub active: bool,
    /// The verified JSON claims, when active.
    pub claims: Option<String>,
    /// The head position the answer reflects (OP-150 m.3 (l)).
    pub as_of: u64,
}

/// Decides and signs authority token projections (CMP-7).
pub trait Projections: Send + Sync {
    /// Decides `request` as a `projection.issue` commit and signs the token when it is allowed.
    fn issue(
        &self,
        request: TokenProjectionRequest,
    ) -> impl Future<Output = Result<TokenProjection, Unavailable>> + Send;

    /// Revokes a refresh family at the domain's head (§9.9.3 rule 6, P50): no refresh of it is
    /// decided again. `true` the first time; an unknown family is `false`.
    fn revoke_family(
        &self,
        domain: Digest,
        family: [u8; 16],
    ) -> impl Future<Output = Result<bool, Unavailable>> + Send;

    /// The current state of the authority token `token` of `domain` (RFC 7662, MD-8). Without
    /// the head or the keys there is no answer; the caller answers `active: false` (OPI-3).
    fn introspect(
        &self,
        domain: Digest,
        token: String,
    ) -> impl Future<Output = Result<Introspection, Unavailable>> + Send;
}

/// The projections of a process that does not serve them yet: every call is [`UNAVAILABLE`].
#[derive(Clone, Copy, Debug, Default)]
pub struct Unserved;

impl Projections for Unserved {
    fn issue(
        &self,
        _request: TokenProjectionRequest,
    ) -> impl Future<Output = Result<TokenProjection, Unavailable>> + Send {
        std::future::ready(Err(Unavailable(String::from(UNAVAILABLE))))
    }

    fn revoke_family(
        &self,
        _domain: Digest,
        _family: [u8; 16],
    ) -> impl Future<Output = Result<bool, Unavailable>> + Send {
        std::future::ready(Err(Unavailable(String::from(UNAVAILABLE))))
    }

    fn introspect(
        &self,
        _domain: Digest,
        _token: String,
    ) -> impl Future<Output = Result<Introspection, Unavailable>> + Send {
        std::future::ready(Err(Unavailable(String::from(UNAVAILABLE))))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use access_kernel::intent::ContextRefs;
    use access_kernel::model::{Id, Window};

    use super::*;
    use crate::instances::core_action;

    // OP-150 m.2, m.3 (s): the stub is the typed unavailable; the token ceiling is 8 KiB
    #[test]
    fn unserved_projection_is_unavailable() {
        let request = TokenProjectionRequest {
            domain: Digest([1; 32]),
            nonce: vec![7; 16],
            intent: IntentEnvelope {
                action: core_action("projection_issue"),
                resources: Vec::new(),
                params: BTreeMap::new(),
                opaque: BTreeMap::new(),
                recipient: None,
                purpose: None,
                context: ContextRefs::default(),
                validity: Window { from: 0, until: 1 },
            },
            payload: Vec::new(),
            basis: ExerciseBasis::Anchor(Id([3; 16])),
            capacity: Capacity::Own,
            ais: Vec::new(),
            pep: String::from("access-identity"),
            issuer: String::from("https://id.example"),
            client_id: String::from("cli_x"),
            kind: TokenKind::Bounds,
            target: None,
            confirmation: Confirmation::DpopJkt([4; 32]),
            resources: vec![String::from("https://rs.example")],
            family: None,
        };
        assert_eq!(
            crate::block_on(Unserved.issue(request)),
            Err(Unavailable(String::from(UNAVAILABLE)))
        );
        assert_eq!(
            crate::block_on(Unserved.revoke_family(Digest([1; 32]), [2; 16])),
            Err(Unavailable(String::from(UNAVAILABLE)))
        );
        assert_eq!(
            crate::block_on(Unserved.introspect(Digest([1; 32]), String::from("t"))),
            Err(Unavailable(String::from(UNAVAILABLE)))
        );
        assert_eq!(MAX_TOKEN_BYTES, 8 * 1024);
    }
}
