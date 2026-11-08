//! Claim Ingest between the planes (CMP-8, §9.13, OP-150 m.2): the identity plane, an upstream
//! carrier adapter or a PEP hands a Claim to the authority plane, which records it as a `claim`
//! record with a disposition. Ingest is not acceptance (INV-2): an admitted Claim counts only
//! while an Acceptance covers it, and nothing here writes authority state other than through the
//! sequencer (PI-22). The authority plane never writes to the identity plane through this seam.

use std::future::Future;

use access_kernel::claim::{Channel, Disposition};
use access_kernel::digest::Digest;
use access_kernel::model::Id;

use crate::idp::Unavailable;

/// Stable code of [`Unavailable`] while no ingest is served.
pub const UNAVAILABLE: &str = "claim-ingest-unavailable";

/// How the Claim arrived (§10.1.2, OP-150 m.3 (i)). The carrier adapter maps its protocol to a
/// Claim before submission; the carrier is kept for the ingest record and quotas.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Carrier {
    /// A `COSE_Sign1` Claim signed by an Instance of its issuer (L2-CLM-1).
    Cose,
    /// An unsigned Claim over an authenticated channel (L2-CLM-5); a PEP fact when the
    /// channel is a PEP.
    Unsigned(Channel),
    /// Mapped from a WebAuthn ceremony of the realm's RP.
    Webauthn,
    /// Mapped from an upstream OpenID provider's ID token.
    Oidc,
    /// Mapped from a Security Event Token (SSF, CAEP, RISC).
    Set,
}

impl Carrier {
    /// The carrier's name in the ingest record.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Cose => "cose",
            Self::Unsigned(Channel::Pep(_)) => "pep",
            Self::Unsigned(Channel::Scim(_)) => "scim",
            Self::Webauthn => "webauthn",
            Self::Oidc => "oidc",
            Self::Set => "set",
        }
    }
}

/// One Claim to ingest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimSubmission {
    /// The domain it is for.
    pub domain: Digest,
    /// How it arrived.
    pub carrier: Carrier,
    /// The Claim bytes as received: a `COSE_Sign1`, or an `unsigned-claim` (L2-CLM-1, L2-CLM-5).
    pub claim: Vec<u8>,
    /// The body beside it, when its class has one and it is disclosed (L2-CLB-1); `None` keeps
    /// the Claim digest-valued (E26).
    pub body: Option<Vec<u8>>,
    /// Digest of the raw carrier artefact (ID token, SET, assertion) kept in the PII vault
    /// (§10.1.2 rule 1); never the artefact itself.
    pub evidence: Option<Digest>,
}

/// Why a recorded Claim is held and not used (L2-CLM-3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Quarantine {
    /// No Acceptance covers it.
    SourceNotAccepted,
    /// Signed too far ahead of trusted time.
    Future,
    /// The issuer's quota is used up (G44): only qualifying Claims are held for it.
    Quota,
}

impl Quarantine {
    /// The quarantine reason of a Kernel disposition; `None` for `admit`.
    #[must_use]
    pub const fn of(d: Disposition) -> Option<Self> {
        match d {
            Disposition::Admit => None,
            Disposition::SourceNotAccepted => Some(Self::SourceNotAccepted),
            Disposition::Future => Some(Self::Future),
            Disposition::Quota => Some(Self::Quota),
        }
    }

    /// The reason word, as in `claim-fields` without its `quarantine:` prefix.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::SourceNotAccepted => "source-not-accepted",
            Self::Future => "future",
            Self::Quota => "quota",
        }
    }
}

/// The authority plane's answer to a [`ClaimSubmission`] (§9.13 rule 3: admit, quarantine or
/// reasoned reject; nothing is dropped silently).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClaimVerdict {
    /// Recorded and admitted.
    Admitted {
        /// The `ClaimID`.
        claim: Id,
        /// Position of its `claim` record.
        position: u64,
        /// Whether an earlier submission had already admitted it.
        replayed: bool,
    },
    /// Recorded and held.
    Quarantined {
        /// The `ClaimID`.
        claim: Id,
        /// Position of its `claim` record.
        position: u64,
        /// Why.
        reason: Quarantine,
    },
    /// Not recorded: the Claim is malformed or does not verify.
    Rejected {
        /// Stable reason code (`claim-signature`, `claim-payload`, `claim-value`, `claim-body`,
        /// `claim-body-digest`, ...).
        code: String,
    },
}

/// Ingests Claims into a domain (CMP-8).
pub trait ClaimIngest: Send + Sync {
    /// Verifies, records and disposes of `submission`.
    fn ingest(
        &self,
        submission: ClaimSubmission,
    ) -> impl Future<Output = Result<ClaimVerdict, Unavailable>> + Send;
}

/// The ingest of a process that does not serve it yet: every call is [`UNAVAILABLE`].
#[derive(Clone, Copy, Debug, Default)]
pub struct Unserved;

impl ClaimIngest for Unserved {
    fn ingest(
        &self,
        _submission: ClaimSubmission,
    ) -> impl Future<Output = Result<ClaimVerdict, Unavailable>> + Send {
        std::future::ready(Err(Unavailable(String::from(UNAVAILABLE))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-150 m.2, CMP-8
    #[test]
    fn unserved_ingest_is_unavailable() {
        let submission = ClaimSubmission {
            domain: Digest([1; 32]),
            carrier: Carrier::Unsigned(Channel::Pep([2; 32])),
            claim: vec![0xa0],
            body: None,
            evidence: None,
        };
        let got = crate::block_on(Unserved.ingest(submission));
        assert_eq!(got, Err(Unavailable(String::from(UNAVAILABLE))));
        assert_eq!(Carrier::Unsigned(Channel::Pep([0; 32])).name(), "pep");
        assert_eq!(Quarantine::of(Disposition::Admit), None);
        assert_eq!(
            Quarantine::of(Disposition::Quota).map(Quarantine::word),
            Some("quota")
        );
    }
}
