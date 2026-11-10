//! Secret release at a secret store that is its own PEP (E22, E36, §7.9.12.4, IDP-39, OP-156
//! m.3 (x)): the store keeps the secret, Access decides whether it may leave. A release is the
//! `secret.release` intent on one `secret:[mount, path…]` resource; the store asks Access with
//! the requester's own statement ([`crate::authorize::Pep::authorize`]) and hands the secret out
//! only through [`Releases::release`], which checks the release Exercise reference first: an
//! ALLOW for exactly this secret, inside the intent's validity, never used before.
//!
//! There is no release without an [`Authorized`]: no token, no session and no earlier release
//! stands in for one: a release without an Exercise is unauthorized (E36). Holding the secret is
//! never authority, and what the secret opens upstream is not Access's guarantee (N-54).

use alloc::string::String;
use alloc::vec::Vec;

use access_kernel::digest::Digest;
use access_kernel::intent::IntentEnvelope;
use access_kernel::model::{ResourceRef, TrustedTime};
use suiss_crypto::digest::context_digest;

use crate::authorize::{Authorized, Evidence, Intent};
use crate::resource::{Replay, ReplayStore};
use crate::transport::Clock;

/// The action namespace of a release.
pub const NAMESPACE: &str = "secret";

/// The action name of a release: `secret.release`.
pub const ACTION: &str = "release";

/// The resource namespace of a secret: `secret:[mount, path…]`.
pub const RESOURCE_NAMESPACE: &str = "secret";

/// Digest context of a release's single use.
pub const RELEASE_CONTEXT: &str = "access/secret-release/v1";

/// One secret of a store: its mount and its path inside the mount.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretRef {
    /// The mount, the first resource path segment.
    pub mount: String,
    /// The path inside the mount.
    pub path: Vec<String>,
}

impl SecretRef {
    /// The resource a release of it names.
    #[must_use]
    pub fn resource(&self) -> ResourceRef {
        let mut path = Vec::with_capacity(self.path.len().saturating_add(1));
        path.push(self.mount.clone());
        path.extend(self.path.iter().cloned());
        ResourceRef {
            namespace: String::from(RESOURCE_NAMESPACE),
            path,
            incarnation: 0,
        }
    }

    /// Whether `envelope` is a release of exactly this secret and nothing else.
    #[must_use]
    pub fn released_by(&self, envelope: &IntentEnvelope) -> bool {
        envelope.action.namespace == NAMESPACE
            && envelope.action.name == ACTION
            && envelope.resources.len() == 1
            && envelope.resources.first().is_some_and(|r| {
                r.namespace == RESOURCE_NAMESPACE && r.path == self.resource().path
            })
    }
}

/// Why a store does not release. A value, not an error: every variant keeps the secret in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Refused {
    /// No trusted time.
    #[error("release-clock")]
    Clock,
    /// The intent is known only by its digest: the store cannot see what it releases.
    #[error("release-intent-unknown")]
    Unknown,
    /// The allowed intent is not `secret.release` of this one secret.
    #[error("release-other-secret")]
    OtherSecret,
    /// Outside the allowed intent's validity.
    #[error("release-outside-validity")]
    OutsideValidity,
    /// This Exercise released a secret already: an Exercise releases once.
    #[error("release-already-used")]
    AlreadyUsed,
    /// The single-use store did not answer; nothing is released unrecorded (MD-8).
    #[error("release-store-unavailable")]
    StoreUnavailable,
    /// The body about to run is not the allowed intent (INV-19).
    #[error("release-intent-body")]
    Body,
}

impl Refused {
    /// Its stable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Clock => "release-clock",
            Self::Unknown => "release-intent-unknown",
            Self::OtherSecret => "release-other-secret",
            Self::OutsideValidity => "release-outside-validity",
            Self::AlreadyUsed => "release-already-used",
            Self::StoreUnavailable => "release-store-unavailable",
            Self::Body => "release-intent-body",
        }
    }
}

/// What a release hands out: the effect's value with the reference the store records with it
/// (EI-10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Released<T> {
    /// What the release effect returned.
    pub value: T,
    /// The release Exercise.
    pub exercise: Digest,
    /// The position the decision reflects.
    pub as_of: u64,
    /// Unix milliseconds the release may be used until: the end of the intent's validity.
    pub until: TrustedTime,
}

/// The single-use key of the release Exercise `exercise`.
#[must_use]
pub fn release_key(exercise: &Digest) -> [u8; 32] {
    context_digest(RELEASE_CONTEXT, &exercise.0).0
}

/// The store's release gate over its single-use port `spent`, shared by every replica of one
/// store.
#[derive(Debug)]
pub struct Releases<S> {
    spent: S,
}

impl<S: ReplayStore> Releases<S> {
    /// A gate recording each release Exercise in `spent`.
    #[must_use]
    pub const fn new(spent: S) -> Self {
        Self { spent }
    }

    /// Releases `asked` through `effect` only under `authorized` for `intent` (E36, INV-19): the
    /// intent is `secret.release` of exactly `asked`, now is inside its validity, and its
    /// Exercise was never released before. The proof is consumed either way.
    ///
    /// # Errors
    /// [`Refused`]: `effect` does not run.
    pub fn release<R, A, T>(
        &self,
        authorized: Authorized<R, A>,
        intent: &Intent<R, A>,
        asked: &SecretRef,
        clock: &impl Clock,
        effect: impl FnOnce(Evidence<'_>) -> T,
    ) -> Result<Released<T>, Refused> {
        let now = clock.now().ok_or(Refused::Clock)?;
        let envelope = intent.envelope().ok_or(Refused::Unknown)?;
        // E36, §7.9.12.4
        if !asked.released_by(envelope) {
            return Err(Refused::OtherSecret);
        }
        let validity = envelope.validity;
        if now < validity.from || now > validity.until {
            return Err(Refused::OutsideValidity);
        }
        if authorized.intent() != intent.digest() {
            return Err(Refused::Body);
        }
        let exercise = *authorized.exercise();
        let as_of = authorized.as_of();
        match self.spent.record(&release_key(&exercise), validity.until) {
            Replay::Fresh => {}
            Replay::Seen => return Err(Refused::AlreadyUsed),
            Replay::Unavailable => return Err(Refused::StoreUnavailable),
        }
        let value = authorized
            .apply(intent.digest(), effect)
            .map_err(|_| Refused::Body)?;
        Ok(Released {
            value,
            exercise,
            as_of,
            until: validity.until,
        })
    }
}

#[cfg(test)]
mod tests;
