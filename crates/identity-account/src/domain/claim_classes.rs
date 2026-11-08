//! The realm issuer's Claim classes outside the Kernel table (OP-153 m.2 N0): their names,
//! value shapes and body digests, as `conformance/cddl/identity-claims.cddl` defines them. The
//! Kernel accepts these classes unchecked (L2-CLB-2); the identity plane builds them here and
//! authority-core reads them by the same names.

use access_kernel::claim::body::BODY_CONTEXT;
use access_kernel::codec::Canonical;
use access_kernel::model::Id;
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::context_digest;

/// A class of the registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IdentityClass {
    /// `recovery_result`: body [`RecoveryResult`] (OP-153 m.3 (c)).
    RecoveryResult,
    /// `domain_verification`: body [`DomainVerification`] (TN-90, OP-153 m.3 (o)).
    DomainVerification,
    /// `membership`: body [`Membership`] (TN-5, OP-153 m.3 (o), (p)).
    Membership,
    /// `guardianship`: body [`Guardianship`] (E53, OP-153 m.3 (q)).
    Guardianship,
    /// `age_range`: an [`AgeRange`] in `value`, no body (OP-153 m.3 (q)).
    AgeRange,
}

impl IdentityClass {
    /// Every class.
    pub const ALL: [Self; 5] = [
        Self::RecoveryResult,
        Self::DomainVerification,
        Self::Membership,
        Self::Guardianship,
        Self::AgeRange,
    ];

    /// The wire name (L2-CLB-1: an ident).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RecoveryResult => "recovery_result",
            Self::DomainVerification => "domain_verification",
            Self::Membership => "membership",
            Self::Guardianship => "guardianship",
            Self::AgeRange => "age_range",
        }
    }

    /// The class of a wire name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.name() == name)
    }

    /// Whether the Claim's `value` is a body digest (L2-CLB-2).
    #[must_use]
    pub const fn has_body(self) -> bool {
        !matches!(self, Self::AgeRange)
    }
}

/// The digest a Claim of `class` carries in `value` for `body` (L2-CLB-1).
///
/// # Errors
/// The body cannot be encoded.
pub fn digest(class: IdentityClass, body: &Value) -> Result<[u8; 32], dcbor::EncodeError> {
    let bytes = dcbor::encode(
        &Value::Array(vec![Value::text(class.name()), body.clone()]),
        Limits::CEILING,
    )?;
    Ok(context_digest(BODY_CONTEXT, &bytes).0)
}

/// The recovery class that proved a recovery (TN-52, OP-153 m.3 (d)).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RecoveryPath {
    /// A registered recovery code.
    RegisteredCode,
    /// A code sent to a registered address.
    SentCode,
    /// A recovery contact's code.
    RecoveryContact,
    /// A second, independent authenticator (TN-63).
    SecondAuthenticator,
    /// Identity re-proofing; its provider adapter comes later (Stage 10).
    IdentityReproofing,
    /// A support agent's reset-intent token (TN-61).
    ResetIntent,
    /// A temporary access pass (TN-62).
    TemporaryAccessPass,
}

impl RecoveryPath {
    /// The wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RegisteredCode => "registered_code",
            Self::SentCode => "sent_code",
            Self::RecoveryContact => "recovery_contact",
            Self::SecondAuthenticator => "second_authenticator",
            Self::IdentityReproofing => "identity_reproofing",
            Self::ResetIntent => "reset_intent",
            Self::TemporaryAccessPass => "temporary_access_pass",
        }
    }
}

/// A finished recovery naming the successor key that may self-sign `instance_recover`
/// (OP-153 m.3 (c)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryResult {
    /// The recovered Party.
    pub party: Id,
    /// `x5t#S256` of the successor key.
    pub successor: [u8; 32],
    /// The recovery attempt.
    pub attempt: Id,
    /// What proved it.
    pub path: RecoveryPath,
    /// The AAL the path reached: 1, 2 or 3.
    pub achieved_aal: u8,
}

/// How an organization proved control of a domain (TN-90).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VerificationMethod {
    /// DNS TXT at `_suiss-access.<domain>`.
    DnsTxt,
    /// HTTPS at `/.well-known/suiss-access-verify`.
    Https,
    /// The upstream identity provider's `hd` or `tid`.
    Idp,
}

impl VerificationMethod {
    /// The wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::DnsTxt => "dns_txt",
            Self::Https => "https",
            Self::Idp => "idp",
        }
    }
}

/// A domain an organization proved control of (OP-153 m.3 (o)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainVerification {
    /// The organization's Party.
    pub organization: Id,
    /// The domain, lower case.
    pub domain: String,
    /// How.
    pub method: VerificationMethod,
    /// When, Unix ms.
    pub verified_at: u64,
}

/// A person's membership of an organization (OP-153 m.3 (o), (p)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Membership {
    /// The organization's Party.
    pub organization: Id,
    /// The member's Party.
    pub member: Id,
    /// An owner: the organization keeps at least one (OP-153 m.3 (p)).
    pub root: bool,
    /// Since, Unix ms.
    pub since: u64,
}

/// What a guardianship rests on (E53).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GuardianshipBasis {
    /// A parent.
    Parent,
    /// A legal guardian.
    LegalGuardian,
}

impl GuardianshipBasis {
    /// The wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Parent => "parent",
            Self::LegalGuardian => "legal_guardian",
        }
    }
}

/// A guardian's standing for a ward (OP-153 m.3 (q)); effective only with an Acceptance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Guardianship {
    /// The guardian's Party.
    pub guardian: Id,
    /// The ward's Party.
    pub ward: Id,
    /// On what basis.
    pub basis: GuardianshipBasis,
    /// Majority, Unix ms, from the country table.
    pub until: Option<u64>,
}

/// An age band (OP-153 m.3 (q)); the date of birth stays in the PII vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AgeRange {
    /// Under 13.
    Under13,
    /// 13 to 15.
    Age13To15,
    /// 16 to 17.
    Age16To17,
    /// 18 or over.
    Age18Plus,
}

impl AgeRange {
    /// The wire name, carried in the Claim's `value`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Under13 => "under_13",
            Self::Age13To15 => "age_13_15",
            Self::Age16To17 => "age_16_17",
            Self::Age18Plus => "age_18_plus",
        }
    }
}

fn map(fields: Vec<(&str, Value)>) -> Value {
    Value::Map(
        fields
            .into_iter()
            .map(|(k, v)| (Value::text(k), v))
            .collect(),
    )
}

impl RecoveryResult {
    /// The body.
    #[must_use]
    pub fn to_value(&self) -> Value {
        map(vec![
            ("party", self.party.to_value()),
            ("successor", Value::Bytes(self.successor.to_vec())),
            ("attempt", self.attempt.to_value()),
            ("path", Value::text(self.path.name())),
            (
                "achieved_aal",
                Value::Unsigned(u64::from(self.achieved_aal)),
            ),
        ])
    }
}

impl DomainVerification {
    /// The body.
    #[must_use]
    pub fn to_value(&self) -> Value {
        map(vec![
            ("organization", self.organization.to_value()),
            ("domain", Value::text(&self.domain)),
            ("method", Value::text(self.method.name())),
            ("verified_at", Value::Unsigned(self.verified_at)),
        ])
    }
}

impl Membership {
    /// The body.
    #[must_use]
    pub fn to_value(&self) -> Value {
        map(vec![
            ("organization", self.organization.to_value()),
            ("member", self.member.to_value()),
            ("root", Value::Bool(self.root)),
            ("since", Value::Unsigned(self.since)),
        ])
    }
}

impl Guardianship {
    /// The body.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut fields = vec![
            ("guardian", self.guardian.to_value()),
            ("ward", self.ward.to_value()),
            ("basis", Value::text(self.basis.name())),
        ];
        if let Some(u) = self.until {
            fields.push(("until", Value::Unsigned(u)));
        }
        map(fields)
    }
}

#[cfg(test)]
mod tests;
