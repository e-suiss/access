//! Step-up as an interaction, not a surface (§8.5, §8.17.5.4, §12.2.3 TN-O3, X29; OP-150 L6):
//! the ceremony opens inline in S1, S3 or a domain flow and is asked for by exactly two sources,
//! an unmet `authentication` `RequirementTerm` of the authority plane or the identity plane's own
//! session policy (X-L3). It names the exact action it is for, it reaches the term's assurance
//! and freshness, and it grants nothing: a stepped-up session is not an allowed Exercise.

use access_kernel::assurance::{HARDWARE_BOUND, NON_CUSTODIAL, PHISHING_RESISTANT, UV};
use access_kernel::claim::body::Class;
use access_kernel::model::{Binding, ProofKind, RequirementTerm};

use super::assurance::Aal;

/// Who asked for the step-up (§8.17.5.4; X-L3: no other source may).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// An unmet `authentication` `RequirementTerm` of a decision (`REQUIRE_ACTION`).
    Requirement,
    /// The identity plane's session policy: `max_age`, `prompt=login`, `acr_values` (TN-44).
    SessionPolicy,
}

/// What the ceremony must reach.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ask {
    /// How fresh the authentication must be: `max_age`, mandatory (TN-44).
    pub max_age_ms: u64,
    /// The AAL the steps must reach.
    pub min_aal: Aal,
    /// User verification is demanded of the passkey step (CT2+).
    pub require_uv: bool,
    /// Only a phishing-resistant step counts (§13.7.3: every CT).
    pub phishing_resistant: bool,
    /// H(AAS) the assertion must commit to, when the term binds the intent digest (CT2+); such a
    /// term is met on the Approval Surface, never by a bare re-authentication (TN-44 rule 3).
    pub statement: Option<[u8; 32]>,
    /// Who asked.
    pub source: Source,
}

impl Ask {
    /// The step-up an unmet `authentication` term asks for (§13.7.3, OP-111 m.4): `None` for a
    /// term of another kind or class, or one without a freshness ceiling (no `max_age`, no
    /// step-up), or one bound to an intent digest without the digest at hand.
    #[must_use]
    pub fn from_term(term: &RequirementTerm, statement: Option<[u8; 32]>) -> Option<Self> {
        if term.proof_kind != ProofKind::Claim || term.class != Class::Authentication.name() {
            return None;
        }
        let max_age_ms = term.freshness_ms?;
        let floor = |dim: &str| term.assurance.get(dim).copied().unwrap_or(0);
        let require_uv = floor(UV) >= 1;
        let hardware = floor(HARDWARE_BOUND) >= 1 || floor(NON_CUSTODIAL) >= 1;
        let aal_floor = match floor("aal") {
            3 => Aal::Aal3,
            2 => Aal::Aal2,
            _ => Aal::Aal1,
        };
        let implied = if hardware && require_uv {
            Aal::Aal3
        } else if require_uv {
            Aal::Aal2
        } else {
            Aal::Aal1
        };
        let statement = match term.binding {
            Binding::IntentDigest => Some(statement?),
            Binding::None | Binding::ActorInstance | Binding::Resource => None,
        };
        Some(Self {
            max_age_ms,
            min_aal: aal_floor.max(implied),
            require_uv,
            phishing_resistant: floor(PHISHING_RESISTANT) >= 1,
            statement,
            source: Source::Requirement,
        })
    }

    /// The step-up the session policy asks for: OIDC `max_age` or `acr_values` on a live
    /// session (TN-44).
    #[must_use]
    pub const fn from_policy(max_age_ms: u64, min_aal: Aal) -> Self {
        Self {
            max_age_ms,
            min_aal,
            require_uv: matches!(min_aal, Aal::Aal2 | Aal::Aal3),
            phishing_resistant: false,
            statement: None,
            source: Source::SessionPolicy,
        }
    }

    /// Whether a re-authentication alone can meet the ask: a statement-bound term cannot, it
    /// needs the Approval Surface and an assertion over H(AAS) (TN-44 rule 3, §13.7.3).
    #[must_use]
    pub const fn by_reauthentication(&self) -> bool {
        self.statement.is_none()
    }
}

#[cfg(test)]
mod tests {
    use access_kernel::assurance::authentication_term;
    use access_kernel::tier::Tier;

    use super::*;

    // §8.5, §8.17.5.4, TN-O3, X29, OP-111 m.4: the step-up is driven by the term: its freshness
    // is max_age, its floors the AAL and UV, its binding whether a statement is needed
    #[test]
    fn a_requirement_term_drives_the_step_up() {
        let ct1 = Ask::from_term(&authentication_term(Tier::Ct1, false), None).unwrap();
        assert_eq!(ct1.max_age_ms, 15 * 60_000);
        assert_eq!(ct1.min_aal, Aal::Aal1);
        assert!(!ct1.require_uv && ct1.phishing_resistant);
        assert_eq!(ct1.statement, None);
        assert!(ct1.by_reauthentication());
        assert_eq!(ct1.source, Source::Requirement);

        let h = [7; 32];
        let ct2 = Ask::from_term(&authentication_term(Tier::Ct2, true), Some(h)).unwrap();
        assert_eq!(ct2.max_age_ms, 5 * 60_000);
        assert_eq!(ct2.min_aal, Aal::Aal2);
        assert!(ct2.require_uv);
        assert_eq!(ct2.statement, Some(h));
        assert!(!ct2.by_reauthentication());

        let ct3 = Ask::from_term(&authentication_term(Tier::Ct3, true), Some(h)).unwrap();
        assert_eq!(ct3.min_aal, Aal::Aal3);
        // TN-44 rule 3: an intent-bound term without its digest cannot be stepped up
        assert_eq!(
            Ask::from_term(&authentication_term(Tier::Ct2, false), None),
            None
        );
    }

    // §8.17.5.4, X-L3: only an authentication term or the session policy asks; another term,
    // or one without freshness, asks for no re-authentication
    #[test]
    fn only_authentication_terms_with_freshness_ask() {
        let mut other = authentication_term(Tier::Ct1, false);
        other.class = String::from("kyc");
        assert_eq!(Ask::from_term(&other, None), None);
        let mut contribution = authentication_term(Tier::Ct1, false);
        contribution.proof_kind = ProofKind::Contribution;
        assert_eq!(Ask::from_term(&contribution, None), None);
        let mut timeless = authentication_term(Tier::Ct1, false);
        timeless.freshness_ms = None;
        assert_eq!(Ask::from_term(&timeless, None), None);
        let policy = Ask::from_policy(300_000, Aal::Aal2);
        assert_eq!(policy.source, Source::SessionPolicy);
        assert!(policy.require_uv && policy.by_reauthentication());
        assert_eq!(policy.max_age_ms, 300_000);
    }

    // §13.7.3: an explicit AAL floor is kept when it is above what the flags imply
    #[test]
    fn the_aal_floor_is_the_higher_of_flags_and_the_term() {
        let mut term = authentication_term(Tier::Ct1, false);
        term.assurance.insert(String::from("aal"), 3);
        assert_eq!(Ask::from_term(&term, None).unwrap().min_aal, Aal::Aal3);
    }
}
