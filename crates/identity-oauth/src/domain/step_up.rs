//! The RFC 9470 step-up bridge (§9.4 A ADOPT, §12.2.3 TN-O3, TN-44, X-L4; OP-150 L6): a
//! resource server or MCP server answers an authentication-strength shortfall with `401` and
//! `WWW-Authenticate: Bearer error="insufficient_user_authentication"`. `max_age` is mandatory,
//! `acr_values` advisory. The challenge carries no intent digest, so a CT2+ term bound to the
//! intent (H(AAS)) never travels this way: it is met by `REQUIRE_ACTION` and an approval. The
//! challenge is not authority (X29).

use access_kernel::claim::body::Class;
use access_kernel::model::{Binding, ProofKind, RequirementTerm};

use super::tokens::acr;
use access_identity_session::domain::assurance::Aal;

/// The RFC 9470 error code.
pub const ERROR: &str = "insufficient_user_authentication";

/// What the challenge asks the client to obtain (RFC 9470 §3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    /// Seconds since the user authenticated, at most; from the term's freshness.
    pub max_age_s: u64,
    /// The `acr` asked for, when the term's floors name an AAL above 1.
    pub acr: Option<Aal>,
}

fn aal_of(term: &RequirementTerm) -> Option<Aal> {
    let floor = |dim: &str| term.assurance.get(dim).copied().unwrap_or(0);
    let hardware = floor("hardware_bound") >= 1 || floor("non_custodial") >= 1;
    let uv = floor("uv") >= 1;
    let implied = if hardware && uv {
        Aal::Aal3
    } else if uv {
        Aal::Aal2
    } else {
        Aal::Aal1
    };
    let named = match floor("aal") {
        3 => Aal::Aal3,
        2 => Aal::Aal2,
        _ => Aal::Aal1,
    };
    let aal = named.max(implied);
    (aal > Aal::Aal1).then_some(aal)
}

/// The challenge for an unmet term: `Some` only for an `authentication` Claim term that is not
/// bound to the intent digest and has a freshness ceiling (TN-44). A term bound to the intent,
/// of another class or kind, or without freshness has no RFC 9470 answer.
#[must_use]
pub fn challenge(term: &RequirementTerm) -> Option<Challenge> {
    if term.proof_kind != ProofKind::Claim || term.class != Class::Authentication.name() {
        return None;
    }
    if !matches!(term.binding, Binding::None | Binding::ActorInstance) {
        return None;
    }
    let ms = term.freshness_ms?;
    Some(Challenge {
        max_age_s: ms.div_ceil(1_000).max(1),
        acr: aal_of(term),
    })
}

impl Challenge {
    /// The `WWW-Authenticate` value (RFC 9470 §3, RFC 6750 §3).
    #[must_use]
    pub fn www_authenticate(&self) -> String {
        let mut out = format!(
            "Bearer error=\"{ERROR}\", error_description=\"A fresher or stronger user authentication is required\", max_age={}",
            self.max_age_s
        );
        if let Some(a) = self.acr {
            out.push_str(", acr_values=\"");
            out.push_str(acr(a));
            out.push('"');
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use access_kernel::assurance::authentication_term;
    use access_kernel::tier::Tier;

    use super::*;

    // §9.4, §12.2.3 TN-O3, TN-44
    #[test]
    fn a_strength_shortfall_becomes_a_challenge() {
        let c = challenge(&authentication_term(Tier::Ct1, false)).unwrap();
        assert_eq!(c.max_age_s, 900);
        assert_eq!(c.acr, None);
        let h = c.www_authenticate();
        assert!(h.starts_with("Bearer error=\"insufficient_user_authentication\""));
        assert!(h.contains("max_age=900"));
        assert!(!h.contains("acr_values"));
        let mut strong = authentication_term(Tier::Ct1, false);
        strong.assurance.insert(String::from("aal"), 2);
        let c = challenge(&strong).unwrap();
        assert_eq!(c.acr, Some(Aal::Aal2));
        assert!(
            c.www_authenticate()
                .contains("acr_values=\"http://idmanagement.gov/ns/assurance/aal/2\"")
        );
    }

    // TN-44 rule 3, §13.7.3
    #[test]
    fn intent_bound_terms_never_travel_the_bridge() {
        assert_eq!(challenge(&authentication_term(Tier::Ct2, false)), None);
        assert_eq!(challenge(&authentication_term(Tier::Ct3, true)), None);
        let mut resource = authentication_term(Tier::Ct1, false);
        resource.binding = Binding::Resource;
        assert_eq!(challenge(&resource), None);
    }

    // TN-44
    #[test]
    fn only_fresh_authentication_terms_qualify() {
        let mut timeless = authentication_term(Tier::Ct1, false);
        timeless.freshness_ms = None;
        assert_eq!(challenge(&timeless), None);
        let mut other = authentication_term(Tier::Ct1, false);
        other.class = String::from("posture_device");
        assert_eq!(challenge(&other), None);
        let mut contribution = authentication_term(Tier::Ct1, false);
        contribution.proof_kind = ProofKind::Contribution;
        assert_eq!(challenge(&contribution), None);
        let mut short = authentication_term(Tier::Ct1, false);
        short.freshness_ms = Some(1);
        assert_eq!(challenge(&short).unwrap().max_age_s, 1);
    }
}
