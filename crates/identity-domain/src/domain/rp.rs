//! The RP ID rule (OP-156 m.3 (i), §12.1.2, §18.1, TN-17): a realm with passkeys never holds
//! its RP ID on the Suiss base domain. Passkeys need a verified custom domain, and the RP ID is
//! that domain or a registrable parent of it. The local profile's `*.localhost`, and a `*.test`
//! base that exists only in test runs, are no Suiss domain (RFC 6761); there is no switch.

use access_identity_webauthn::domain::psl::Psl;
use access_identity_webauthn::domain::rp::PublicSuffix as _;

use super::host::{Base, at_or_under, dns_name, localhost};

/// Why an RP ID cannot carry the realm's passkeys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RpIdError {
    /// Not a DNS name, or a public suffix.
    #[error("not a registrable name")]
    Name,
    /// On the Suiss base domain, under it or above it.
    #[error("on the Suiss domain")]
    SuissDomain,
    /// It covers none of the realm's verified custom domains nor its own issuer host.
    #[error("no verified custom domain")]
    NoCustomDomain,
}

impl RpIdError {
    /// Stable reason code (RFC 9457).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Name => "invalid-rp-id",
            Self::SuissDomain => "rp-id-on-suiss-domain",
            Self::NoCustomDomain => "passkeys-need-custom-domain",
        }
    }
}

/// Whether `rp_id` lies on the Suiss base domain: the base, a name under it, or a parent of
/// it. Never true for the local profile.
#[must_use]
pub fn on_suiss_domain(rp_id: &str, base: &Base) -> bool {
    base.is_suiss() && base.touches(rp_id)
}

/// Checks that `rp_id` may carry passkeys for a realm whose issuer host is `issuer_host` and
/// whose verified custom domains are `verified`: a registrable name off the Suiss domain that
/// is one of those hosts or a parent of one.
///
/// # Errors
/// [`RpIdError`].
pub fn check(
    rp_id: &str,
    base: &Base,
    issuer_host: &str,
    verified: &[String],
) -> Result<(), RpIdError> {
    let registrable = Psl.registrable(rp_id).is_some();
    if !dns_name(rp_id) || !(registrable || localhost(rp_id)) {
        return Err(RpIdError::Name);
    }
    if on_suiss_domain(rp_id, base) {
        return Err(RpIdError::SuissDomain);
    }
    let covers = |h: &str| at_or_under(h, rp_id);
    if covers(issuer_host) || verified.iter().any(|h| covers(h)) {
        Ok(())
    } else {
        Err(RpIdError::NoCustomDomain)
    }
}

/// The RP ID a realm's passkeys register under, if any: the pinned one when it still passes
/// [`check`], else the issuer host when that is off the Suiss domain. `None` means passkey
/// registration is closed until a verified custom domain is pinned.
#[must_use]
pub fn effective(
    pinned: Option<&str>,
    base: &Base,
    issuer_host: &str,
    verified: &[String],
) -> Option<String> {
    match pinned {
        Some(rp) => check(rp, base, issuer_host, verified)
            .is_ok()
            .then(|| rp.to_owned()),
        None => (!on_suiss_domain(issuer_host, base)).then(|| issuer_host.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-156 m.3 (i), §18.1, TN-17
    #[test]
    fn a_suiss_rp_id_is_refused_and_a_verified_custom_domain_is_required() {
        let base = Base::new("suiss.id");
        let verified = vec![String::from("login.acme.example")];
        let issuer = "acme.suiss.id";
        assert_eq!(
            check("acme.suiss.id", &base, issuer, &verified),
            Err(RpIdError::SuissDomain)
        );
        assert_eq!(
            check("suiss.id", &base, issuer, &verified),
            Err(RpIdError::SuissDomain)
        );
        assert_eq!(
            check("login.acme.example", &base, issuer, &verified),
            Ok(())
        );
        assert_eq!(check("acme.example", &base, issuer, &verified), Ok(()));
        assert_eq!(
            check("other.example", &base, issuer, &verified),
            Err(RpIdError::NoCustomDomain)
        );
        assert_eq!(
            check("example", &base, issuer, &verified),
            Err(RpIdError::Name)
        );
        assert_eq!(
            check("co.uk", &base, issuer, &verified),
            Err(RpIdError::Name)
        );
        assert_eq!(effective(None, &base, issuer, &verified), None);
        assert_eq!(
            effective(Some("acme.example"), &base, issuer, &verified).as_deref(),
            Some("acme.example")
        );
        assert_eq!(effective(Some("acme.example"), &base, issuer, &[]), None);
    }

    // OP-156 m.3 (i), OP-69
    #[test]
    fn localhost_is_not_a_suiss_domain() {
        let base = Base::new("localhost");
        assert_eq!(
            check("acme.localhost", &base, "acme.localhost", &[]),
            Ok(())
        );
        assert_eq!(
            effective(None, &base, "acme.localhost", &[]).as_deref(),
            Some("acme.localhost")
        );
        let issuer_bound = Base::new("suiss.id");
        assert_eq!(
            effective(None, &issuer_bound, "login.acme.example", &[]).as_deref(),
            Some("login.acme.example")
        );
    }
}
