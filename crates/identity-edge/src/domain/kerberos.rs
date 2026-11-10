//! The keytab policy a Kerberos gateway's acceptances are held to (§10.6.4, IDP-17, OP-155
//! m.3 (o)): one exact SPN, AES256 only, and key versions tracked so that a rotated or
//! emergency-replaced key stops being accepted. Sans-I/O.

use access_internal_api::edge::kerberos::{Authenticate, ENCTYPES};
use access_store::edge::KeytabPolicy;

use super::Refusal;

/// How long a ticket under a superseded key version stays acceptable: the default ticket
/// lifetime, after which every ticket issued under the old key has expired.
pub const SUPERSEDED_GRACE_MS: u64 = 10 * 60 * 60 * 1000;

/// One day.
pub const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// Longest keytab rotation period.
pub const MAX_ROTATE_DAYS: u16 = 365;

/// The realm of a principal, the part after its last `@`.
#[must_use]
pub fn realm_of(principal: &str) -> Option<&str> {
    principal
        .rsplit_once('@')
        .map(|(_, r)| r)
        .filter(|r| !r.is_empty())
}

/// Whether `spn` is a service principal `service/host@REALM`.
#[must_use]
pub fn valid_spn(spn: &str) -> bool {
    let Some((name, realm)) = spn.rsplit_once('@') else {
        return false;
    };
    let mut parts = name.split('/');
    let (Some(service), Some(host), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let printable = |s: &str| {
        !s.is_empty()
            && s.len() <= 255
            && s.chars()
                .all(|c| c.is_ascii_graphic() && c != '@' && c != '/' && c != '\\')
    };
    spn.len() <= 512 && printable(service) && printable(host) && printable(realm)
}

/// The user name of `principal` when it is a single-component principal of the SPN's realm,
/// `user@REALM`; `None` otherwise (a service principal or another realm authenticates nobody).
#[must_use]
pub fn user_of<'a>(principal: &'a str, spn: &str) -> Option<&'a str> {
    let (user, realm) = principal.rsplit_once('@')?;
    let simple = !user.is_empty() && !user.contains(['/', '@', '\\']) && user.len() <= 256;
    (simple && Some(realm) == realm_of(spn)).then_some(user)
}

/// SPN, enctype and floor, checked before the key version is recorded.
///
/// # Errors
/// [`Refusal::Spn`], [`Refusal::Enctype`], [`Refusal::Kvno`].
pub fn admissible(p: &KeytabPolicy, q: &Authenticate) -> Result<(), Refusal> {
    if q.spn != p.spn {
        return Err(Refusal::Spn);
    }
    if !ENCTYPES.contains(&q.etype) {
        return Err(Refusal::Enctype);
    }
    if q.kvno < p.kvno_floor {
        return Err(Refusal::Kvno);
    }
    Ok(())
}

/// The key version against every version seen (`(kvno, first seen)`, this one included): a
/// newer version seen longer than [`SUPERSEDED_GRACE_MS`] ago supersedes it, and the newest
/// version first seen longer than the rotation period ago is overdue.
///
/// # Errors
/// [`Refusal::Kvno`].
pub fn current(p: &KeytabPolicy, kvno: u32, seen: &[(u32, u64)], now: u64) -> Result<(), Refusal> {
    let superseded = seen
        .iter()
        .any(|(k, at)| *k > kvno && at.saturating_add(SUPERSEDED_GRACE_MS) < now);
    let period = u64::from(p.rotate_days).saturating_mul(DAY_MS);
    let overdue = seen
        .iter()
        .max_by_key(|(k, _)| *k)
        .is_some_and(|(_, at)| at.saturating_add(period) < now);
    if superseded || overdue {
        Err(Refusal::Kvno)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use access_internal_api::edge::kerberos::{AES256_SHA1, AES256_SHA384};

    use super::*;

    const SPN: &str = "HTTP/access.corp.example@CORP.EXAMPLE";

    fn policy() -> KeytabPolicy {
        KeytabPolicy {
            spn: String::from(SPN),
            rotate_days: 30,
            kvno_floor: 2,
        }
    }

    fn q(spn: &str, etype: i32, kvno: u32) -> Authenticate {
        Authenticate {
            realm: String::from("corp"),
            principal: String::from("ada@CORP.EXAMPLE"),
            spn: String::from(spn),
            kvno,
            etype,
        }
    }

    // IDP-17, OP-155 m.3 (o)
    #[test]
    fn only_the_exact_spn_and_aes256_are_accepted() {
        let p = policy();
        assert!(admissible(&p, &q(SPN, AES256_SHA1, 2)).is_ok());
        assert!(admissible(&p, &q(SPN, AES256_SHA384, 3)).is_ok());
        for wrong in [
            "HTTP/access.corp.example@corp.example",
            "http/access.corp.example@CORP.EXAMPLE",
            "HTTP/Access.corp.example@CORP.EXAMPLE",
            "HTTP/other.corp.example@CORP.EXAMPLE",
            "HTTP/access.corp.example",
        ] {
            assert_eq!(
                admissible(&p, &q(wrong, AES256_SHA1, 2)),
                Err(Refusal::Spn),
                "{wrong}"
            );
        }
        for etype in [23, 17, 19, 3, 1, -128] {
            assert_eq!(
                admissible(&p, &q(SPN, etype, 2)),
                Err(Refusal::Enctype),
                "{etype}"
            );
        }
        assert_eq!(admissible(&p, &q(SPN, AES256_SHA1, 1)), Err(Refusal::Kvno));
    }

    // OP-155 m.3 (o)
    #[test]
    fn a_rotated_key_stops_after_a_ticket_lifetime_and_an_old_key_is_overdue() {
        let p = policy();
        let now = 100 * DAY_MS;
        assert!(current(&p, 3, &[(3, now)], now).is_ok());
        let fresh = [(3, now - DAY_MS), (4, now - SUPERSEDED_GRACE_MS + 1)];
        assert!(current(&p, 3, &fresh, now).is_ok());
        let rotated = [(3, now - DAY_MS), (4, now - SUPERSEDED_GRACE_MS - 1)];
        assert_eq!(current(&p, 3, &rotated, now), Err(Refusal::Kvno));
        assert!(current(&p, 4, &rotated, now).is_ok());
        let stale = [(4, now - 31 * DAY_MS)];
        assert_eq!(current(&p, 4, &stale, now), Err(Refusal::Kvno));
    }

    // IDP-17
    #[test]
    fn only_single_component_principals_of_the_spn_realm_are_users() {
        assert_eq!(user_of("ada@CORP.EXAMPLE", SPN), Some("ada"));
        assert_eq!(user_of("ada@OTHER.EXAMPLE", SPN), None);
        assert_eq!(user_of("HTTP/host@CORP.EXAMPLE", SPN), None);
        assert_eq!(user_of("@CORP.EXAMPLE", SPN), None);
        assert_eq!(user_of("ada", SPN), None);
        assert!(valid_spn(SPN));
        assert!(!valid_spn("HTTP@CORP.EXAMPLE"));
        assert!(!valid_spn("HTTP/a/b@CORP.EXAMPLE"));
        assert!(!valid_spn("HTTP/host@"));
        assert!(!valid_spn("HTTP/ho st@CORP.EXAMPLE"));
    }
}
