//! The OIDC `claims` request parameter (OIDC Core §5.5, §10.4.6, OP-148) and honest e-mail and
//! profile claims: an address is released with `email_verified: true` only when the account
//! proved control of it; an address a provider gave without vouching is never released (IDP-31
//! (3), OP-153 m.3 (l)). A claim is a release of identity data, never authority (OP-153 m.3 (z)).

use std::collections::BTreeSet;

use serde_json::{Map, Value};

/// Longest `claims` parameter read.
pub const MAX_CLAIMS_PARAM: usize = 4096;

/// The claims this realm can release.
pub const SUPPORTED: [&str; 7] = [
    "email",
    "email_verified",
    "name",
    "given_name",
    "family_name",
    "locale",
    "zoneinfo",
];

/// Where a requested claim goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// The ID token.
    IdToken,
    /// The user-info answer.
    Userinfo,
}

/// The claims a request asks for, per target; unknown claims are left out (OIDC Core §5.5).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Requested {
    /// For the ID token.
    pub id_token: BTreeSet<&'static str>,
    /// For user-info.
    pub userinfo: BTreeSet<&'static str>,
}

/// The `claims` parameter is not a JSON object of the §5.5 shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid claims parameter")]
pub struct InvalidClaims;

fn members(v: Option<&Value>) -> Result<BTreeSet<&'static str>, InvalidClaims> {
    let Some(v) = v else {
        return Ok(BTreeSet::new());
    };
    let m = v.as_object().ok_or(InvalidClaims)?;
    let mut out = BTreeSet::new();
    for (name, spec) in m {
        let ok = match spec {
            Value::Null => true,
            Value::Object(o) => o.iter().all(|(k, v)| match k.as_str() {
                "essential" => v.is_boolean(),
                "values" => v.is_array(),
                _ => true,
            }),
            _ => false,
        };
        if !ok {
            return Err(InvalidClaims);
        }
        if let Some(s) = SUPPORTED.iter().find(|s| **s == name.as_str()) {
            out.insert(*s);
        }
    }
    Ok(out)
}

/// Parses the `claims` parameter.
///
/// # Errors
/// [`InvalidClaims`].
pub fn parse(raw: &str) -> Result<Requested, InvalidClaims> {
    if raw.len() > MAX_CLAIMS_PARAM {
        return Err(InvalidClaims);
    }
    let v: Value = serde_json::from_str(raw).map_err(|_| InvalidClaims)?;
    let top = v.as_object().ok_or(InvalidClaims)?;
    Ok(Requested {
        id_token: members(top.get("id_token"))?,
        userinfo: members(top.get("userinfo"))?,
    })
}

/// What the account holds to release.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Held {
    /// Its e-mail identifier whose mailbox it proved (TN-66).
    pub proven_email: Option<String>,
    /// Profile fields by claim name.
    pub profile: Vec<(&'static str, String)>,
}

/// The claims released to `target` for `scopes` and the `claims` request: the `email` scope or
/// an `email` claim request releases a proven address with `email_verified: true` and nothing
/// otherwise; the `profile` scope or a request releases the profile fields held.
#[must_use]
pub fn release(
    scopes: &[&str],
    requested: &Requested,
    target: Target,
    held: &Held,
) -> Map<String, Value> {
    let asked = match target {
        Target::IdToken => &requested.id_token,
        Target::Userinfo => &requested.userinfo,
    };
    let want = |claim: &str, scope: &str| asked.contains(claim) || scopes.contains(&scope);
    let mut out = Map::new();
    if (want("email", "email") || asked.contains("email_verified"))
        && let Some(e) = &held.proven_email
    {
        out.insert("email".into(), Value::from(e.as_str()));
        out.insert("email_verified".into(), Value::Bool(true));
    }
    for (claim, value) in &held.profile {
        if want(claim, "profile") {
            out.insert((*claim).into(), Value::from(value.as_str()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // OP-148, §10.4.6
    #[test]
    fn the_claims_parameter_asks_per_target_and_unknown_claims_are_left_out() {
        let r = parse(
            r#"{"userinfo":{"email":{"essential":true},"nickname":null},"id_token":{"name":null}}"#,
        )
        .unwrap();
        assert_eq!(r.userinfo.iter().copied().collect::<Vec<_>>(), ["email"]);
        assert_eq!(r.id_token.iter().copied().collect::<Vec<_>>(), ["name"]);
        assert_eq!(parse("[]"), Err(InvalidClaims));
        assert_eq!(parse(r#"{"userinfo":{"email":1}}"#), Err(InvalidClaims));
        assert_eq!(
            parse(r#"{"userinfo":{"email":{"essential":"yes"}}}"#),
            Err(InvalidClaims)
        );
        assert_eq!(parse(&"x".repeat(5000)), Err(InvalidClaims));
    }

    // IDP-31 (3), OP-153 m.3 (l), TN-66
    #[test]
    fn only_a_proven_address_is_released_and_always_as_verified() {
        let r = parse(r#"{"id_token":{"email":null}}"#).unwrap();
        let none = Held::default();
        assert!(release(&[], &r, Target::IdToken, &none).is_empty());
        let held = Held {
            proven_email: Some("ada@example.com".into()),
            profile: vec![("name", "Ada".into())],
        };
        let id = release(&[], &r, Target::IdToken, &held);
        assert_eq!(id["email"], "ada@example.com");
        assert_eq!(id["email_verified"], true);
        assert!(!id.contains_key("name"));
        let info = release(&["profile"], &r, Target::Userinfo, &held);
        assert_eq!(info["name"], "Ada");
        assert!(!info.contains_key("email"));
        assert_eq!(
            release(&["email"], &Requested::default(), Target::Userinfo, &held).len(),
            2
        );
    }
}
