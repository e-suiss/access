//! Per-client tolerance profiles (§10.6.2, IDP-23, IDP-40, OP-155 m.3 (g)): data in the P0
//! interop profile format (`conformance/cddl/interop-profile.cddl`), one per known SCIM client,
//! chosen when the client is registered. A profile tolerates format only: none of its 17 rules
//! touches authentication, a size, depth or rate limit, or the client's scope (IDP-40 (5)); an
//! unknown rule or member makes the whole profile invalid.

use std::collections::BTreeSet;

use serde_json::Value;

/// A tolerance rule (`scim-rule` of the interop profile).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rule {
    /// Entra's `aadOptscim062020` flag: its query parameter is accepted on every request.
    AadOptScim062020,
    /// `"True"`/`"False"` text for a boolean in a PATCH value.
    PatchBoolAsString,
    /// A schema URN in a PATCH path matched without regard to case.
    PatchPathCaseInsensitive,
    /// `Add`, `Replace`, `Remove` in any letter case.
    PatchOpCaseInsensitive,
    /// `remove` on `members` with a value list removes those members.
    PatchRemoveMemberByValue,
    /// A one-element list for a single-valued attribute.
    PatchSingleValueArray,
    /// A schema URN in a filter matched without regard to case.
    FilterAttributeCaseInsensitive,
    /// Unknown attributes are dropped instead of refused.
    IgnoreUnknownAttributes,
    /// `""`, `[]` or `null` in `add` or `replace` clears the attribute.
    EmptyValueClears,
    /// Group lists leave `members` out unless asked.
    GroupMembersOmitted,
    /// `userName` filters ignore case (the server's uniqueness always does).
    UserNameCaseInsensitive,
    /// A body without `schemas` takes the resource type's core schema.
    MissingSchemas,
    /// Enterprise extension attributes as top-level `urn:…:User:name` members.
    EnterpriseExtensionFlattened,
    /// `application/json` besides `application/scim+json`.
    ContentTypeJson,
    /// `"true"`/`"false"` text for `active` in a created or replaced resource.
    ActiveAsString,
    /// No `ETag` header in answers.
    NoEtag,
    /// A cursor page leaves `totalResults` out.
    ListWithoutTotal,
}

impl Rule {
    /// Every rule, in the contract's order.
    pub const ALL: [Self; 17] = [
        Self::AadOptScim062020,
        Self::PatchBoolAsString,
        Self::PatchPathCaseInsensitive,
        Self::PatchOpCaseInsensitive,
        Self::PatchRemoveMemberByValue,
        Self::PatchSingleValueArray,
        Self::FilterAttributeCaseInsensitive,
        Self::IgnoreUnknownAttributes,
        Self::EmptyValueClears,
        Self::GroupMembersOmitted,
        Self::UserNameCaseInsensitive,
        Self::MissingSchemas,
        Self::EnterpriseExtensionFlattened,
        Self::ContentTypeJson,
        Self::ActiveAsString,
        Self::NoEtag,
        Self::ListWithoutTotal,
    ];

    /// The contract name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::AadOptScim062020 => "scim.aad_opt_scim_062020",
            Self::PatchBoolAsString => "scim.patch_bool_as_string",
            Self::PatchPathCaseInsensitive => "scim.patch_path_case_insensitive",
            Self::PatchOpCaseInsensitive => "scim.patch_op_case_insensitive",
            Self::PatchRemoveMemberByValue => "scim.patch_remove_member_by_value",
            Self::PatchSingleValueArray => "scim.patch_single_value_array",
            Self::FilterAttributeCaseInsensitive => "scim.filter_attribute_case_insensitive",
            Self::IgnoreUnknownAttributes => "scim.ignore_unknown_attributes",
            Self::EmptyValueClears => "scim.empty_value_clears",
            Self::GroupMembersOmitted => "scim.group_members_omitted",
            Self::UserNameCaseInsensitive => "scim.user_name_case_insensitive",
            Self::MissingSchemas => "scim.missing_schemas",
            Self::EnterpriseExtensionFlattened => "scim.enterprise_extension_flattened",
            Self::ContentTypeJson => "scim.content_type_json",
            Self::ActiveAsString => "scim.active_as_string",
            Self::NoEtag => "scim.no_etag",
            Self::ListWithoutTotal => "scim.list_without_total",
        }
    }

    /// The rule of a contract name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.name() == name)
    }
}

/// Why a profile was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid tolerance profile: {0}")]
pub struct ProfileError(pub &'static str);

/// One client's tolerances.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Profile {
    /// The profile name, `scim.<counterpart>`; empty for the strict server.
    pub name: String,
    /// The rules it applies.
    pub rules: BTreeSet<Rule>,
}

impl Profile {
    /// The strict server: no tolerance at all.
    #[must_use]
    pub fn strict() -> Self {
        Self::default()
    }

    /// Whether `rule` applies.
    #[must_use]
    pub fn has(&self, rule: Rule) -> bool {
        self.rules.contains(&rule)
    }
}

const MEMBERS: [&str; 7] = [
    "v",
    "profile",
    "protocol",
    "counterpart",
    "revision",
    "template",
    "tolerances",
];

fn test_name(t: &str) -> bool {
    let parts: Vec<&str> = t.split("::").collect();
    (2..=7).contains(&parts.len())
        && parts.iter().all(|p| {
            (1..=64).contains(&p.len())
                && p.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        })
}

fn profile_name(p: &str) -> bool {
    let Some(rest) = p.strip_prefix("scim.") else {
        return false;
    };
    (1..=63).contains(&rest.len())
        && rest
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && rest
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// Reads a SCIM interop profile.
///
/// # Errors
/// [`ProfileError`]: not version 1, not a SCIM profile, an unknown member or rule, or a
/// tolerance that names no test case.
pub fn parse(json: &Value) -> Result<Profile, ProfileError> {
    let o = json.as_object().ok_or(ProfileError("not an object"))?;
    if o.keys().any(|k| !MEMBERS.contains(&k.as_str())) {
        return Err(ProfileError("unknown member"));
    }
    if o.get("v").and_then(Value::as_u64) != Some(1) {
        return Err(ProfileError("version"));
    }
    if o.get("protocol").and_then(Value::as_str) != Some("scim") {
        return Err(ProfileError("protocol"));
    }
    let name = o
        .get("profile")
        .and_then(Value::as_str)
        .filter(|p| profile_name(p))
        .ok_or(ProfileError("profile"))?;
    let counterpart_ok = o
        .get("counterpart")
        .and_then(Value::as_str)
        .is_some_and(|c| (1..=128).contains(&c.len()));
    if !counterpart_ok || o.get("revision").and_then(Value::as_u64).is_none() {
        return Err(ProfileError("counterpart or revision"));
    }
    let mut rules = BTreeSet::new();
    for t in o
        .get("tolerances")
        .and_then(Value::as_array)
        .ok_or(ProfileError("tolerances"))?
    {
        let t = t.as_object().ok_or(ProfileError("tolerance"))?;
        if t.keys()
            .any(|k| !["rule", "value", "test", "source"].contains(&k.as_str()))
        {
            return Err(ProfileError("unknown tolerance member"));
        }
        let rule = t
            .get("rule")
            .and_then(Value::as_str)
            .and_then(Rule::parse)
            .ok_or(ProfileError("rule"))?;
        if !t.get("test").and_then(Value::as_str).is_some_and(test_name) {
            return Err(ProfileError("test"));
        }
        if !rules.insert(rule) {
            return Err(ProfileError("repeated rule"));
        }
    }
    Ok(Profile {
        name: name.to_owned(),
        rules,
    })
}

/// The shipped profiles' files, by name (OP-155 m.3 (g)).
pub const SHIPPED: [(&str, &str); 5] = [
    ("scim.entra", include_str!("../../profiles/entra.json")),
    ("scim.okta", include_str!("../../profiles/okta.json")),
    (
        "scim.google-workspace",
        include_str!("../../profiles/google-workspace.json"),
    ),
    (
        "scim.onelogin",
        include_str!("../../profiles/onelogin.json"),
    ),
    (
        "scim.jumpcloud",
        include_str!("../../profiles/jumpcloud.json"),
    ),
];

/// The shipped profile `name`; `None` for a name the server does not ship or a file that does
/// not read.
#[must_use]
pub fn shipped(name: &str) -> Option<Profile> {
    let (_, text) = SHIPPED.iter().find(|(n, _)| *n == name)?;
    let json: Value = serde_json::from_str(text).ok()?;
    parse(&json).ok().filter(|p| p.name == name)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // IDP-23, IDP-40, OP-155 m.3 (g)
    #[test]
    fn every_shipped_profile_reads_and_the_contract_lists_the_rules() {
        for (name, _) in SHIPPED {
            assert_eq!(shipped(name).unwrap().name, name);
        }
        let cddl = include_str!("../../../../conformance/cddl/interop-profile.cddl");
        let listed: Vec<&str> = cddl.split('"').filter(|s| s.starts_with("scim.")).collect();
        let ours: Vec<&str> = Rule::ALL.into_iter().map(Rule::name).collect();
        assert_eq!(listed, ours);
    }

    // IDP-40 (5)
    #[test]
    fn a_relaxing_or_unknown_rule_spoils_the_whole_profile() {
        let base = serde_json::json!({
            "v": 1, "profile": "scim.entra", "protocol": "scim",
            "counterpart": "Entra", "revision": 1,
            "tolerances": [{ "rule": "scim.no_etag", "test": "scim_profiles::entra::no_etag" }],
        });
        assert!(parse(&base).is_ok());
        let mut relaxing = base.clone();
        relaxing["tolerances"][0]["rule"] = Value::from("scim.skip_authentication");
        assert!(parse(&relaxing).is_err());
        let mut untested = base.clone();
        untested["tolerances"][0]
            .as_object_mut()
            .unwrap()
            .remove("test");
        assert!(parse(&untested).is_err());
        let mut extra = base;
        extra["max_results"] = Value::from(10_000);
        assert!(parse(&extra).is_err());
    }
}
