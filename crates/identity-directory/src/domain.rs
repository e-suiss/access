//! What an AD sync reads and what it may change (§10.6.4, IDP-17, OP-155 m.3 (n)). Sans-I/O.
//!
//! - The pull is incremental on `uSNChanged`: each run asks for entries above the last
//!   watermark and moves the watermark to the highest value it saw.
//! - Accounts are keyed by `objectGUID`, never by a name that can be reused.
//! - Passwords never travel: no hash attribute is ever requested and no replication control is
//!   ever sent, so the connector cannot perform `DCSync`. Passwords stay with delegation or
//!   SPNEGO.
//! - Memberships follow the same rules as SCIM: a group has exactly one membership issuer, and a
//!   connector's memberships count only where the realm accepted it as that group's issuer
//!   (`subject-selection` Acceptance). Without one, nothing is selected.

use std::collections::{BTreeMap, BTreeSet};

/// Attributes that hold password material; the connector never asks for one (IDP-17).
pub const FORBIDDEN: &[&str] = &[
    "unicodePwd",
    "dBCSPwd",
    "ntPwdHistory",
    "lmPwdHistory",
    "supplementalCredentials",
    "userPassword",
    "msDS-ManagedPassword",
    "msLAPS-Password",
    "ms-Mcs-AdmPwd",
];

/// The attributes one pull reads; the only ones it ever reads.
pub const READ: &[&str] = &[
    "objectGUID",
    "objectClass",
    "sAMAccountName",
    "userPrincipalName",
    "mail",
    "displayName",
    "cn",
    "member",
    "uSNChanged",
    "userAccountControl",
];

/// Most entries one pull takes; the rest waits for the next run.
pub const MAX_ENTRIES: usize = 50_000;

/// The `userAccountControl` bit of a disabled account.
pub const ACCOUNT_DISABLE: u64 = 0x2;

/// The search filter of a pull above `watermark` (RFC 4515).
#[must_use]
pub fn filter(watermark: u64) -> String {
    format!(
        "(&(|(objectClass=user)(objectClass=inetOrgPerson)(objectClass=group)(objectClass=groupOfNames))(uSNChanged>={}))",
        watermark.saturating_add(1)
    )
}

/// One entry as the source returned it: attribute names folded to lower case.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SourceEntry {
    /// Its DN.
    pub dn: String,
    /// Its attributes.
    pub attributes: BTreeMap<String, Vec<Vec<u8>>>,
}

impl SourceEntry {
    fn first(&self, name: &str) -> Option<&[u8]> {
        self.attributes
            .get(name)
            .and_then(|v| v.first())
            .map(Vec::as_slice)
    }

    fn text(&self, name: &str) -> Option<String> {
        self.first(name)
            .and_then(|v| core::str::from_utf8(v).ok())
            .map(|s| String::from(s.trim()))
            .filter(|s| !s.is_empty())
    }

    fn classes(&self) -> BTreeSet<String> {
        self.attributes
            .get("objectclass")
            .into_iter()
            .flatten()
            .filter_map(|v| core::str::from_utf8(v).ok())
            .map(str::to_ascii_lowercase)
            .collect()
    }
}

/// What a pulled entry means for the realm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    /// A person: create or update the account linked to `guid`.
    Person {
        /// `objectGUID`.
        guid: [u8; 16],
        /// The login name (`sAMAccountName`, else the local part of the UPN).
        username: String,
        /// `mail`, when present.
        mail: Option<String>,
        /// Whether the source disabled it.
        disabled: bool,
        /// Its DN, to resolve group members.
        dn: String,
        /// `uSNChanged`.
        usn: u64,
    },
    /// A group and its members' DNs.
    Group {
        /// `objectGUID`.
        guid: [u8; 16],
        /// `cn`.
        name: String,
        /// The members' DNs.
        members: Vec<String>,
        /// `uSNChanged`.
        usn: u64,
    },
}

impl Change {
    /// Its `uSNChanged`.
    #[must_use]
    pub const fn usn(&self) -> u64 {
        match self {
            Self::Person { usn, .. } | Self::Group { usn, .. } => *usn,
        }
    }
}

/// The meaning of `e`; `None` for an entry without a GUID, a change counter or a name.
#[must_use]
pub fn change(e: &SourceEntry) -> Option<Change> {
    let guid = <[u8; 16]>::try_from(e.first("objectguid")?).ok()?;
    let usn = e.text("usnchanged")?.parse::<u64>().ok()?;
    let classes = e.classes();
    if classes.contains("group") || classes.contains("groupofnames") {
        let members = e
            .attributes
            .get("member")
            .into_iter()
            .flatten()
            .filter_map(|v| String::from_utf8(v.clone()).ok())
            .collect();
        return Some(Change::Group {
            guid,
            name: e.text("cn")?,
            members,
            usn,
        });
    }
    if !(classes.contains("user") || classes.contains("inetorgperson")) {
        return None;
    }
    let username = e.text("samaccountname").or_else(|| {
        e.text("userprincipalname")
            .and_then(|u| u.split('@').next().map(String::from))
    })?;
    let disabled = e
        .text("useraccountcontrol")
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|uac| uac & ACCOUNT_DISABLE != 0);
    Some(Change::Person {
        guid,
        username,
        mail: e.text("mail"),
        disabled,
        dn: e.dn.clone(),
        usn,
    })
}

/// The watermark after `changes`: the highest `uSNChanged` seen, never lower than `before`.
#[must_use]
pub fn watermark(before: u64, changes: &[Change]) -> u64 {
    changes.iter().map(Change::usn).fold(before, u64::max)
}

/// How the realm decided a group's memberships (TN-117, OP-155 m.3 (g), (n)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupIssuer {
    /// The realm group's single membership issuer, e.g. `upstream:corp-ad`.
    pub issuer: String,
    /// Whether a `subject-selection` Acceptance names that issuer for the group.
    pub accepted: bool,
}

/// The (group, member DN) pairs a connector named `connector` may assert: only for groups whose
/// one membership issuer is this connector and whose Acceptance selects it. Without an
/// Acceptance nothing is selected.
#[must_use]
pub fn memberships(
    connector: &str,
    changes: &[Change],
    realm: &BTreeMap<String, GroupIssuer>,
) -> Vec<(String, String)> {
    let mine = format!("upstream:{connector}");
    changes
        .iter()
        .filter_map(|c| match c {
            Change::Group { name, members, .. } => Some((name, members)),
            Change::Person { .. } => None,
        })
        .filter(|(name, _)| {
            realm
                .get(name.as_str())
                .is_some_and(|g| g.issuer == mine && g.accepted)
        })
        .flat_map(|(name, members)| members.iter().map(move |m| (name.clone(), m.clone())))
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    fn entry(dn: &str, attrs: &[(&str, &[&[u8]])]) -> SourceEntry {
        SourceEntry {
            dn: String::from(dn),
            attributes: attrs
                .iter()
                .map(|(k, v)| {
                    (
                        k.to_ascii_lowercase(),
                        v.iter().map(|x| x.to_vec()).collect(),
                    )
                })
                .collect(),
        }
    }

    fn sample() -> Vec<Change> {
        let ada = entry(
            "cn=Ada,ou=people,dc=corp",
            &[
                ("objectClass", &[b"top", b"user"]),
                ("objectGUID", &[&[1; 16]]),
                ("sAMAccountName", &[b"ada"]),
                ("mail", &[b"ada@corp.example"]),
                ("uSNChanged", &[b"101"]),
                ("userAccountControl", &[b"512"]),
            ],
        );
        let staff = entry(
            "cn=staff,ou=groups,dc=corp",
            &[
                ("objectClass", &[b"group"]),
                ("objectGUID", &[&[2; 16]]),
                ("cn", &[b"staff"]),
                ("member", &[b"cn=Ada,ou=people,dc=corp"]),
                ("uSNChanged", &[b"105"]),
            ],
        );
        [ada, staff].iter().filter_map(change).collect()
    }

    // §10.6.4, IDP-17
    #[test]
    fn a_pull_is_incremental_and_reads_no_password_material() {
        let changes = sample();
        assert_eq!(changes.len(), 2);
        assert_eq!(watermark(100, &changes), 105);
        assert_eq!(watermark(200, &changes), 200);
        assert!(filter(105).contains("(uSNChanged>=106)"));
        for f in FORBIDDEN {
            assert!(!READ.iter().any(|r| r.eq_ignore_ascii_case(f)), "{f}");
        }
        assert!(
            matches!(&changes[0], Change::Person { username, disabled: false, .. } if username == "ada")
        );
    }

    // OP-155 m.3 (g), (n), TN-117
    #[test]
    fn ad_sync_membership_without_an_acceptance_selects_nothing() {
        let changes = sample();
        let mut realm = BTreeMap::new();
        realm.insert(
            String::from("staff"),
            GroupIssuer {
                issuer: String::from("upstream:corp-ad"),
                accepted: false,
            },
        );
        assert_eq!(memberships("corp-ad", &changes, &realm), Vec::new());
        realm.insert(
            String::from("staff"),
            GroupIssuer {
                issuer: String::from("admin"),
                accepted: true,
            },
        );
        assert_eq!(memberships("corp-ad", &changes, &realm), Vec::new());
        realm.insert(
            String::from("staff"),
            GroupIssuer {
                issuer: String::from("upstream:corp-ad"),
                accepted: true,
            },
        );
        assert_eq!(
            memberships("corp-ad", &changes, &realm),
            vec![(
                String::from("staff"),
                String::from("cn=Ada,ou=people,dc=corp")
            )]
        );
        assert_eq!(memberships("other-ad", &changes, &realm), Vec::new());
    }
}
