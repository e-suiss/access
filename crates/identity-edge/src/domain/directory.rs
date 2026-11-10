//! The read-only LDAP directory of a realm (§10.6.3, IDP-16, OP-155 m.3 (n)). Sans-I/O.
//!
//! - The naming context is `o=<realm slug>`, with `ou=people` and `ou=groups` under it.
//! - A person is `uid=<uid>,ou=people,…`: `inetOrgPerson` and `posixAccount`; the uid is the
//!   account's username, else its e-mail address.
//! - A group is `cn=<name>,ou=groups,…`: `groupOfNames` and `posixGroup` in one entry.
//!   `memberOf` is operational.
//! - `uidNumber` and `gidNumber` are 65 536 + (the first four bytes of SHA-256(uuid) mod
//!   (2^31 − 65 536)); a group's uuid is derived from the realm and its name.
//! - Filters are evaluated in RFC 4511 three-valued logic. Groups do not nest, so the in-chain
//!   rule `1.2.840.113556.1.4.1941` matches direct membership.

use std::collections::BTreeMap;

use access_internal_api::edge::ldap::{Entry, Filter, Node, Scope};

/// The lowest uid and gid number the directory gives out.
pub const ID_BASE: u32 = 65_536;

/// The in-chain matching rule.
pub const IN_CHAIN: &str = "1.2.840.113556.1.4.1941";

/// A person's or group's uid or gid number (OP-155 m.3 (n)).
#[must_use]
pub fn posix_id(uuid: &[u8; 16]) -> u32 {
    let h = suiss_crypto::digest::sha256(uuid);
    let first = u32::from_be_bytes([h[0], h[1], h[2], h[3]]);
    let span = (1_u32 << 31) - ID_BASE;
    ID_BASE.saturating_add(first.checked_rem(span).unwrap_or(0))
}

/// The stable uuid of group `name` of a realm.
#[must_use]
pub fn group_uuid(tenant: &[u8; 16], realm: &[u8; 16], name: &str) -> [u8; 16] {
    let mut m = b"access/ldap-group/v1".to_vec();
    m.push(0);
    m.extend_from_slice(tenant);
    m.extend_from_slice(realm);
    m.extend_from_slice(name.as_bytes());
    let h = suiss_crypto::digest::sha256(&m);
    let mut out = [0_u8; 16];
    out.copy_from_slice(&h[..16]);
    out
}

/// One relative distinguished name component, normalised: type in lower case, value with
/// escapes resolved, surrounding spaces trimmed and case folded.
pub type Rdn = (String, String);

/// A normalised DN, most specific component first.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Dn(pub Vec<Rdn>);

fn fold(v: &str) -> String {
    v.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => b.checked_sub(b'0'),
        b'a'..=b'f' => b.checked_sub(b'a' - 10),
        b'A'..=b'F' => b.checked_sub(b'A' - 10),
        _ => None,
    }
}

impl Dn {
    /// Parses an RFC 4514 string: `\`-escapes (a special character or two hex digits) are
    /// resolved; multi-valued RDNs and empty components are refused. The empty string is the
    /// root.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        if s.trim().is_empty() {
            return Some(Self(Vec::new()));
        }
        let bytes = s.as_bytes();
        let mut rdns = Vec::new();
        let mut cur: Vec<u8> = Vec::new();
        let mut parts: Vec<Vec<u8>> = Vec::new();
        let mut i = 0;
        while let Some(&b) = bytes.get(i) {
            match b {
                b'\\' => {
                    let next = *bytes.get(i.checked_add(1)?)?;
                    if let (Some(h), Some(l)) = (
                        hex_val(next),
                        bytes.get(i.checked_add(2)?).copied().and_then(hex_val),
                    ) {
                        cur.push(h.checked_mul(16)?.checked_add(l)?);
                        i = i.checked_add(3)?;
                    } else {
                        cur.push(next);
                        i = i.checked_add(2)?;
                    }
                    continue;
                }
                b',' | b';' => parts.push(core::mem::take(&mut cur)),
                b'+' => return None,
                _ => cur.push(b),
            }
            i = i.checked_add(1)?;
        }
        parts.push(cur);
        for p in parts {
            let text = String::from_utf8(p).ok()?;
            let (t, v) = text.split_once('=')?;
            let t = t.trim().to_ascii_lowercase();
            let v = fold(v);
            if t.is_empty()
                || v.is_empty()
                || !t
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
            {
                return None;
            }
            rdns.push((t, v));
        }
        Some(Self(rdns))
    }

    /// The canonical text: `type=value` joined by `,`, special characters escaped.
    #[must_use]
    pub fn text(&self) -> String {
        self.0
            .iter()
            .map(|(t, v)| format!("{t}={}", escape(v)))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Whether `self` is `base` or under it.
    #[must_use]
    pub fn under(&self, base: &Self) -> bool {
        self.0.len() >= base.0.len() && self.0.ends_with(&base.0)
    }

    /// The parent; the root for a one-component DN.
    #[must_use]
    pub fn parent(&self) -> Self {
        Self(self.0.get(1..).unwrap_or_default().to_vec())
    }

    fn child(&self, t: &str, v: &str) -> Self {
        let mut d = vec![(String::from(t), fold(v))];
        d.extend(self.0.iter().cloned());
        Self(d)
    }
}

/// RFC 4514 §2.4 escaping of one value.
#[must_use]
pub fn escape(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let last = v.chars().count().saturating_sub(1);
    for (i, c) in v.chars().enumerate() {
        let special = matches!(c, ',' | '+' | '"' | '\\' | '<' | '>' | ';' | '=')
            || (i == 0 && matches!(c, '#' | ' '))
            || (i == last && c == ' ');
        if special {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// A person of the directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Person {
    /// The subject.
    pub subject: [u8; 16],
    /// The uid.
    pub uid: String,
    /// The e-mail address, when the account has one.
    pub mail: Option<String>,
}

/// A group of the directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    /// Its name.
    pub name: String,
    /// Its display name.
    pub display_name: String,
    /// Its stable uuid ([`group_uuid`]).
    pub uuid: [u8; 16],
    /// Its members.
    pub members: Vec<[u8; 16]>,
}

/// An entry with its attributes, user and operational apart.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node3 {
    /// Its normalised DN.
    pub dn: Dn,
    /// User attributes by lower-case name: (name as published, values).
    pub user: BTreeMap<String, (String, Vec<String>)>,
    /// Operational attributes, returned only when asked for.
    pub operational: BTreeMap<String, (String, Vec<String>)>,
}

fn put(map: &mut BTreeMap<String, (String, Vec<String>)>, name: &str, values: Vec<String>) {
    if !values.is_empty() {
        map.insert(name.to_ascii_lowercase(), (String::from(name), values));
    }
}

fn s(v: &str) -> String {
    String::from(v)
}

/// The UUID text form of 16 bytes.
#[must_use]
pub fn uuid_text(b: &[u8; 16]) -> String {
    let mut out = String::with_capacity(36);
    for (i, x) in b.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{x:02x}"));
    }
    out
}

/// The directory tree of a realm.
#[derive(Clone, Debug)]
pub struct Tree {
    /// The naming context.
    pub suffix: Dn,
    /// Every entry, sorted by canonical DN text.
    pub entries: Vec<Node3>,
}

/// The naming context of realm `slug`.
#[must_use]
pub fn suffix(slug: &str) -> Dn {
    Dn(vec![(s("o"), fold(slug))])
}

/// The DN of a person.
#[must_use]
pub fn person_dn(slug: &str, uid: &str) -> Dn {
    suffix(slug).child("ou", "people").child("uid", uid)
}

fn person_entry(people_ou: &Dn, p: &Person, member_of: Vec<String>) -> Node3 {
    let dn = people_ou.child("uid", &p.uid);
    let id = posix_id(&p.subject).to_string();
    let mut user = BTreeMap::new();
    put(
        &mut user,
        "objectClass",
        vec![
            s("top"),
            s("person"),
            s("organizationalPerson"),
            s("inetOrgPerson"),
            s("posixAccount"),
        ],
    );
    put(&mut user, "uid", vec![p.uid.clone()]);
    put(&mut user, "cn", vec![p.uid.clone()]);
    put(&mut user, "sn", vec![p.uid.clone()]);
    put(&mut user, "displayName", vec![p.uid.clone()]);
    put(&mut user, "mail", p.mail.iter().cloned().collect());
    put(&mut user, "uidNumber", vec![id.clone()]);
    put(&mut user, "gidNumber", vec![id]);
    put(&mut user, "homeDirectory", vec![format!("/home/{}", p.uid)]);
    let mut operational = BTreeMap::new();
    put(&mut operational, "entryUUID", vec![uuid_text(&p.subject)]);
    put(&mut operational, "memberOf", member_of);
    Node3 {
        dn,
        user,
        operational,
    }
}

impl Tree {
    /// The tree of realm `slug` over `people` and `groups`.
    #[must_use]
    pub fn build(slug: &str, people: &[Person], groups: &[Group]) -> Self {
        let root = suffix(slug);
        let people_ou = root.child("ou", "people");
        let groups_ou = root.child("ou", "groups");
        let by_subject: BTreeMap<[u8; 16], &Person> =
            people.iter().map(|p| (p.subject, p)).collect();
        let mut member_of: BTreeMap<[u8; 16], Vec<String>> = BTreeMap::new();
        let mut entries = Vec::new();
        for g in groups {
            let dn = groups_ou.child("cn", &g.name);
            let mut user = BTreeMap::new();
            let members: Vec<&Person> = g
                .members
                .iter()
                .filter_map(|m| by_subject.get(m).copied())
                .collect();
            for p in &members {
                member_of.entry(p.subject).or_default().push(dn.text());
            }
            put(
                &mut user,
                "objectClass",
                vec![s("top"), s("groupOfNames"), s("posixGroup")],
            );
            put(&mut user, "cn", vec![g.name.clone()]);
            put(&mut user, "description", vec![g.display_name.clone()]);
            put(&mut user, "gidNumber", vec![posix_id(&g.uuid).to_string()]);
            put(
                &mut user,
                "member",
                members
                    .iter()
                    .map(|p| people_ou.child("uid", &p.uid).text())
                    .collect(),
            );
            put(
                &mut user,
                "memberUid",
                members.iter().map(|p| p.uid.clone()).collect(),
            );
            let mut operational = BTreeMap::new();
            put(&mut operational, "entryUUID", vec![uuid_text(&g.uuid)]);
            entries.push(Node3 {
                dn,
                user,
                operational,
            });
        }
        for p in people {
            let held = member_of.remove(&p.subject).unwrap_or_default();
            entries.push(person_entry(&people_ou, p, held));
        }
        for (ou, name) in [(&people_ou, "people"), (&groups_ou, "groups")] {
            let mut user = BTreeMap::new();
            put(
                &mut user,
                "objectClass",
                vec![s("top"), s("organizationalUnit")],
            );
            put(&mut user, "ou", vec![s(name)]);
            entries.push(Node3 {
                dn: ou.clone(),
                user,
                operational: BTreeMap::new(),
            });
        }
        let mut user = BTreeMap::new();
        put(&mut user, "objectClass", vec![s("top"), s("organization")]);
        put(&mut user, "o", vec![s(slug)]);
        entries.push(Node3 {
            dn: root.clone(),
            user,
            operational: BTreeMap::new(),
        });
        for e in &mut entries {
            let inner = e.dn.0.len() < 3;
            put(
                &mut e.operational,
                "hasSubordinates",
                vec![s(if inner { "TRUE" } else { "FALSE" })],
            );
            put(&mut e.operational, "entryDN", vec![e.dn.text()]);
            put(
                &mut e.operational,
                "subschemaSubentry",
                vec![s("cn=Subschema")],
            );
        }
        entries.sort_by_key(|e| e.dn.text());
        Self {
            suffix: root,
            entries,
        }
    }

    /// Whether the entry named `dn` exists.
    #[must_use]
    pub fn has(&self, dn: &Dn) -> bool {
        self.entries.iter().any(|e| e.dn == *dn)
    }
}

/// Whether `e` is in `scope` of `base`.
#[must_use]
pub fn in_scope(e: &Dn, base: &Dn, scope: Scope) -> bool {
    match scope {
        Scope::Base => e == base,
        Scope::One => e.parent() == *base,
        Scope::Sub => e.under(base),
    }
}

/// RFC 4511 §4.5.1.7 filter results.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Truth {
    /// TRUE.
    True,
    /// FALSE.
    False,
    /// Undefined.
    Undefined,
}

fn numeric(name: &str) -> bool {
    matches!(name, "uidnumber" | "gidnumber")
}

fn dn_valued(name: &str) -> bool {
    matches!(name, "member" | "memberof" | "entrydn")
}

fn attr_key(name: &str) -> String {
    let base = name.split(';').next().unwrap_or(name);
    base.to_ascii_lowercase()
}

fn values<'a>(e: &'a Node3, name: &str) -> Option<&'a [String]> {
    e.user
        .get(name)
        .or_else(|| e.operational.get(name))
        .map(|(_, v)| v.as_slice())
}

fn known(name: &str) -> bool {
    matches!(
        name,
        "objectclass"
            | "uid"
            | "cn"
            | "sn"
            | "displayname"
            | "mail"
            | "uidnumber"
            | "gidnumber"
            | "homedirectory"
            | "description"
            | "member"
            | "memberuid"
            | "memberof"
            | "ou"
            | "o"
            | "entryuuid"
            | "entrydn"
            | "hassubordinates"
            | "subschemasubentry"
    )
}

fn norm(name: &str, v: &str) -> String {
    if dn_valued(name) {
        Dn::parse(v).map_or_else(|| fold(v), |d| d.text())
    } else {
        fold(v)
    }
}

fn compare(e: &Node3, name: &str, assertion: &str, test: impl Fn(&str, &str) -> bool) -> Truth {
    let name = attr_key(name);
    if !known(&name) {
        return Truth::Undefined;
    }
    let Some(vals) = values(e, &name) else {
        return Truth::False;
    };
    let a = norm(&name, assertion);
    if vals.iter().any(|v| test(&norm(&name, v), &a)) {
        Truth::True
    } else {
        Truth::False
    }
}

fn order(name: &str, v: &str, a: &str) -> core::cmp::Ordering {
    if numeric(&attr_key(name))
        && let (Ok(x), Ok(y)) = (v.parse::<i64>(), a.parse::<i64>())
    {
        return x.cmp(&y);
    }
    v.cmp(a)
}

fn substr(v: &str, initial: &str, any: &[String], fin: &str) -> bool {
    let (i, f) = (fold(initial), fold(fin));
    let Some(mut rest) = v.strip_prefix(i.as_str()) else {
        return false;
    };
    for part in any {
        let p = fold(part);
        match rest.find(p.as_str()) {
            Some(at) => rest = rest.get(at.saturating_add(p.len())..).unwrap_or_default(),
            None => return false,
        }
    }
    rest.len() >= f.len() && rest.ends_with(f.as_str())
}

fn leaf(e: &Node3, n: &Node) -> Truth {
    match n {
        Node::Eq(t, v) | Node::Approx(t, v) => compare(e, t, v, |x, a| x == a),
        Node::Ge(t, v) => compare(e, t, v, |x, a| order(t, x, a) != core::cmp::Ordering::Less),
        Node::Le(t, v) => compare(e, t, v, |x, a| {
            order(t, x, a) != core::cmp::Ordering::Greater
        }),
        Node::Present(t) => {
            let name = attr_key(t);
            if values(e, &name).is_some() {
                Truth::True
            } else {
                Truth::False
            }
        }
        Node::Substr(t, initial, any, fin) => {
            let name = attr_key(t);
            if !known(&name) {
                return Truth::Undefined;
            }
            match values(e, &name) {
                Some(vals) if vals.iter().any(|v| substr(&fold(v), initial, any, fin)) => {
                    Truth::True
                }
                _ => Truth::False,
            }
        }
        Node::Chain(t, dn) => {
            let name = attr_key(t);
            if dn_valued(&name) {
                compare(e, t, dn, |x, a| x == a)
            } else {
                Truth::Undefined
            }
        }
        Node::Undefined | Node::And(_) | Node::Or(_) | Node::Not => Truth::Undefined,
    }
}

/// Evaluates `f` on `e` without recursion: the nodes are folded right to left on a stack.
#[must_use]
pub fn matches(e: &Node3, f: &Filter) -> Truth {
    let mut stack: Vec<Truth> = Vec::new();
    for n in f.nodes().iter().rev() {
        let t = match n {
            Node::Not => match stack.pop() {
                Some(Truth::True) => Truth::False,
                Some(Truth::False) => Truth::True,
                _ => Truth::Undefined,
            },
            Node::And(k) | Node::Or(k) => {
                let and = matches!(n, Node::And(_));
                let mut acc = if and { Truth::True } else { Truth::False };
                for _ in 0..*k {
                    let x = stack.pop().unwrap_or(Truth::Undefined);
                    acc = match (and, acc, x) {
                        (true, Truth::False, _) | (true, _, Truth::False) => Truth::False,
                        (true, Truth::Undefined, _) | (true, _, Truth::Undefined) => {
                            Truth::Undefined
                        }
                        (false, Truth::True, _) | (false, _, Truth::True) | (true, _, _) => {
                            Truth::True
                        }
                        (false, Truth::Undefined, _) | (false, _, Truth::Undefined) => {
                            Truth::Undefined
                        }
                        (false, _, _) => Truth::False,
                    };
                }
                acc
            }
            other => leaf(e, other),
        };
        stack.push(t);
    }
    stack.pop().unwrap_or(Truth::Undefined)
}

/// What a search asked to see of each entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selection {
    all_user: bool,
    all_operational: bool,
    named: Vec<String>,
    types_only: bool,
}

impl Selection {
    /// From the search's attribute list (RFC 4511 §4.5.1.8).
    #[must_use]
    pub fn new(attributes: &[String], types_only: bool) -> Self {
        let none = attributes.len() == 1 && attributes.first().is_some_and(|a| a == "1.1");
        Self {
            all_user: !none && (attributes.is_empty() || attributes.iter().any(|a| a == "*")),
            all_operational: attributes.iter().any(|a| a == "+"),
            named: attributes
                .iter()
                .filter(|a| !matches!(a.as_str(), "*" | "+" | "1.1"))
                .map(|a| attr_key(a))
                .collect(),
            types_only,
        }
    }

    /// The entry as the client sees it.
    #[must_use]
    pub fn render(&self, e: &Node3) -> Entry {
        let pick = |m: &BTreeMap<String, (String, Vec<String>)>, all: bool| {
            m.iter()
                .filter(|(k, _)| all || self.named.contains(k))
                .map(|(_, (name, vals))| {
                    (
                        name.clone(),
                        if self.types_only {
                            Vec::new()
                        } else {
                            vals.clone()
                        },
                    )
                })
                .collect::<Vec<_>>()
        };
        let mut attributes = pick(&e.user, self.all_user);
        attributes.extend(pick(&e.operational, self.all_operational));
        Entry {
            dn: e.dn.text(),
            attributes,
        }
    }
}

/// The equality assertion on `uid` or `mail` every match must satisfy, when the filter's top
/// level requires one: the directory then reads one account instead of all.
#[must_use]
pub fn narrowing(f: &Filter) -> Option<String> {
    let nodes = f.nodes();
    let pick = |n: &Node| match n {
        Node::Eq(t, v) if matches!(attr_key(t).as_str(), "uid" | "mail") => Some(v.clone()),
        _ => None,
    };
    match nodes.first()? {
        Node::And(_) => {
            let mut depth: usize = 0;
            let mut need: usize = 1;
            for n in nodes.get(1..)? {
                if depth == 0
                    && let Some(v) = pick(n)
                {
                    return Some(v);
                }
                let k = match n {
                    Node::And(k) | Node::Or(k) => usize::from(*k),
                    Node::Not => 1,
                    _ => 0,
                };
                if k > 0 {
                    depth = depth.saturating_add(1);
                    need = k;
                } else if depth > 0 {
                    need = need.saturating_sub(1);
                    if need == 0 {
                        depth = 0;
                    }
                }
            }
            None
        }
        n => pick(n),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

    use super::*;

    fn people() -> Vec<Person> {
        vec![
            Person {
                subject: [1; 16],
                uid: s("ada"),
                mail: Some(s("ada@corp.example")),
            },
            Person {
                subject: [2; 16],
                uid: s("bob"),
                mail: None,
            },
        ]
    }

    fn tree() -> Tree {
        let staff = Group {
            name: s("staff"),
            display_name: s("Staff"),
            uuid: group_uuid(&[9; 16], &[8; 16], "staff"),
            members: vec![[1; 16]],
        };
        Tree::build("corp", &people(), &[staff])
    }

    fn f(nodes: Vec<Node>) -> Filter {
        Filter::new(nodes).unwrap()
    }

    fn eq(a: &str, v: &str) -> Node {
        Node::Eq(s(a), s(v))
    }

    // OP-155 m.3 (n)
    #[test]
    fn posix_ids_are_deterministic_and_above_the_base() {
        let a = posix_id(&[1; 16]);
        assert_eq!(a, posix_id(&[1; 16]));
        assert!((ID_BASE..(1 << 31)).contains(&a));
        let h = suiss_crypto::digest::sha256(&[1_u8; 16]);
        let first = u32::from_be_bytes([h[0], h[1], h[2], h[3]]);
        assert_eq!(a, 65_536 + first % ((1 << 31) - 65_536));
    }

    // §10.6.3: DN normalisation and escaping
    #[test]
    fn dns_normalise() {
        let d = Dn::parse(" UID = Ada ,OU=People, o=Corp").unwrap();
        assert_eq!(d.text(), "uid=ada,ou=people,o=corp");
        assert_eq!(
            Dn::parse("cn=a\\2cb,o=corp").unwrap().text(),
            "cn=a\\,b,o=corp"
        );
        assert!(Dn::parse("cn=a+sn=b,o=corp").is_none());
        assert!(Dn::parse("cn=,o=corp").is_none());
        assert!(
            Dn::parse("uid=ada,ou=people,o=corp")
                .unwrap()
                .under(&suffix("corp"))
        );
    }

    // §10.6.3: groupOfNames and posixGroup in one entry, memberOf operational
    #[test]
    fn the_tree_has_people_and_groups() {
        let t = tree();
        let g = t
            .entries
            .iter()
            .find(|e| e.dn.text() == "cn=staff,ou=groups,o=corp")
            .unwrap();
        let oc = &g.user["objectclass"].1;
        assert!(oc.contains(&s("groupOfNames")) && oc.contains(&s("posixGroup")));
        assert_eq!(g.user["member"].1, vec![s("uid=ada,ou=people,o=corp")]);
        let ada = t
            .entries
            .iter()
            .find(|e| e.dn.text() == "uid=ada,ou=people,o=corp")
            .unwrap();
        assert!(!ada.user.contains_key("memberof"));
        assert_eq!(
            ada.operational["memberof"].1,
            vec![s("cn=staff,ou=groups,o=corp")]
        );
        let plain = Selection::new(&[], false).render(ada);
        assert!(plain.attributes.iter().all(|(n, _)| n != "memberOf"));
        let ops = Selection::new(&[s("+")], false).render(ada);
        assert!(ops.attributes.iter().any(|(n, _)| n == "memberOf"));
    }

    // §10.6.3: three-valued filters and the in-chain rule
    #[test]
    fn filters_evaluate() {
        let t = tree();
        let ada = t
            .entries
            .iter()
            .find(|e| e.dn.text().starts_with("uid=ada"))
            .unwrap();
        let bob = t
            .entries
            .iter()
            .find(|e| e.dn.text().starts_with("uid=bob"))
            .unwrap();
        let person = f(vec![
            Node::And(2),
            eq("objectClass", "PERSON"),
            eq("uid", "ADA"),
        ]);
        assert_eq!(matches(ada, &person), Truth::True);
        assert_eq!(matches(bob, &person), Truth::False);
        let chain = f(vec![Node::Chain(
            s("memberOf"),
            s("CN=Staff,OU=Groups,O=Corp"),
        )]);
        assert_eq!(matches(ada, &chain), Truth::True);
        assert_eq!(matches(bob, &chain), Truth::False);
        let unknown = f(vec![Node::Not, eq("userPassword", "x")]);
        assert_eq!(matches(ada, &unknown), Truth::Undefined);
        let or = f(vec![Node::Or(2), Node::Undefined, eq("uid", "bob")]);
        assert_eq!(matches(bob, &or), Truth::True);
        assert_eq!(matches(ada, &or), Truth::Undefined);
        let sub = f(vec![Node::Substr(
            s("mail"),
            s("ad"),
            vec![s("@")],
            s(".example"),
        )]);
        assert_eq!(matches(ada, &sub), Truth::True);
        let ge = f(vec![Node::Ge(s("uidNumber"), s("65536"))]);
        assert_eq!(matches(ada, &ge), Truth::True);
        assert_eq!(narrowing(&person).as_deref(), Some("ADA"));
        assert_eq!(narrowing(&or), None);
    }

    // §10.6.3
    #[test]
    fn scopes_select() {
        let base = suffix("corp");
        let people = Dn::parse("ou=people,o=corp").unwrap();
        let ada = Dn::parse("uid=ada,ou=people,o=corp").unwrap();
        assert!(in_scope(&ada, &base, Scope::Sub));
        assert!(!in_scope(&ada, &base, Scope::One));
        assert!(in_scope(&people, &base, Scope::One));
        assert!(in_scope(&base, &base, Scope::Base));
    }
}
