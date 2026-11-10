//! The `ssh.login` action (IDP-32, OP-156 m.3 (o)): its Action Schema, the catalog a realm
//! accepts with the existing `schema-definition` Acceptance, and the resource of a server group.
//! A Grant of `ssh.login` names the principals a certificate may carry and the constraints it
//! must carry; a certificate is a projection of it, never a source of authority.

use std::collections::{BTreeMap, BTreeSet};

use access_kernel::codec::Canonical as _;
use access_kernel::model::{ActionRef, Id, ResourceRef, SubjectSelector};
use access_kernel::schema::{ActionSchema, EffectClass, Spp, action_digest};
use suiss_crypto::dcbor::Value;

use super::cert::Extension;

/// The action's namespace, which is also its resources' namespace.
pub const NAMESPACE: &str = "ssh";

/// The action's name.
pub const LOGIN: &str = "login";

/// The first path segment of a server group's resource.
pub const HOST_GROUP: &str = "host-group";

/// The parameter that lists the principals (server user names).
pub const PRINCIPAL: &str = "principal";

/// The parameter of the `force-command` option.
pub const FORCE_COMMAND: &str = "force_command";

/// The parameter of the `source-address` option's entries.
pub const SOURCE_ADDRESS: &str = "source_address";

/// The parameter that binds the holder's ephemeral key into the projection.
pub const PUBLIC_KEY: &str = "public_key";

/// Longest server group name.
pub const MAX_GROUP: usize = 63;

/// Whether `name` may name a server group: a lower-case letter, then up to 62 lower-case letters,
/// digits and `-`.
#[must_use]
pub fn group_ok(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && name.len() <= MAX_GROUP
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The Action Schema of `ssh.login`, version 1: reversible (CT1), the certificate's parameters
/// typed, its effect shown as irreversible (a session cannot be taken back).
#[must_use]
pub fn login_schema() -> ActionSchema {
    let mut params = BTreeMap::from([
        (String::from(PRINCIPAL), String::from("text")),
        (String::from(FORCE_COMMAND), String::from("text")),
        (String::from(SOURCE_ADDRESS), String::from("text")),
        (String::from(PUBLIC_KEY), String::from("bytes")),
    ]);
    for e in Extension::ALL {
        params.insert(String::from(e.param()), String::from("bool"));
    }
    ActionSchema {
        name: String::from(LOGIN),
        major: 1,
        effect: EffectClass::Reversible,
        reserved: false,
        consumption_bearing: false,
        params,
        resource_types: BTreeSet::new(),
        render: None,
        reversibility: None,
    }
}

/// The reference a Grant of `ssh.login` names.
#[must_use]
pub fn login_ref() -> ActionRef {
    ActionRef {
        namespace: String::from(NAMESPACE),
        name: String::from(LOGIN),
        major: 1,
        schema: action_digest(&login_schema()),
    }
}

/// The `ssh` catalog as `publisher` publishes it.
#[must_use]
pub fn catalog(publisher: Id) -> Spp {
    Spp {
        publisher,
        namespace: String::from(NAMESPACE),
        catalog_version: 1,
        actions: vec![login_schema()],
        retirements: BTreeSet::new(),
        core_spec_min: None,
    }
}

/// The content of the `schema-definition` Acceptance by `publisher` of the `ssh` catalog, which
/// the domain root signs as an `acceptance_establish` (OP-141 m.35 (c)).
#[must_use]
pub fn acceptance(publisher: Id) -> Value {
    Value::Map(vec![
        (Value::text("issuer"), publisher.to_value()),
        (Value::text("use"), Value::text("schema-definition")),
        (
            Value::text("classes"),
            Value::Array(vec![Value::text("action_schema")]),
        ),
        (Value::text("subject"), SubjectSelector::Public.to_value()),
        (
            Value::text("validity"),
            Value::Array(vec![Value::Unsigned(0), Value::Unsigned(u64::MAX)]),
        ),
        (Value::text("spp"), catalog(publisher).to_value()),
    ])
}

/// The resource of server group `name`.
#[must_use]
pub fn host_group(name: &str) -> ResourceRef {
    ResourceRef {
        namespace: String::from(NAMESPACE),
        path: vec![String::from(HOST_GROUP), String::from(name)],
        incarnation: 0,
    }
}

/// The server group a resource names, if it is one.
#[must_use]
pub fn group_of(resource: &ResourceRef) -> Option<&str> {
    match resource.path.as_slice() {
        [kind, name] if resource.namespace == NAMESPACE && kind == HOST_GROUP && group_ok(name) => {
            Some(name.as_str())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    #[test]
    fn the_login_action_is_typed_and_its_groups_named() {
        let s = login_schema();
        assert_eq!(s.params.get(PRINCIPAL).map(String::as_str), Some("text"));
        assert_eq!(s.params.get("permit_pty").map(String::as_str), Some("bool"));
        assert_eq!(login_ref().schema, action_digest(&s));
        assert_eq!(catalog(Id([1; 16])).refs().len(), 1);
        assert!(group_ok("prod-web"));
        assert!(!group_ok("Prod"));
        assert!(!group_ok("-x"));
        assert!(!group_ok(""));
        assert_eq!(group_of(&host_group("prod-web")), Some("prod-web"));
        let mut other = host_group("prod-web");
        other.namespace = String::from("work");
        assert_eq!(group_of(&other), None);
    }
}
