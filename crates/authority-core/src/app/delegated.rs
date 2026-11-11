//! Delegated administration (TN-114, §12.5.2, C28, X20, OP-157 m.3 (t)): an admin Grant is a
//! Grant on meta-action `ActionRef`s, and a realm opens the path to new ones with the staged
//! flag `idp.realm.delegated_admin`. While it is closed, only root holds meta-actions; closing it
//! does not end the admin Grants already issued.

use access_kernel::meta::{self, GrantState, Payload};
use access_kernel::model::{ActionSet, AuthoritySet};

use crate::app::breakglass;

/// The blocker subcode and problem of a new admin Grant while the flag is closed.
pub const OFF: &str = "delegated-admin-off";

/// The holder-side meta-actions: an approval, a token, a Party's own sign-up and its own
/// Instances, Mandates and renunciation act on nobody else, so holding them is not
/// administration (§5.9, CI-14, L0-META-7).
const NOT_ADMIN: [&str; 10] = [
    "contribute",
    "projection_issue",
    "party_register",
    "instance_create",
    "instance_rekey",
    "instance_recover",
    "mandate_bind",
    "mandate_rebind",
    "mandate_revoke",
    "grant_renounce",
];

fn meta_names(set: &ActionSet) -> impl Iterator<Item = &str> {
    set.exact
        .iter()
        .filter(|a| meta::is_meta(&a.namespace, &a.name) && !NOT_ADMIN.contains(&a.name.as_str()))
        .map(|a| a.name.as_str())
}

fn prefixes_meta(set: &ActionSet) -> bool {
    set.prefix.iter().any(|(ns, _)| ns == meta::NAMESPACE)
}

/// Whether `set` names any meta-action (TN-114): it makes an admin Grant.
#[must_use]
pub fn names_meta(set: &AuthoritySet) -> bool {
    prefixes_meta(&set.actions) || meta_names(&set.actions).next().is_some()
}

/// Whether `new` carries a meta-action `old` did not have.
fn adds_meta(old: &AuthoritySet, new: &AuthoritySet) -> bool {
    if prefixes_meta(&new.actions) && !prefixes_meta(&old.actions) {
        return true;
    }
    let kept: Vec<&str> = meta_names(&old.actions).collect();
    meta_names(&new.actions).any(|n| !kept.contains(&n))
}

/// Whether `payload` makes a new admin Grant, which the realm's flag must allow (OP-157 m.3 (t)):
/// a Grant naming a meta-action, or an amendment adding one to `current`. A reserved break-glass
/// Grant is its own pre-issued exception (G29), a narrowing or an unchanged admin Grant stays
/// (narrowing does not spread back), and any other payload is unaffected.
#[must_use]
pub fn needs_open(payload: &Payload, current: Option<&GrantState>) -> bool {
    match payload {
        Payload::GrantIssue(g) => {
            names_meta(&g.authority.authority) && !breakglass::is_breakglass(&g.authority.authority)
        }
        Payload::GrantAmend { authority, .. } => {
            let set = &authority.authority;
            !breakglass::is_breakglass(set)
                && current.is_none_or(|g| adds_meta(&g.content.authority.authority, set))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests;
