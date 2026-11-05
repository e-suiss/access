//! The role claim of an authority token (§5.3, §5.17, INV-33, S-1, OP-141 m.32): a role is the
//! Named `AuthoritySet` a Grant pins, and a token names it only as the projection of that
//! Grant, when the token's decided bounds cover the whole named version. A role claim therefore
//! never says more than the token's own authority ⊆ (`AuthoritySet` ∩ Mandate).

use std::collections::BTreeSet;

use access_authority_sequencer::ports::DomainLog;
use access_kernel::algebra::{Catalog, subsumes};
use access_kernel::codec::Canonical as _;
use access_kernel::meta::{ExerciseBasis, GrantState, View as _, authority_set_key, kind};
use access_kernel::model::AuthoritySet;

use crate::CoreError;
use crate::app::Authority;
use crate::domain::{accepted_catalog, read};
use crate::ports::{Binding, Reader, Salts};

/// The claim that carries a token's roles (RFC 9068 §2.2.3.1).
pub const ROLES_CLAIM: &str = "roles";

fn namespaces(set: &AuthoritySet) -> BTreeSet<String> {
    set.actions
        .exact
        .iter()
        .map(|a| a.namespace.clone())
        .chain(set.actions.prefix.iter().map(|(ns, _)| ns.clone()))
        .collect()
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// The roles a token of `bounds` decided on `basis` may name at `now`: the name of the
    /// Named `AuthoritySet` version the basis Grant pins, when that version lies within
    /// `bounds`; otherwise none.
    pub(crate) async fn projected_roles(
        &self,
        basis: &ExerciseBasis,
        bounds: &AuthoritySet,
        now: u64,
    ) -> Result<Vec<String>, CoreError> {
        let grant = match basis {
            ExerciseBasis::Holding(h) => h.grant,
            ExerciseBasis::Public(g) => *g,
            ExerciseBasis::Anchor(_) => return Ok(Vec::new()),
        };
        self.settled(|snap| {
            let Some((name, version, _)) =
                read::<GrantState>(snap, kind::GRANT, &grant).and_then(|g| g.content.named)
            else {
                return Vec::new();
            };
            let Some(named) = snap
                .get(&authority_set_key(&name, Some(version)))
                .and_then(|v| v.get("authority").cloned())
                .and_then(|a| AuthoritySet::from_value(&a).ok())
            else {
                return Vec::new();
            };
            let mut catalog = Catalog::default();
            for ns in namespaces(&named).union(&namespaces(bounds)) {
                catalog = accepted_catalog(snap, ns, now, &catalog);
            }
            if subsumes(&named, bounds, &catalog) {
                vec![name]
            } else {
                Vec::new()
            }
        })
        .await
    }
}
