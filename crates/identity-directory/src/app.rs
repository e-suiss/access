//! One sync run (§10.6.4, OP-155 m.3 (n)): pull above the watermark, read the changes, and keep
//! only the memberships the realm accepted this connector for.

use std::collections::BTreeMap;

use crate::adapters::PullError;
use crate::domain::{Change, GroupIssuer, change, memberships, watermark};
use crate::ports::Directory;

/// What one run found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pulled {
    /// The people and groups that changed.
    pub changes: Vec<Change>,
    /// The (group, member DN) pairs this connector may assert.
    pub memberships: Vec<(String, String)>,
    /// The watermark the next run starts from.
    pub watermark: u64,
}

/// Pulls from `source` above `since` for connector `connector`; `groups` is how the realm
/// decided each group's membership issuer.
///
/// # Errors
/// [`PullError`]; nothing was read then.
pub async fn pull<D: Directory>(
    source: &D,
    connector: &str,
    since: u64,
    groups: &BTreeMap<String, GroupIssuer>,
) -> Result<Pulled, PullError> {
    let changes: Vec<Change> = source
        .changes(since)
        .await?
        .iter()
        .filter_map(change)
        .collect();
    Ok(Pulled {
        memberships: memberships(connector, &changes, groups),
        watermark: watermark(since, &changes),
        changes,
    })
}
