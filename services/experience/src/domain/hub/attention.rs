//! The Needs Attention link (§8.17.6.5, IA-1, X5, X6, OP-156 m.3 (t)): Access keeps no queue of
//! approvals. The hub shows one link, "N approvals waiting for you →", to the coordinator the
//! realm named with `idp.realm.coordinator`, and the count is the coordinator's, never Access's.

use crate::contract::Attention;

/// "{ $count } approvals waiting for you →".
pub const APPROVALS_WAITING: &str = "attention.approvals_waiting";

/// The longest coordinator URL the link carries.
const MAX_URL: usize = 2048;

/// The link to `coordinator` with the `count` it reported; nothing without a coordinator, an
/// `https` URL, or a count, and nothing when none waits.
#[must_use]
pub fn link(coordinator: Option<&str>, count: Option<u64>) -> Option<Attention> {
    let href = coordinator.filter(|u| {
        u.len() <= MAX_URL && u.starts_with("https://") && !u.chars().any(char::is_control)
    })?;
    let count = count.filter(|c| *c > 0)?;
    Some(Attention {
        href: String::from(href),
        count,
        text: String::from(APPROVALS_WAITING),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // IA-1, X6, OP-156 m.3 (t)
    #[test]
    fn the_link_goes_to_the_coordinator_with_its_count_and_nothing_else() {
        let a = link(Some("https://work.example/attention"), Some(3)).unwrap();
        assert_eq!(a.href, "https://work.example/attention");
        assert_eq!(a.count, 3);
        assert_eq!(a.text, APPROVALS_WAITING);
        assert_eq!(link(None, Some(3)), None);
        assert_eq!(link(Some("https://work.example/a"), None), None);
        assert_eq!(link(Some("https://work.example/a"), Some(0)), None);
        assert_eq!(link(Some("http://work.example/a"), Some(1)), None);
        assert_eq!(link(Some("javascript:alert(1)"), Some(1)), None);
    }
}
