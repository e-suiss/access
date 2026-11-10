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

/// The coordinator's Needs Attention endpoint a realm's Suiss discovery document names.
#[must_use]
pub fn coordinator_of(discovery: &serde_json::Value) -> Option<String> {
    discovery
        .get("suiss_coordinator")?
        .get("attention")?
        .as_str()
        .filter(|u| https(u))
        .map(String::from)
}

fn https(u: &str) -> bool {
    u.len() <= MAX_URL && u.starts_with("https://") && !u.chars().any(char::is_control)
}

/// The origin of an `https` URL, `https://host[:port]`.
fn origin(u: &str) -> Option<&str> {
    let rest = u.strip_prefix("https://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let host = rest.get(..end)?;
    (!host.is_empty() && !host.contains('@')).then(|| u.get(..end.checked_add(8)?))?
}

/// The link from the coordinator's answer `{count, href}` at `endpoint`: its `href` must be on
/// the endpoint's own origin, or there is no link.
#[must_use]
pub fn answered(endpoint: &str, answer: &serde_json::Value) -> Option<Attention> {
    let href = answer.get("href")?.as_str()?;
    if origin(href)? != origin(endpoint)? {
        return None;
    }
    link(Some(href), answer.get("count")?.as_u64())
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

    // OP-156 m.3 (t)
    #[test]
    fn the_coordinator_answers_on_its_own_origin_only() {
        let doc =
            serde_json::json!({ "suiss_coordinator": { "attention": "https://work.example/a" } });
        assert_eq!(
            coordinator_of(&doc).as_deref(),
            Some("https://work.example/a")
        );
        assert_eq!(coordinator_of(&serde_json::json!({})), None);
        let plain =
            serde_json::json!({ "suiss_coordinator": { "attention": "http://work.example/a" } });
        assert_eq!(coordinator_of(&plain), None);
        let ok = serde_json::json!({ "count": 2, "href": "https://work.example/inbox" });
        assert_eq!(answered("https://work.example/a", &ok).unwrap().count, 2);
        let elsewhere = serde_json::json!({ "count": 2, "href": "https://evil.example/inbox" });
        assert_eq!(answered("https://work.example/a", &elsewhere), None);
        let lookalike = serde_json::json!({ "count": 2, "href": "https://work.example.evil/x" });
        assert_eq!(answered("https://work.example/a", &lookalike), None);
    }
}
