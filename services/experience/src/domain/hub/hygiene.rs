//! Inventory hygiene (§8.17.12, XI-19, OP-157 m.3 (w)): from the domain's `hygiene` marks, one
//! row per kind beside Changes, "3 delegations not used for 90 days". A row is a suggestion and
//! offers no action of its own; nothing changes until the reader acts on a Grant.

use serde_json::Value;

use crate::contract::{HygieneRow, Owner};

/// "{ $count } delegations not used for 90 days".
pub const UNUSED: &str = "hygiene.unused";
/// "{ $count } delegations end within 7 days".
pub const EXPIRING: &str = "hygiene.expiring";
/// "{ $count } broad delegations: any resource, or they can be passed on".
pub const BROAD: &str = "hygiene.broad";
/// "A suggestion only. Nothing changes until you act."
pub const SUGGESTION: &str = "hygiene.suggestion";

/// The kinds in the order the rows show them, with their text keys.
pub const KINDS: [(&str, &str); 3] = [("unused", UNUSED), ("expiring", EXPIRING), ("broad", BROAD)];

/// The hygiene rows of one domain's inventory answer.
#[must_use]
pub fn rows(inventory: &[Value], (domain, label): (&str, Option<&String>)) -> Vec<HygieneRow> {
    KINDS
        .iter()
        .filter_map(|(kind, text)| {
            let grants: Vec<String> = inventory
                .iter()
                .filter(|v| v["type"] == "hygiene" && v[*kind] == true)
                .filter_map(|v| v["grant"].as_str().map(String::from))
                .collect();
            (!grants.is_empty()).then(|| HygieneRow {
                domain: String::from(domain),
                label: label.cloned(),
                owner: Owner::Access,
                kind: String::from(*kind),
                count: u64::try_from(grants.len()).unwrap_or(u64::MAX),
                grants,
                text: String::from(*text),
                suggestion: String::from(SUGGESTION),
                derived: true,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    // XI-19, §8.17.12, OP-157 m.3 (w)
    #[test]
    fn each_kind_is_one_counted_suggestion() {
        let inv = vec![
            json!({ "type": "holding", "grant": "g0" }),
            json!({ "type": "hygiene", "grant": "g1", "unused": true, "expiring": false, "broad": true }),
            json!({ "type": "hygiene", "grant": "g2", "unused": true, "expiring": true, "broad": false }),
        ];
        let r = rows(&inv, ("d", None));
        assert_eq!(
            r.iter()
                .map(|r| (r.kind.as_str(), r.count))
                .collect::<Vec<_>>(),
            [("unused", 2), ("expiring", 1), ("broad", 1)]
        );
        assert!(r.iter().all(|r| r.suggestion == SUGGESTION && r.derived));
        assert_eq!(r[0].grants, ["g1", "g2"]);
        assert!(rows(&inv[..1], ("d", None)).is_empty());
    }
}
