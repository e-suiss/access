#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::assert_is_empty,
    reason = "test code"
)]

use serde_json::json;

use super::*;

fn pin(b: u8) -> String {
    b64url_encode(&[b; 32])
}

// OP-156 m.3 (a), (n)
#[test]
fn a_pin_body_is_the_whole_list_by_name_under_mcp_pin() {
    let c = McpPinChange::parse(
        "tools",
        &json!({ "tools": [
            { "name": "send_mail", "pin": pin(2) },
            { "name": "read.inbox", "pin": pin(1) },
        ]}),
    )
    .unwrap();
    assert_eq!(c.action(), IdpAction::ProxyMcpPin);
    assert_eq!(c.tools[0].name, "read.inbox");
    assert_eq!(c.tools[1].pin, [2; 32]);
    c.check().unwrap();
    assert_eq!(c.path(), ["proxy", "tools", "mcp-pins"]);
    assert_eq!(from_json(&to_json(&c.tools)).unwrap(), c.tools);
    let empty = McpPinChange::parse("tools", &json!({ "tools": [] })).unwrap();
    assert!(empty.tools.is_empty());
}

// OP-156 m.3 (n)
#[test]
fn a_list_outside_the_rules_is_refused() {
    let bad = [
        json!({}),
        json!({ "tools": [{ "name": "a", "pin": pin(1) }], "extra": 1 }),
        json!({ "tools": [{ "name": "a", "pin": pin(1) }, { "name": "a", "pin": pin(2) }] }),
        json!({ "tools": [{ "name": "a b", "pin": pin(1) }] }),
        json!({ "tools": [{ "name": "a", "pin": "short" }] }),
        json!({ "tools": [{ "name": "a", "pin": pin(1), "description": "x" }] }),
        json!({ "tools": [{ "name": "x".repeat(129), "pin": pin(1) }] }),
    ];
    for b in bad {
        assert_eq!(McpPinChange::parse("tools", &b), Err(PinError), "{b}");
    }
    let many: Vec<_> = (0..=MAX_TOOLS)
        .map(|i| json!({ "name": format!("t{i}"), "pin": pin(1) }))
        .collect();
    assert!(McpPinChange::parse("tools", &json!({ "tools": many })).is_err());
    assert!(McpPinChange::parse("Tools", &json!({ "tools": [] })).is_err());
}

// AG-42, OP-156 m.3 (n)
#[test]
fn ag_42_a_changed_or_new_tool_does_not_stand_pinned() {
    let pinned = vec![PinnedTool {
        name: String::from("search"),
        pin: [1; 32],
    }];
    assert_eq!(standing(&pinned, "search", &[1; 32]), Standing::Pinned);
    assert_eq!(standing(&pinned, "search", &[2; 32]), Standing::Changed);
    assert_eq!(standing(&pinned, "delete", &[1; 32]), Standing::New);
    assert_eq!(standing(&[], "search", &[1; 32]), Standing::New);
}
