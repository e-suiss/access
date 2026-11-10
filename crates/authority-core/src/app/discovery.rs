//! Shadow agent discovery, stage 2 (AG-39, AG-43, OP-156 m.3 (w)): the connectors read which
//! third-party applications people granted access in a connected service, and the report names
//! the ones no registered agent or client of the realm accounts for. A report changes nothing:
//! acting on one is its own Exercise. Parsing is sans-I/O; the connector's own credentials and
//! calls to the service stay in its adapter.

use std::collections::BTreeSet;

use serde_json::Value;

/// A connected service the discovery connectors read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Connector {
    /// Google Workspace Admin SDK, `users.tokens.list`.
    GoogleWorkspace,
    /// Microsoft Graph, `oauth2PermissionGrants`.
    MicrosoftGraph,
}

impl Connector {
    /// The wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::GoogleWorkspace => "google-workspace",
            Self::MicrosoftGraph => "microsoft-graph",
        }
    }
}

/// One application's access in a connected service.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AppGrant {
    /// The service.
    pub connector: Connector,
    /// The application's client id in that service.
    pub app: String,
    /// Its display name, when the service gives one.
    pub name: Option<String>,
    /// Whose access it is in the service; `None` for an access granted for everyone.
    pub principal: Option<String>,
    /// The scopes, sorted.
    pub scopes: BTreeSet<String>,
}

/// Most grants one answer is read for.
pub const MAX_GRANTS: usize = 1_000;

fn text(v: &Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 512)
        .map(String::from)
}

/// The grants in a `connector` answer; `None` for an answer out of shape.
#[must_use]
pub fn parse(connector: Connector, answer: &Value) -> Option<Vec<AppGrant>> {
    let (list, key) = match connector {
        Connector::GoogleWorkspace => (answer.get("items")?.as_array()?, "items"),
        Connector::MicrosoftGraph => (answer.get("value")?.as_array()?, "value"),
    };
    if key.is_empty() || list.len() > MAX_GRANTS {
        return None;
    }
    list.iter()
        .map(|g| {
            let app = text(g, "clientId")?;
            let (name, principal, scopes) = match connector {
                Connector::GoogleWorkspace => (
                    text(g, "displayText"),
                    text(g, "userKey"),
                    g.get("scopes")?
                        .as_array()?
                        .iter()
                        .filter_map(Value::as_str)
                        .map(String::from)
                        .collect(),
                ),
                Connector::MicrosoftGraph => (
                    None,
                    match text(g, "consentType")?.as_str() {
                        "Principal" => Some(text(g, "principalId")?),
                        "AllPrincipals" => None,
                        _ => return None,
                    },
                    text(g, "scope")?
                        .split_whitespace()
                        .map(String::from)
                        .collect(),
                ),
            };
            Some(AppGrant {
                connector,
                app,
                name,
                principal,
                scopes,
            })
        })
        .collect()
}

/// The grants of applications `registered` does not name: each a shadow agent to look at.
#[must_use]
pub fn unregistered(grants: &[AppGrant], registered: &BTreeSet<String>) -> Vec<AppGrant> {
    let mut out: Vec<AppGrant> = grants
        .iter()
        .filter(|g| !registered.contains(&g.app))
        .cloned()
        .collect();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn example(name: &str) -> Value {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../conformance/discovery")
            .join(name);
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    // AG-39, AG-43, OP-156 m.3 (w), Ek B 4390
    #[test]
    fn the_recorded_answers_report_the_applications_no_agent_accounts_for() {
        let google = parse(
            Connector::GoogleWorkspace,
            &example("google-workspace-tokens.json"),
        )
        .unwrap();
        assert_eq!(google.len(), 2);
        let graph = parse(
            Connector::MicrosoftGraph,
            &example("microsoft-graph-grants.json"),
        )
        .unwrap();
        assert_eq!(graph.len(), 2);
        assert_eq!(graph[1].principal, None);
        assert!(graph[0].scopes.contains("Mail.ReadWrite"));
        let registered = BTreeSet::from([
            String::from("100000000001-registered.apps.googleusercontent.com"),
            String::from("00000000-0000-4000-8000-000000000001"),
        ]);
        let all: Vec<AppGrant> = google.into_iter().chain(graph).collect();
        let shadow = unregistered(&all, &registered);
        let apps: Vec<&str> = shadow.iter().map(|g| g.app.as_str()).collect();
        assert_eq!(
            apps,
            [
                "100000000002-unknown.apps.googleusercontent.com",
                "00000000-0000-4000-8000-000000000002"
            ]
        );
        assert_eq!(shadow[0].name.as_deref(), Some("Inbox Autopilot"));
    }

    // AG-43
    #[test]
    fn an_answer_out_of_shape_reports_nothing() {
        assert!(parse(Connector::GoogleWorkspace, &serde_json::json!({})).is_none());
        let odd = serde_json::json!({ "value": [{ "clientId": "a", "consentType": "Other", "scope": "x" }] });
        assert!(parse(Connector::MicrosoftGraph, &odd).is_none());
        assert_eq!(Connector::MicrosoftGraph.name(), "microsoft-graph");
    }
}
