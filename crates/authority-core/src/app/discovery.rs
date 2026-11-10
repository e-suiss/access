//! Shadow agent discovery, stage 2 (AG-39, AG-43, OP-156 m.3 (w), m.4 Q20): a discovery
//! connector issues each third-party application's access in a connected service as a
//! `discovered_app` Claim under its own issuer key (`product-seam.cddl`). Access keeps a disclosed
//! body that matches the Claim's value, and the `discovery` search, for the domain's auditors
//! alone, reports each application with whether a live agent or system Party of the domain
//! accounts for it. A report is advisory and changes nothing: acting on one is its own Exercise.

use std::collections::{BTreeMap, BTreeSet};

use access_authority_sequencer::ports::DomainLog;
use access_kernel::claim::body::BODY_CONTEXT;
use access_kernel::meta::{ActorKind, PartyState, kind};
use access_kernel::model::{EqValue, Id};
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::context_digest;

use crate::CoreError;
use crate::app::Authority;
use crate::domain::read;
use crate::ports::{Binding, Reader, Salts};

/// The Claim class.
pub const CLASS: &str = "discovered_app";

/// The connectors a body may name.
pub const CONNECTORS: [&str; 2] = ["google-workspace", "microsoft-graph"];

/// Most rows one report reads.
pub const PAGE: u32 = 1_000;

/// A disclosed `discovered-app` body.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Discovered {
    /// The connected service.
    pub connector: String,
    /// The application's client id in it.
    pub app: String,
    /// Its display name.
    pub name: Option<String>,
    /// Whose access it is in the service.
    pub principal: Option<String>,
    /// Its scopes.
    pub scopes: BTreeSet<String>,
}

/// One kept report row: the body, the Claim and who it is about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    /// The body.
    pub app: Discovered,
    /// The Claim.
    pub claim: Id,
    /// The connector's Party.
    pub issuer: Id,
    /// The Party the access belongs to.
    pub subject: Id,
    /// Its record.
    pub pos: u64,
}

/// One application as the `discovery` search reports it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Shadow {
    /// The connected service.
    pub connector: String,
    /// The application's client id in it.
    pub app: String,
    /// Its display name, when a connector gave one.
    pub name: Option<String>,
    /// Every scope any report named.
    pub scopes: BTreeSet<String>,
    /// How many accesses were reported.
    pub grants: usize,
    /// The live agent or system Parties it was reported about; empty when none accounts for it.
    pub accounted_by: Vec<Id>,
    /// The Claims.
    pub claims: Vec<Id>,
}

impl Shadow {
    /// Whether no registered agent or system Party accounts for it.
    #[must_use]
    pub fn unregistered(&self) -> bool {
        self.accounted_by.is_empty()
    }
}

fn text(v: &Value, max: usize) -> Option<String> {
    match v {
        Value::Text(t) if (1..=max).contains(&t.len()) => Some(t.clone()),
        _ => None,
    }
}

/// The body a disclosed `discovered_app` Claim carries, when it is the CDDL shape and its
/// digest is `value` (L2-CLB-1).
#[must_use]
pub fn decode(value: Option<&EqValue>, body: &[u8]) -> Option<Discovered> {
    let v = dcbor::decode(body, Limits::CEILING).ok()?;
    let Value::Map(entries) = &v else {
        return None;
    };
    let tagged = dcbor::encode(
        &Value::Array(vec![Value::text(CLASS), v.clone()]),
        Limits::CEILING,
    )
    .ok()?;
    match value {
        Some(EqValue::Bytes(d)) if d.as_slice() == context_digest(BODY_CONTEXT, &tagged).0 => {}
        _ => return None,
    }
    let mut out = Discovered {
        connector: String::new(),
        app: String::new(),
        name: None,
        principal: None,
        scopes: BTreeSet::new(),
    };
    let mut scopes = false;
    for (k, val) in entries {
        match k {
            Value::Text(k) if k == "connector" => out.connector = text(val, 64)?,
            Value::Text(k) if k == "app" => out.app = text(val, 512)?,
            Value::Text(k) if k == "name" => out.name = Some(text(val, 512)?),
            Value::Text(k) if k == "principal" => out.principal = Some(text(val, 512)?),
            Value::Text(k) if k == "scopes" => {
                let Value::Array(items) = val else {
                    return None;
                };
                if items.len() > 256 {
                    return None;
                }
                out.scopes = items
                    .iter()
                    .map(|i| text(i, 512))
                    .collect::<Option<BTreeSet<_>>>()?;
                scopes = true;
            }
            _ => return None,
        }
    }
    (scopes && CONNECTORS.contains(&out.connector.as_str()) && !out.app.is_empty()).then_some(out)
}

/// The report of `rows`, given which subjects are live agent or system Parties.
#[must_use]
pub fn report(rows: &[Row], accounts: impl Fn(&Id) -> bool) -> Vec<Shadow> {
    let mut by: BTreeMap<(String, String), Shadow> = BTreeMap::new();
    for r in rows {
        let s = by
            .entry((r.app.connector.clone(), r.app.app.clone()))
            .or_insert_with(|| Shadow {
                connector: r.app.connector.clone(),
                app: r.app.app.clone(),
                name: None,
                scopes: BTreeSet::new(),
                grants: 0,
                accounted_by: Vec::new(),
                claims: Vec::new(),
            });
        if s.name.is_none() {
            s.name.clone_from(&r.app.name);
        }
        s.scopes.extend(r.app.scopes.iter().cloned());
        s.grants = s.grants.saturating_add(1);
        s.claims.push(r.claim);
        if accounts(&r.subject) && !s.accounted_by.contains(&r.subject) {
            s.accounted_by.push(r.subject);
        }
    }
    by.into_values().collect()
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// The `discovery` report: every application a connector reported, with the live agent or
    /// system Parties that account for it; only those no one accounts for when `unregistered`.
    ///
    /// # Errors
    /// The reader's errors.
    pub(crate) async fn discovery(&self, unregistered: bool) -> Result<Vec<Shadow>, CoreError> {
        let rows = self.reader.discovered(PAGE).await?;
        let subjects: BTreeSet<Id> = rows.iter().map(|r| r.subject).collect();
        let accounts = self
            .settled(|snap| {
                subjects
                    .iter()
                    .filter(|p| {
                        read::<PartyState>(snap, kind::PARTY, p).is_some_and(|s| {
                            s.ended.is_none()
                                && matches!(s.actor_kind, ActorKind::Agent | ActorKind::System)
                        })
                    })
                    .copied()
                    .collect::<BTreeSet<Id>>()
            })
            .await?;
        Ok(report(&rows, |p| accounts.contains(p))
            .into_iter()
            .filter(|s| !unregistered || s.unregistered())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(connector: &str, app: &str) -> (Vec<u8>, EqValue) {
        let v = Value::Map(vec![
            (Value::text("app"), Value::text(app)),
            (Value::text("connector"), Value::text(connector)),
            (
                Value::text("scopes"),
                Value::Array(vec![Value::text("Mail.Read")]),
            ),
        ]);
        let tagged = dcbor::encode(
            &Value::Array(vec![Value::text(CLASS), v.clone()]),
            Limits::CEILING,
        )
        .unwrap_or_default();
        (
            dcbor::encode(&v, Limits::CEILING).unwrap_or_default(),
            EqValue::Bytes(context_digest(BODY_CONTEXT, &tagged).0.to_vec()),
        )
    }

    // AG-43, L2-CLB-1, OP-156 m.4 Q20
    #[test]
    fn only_a_body_matching_its_value_is_kept_and_reported() {
        let (b, v) = body("microsoft-graph", "app-1");
        let d = decode(Some(&v), &b).unwrap_or_else(|| Discovered {
            connector: String::new(),
            app: String::new(),
            name: None,
            principal: None,
            scopes: BTreeSet::new(),
        });
        assert_eq!(d.app, "app-1");
        assert_eq!(decode(Some(&EqValue::Bytes(vec![0; 32])), &b), None);
        let (other, ov) = body("slack", "app-2");
        assert_eq!(decode(Some(&ov), &other), None);
        let agent = Id([1; 16]);
        let person = Id([2; 16]);
        let row = |app: &str, subject: Id| Row {
            app: Discovered {
                app: String::from(app),
                ..d.clone()
            },
            claim: Id([3; 16]),
            issuer: Id([4; 16]),
            subject,
            pos: 1,
        };
        let r = report(
            &[row("a", person), row("a", agent), row("b", person)],
            |p| *p == agent,
        );
        assert_eq!(r.len(), 2);
        assert!(!r[0].unregistered());
        assert_eq!(r[0].grants, 2);
        assert!(r[1].unregistered());
    }
}
