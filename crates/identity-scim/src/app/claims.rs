//! The SCIM client as a Claim source (§9.13.8 k.7, §10.1.2, §10.6.2, IDP-23, IDP-35, INV-16,
//! Ek B 4821, 4925, 4926, 5059): a group membership is the client's `member` Claim whose value is
//! the group's id, and the HR attributes are its `hr_*` Claims. Each is an unsigned Claim over
//! the SCIM channel, named by the SHA-256 of the client's bearer secret, with the client's own
//! issuer Party as issuer. Nothing here writes a Grant or any authority state: a Claim selects
//! holders only through a `subject-selection` Acceptance of that issuer and a rule-shaped Grant
//! the domain wrote itself. A retired client's queued Claims are not issued.

use std::collections::BTreeMap;

use access_identity_account::adapters::pg::PgTx;
use access_identity_account::domain::claims::{
    BINDING_TTL_MS, Bind, ClaimOrder, Content, Placement, line,
};
use access_identity_account::ports::AccountTx;
use access_internal_api::claims::{Carrier, ClaimIngest, ClaimSubmission, ClaimVerdict};
use access_internal_api::idp::Unavailable;
use access_kernel::claim::{self, Channel, Unsigned};
use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::model::{EqValue, Id};
use access_store::identity::{Cursor, TenantTx, ack, cursor, poll};
use access_store::issuer::{self as store, IssuedClaim};
use access_store::{Pool, idp};
use serde_json::Value;

use crate::domain::resource::datetime_ms;
use crate::domain::schema::{ENTERPRISE, HR};
use crate::ports::Clock;

/// The identity outbox kind prefix of the SCIM clients' Claim orders.
pub const OUTBOX_PREFIX: &str = "scim_claim.";

/// The SCIM courier's outbox cursor.
pub const CONSUMER: &str = "scim-claims";

/// The class of a SCIM group membership (§9.13.8 k.7).
pub const MEMBER: &str = "member";

/// The HR attribute classes and where each comes from (IDP-35): `(class, extension, attribute,
/// sub-attribute)`.
pub const HR_CLASSES: [(&str, &str, &str, Option<&str>); 6] = [
    ("hr_department", ENTERPRISE, "department", None),
    ("hr_title", "", "title", None),
    ("hr_manager", ENTERPRISE, "manager", Some("value")),
    ("hr_start", HR, "startDate", None),
    ("hr_end", HR, "endDate", None),
    ("hr_employment_status", HR, "employmentStatus", None),
];

/// How long a SCIM Claim holds before the client must state it again: as a binding Claim.
pub const TTL_MS: u64 = BINDING_TTL_MS;

/// Orders read per step.
pub const BATCH: u32 = 64;

/// The line of `subject`'s membership Claims of `group` from `client`.
#[must_use]
pub fn member_line(client: &str, group: &[u8; 16]) -> [u8; 32] {
    line(&[b"scim_member", client.as_bytes(), group])
}

/// The line of `subject`'s `class` Claims from `client`.
#[must_use]
pub fn hr_line(client: &str, class: &str) -> [u8; 32] {
    line(&[b"scim_hr", client.as_bytes(), class.as_bytes()])
}

fn order(
    subject: [u8; 16],
    class: &str,
    value: EqValue,
    (line, at, retract): ([u8; 32], u64, bool),
) -> ClaimOrder {
    ClaimOrder {
        subject,
        class: String::from(class),
        at,
        ttl_ms: TTL_MS,
        content: Content::Scalar(value),
        assurance: BTreeMap::new(),
        bind: Bind::None,
        line: Some(line),
        retract,
    }
}

/// The client's `member` Claim that `subject` is in `group`, or its retraction.
#[must_use]
pub fn member(
    subject: [u8; 16],
    client: &str,
    group: [u8; 16],
    at: u64,
    retract: bool,
) -> ClaimOrder {
    order(
        subject,
        MEMBER,
        EqValue::Bytes(group.to_vec()),
        (member_line(client, &group), at, retract),
    )
}

fn hr_value(resource: Option<&Value>, ext: &str, attr: &str, sub: Option<&str>) -> Option<EqValue> {
    let r = resource?;
    let holder = if ext.is_empty() { r } else { r.get(ext)? };
    let v = holder.get(attr)?;
    let v = match sub {
        Some(s) => v.get(s)?,
        None => v,
    };
    let text = v.as_str()?;
    if attr.ends_with("Date") {
        return datetime_ms(text).map(EqValue::Int);
    }
    Some(EqValue::Text(String::from(text)))
}

/// The HR Claim orders that take `before` to `after` for `subject` (IDP-35): a new or changed
/// value is stated, a value that went away is retracted, an unchanged one is left alone.
#[must_use]
pub fn hr(
    subject: [u8; 16],
    client: &str,
    (before, after): (Option<&Value>, Option<&Value>),
    at: u64,
) -> Vec<ClaimOrder> {
    let mut out = Vec::new();
    for (class, ext, attr, sub) in HR_CLASSES {
        let old = hr_value(before, ext, attr, sub);
        let new = hr_value(after, ext, attr, sub);
        match (old, new) {
            (o, Some(n)) if o.as_ref() != Some(&n) => {
                out.push(order(
                    subject,
                    class,
                    n,
                    (hr_line(client, class), at, false),
                ));
            }
            (Some(o), None) => {
                out.push(order(subject, class, o, (hr_line(client, class), at, true)));
            }
            _ => {}
        }
    }
    out
}

/// Queues `order` from `client` in the caller's transaction (OP-10).
///
/// # Errors
/// [`access_identity_account::AccountError`].
pub async fn queue(
    tx: &mut PgTx,
    client: &str,
    order: &ClaimOrder,
) -> Result<(), access_identity_account::AccountError> {
    let bytes = order
        .to_bytes()
        .map_err(|_| access_identity_account::AccountError::Corrupt)?;
    let name = client.as_bytes();
    let len =
        u8::try_from(name.len()).map_err(|_| access_identity_account::AccountError::Corrupt)?;
    let mut payload = Vec::with_capacity(bytes.len().saturating_add(name.len()).saturating_add(1));
    payload.push(len);
    payload.extend_from_slice(name);
    payload.extend_from_slice(&bytes);
    tx.outbox(&format!("{OUTBOX_PREFIX}{}", order.class), &payload)
        .await
}

fn unframe(payload: &[u8]) -> Option<(String, ClaimOrder)> {
    let (&len, rest) = payload.split_first()?;
    let (name, order) = rest.split_at_checked(usize::from(len))?;
    let name = String::from_utf8(name.to_vec()).ok()?;
    Some((name, ClaimOrder::from_bytes(order).ok()?))
}

/// What became of one order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Issued {
    /// Submitted and answered by Claim Ingest.
    Answered(ClaimVerdict),
    /// Not a Claim: why, by stable word.
    Unplaced(&'static str),
    /// Not a Claim: the statement can never be sent, by stable word.
    Refused(&'static str),
}

/// The SCIM clients' courier.
pub struct Courier<I, C> {
    /// `access_app`, for the realm's rows.
    pub app: Pool,
    /// `access_outbox_reader`, for the outbox and the cursor.
    pub reader: Pool,
    /// Claim Ingest of the authority plane.
    pub ingest: I,
    /// Time.
    pub clock: C,
}

fn down(e: impl std::fmt::Display) -> Unavailable {
    Unavailable(format!("scim claims: {e}"))
}

fn word(v: &ClaimVerdict) -> String {
    match v {
        ClaimVerdict::Admitted { .. } => String::from("admitted"),
        ClaimVerdict::Quarantined { reason, .. } => format!("quarantined-{}", reason.word()),
        ClaimVerdict::Rejected { code } => format!("rejected-{code}"),
    }
}

impl<I: ClaimIngest, C: Clock> Courier<I, C> {
    /// Issues `order` of `client` in `(tenant, realm)` now.
    ///
    /// # Errors
    /// [`Unavailable`]; the order can be issued again.
    pub async fn issue(
        &self,
        (tenant, realm): (
            access_store::identity::TenantId,
            access_store::identity::RealmId,
        ),
        client: &str,
        order: &ClaimOrder,
    ) -> Result<Issued, Unavailable> {
        let mut tx = TenantTx::begin(&self.app, tenant, realm)
            .await
            .map_err(down)?;
        let Some(source) = access_store::scim::client(&mut tx, client)
            .await
            .map_err(down)?
            .filter(|c| c.live)
        else {
            return Ok(Issued::Unplaced("client-retired"));
        };
        let Some(g) = idp::governance(&mut tx).await.map_err(down)? else {
            return Ok(Issued::Unplaced("no-realm"));
        };
        let Some(party) = idp::subject_party(&mut tx, &order.subject)
            .await
            .map_err(down)?
        else {
            return Ok(Issued::Unplaced("no-party"));
        };
        let supersedes = match &order.line {
            Some(l) => store::last_in_line(&mut tx, &order.subject, &g.domain, l)
                .await
                .map_err(down)?,
            None => None,
        };
        tx.commit().await.map_err(down)?;
        let p = Placement {
            domain: Digest(*g.domain.as_bytes()),
            issuer: Id(source.issuer),
            subject: Id(party),
            instance: None,
            supersedes: supersedes.map(Id),
            now: self.clock.now_ms(),
        };
        let Ok(prepared) = order.prepare(&p) else {
            return Ok(Issued::Unplaced("bad-order"));
        };
        let channel = Channel::Scim(source.secret_sha256);
        let Ok(bytes) = (Unsigned {
            statement: prepared.statement,
            channel,
        })
        .to_bytes() else {
            return Ok(Issued::Refused("unencodable"));
        };
        let id = claim::claim_id(&bytes);
        let verdict = self
            .ingest
            .ingest(ClaimSubmission {
                domain: p.domain,
                carrier: Carrier::Unsigned(channel),
                claim: bytes,
                body: prepared.body,
                evidence: None,
            })
            .await?;
        let line = order.line.unwrap_or_else(|| {
            let mut l = [0; 32];
            l[..16].copy_from_slice(&id.0);
            l
        });
        let disposition = word(&verdict);
        let mut t = TenantTx::begin(&self.app, tenant, realm)
            .await
            .map_err(down)?;
        store::record_issued(
            &mut t,
            &IssuedClaim {
                subject: order.subject,
                class: &order.class,
                line,
                domain: access_store::scope::DomainId::from_bytes(p.domain.0),
                claim: id.0,
                disposition: &disposition,
            },
        )
        .await
        .map_err(down)?;
        t.commit().await.map_err(down)?;
        Ok(Issued::Answered(verdict))
    }

    /// Issues the queued SCIM orders after the cursor, at least once. An order that cannot
    /// become a Claim is passed; an outage stops the step where it is.
    ///
    /// # Errors
    /// [`Unavailable`].
    pub async fn step(&self) -> Result<(u32, u32), Unavailable> {
        let mut at = cursor(&self.reader, CONSUMER).await.map_err(down)?;
        let (mut answered, mut unplaced) = (0_u32, 0_u32);
        for e in poll(&self.reader, at, BATCH).await.map_err(down)? {
            if e.kind.starts_with(OUTBOX_PREFIX) {
                let issued = match unframe(&e.payload) {
                    Some((client, order)) => {
                        self.issue((e.tenant, e.realm), &client, &order).await?
                    }
                    None => Issued::Unplaced("unreadable"),
                };
                match issued {
                    Issued::Answered(_) => answered = answered.saturating_add(1),
                    Issued::Unplaced(why) => {
                        tracing::debug!(why, kind = %e.kind, "scim claim not placed");
                        unplaced = unplaced.saturating_add(1);
                    }
                    Issued::Refused(why) => {
                        tracing::warn!(
                            event = "claim.order.refused",
                            kind = %e.kind,
                            reason = why,
                            xid = e.xid,
                            id = e.id,
                            "scim claim order refused"
                        );
                        unplaced = unplaced.saturating_add(1);
                    }
                }
            }
            at = Cursor {
                xid: e.xid,
                id: e.id,
            };
            ack(&self.reader, CONSUMER, at).await.map_err(down)?;
        }
        Ok((answered, unplaced))
    }

    /// Steps every `every` until `stop` turns true.
    pub async fn run(&self, every: std::time::Duration, stop: &tokio::sync::watch::Receiver<bool>) {
        let mut stop = stop.clone();
        loop {
            if let Err(error) = self.step().await {
                tracing::warn!(error = %error.0, "scim claim courier step failed");
            }
            let _ = tokio::time::timeout(every, stop.changed()).await;
            if *stop.borrow() {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use serde_json::json;

    use super::*;

    // IDP-35, Ek B 4925
    #[test]
    fn hr_attributes_become_claims_and_go_away_by_retraction() {
        let before = json!({ "title": "Engineer", ENTERPRISE: { "department": "R&D" } });
        let after = json!({
            "title": "Engineer",
            ENTERPRISE: { "manager": { "value": "m-1" } },
            HR: { "startDate": "2026-12-01T00:00:00Z", "employmentStatus": "active" },
        });
        let orders = hr([1; 16], "entra", (Some(&before), Some(&after)), 5);
        let by = |c: &str| orders.iter().find(|o| o.class == c).cloned();
        assert!(by("hr_title").is_none());
        assert!(by("hr_department").unwrap().retract);
        assert_eq!(
            by("hr_manager").unwrap().content,
            Content::Scalar(EqValue::Text(String::from("m-1")))
        );
        assert!(matches!(
            by("hr_start").unwrap().content,
            Content::Scalar(EqValue::Int(_))
        ));
        assert_eq!(
            by("hr_employment_status").unwrap().line,
            Some(hr_line("entra", "hr_employment_status"))
        );
    }

    // §9.13.8 k.7, INV-16
    #[test]
    fn a_membership_is_a_member_claim_valued_by_the_group() {
        let o = member([1; 16], "entra", [7; 16], 5, false);
        assert_eq!(o.class, MEMBER);
        assert_eq!(o.content, Content::Scalar(EqValue::Bytes(vec![7; 16])));
        assert_ne!(
            member_line("entra", &[7; 16]),
            member_line("okta", &[7; 16])
        );
        let mut payload = vec![5];
        payload.extend_from_slice(b"entra");
        payload.extend_from_slice(&o.to_bytes().unwrap());
        assert_eq!(unframe(&payload).unwrap(), (String::from("entra"), o));
    }
}
