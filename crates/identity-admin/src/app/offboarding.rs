//! Offboarding (OP-157 m.3 (v), §8.17.9.6, §12.3.5, E6, X20, TN-75): what departing a Party
//! would touch, channel by channel, and the record of a departure once it committed.
//!
//! The preview names every channel and offers its choices with no default: direct Grants
//! (keep or revoke), Instances (terminate), rule-shaped holdings (retain, exclude or restrict),
//! the self-anchor (retire or hand over) and re-entry (allowed or blocked). The rule-shaped
//! holdings whose episode already ended are shown as "role ended", never chosen for. A Party
//! reads as offboarded only once its departure Exercise committed and was recorded here; the
//! record keeps every choice, and a blocked re-entry keeps the account from being reactivated.

use access_identity_account::app::SUBJECT_PREFIX;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::model::Id;
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::offboarding::NewOffboarding;
use serde_json::{Value as Json, json};

use super::rest::rfc3339;
use super::{Admin, Applied};
use crate::AdminError;
use crate::ports::{Decider, Departing, Governance, Instances, RealmKeys, Selects};

/// The choices of each channel, in the order the preview lists them (§8.17.9.6).
pub const GRANT_CHOICES: [&str; 2] = ["keep", "revoke"];
/// An Instance is ended.
pub const INSTANCE_CHOICES: [&str; 1] = ["terminate"];
/// A rule-shaped holding is kept, its holder excludes the Party, or it is restricted.
pub const HOLDING_CHOICES: [&str; 3] = ["retain", "exclude", "restrict"];
/// The self-anchor is retired or handed over to another root.
pub const ANCHOR_CHOICES: [&str; 2] = ["retire", "transfer"];
/// The person may come back on this account, or not.
pub const REENTRY_CHOICES: [&str; 2] = ["allowed", "blocked"];

/// Who the departure's audit row names: the committed decision, correlated by its `ExerciseID`.
const DECIDED_BY: &str = "idp-decision";

fn party_key(key: &str) -> Option<[u8; 16]> {
    b64url_decode(key)
        .ok()
        .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
}

fn selects(s: &[Selects]) -> Json {
    Json::Array(
        s.iter()
            .map(|c| json!({ "class": c.class, "value": c.value }))
            .collect(),
    )
}

fn ids(v: &[Id]) -> Vec<String> {
    v.iter().map(|i| b64url_encode(&i.0)).collect()
}

/// The preview view of `d` for `party`, with the account it is bound to, the HR source names
/// by issuer and its recorded departure.
fn view(
    party: [u8; 16],
    account: Option<&str>,
    d: &Departing,
    sources: &[(String, [u8; 16])],
    recorded: Option<&access_store::offboarding::OffboardingRow>,
) -> Json {
    let source = |issuer: Option<Id>| {
        issuer.and_then(|i| {
            sources
                .iter()
                .find(|(_, s)| *s == i.0)
                .map(|(n, _)| n.clone())
        })
    };
    let departure = recorded.map(|r| {
        json!({
            "exercise_id": b64url_encode(&r.departure),
            "position": r.departure_pos.to_string(),
            "committed_at": rfc3339(r.committed_ms),
            "reentry": r.reentry,
            "choices": serde_json::from_str::<Json>(&r.choices).unwrap_or(Json::Null),
        })
    });
    json!({
        "party": b64url_encode(&party),
        "account_id": account,
        // §8.17.9.6
        "status": if recorded.is_some() { "offboarded" } else { "active" },
        "departure": departure,
        "departed_position": d.departed.map(|p| p.to_string()),
        "channels": {
            "grants": d.direct.iter().map(|g| json!({
                "grant": b64url_encode(&g.0),
                "choices": GRANT_CHOICES,
            })).collect::<Vec<_>>(),
            "instances": d.instances.iter().map(|i| json!({
                "instance": b64url_encode(&i.0),
                "choices": INSTANCE_CHOICES,
            })).collect::<Vec<_>>(),
            "holdings": d.holdings.iter().map(|h| json!({
                "grant": b64url_encode(&h.grant.0),
                "selects": selects(&h.selects),
                "since": h.since.to_string(),
                "stale": h.stale,
                "choices": HOLDING_CHOICES,
            })).collect::<Vec<_>>(),
            "self_anchor": {
                "anchor": d.anchor.map(|a| b64url_encode(&a.0)),
                "given": ids(&d.given),
                "choices": ANCHOR_CHOICES,
            },
            "reentry": { "choices": REENTRY_CHOICES },
        },
        // §8.17.9.6
        "survive": d.direct.len(),
        "derived": d.derived.iter().map(|(g, from)| json!({
            "grant": b64url_encode(&g.0),
            "from": b64url_encode(&from.0),
            "kept_with": d.direct.contains(from),
        })).collect::<Vec<_>>(),
        // §8.17.9.6, INV-31
        "ended": d.ended.iter().map(|e| json!({
            "grant": b64url_encode(&e.grant.0),
            "selects": selects(&e.selects),
            "at": e.at.map(rfc3339),
            "source": source(e.issuer),
            "issuer": e.issuer.map(|i| b64url_encode(&i.0)),
        })).collect::<Vec<_>>(),
    })
}

/// What a departure records: the departed Party, every channel's choice as the commit gave it,
/// whether re-entry is blocked, and the key that signed the commit's envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Departure {
    /// The Party.
    pub party: [u8; 16],
    /// The choices, as JSON.
    pub choices: String,
    /// Whether the person may not come back on the account.
    pub reentry_blocked: bool,
    /// The envelope's signing key id.
    pub actor: [u8; 32],
}

impl<D: Decider, G: Governance + Instances, K: RealmKeys> Admin<'_, D, G, K> {
    /// The offboarding preview of the Party `key` (base64url) in `t`'s realm; `None` for a key
    /// that is no Party of the realm's governing domain.
    ///
    /// # Errors
    /// [`AdminError`].
    pub(crate) async fn offboarding_view(
        &self,
        t: &mut TenantTx,
        key: &str,
    ) -> Result<Option<Json>, AdminError> {
        let Some(party) = party_key(key) else {
            return Ok(None);
        };
        let g = access_store::idp::governance(t)
            .await?
            .ok_or(AdminError::NoRealm)?;
        let Some(d) = self
            .governance
            .offboarding(
                access_kernel::digest::Digest(*g.domain.as_bytes()),
                Id(party),
            )
            .await
            .map_err(|e| AdminError::Unavailable(e.0))?
        else {
            return Ok(None);
        };
        let account = access_store::idp::party_subject(t, &party)
            .await?
            .map(|s| self.ids.encode(SUBJECT_PREFIX, s))
            .transpose()?;
        let sources: Vec<(String, [u8; 16])> = t
            .hr_sources()
            .await?
            .into_iter()
            .map(|s| (s.name, s.issuer))
            .collect();
        let recorded = t.offboarding(party).await?;
        Ok(Some(view(
            party,
            account.as_deref(),
            &d,
            &sources,
            recorded.as_ref(),
        )))
    }

    /// Commits the departure Exercise of an offboarding with the caller's AIS and, once it is
    /// committed, records the offboarding with its `offboarding.committed` audit row in one
    /// transaction (OP-157 m.3 (v)). A retry of a committed departure records nothing twice.
    ///
    /// # Errors
    /// [`AdminError`].
    pub async fn offboard(
        &self,
        place: (TenantId, RealmId),
        departure: &Departure,
        submission: access_internal_api::idp::Submission,
    ) -> Result<Applied, AdminError> {
        let applied = self.meta(place, submission).await?;
        let (exercise, position) = match &applied {
            Applied::Written {
                exercise, position, ..
            }
            | Applied::AlreadyWritten { exercise, position } => (*exercise, *position),
            Applied::NotAllowed { .. } => return Ok(applied),
        };
        let mut t = TenantTx::begin(self.app, place.0, place.1).await?;
        if t.offboarding(departure.party)
            .await?
            .is_some_and(|r| r.departure == exercise.0)
        {
            t.commit().await?;
            return Ok(applied);
        }
        let subject = access_store::idp::party_subject(&mut t, &departure.party).await?;
        t.record_offboarding(&NewOffboarding {
            party: departure.party,
            subject,
            choices: &departure.choices,
            reentry: if departure.reentry_blocked {
                "blocked"
            } else {
                "allowed"
            },
            departure: exercise.0,
            departure_pos: position,
            actor: departure.actor,
        })
        .await?;
        // OP-157 m.3 (aa)
        t.audit(&access_store::audit::AuditEvent {
            event_type: "offboarding.committed",
            actor: DECIDED_BY,
            target: &b64url_encode(&departure.party),
            correlation: &b64url_encode(&exercise.0),
        })
        .await?;
        t.commit().await?;
        Ok(applied)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;
    use crate::ports::{EndedByRule, HeldByRule};

    // §8.17.9.6, E6, OP-157 m.3 (v)
    #[test]
    fn the_preview_names_every_channel_and_says_offboarded_only_once_recorded() {
        let d = Departing {
            anchor: Some(Id([1; 16])),
            departed: None,
            direct: vec![Id([2; 16]), Id([3; 16])],
            instances: vec![Id([4; 16])],
            holdings: vec![HeldByRule {
                grant: Id([5; 16]),
                selects: vec![Selects {
                    class: String::from("hr_department"),
                    value: Some(String::from("Finance")),
                }],
                since: 7,
                stale: false,
            }],
            given: vec![Id([6; 16])],
            derived: vec![(Id([8; 16]), Id([2; 16]))],
            ended: vec![EndedByRule {
                grant: Id([9; 16]),
                selects: vec![Selects {
                    class: String::from("hr_department"),
                    value: Some(String::from("R&D")),
                }],
                at: Some(0),
                issuer: Some(Id([10; 16])),
            }],
        };
        let sources = [(String::from("workday"), [10; 16])];
        let v = view([11; 16], None, &d, &sources, None);
        assert_eq!(v["status"], "active");
        assert_eq!(v["departure"], Json::Null);
        assert_eq!(v["channels"]["grants"].as_array().unwrap().len(), 2);
        assert_eq!(
            v["channels"]["grants"][0]["choices"],
            json!(["keep", "revoke"])
        );
        assert_eq!(
            v["channels"]["holdings"][0]["choices"],
            json!(["retain", "exclude", "restrict"])
        );
        assert_eq!(
            v["channels"]["self_anchor"]["choices"],
            json!(["retire", "transfer"])
        );
        assert_eq!(
            v["channels"]["reentry"]["choices"],
            json!(["allowed", "blocked"])
        );
        assert_eq!(v["survive"], 2);
        assert_eq!(v["derived"][0]["kept_with"], true);
        assert_eq!(v["ended"][0]["source"], "workday");
        assert_eq!(v["ended"][0]["selects"][0]["value"], "R&D");
        let row = access_store::offboarding::OffboardingRow {
            version: 1,
            subject: None,
            choices: String::from(r#"{"reentry":"blocked"}"#),
            reentry: String::from("blocked"),
            departure: [12; 32],
            departure_pos: 40,
            committed_ms: 0,
        };
        let v = view([11; 16], None, &d, &sources, Some(&row));
        assert_eq!(v["status"], "offboarded");
        assert_eq!(v["departure"]["position"], "40");
        assert_eq!(v["departure"]["choices"]["reentry"], "blocked");
    }
}
