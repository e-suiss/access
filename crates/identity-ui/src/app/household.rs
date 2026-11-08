//! The person's side of ownership handovers and parent consent on the hosted Frontend API
//! (TN-91, E53, E47, OP-153 m.3 (p), (q)). A handover's recipient contributes with its own
//! session, and any owner or the recipient cancels it until it commits; the proposal and the
//! completion are the owner's signed `anchor_transfer`, never a cookie. A ward asks its guardian
//! for consent, the guardian is told through Relay and decides once before the request lapses;
//! silence is never consent.

use access_identity_account::adapters::system::{SystemClock, SystemEntropy};
use access_identity_account::domain::login::Problem;
use access_identity_account::notify::message::{Address, Body, Message, Notice};
use access_identity_account::notify::notifier::OutboxNotifier;
use access_identity_account::notify::ports::Notifier as _;
use access_identity_oauth::ports::RealmEntry;
use access_identity_session::ports::Clock;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_store::StoreError;
use access_store::identity::TenantTx;
use access_store::org_authority::TransferState;
use serde::Deserialize;
use serde_json::json;

use super::{Browser, Hosted, Reply};
use crate::ports::{Kits, Messages, RealmKit};

/// How long a parent consent request lives: 72 hours (OP-153 m.3 (q), PD).
pub const CONSENT_TTL_S: i64 = 72 * 3_600;

/// No such handover, or it is no longer open (TN-91).
pub const NO_HANDOVER: Problem = Problem {
    status: 404,
    code: "not-found",
    title: "No such open handover",
    retry_after_s: None,
};

/// Only the recipient contributes; only an owner or the recipient cancels (TN-91).
pub const NOT_YOURS: Problem = Problem {
    status: 403,
    code: "not-the-handover",
    title: "This handover is not yours to act on",
    retry_after_s: None,
};

/// No live guardianship of the person, or the consent is not the person's (E53).
pub const NO_GUARDIANSHIP: Problem = Problem {
    status: 404,
    code: "not-found",
    title: "No such guardianship or consent",
    retry_after_s: None,
};

/// Only the guardian decides a consent, once, before it lapses (E53, E47).
pub const NOT_THE_GUARDIAN: Problem = Problem {
    status: 403,
    code: "not-the-guardian",
    title: "Only the guardian decides this request",
    retry_after_s: None,
};

/// The consent was decided already or lapsed (E47).
pub const CONSENT_CLOSED: Problem = Problem {
    status: 409,
    code: "consent-closed",
    title: "This request was answered or has lapsed",
    retry_after_s: None,
};

const INVALID: Problem = Problem {
    status: 400,
    code: "invalid-body",
    title: "The request body is not valid",
    retry_after_s: None,
};

const UNAVAILABLE: Problem = Problem {
    status: 503,
    code: "unavailable",
    title: "Try again shortly",
    retry_after_s: Some(5),
};

/// `POST /v1/account/guardian-consents`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentAsk {
    /// The SHA-256 digest of what is asked for, base64url (E47): the request itself stays with
    /// the product that asked.
    pub purpose: String,
    /// The guardianship, base64url, when the ward has more than one guardian.
    #[serde(default)]
    pub guardianship: Option<String>,
}

/// `POST /v1/account/guardian-consents/{consent}`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentDecision {
    /// The guardian approves; `false` declines.
    pub approve: bool,
}

fn failed(e: &StoreError) -> Reply {
    tracing::warn!(error = %e, "household step failed");
    Reply::problem(UNAVAILABLE)
}

fn id16(text: &str) -> Option<[u8; 16]> {
    b64url_decode(text)
        .ok()
        .and_then(|v| <[u8; 16]>::try_from(v.as_slice()).ok())
}

/// What a consent answers the ward's request with now (E47): approved allows, a decline or a
/// lapse denies, and an open request still requires the guardian's action. Silence is never
/// consent.
#[must_use]
pub fn consent_outcome(decision: Option<&str>, expired: bool) -> &'static str {
    match decision {
        Some("approved") => "allow",
        Some(_) => "deny",
        None if expired => "deny",
        None => "require_action",
    }
}

fn ms_text(ms: i64) -> String {
    u64::try_from(ms)
        .ok()
        .and_then(|m| i64::try_from(m / 1000).ok())
        .and_then(|s| time::OffsetDateTime::from_unix_timestamp(s).ok())
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}

/// Tells the guardian `guardian` at its registered address that a consent is asked and lapses
/// at `until_ms` (E53, E47).
async fn tell_guardian(
    t: &mut TenantTx,
    kit: &RealmKit,
    guardian: [u8; 16],
    now: u64,
    until_ms: u64,
) -> Result<(), StoreError> {
    let Some((kind, stored)) = t.contact(guardian).await? else {
        return Ok(());
    };
    let Some(value) =
        access_identity_account::app::vault::reveal_with_kek(t, &*kit.kek, guardian, &stored)
            .await
            .map_err(|_| StoreError::Range)?
    else {
        return Ok(());
    };
    let (to, valid_since_ms) = if kind == "phone" {
        (Address::Phone(value), None)
    } else {
        let since = t.mailbox_since(guardian).await?;
        (
            Address::Email(value),
            Some(
                since
                    .and_then(|v| u64::try_from(v).ok())
                    .unwrap_or(1)
                    .max(1),
            ),
        )
    };
    let realm = kit.realm();
    OutboxNotifier::new(&realm, &SystemEntropy, &SystemClock)
        .notify(
            t,
            &Message {
                subject: guardian,
                to,
                locale: None,
                valid_since_ms,
                body: Body::Notice {
                    notice: Notice::GuardianConsent,
                    at_ms: now,
                    until_ms: Some(until_ms),
                },
            },
        )
        .await
        .map(|_| ())
        .map_err(|_| StoreError::Range)
}

impl<K, C, M> Hosted<K, C, M>
where
    K: Kits,
    C: Clock + Sync,
    M: Messages,
{
    async fn household_tx(&self, kit: &RealmKit) -> Result<TenantTx, Reply> {
        TenantTx::begin(&self.db, kit.tenant, kit.realm)
            .await
            .map_err(|e| failed(&e))
    }

    /// `GET /v1/account/handovers` (TN-91): the open ownership handovers of the person's
    /// organizations that the person receives or, as an owner, may cancel.
    pub async fn handovers(&self, entry: &RealmEntry, b: &Browser<'_>) -> Reply {
        let (kit, me) = match self.me(entry, b).await {
            Ok(m) => m,
            Err(r) => return r,
        };
        let mut t = match self.household_tx(&kit).await {
            Ok(t) => t,
            Err(r) => return r,
        };
        let orgs = match t.orgs_of(me).await {
            Ok(o) => o,
            Err(e) => return failed(&e),
        };
        let mut items = Vec::new();
        for (o, m) in orgs {
            let list = match t.transfers(o.id).await {
                Ok(l) => l,
                Err(e) => return failed(&e),
            };
            for h in list.into_iter().filter(|h| {
                matches!(
                    h.state,
                    TransferState::Proposed | TransferState::Contributed
                ) && (h.to == me || m.owner)
            }) {
                items.push(json!({
                    "organization": b64url_encode(&o.party),
                    "display_name": o.display_name,
                    "handover": b64url_encode(&h.id),
                    "as": if h.to == me { "recipient" } else { "owner" },
                    "state": h.state.word(),
                    "effective_at": ms_text(h.effective_ms),
                }));
            }
        }
        if let Err(e) = t.commit().await {
            return failed(&e);
        }
        Reply::json(200, json!({ "items": items }))
    }

    /// The open handover `handover` of organization `org` and whether `me` owns the
    /// organization.
    async fn open_handover(
        t: &mut TenantTx,
        me: [u8; 16],
        org: &str,
        handover: &str,
    ) -> Result<(access_store::org_authority::Transfer, bool), Reply> {
        let (Some(party), Some(id)) = (id16(org), id16(handover)) else {
            return Err(Reply::problem(NO_HANDOVER));
        };
        let org = match t.org_by_party(party).await {
            Ok(Some(o)) if !o.ended => o,
            Ok(_) => return Err(Reply::problem(NO_HANDOVER)),
            Err(e) => return Err(failed(&e)),
        };
        let h = match t.transfer(id).await {
            Ok(Some(h))
                if h.org == org.id
                    && matches!(
                        h.state,
                        TransferState::Proposed | TransferState::Contributed
                    ) =>
            {
                h
            }
            Ok(_) => return Err(Reply::problem(NO_HANDOVER)),
            Err(e) => return Err(failed(&e)),
        };
        let owner = match t.members(org.id).await {
            Ok(m) => m.iter().any(|m| m.subject == me && m.owner),
            Err(e) => return Err(failed(&e)),
        };
        Ok((h, owner))
    }

    /// `POST /v1/organizations/{organization}/handovers/{handover}/contribution` (TN-91,
    /// OP-153 m.17 (b)): the recipient's own contribution, once.
    pub async fn contribute_handover(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        org: &str,
        handover: &str,
    ) -> Reply {
        let (kit, me) = match self.me(entry, b).await {
            Ok(m) => m,
            Err(r) => return r,
        };
        let mut t = match self.household_tx(&kit).await {
            Ok(t) => t,
            Err(r) => return r,
        };
        let (h, _) = match Self::open_handover(&mut t, me, org, handover).await {
            Ok(x) => x,
            Err(r) => return r,
        };
        if h.to != me {
            return Reply::problem(NOT_YOURS);
        }
        match t.contribute_transfer(h.id).await {
            Ok(true) => {}
            Ok(false) => return Reply::problem(NO_HANDOVER),
            Err(e) => return failed(&e),
        }
        if let Err(e) = t.commit().await {
            return failed(&e);
        }
        Reply::json(
            200,
            json!({ "state": "contributed", "effective_at": ms_text(h.effective_ms) }),
        )
    }

    /// `DELETE /v1/organizations/{organization}/handovers/{handover}` (TN-91): any owner or
    /// the recipient cancels until it commits; the row is kept (OP-73).
    pub async fn cancel_handover(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        org: &str,
        handover: &str,
    ) -> Reply {
        let (kit, me) = match self.me(entry, b).await {
            Ok(m) => m,
            Err(r) => return r,
        };
        let mut t = match self.household_tx(&kit).await {
            Ok(t) => t,
            Err(r) => return r,
        };
        let (h, owner) = match Self::open_handover(&mut t, me, org, handover).await {
            Ok(x) => x,
            Err(r) => return r,
        };
        if !owner && h.to != me {
            return Reply::problem(NOT_YOURS);
        }
        match t.cancel_transfer(h.id, me).await {
            Ok(true) => {}
            Ok(false) => return Reply::problem(NO_HANDOVER),
            Err(e) => return failed(&e),
        }
        if let Err(e) = t.commit().await {
            return failed(&e);
        }
        Reply::json(200, json!({ "state": "cancelled" }))
    }

    /// `POST /v1/account/guardian-consents` (E53, E47): the ward asks its guardian; the request
    /// lives [`CONSENT_TTL_S`] and the guardian is told through Relay. It answers
    /// `require_action` until the guardian decides.
    pub async fn ask_consent(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        ask: &ConsentAsk,
    ) -> Reply {
        let (kit, me) = match self.me(entry, b).await {
            Ok(m) => m,
            Err(r) => return r,
        };
        let Some(purpose) = b64url_decode(&ask.purpose)
            .ok()
            .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
        else {
            return Reply::problem(INVALID);
        };
        let named = match ask.guardianship.as_deref().map(id16) {
            Some(None) => return Reply::problem(INVALID),
            Some(Some(g)) => Some(g),
            None => None,
        };
        let mut t = match self.household_tx(&kit).await {
            Ok(t) => t,
            Err(r) => return r,
        };
        let live: Vec<_> = match t.guardianships_of(me).await {
            Ok(g) => g
                .into_iter()
                .filter(|g| g.ward == me && g.ended_by.is_none())
                .filter(|g| named.is_none_or(|n| n == g.id))
                .collect(),
            Err(e) => return failed(&e),
        };
        let [g] = live.as_slice() else {
            return Reply::problem(NO_GUARDIANSHIP);
        };
        let consent = match t.insert_consent(g.id, &purpose, CONSENT_TTL_S).await {
            Ok(c) => c,
            Err(e) => return failed(&e),
        };
        let row = match t.consent(consent).await {
            Ok(Some(c)) => c,
            Ok(None) => return Reply::problem(UNAVAILABLE),
            Err(e) => return failed(&e),
        };
        let now = match t.server_time().await {
            Ok(n) => n,
            Err(e) => return failed(&e),
        };
        let until = u64::try_from(row.expires_ms).unwrap_or(now);
        if let Err(e) = tell_guardian(&mut t, &kit, g.guardian, now, until).await {
            return failed(&e);
        }
        if let Err(e) = t.commit().await {
            return failed(&e);
        }
        Reply::json(
            202,
            json!({
                "consent": b64url_encode(&consent),
                "outcome": "require_action",
                "expires_at": ms_text(row.expires_ms),
            }),
        )
    }

    /// The consent `id` and its guardianship, when `me` is its ward or its guardian.
    async fn consent_of(
        t: &mut TenantTx,
        me: [u8; 16],
        id: &str,
    ) -> Result<
        (
            access_store::org_authority::Consent,
            access_store::org_authority::Guardianship,
        ),
        Reply,
    > {
        let Some(id) = id16(id) else {
            return Err(Reply::problem(NO_GUARDIANSHIP));
        };
        let c = match t.consent(id).await {
            Ok(Some(c)) => c,
            Ok(None) => return Err(Reply::problem(NO_GUARDIANSHIP)),
            Err(e) => return Err(failed(&e)),
        };
        let g = match t.guardianship(c.guardianship).await {
            Ok(Some(g)) if g.ward == me || g.guardian == me => g,
            Ok(_) => return Err(Reply::problem(NO_GUARDIANSHIP)),
            Err(e) => return Err(failed(&e)),
        };
        Ok((c, g))
    }

    /// `GET /v1/account/guardian-consents/{consent}` (E47): what the consent answers now, to
    /// its ward or its guardian.
    pub async fn consent(&self, entry: &RealmEntry, b: &Browser<'_>, id: &str) -> Reply {
        let (kit, me) = match self.me(entry, b).await {
            Ok(m) => m,
            Err(r) => return r,
        };
        let mut t = match self.household_tx(&kit).await {
            Ok(t) => t,
            Err(r) => return r,
        };
        let (c, _) = match Self::consent_of(&mut t, me, id).await {
            Ok(x) => x,
            Err(r) => return r,
        };
        if let Err(e) = t.commit().await {
            return failed(&e);
        }
        Reply::json(
            200,
            json!({
                "consent": id,
                "outcome": consent_outcome(c.decision.as_deref(), c.expired),
                "expires_at": ms_text(c.expires_ms),
            }),
        )
    }

    /// `POST /v1/account/guardian-consents/{consent}` (E53, E47): the guardian decides once,
    /// before the request lapses; nobody else can.
    pub async fn decide_consent(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        id: &str,
        d: &ConsentDecision,
    ) -> Reply {
        let (kit, me) = match self.me(entry, b).await {
            Ok(m) => m,
            Err(r) => return r,
        };
        let mut t = match self.household_tx(&kit).await {
            Ok(t) => t,
            Err(r) => return r,
        };
        let (c, g) = match Self::consent_of(&mut t, me, id).await {
            Ok(x) => x,
            Err(r) => return r,
        };
        if g.guardian != me || g.ended_by.is_some() {
            return Reply::problem(NOT_THE_GUARDIAN);
        }
        if c.decision.is_some() || c.expired {
            return Reply::problem(CONSENT_CLOSED);
        }
        match t.decide_consent(c.id, d.approve).await {
            Ok(true) => {}
            Ok(false) => return Reply::problem(CONSENT_CLOSED),
            Err(e) => return failed(&e),
        }
        let after = match t.consent(c.id).await {
            Ok(Some(c)) => c,
            Ok(None) => return Reply::problem(UNAVAILABLE),
            Err(e) => return failed(&e),
        };
        if let Err(e) = t.commit().await {
            return failed(&e);
        }
        Reply::json(
            200,
            json!({
                "consent": id,
                "outcome": consent_outcome(after.decision.as_deref(), after.expired),
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // E47, E53, Ek B 3633: silence is never consent
    #[test]
    fn only_an_approval_allows_and_a_lapse_denies() {
        assert_eq!(consent_outcome(Some("approved"), false), "allow");
        assert_eq!(consent_outcome(Some("declined"), false), "deny");
        assert_eq!(consent_outcome(None, true), "deny");
        assert_eq!(consent_outcome(None, false), "require_action");
    }
}
