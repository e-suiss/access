//! The approval channels outside the page (OP-157 m.3 (m), m.17, §13.7.3, SEC26, TN-100): the
//! invitation a pushed request sends, one per approver and intent and at most five an hour from a
//! requester, and the approver device's in-notification CT1 answer. A refusal is recorded. An
//! approval is checked in full and counts only with the approver's passkey assertion over H(AAS)
//! for the realm's RP ID, verified as the Approval Surface verifies it (verifier name binding,
//! §10.3.1); it then becomes the `authentication` Claim bound to the statement and the
//! contribution, and uses the invitation up. A device key's signature alone is never one.

use access_crypto::Secret;
use access_identity_account::app::vault::reveal_with_kek;
use access_identity_account::domain::login::Problem;
use access_identity_account::notify::message::{Address, Body, Message, Prompt};
use access_identity_account::notify::ports::Notifier;
use access_identity_oauth::ports::RealmEntry;
use access_internal_api::approvals::Contribution;
use access_kernel::aas::{self, Act};
use access_kernel::assurance;
use access_kernel::codec::Canonical as _;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::meta::ExerciseBasis;
use access_kernel::render;
use access_kernel::tier::Tier;
use access_store::approvals::{self as store, ApprovalChannel, NewInvite};
use access_store::identity::TenantTx;
use access_store::idp;
use serde_json::{Value, json};

use super::approve::{committed, cooled, issue_claim, problem, tier_of, unknown_reply};
use super::me::{Devices, unavailable};
use super::{Hosted, Reply};
use crate::domain::approval::{
    ApprovalPush, Envelope, INVITE_WINDOW_MS, INVITES_PER_HOUR, InlineAnswer, InlineDecision, Kept,
    Pushed, SDK_SURFACE_PROFILE, envelope, inline_answer, requester_party,
};
use crate::ports::{ApprovalClaims, Approvals, Kits, Messages, RealmKit};

/// `approval-inline-assertion-required`: every check passed, but the answer carries no
/// passkey assertion bound to H(AAS) (§10.2, §10.3.1, MD-11, OP-157 m.17).
const ASSERTION_REQUIRED: Problem = Problem {
    status: 409,
    code: "approval-inline-assertion-required",
    title: "Open this request on the Approval Surface to approve it",
    retry_after_s: None,
};

/// `approval-invite-limit`: a requester reached the hourly limit for an approver.
pub(super) fn invite_limit() -> Problem {
    Problem {
        status: 429,
        code: "approval-invite-limit",
        title: "Too many approval requests to this person; try again later",
        retry_after_s: Some(INVITE_WINDOW_MS / 1_000),
    }
}

/// What a push invites: the approver, the requester and what is shown.
pub(super) struct Invitation {
    requester: [u8; 16],
    approver: [u8; 16],
    intent: [u8; 32],
    tier: Tier,
    render: Option<Vec<u8>>,
    render_digest: [u8; 32],
    expires_at: u64,
}

/// §13.7.3, SEC26, TN-100: a notification can carry an approval only up to CT1.
const fn inline_tier(code: u8) -> bool {
    code <= 1
}

/// OP-157 m.17: user verification is asked for only when an open term asks for it.
fn uv_asked(unmet: &[access_kernel::combinator::Unmet]) -> bool {
    unmet.iter().any(|u| {
        u.term
            .assurance
            .get(access_kernel::assurance::UV)
            .is_some_and(|level| *level >= 1)
    })
}

fn assertion_rejected() -> Reply {
    problem(401, "assertion-rejected", "The passkey was not accepted")
}

/// What Access gives the coordinator for ranking (§8.17.11.1, OP-157 m.3 (m)): facts only, never
/// a score, rank or urgency. `reserved` is read from the tier: an amount-free CT3 is a reserved
/// action; `budget_ratio` is absent here, the coordinator already reads budgets from Access.
pub(super) fn facts(i: &Invitation, class: &str) -> Value {
    let amount = i
        .render
        .as_deref()
        .and_then(|b| render::decode(b).ok())
        .and_then(|r| {
            r.fields
                .iter()
                .find(|f| f.name == "amount")
                .map(|f| f.text.clone())
        });
    let reserved = i.tier == Tier::Ct3 && amount.is_none();
    match amount {
        Some(a) => json!({ "class": class, "amount": a, "reserved": reserved }),
        None => json!({ "class": class, "reserved": reserved }),
    }
}

const fn tier_code(tier: Tier) -> u8 {
    match tier {
        Tier::Ct0 => 0,
        Tier::Ct1 => 1,
        Tier::Ct2 => 2,
        Tier::Ct3 => 3,
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

impl<K, C, M> Hosted<K, C, M>
where
    K: Kits,
    C: crate::ports::Clock + Sync,
    M: Messages,
{
    /// The invitation of a push, when its approver and opening are known: the approver is the
    /// holder of the contribution's Grant (an Anchor basis names no approver subject here).
    pub(super) async fn approval_invitation<A, I, P: Approvals, Q>(
        &self,
        devices: &Devices<A, I, P, Q>,
        kit: &RealmKit,
        request: &Value,
        p: &Pushed,
        env: &Envelope,
    ) -> Result<Option<Invitation>, Reply> {
        let (ExerciseBasis::Holding(h), Some(requester)) = (&env.basis, requester_party(request))
        else {
            return Ok(None);
        };
        let Some(opening) = devices
            .approvals
            .opening(p.domain, p.intent)
            .await
            .map_err(|_| unavailable())?
        else {
            return Ok(None);
        };
        let Some(tier) = tier_of(opening.tier) else {
            return Ok(None);
        };
        let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm)
            .await
            .map_err(|_| unavailable())?;
        let approver = idp::party_subject(&mut t, &h.holder.0)
            .await
            .map_err(|_| unavailable())?;
        t.commit().await.map_err(|_| unavailable())?;
        Ok(approver.map(|approver| Invitation {
            requester,
            approver,
            intent: p.intent.0,
            tier,
            render: opening.render.clone(),
            render_digest: opening.render_digest.0,
            expires_at: p.expires_at,
        }))
    }

    /// Whether the requester may invite this approver now: an intent already invited never
    /// counts (dedup, A-3).
    pub(super) async fn window_open(
        &self,
        t: &mut TenantTx,
        i: &Invitation,
        now: u64,
    ) -> Result<bool, access_store::StoreError> {
        if store::invite(t, &i.approver, &i.intent).await?.is_some() {
            return Ok(true);
        }
        let (count, _) = store::invites_since(
            t,
            &i.requester,
            &i.approver,
            now.saturating_sub(INVITE_WINDOW_MS),
        )
        .await?;
        Ok(count < INVITES_PER_HOUR)
    }

    /// Records the invitation and sends it, once: inside the notification only for CT1 in a realm
    /// that opened it and to a registered, activated approver device, otherwise a link to the
    /// Approval Surface.
    #[expect(clippy::too_many_arguments, reason = "one push's facts")]
    #[expect(
        clippy::too_many_lines,
        reason = "one invitation: the record, then inside the notification or by link"
    )]
    pub(super) async fn invite(
        &self,
        kit: &RealmKit,
        t: &mut TenantTx,
        i: &Invitation,
        request_id: [u8; 16],
        digest: &[u8; 32],
        push: &ApprovalPush,
        now: u64,
    ) -> Result<(), access_store::StoreError> {
        let new = store::insert_invite(
            t,
            &NewInvite {
                request: request_id,
                requester: i.requester,
                approver: i.approver,
                intent: i.intent,
                tier: tier_code(i.tier),
                now_ms: now,
            },
        )
        .await?;
        if !new {
            return Ok(());
        }
        let realm = kit.realm();
        let notifier = self.messages.notifier(&realm);
        let inline = inline_tier(tier_code(i.tier))
            && store::approval_channel_enabled(t, ApprovalChannel::Inline).await?;
        if inline
            && let Some(bytes) = i.render.as_deref()
            && bytes.len() <= access_identity_account::notify::message::INLINE_RENDER_MAX
        {
            let mut sent = false;
            for device in t.device_keys(i.approver).await? {
                let activated = t
                    .app_factor_key(device.id)
                    .await?
                    .is_some_and(|k| k.hardware_attested && k.app_pin);
                if !activated {
                    continue;
                }
                let message = Message {
                    subject: i.approver,
                    to: Address::Device(b64url_encode(&device.thumbprint)),
                    locale: None,
                    valid_since_ms: None,
                    body: Body::ApprovalInline {
                        intent: hex(&i.intent),
                        render: b64url_encode(bytes),
                        render_digest: hex(&i.render_digest),
                        expires_at_ms: i.expires_at,
                    },
                };
                if let Err(e) = notifier.notify(t, &message).await {
                    tracing::warn!(error = %e, "approval_inline not queued");
                    return Err(access_store::StoreError::Range);
                }
                sent = true;
            }
            if sent {
                return Ok(());
            }
        }
        let Some(redirect) = push.redirect_uri.as_deref() else {
            return Ok(());
        };
        let Some(name) = requester_name(push) else {
            return Ok(());
        };
        let Some((kind, stored)) = t.contact(i.approver).await? else {
            return Ok(());
        };
        let Some(value) = reveal_with_kek(t, &*kit.kek, i.approver, &stored)
            .await
            .map_err(|_| access_store::StoreError::Range)?
        else {
            return Ok(());
        };
        let (to, valid_since_ms) = if kind == "phone" {
            (Address::Phone(value), None)
        } else {
            let since = t
                .mailbox_since(i.approver)
                .await?
                .and_then(|v| u64::try_from(v).ok())
                .unwrap_or(1)
                .max(1);
            (Address::Email(value), Some(since))
        };
        let link = format!(
            "{}/v1/approve?request={}&redirect_uri={}&state={}",
            kit.issuer,
            b64url_encode(digest),
            urlencoding(redirect),
            urlencoding(push.state.as_deref().unwrap_or("invite")),
        );
        let message = Message {
            subject: i.approver,
            to,
            locale: None,
            valid_since_ms,
            body: Body::Prompt {
                prompt: Prompt::ApprovalRequested,
                link: Secret::new(link),
                name,
                expires_at_ms: i.expires_at,
            },
        };
        if let Err(e) = notifier.notify(t, &message).await {
            tracing::warn!(error = %e, "approval_requested not queued");
            return Err(access_store::StoreError::Range);
        }
        Ok(())
    }

    /// `POST /v1/approve/inline` (`approval-inline.cddl`, §13.7.3, SEC26, TN-100, OP-157 m.17).
    #[expect(
        clippy::too_many_lines,
        reason = "one answer: key, invitation, render, statement, eligibility, assertion"
    )]
    pub async fn answer_inline<A, I, P: Approvals, Q: ApprovalClaims>(
        &self,
        devices: &Devices<A, I, P, Q>,
        entry: &RealmEntry,
        body: &InlineAnswer,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let now = self.clock.now_ms();
        let (Ok(bytes), Ok(signature)) =
            (b64url_decode(&body.answer), b64url_decode(&body.signature))
        else {
            return problem(400, "invalid-request", "The answer does not decode");
        };
        let Ok(answer) = inline_answer(&bytes) else {
            return problem(400, "invalid-request", "The answer does not decode");
        };
        let assertion = match &body.assertion {
            None => None,
            Some(a) => match super::credential::assertion_parts(
                &a.credential_id,
                &a.authenticator_data,
                &a.client_data_json,
                &a.signature,
                a.user_handle.as_deref(),
            ) {
                Some(parsed) => Some(parsed),
                None => {
                    return problem(400, "invalid-request", "The assertion does not decode");
                }
            },
        };
        let found = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            let enabled = store::approval_channel_enabled(&mut t, ApprovalChannel::Inline).await?;
            let key = t.device_key_by_thumbprint(&answer.device_key).await?;
            let factor = match &key {
                Some(k) => t.app_factor_key(k.id).await?,
                None => None,
            };
            t.commit().await?;
            Ok::<_, access_store::StoreError>((enabled, key, factor))
        };
        let Ok((enabled, key, factor)) = found.await else {
            return unavailable();
        };
        if !enabled {
            return problem(
                409,
                "approval-inline-off",
                "Notification approval is not open in this realm",
            );
        }
        let (Some(key), Some(factor)) = (key, factor) else {
            return problem(401, "approver-unknown", "This device can't approve here");
        };
        // MD-11, SA-54, OP-157 m.3 (m)
        if !factor.hardware_attested
            || !factor.app_pin
            || !access_identity_account::domain::approver::verify(
                &key.public_key,
                &bytes,
                &signature,
            )
        {
            return problem(401, "approver-unknown", "This device can't approve here");
        }
        // OP-157 m.3 (m)
        let row = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            let invite = store::invite(&mut t, &key.subject, &answer.intent).await?;
            let row = match &invite {
                Some(i) => store::approval(&mut t, &i.request).await?,
                None => None,
            };
            t.commit().await?;
            Ok::<_, access_store::StoreError>(invite.zip(row))
        };
        let (invite, row) = match row.await {
            Ok(Some(found)) => found,
            Ok(None) => return unknown_reply(),
            Err(_) => return unavailable(),
        };
        if invite.answered_ms.is_some() || row.finished_ms.is_some() || row.expires_ms <= now {
            return unknown_reply();
        }
        // §13.7.3
        if !inline_tier(invite.tier) {
            return problem(
                409,
                "approval-inline-off",
                "This request can't be approved from a notification",
            );
        }
        let InlineDecision::Approve(act) = answer.decision else {
            // C30
            let done = async {
                let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
                store::answer_invite(&mut t, &invite.id, "denied", now).await?;
                t.commit().await
            };
            return match done.await {
                Ok(()) => Reply::json(200, json!({ "decision": "denied" })),
                Err(_) => unavailable(),
            };
        };
        let (Ok(kept), Ok(request)) = (
            serde_json::from_slice::<Kept>(&row.contribution),
            serde_json::from_slice::<Value>(&row.request),
        ) else {
            return unavailable();
        };
        let Ok(env) = envelope(&kept.contribution) else {
            return unavailable();
        };
        let Ok(p) = crate::domain::approval::pushed(&request) else {
            return unavailable();
        };
        // §13.7.3, OP-157 m.3 (m)
        let Ok(Some(opening)) = devices.approvals.opening(p.domain, p.intent).await else {
            return unknown_reply();
        };
        let Some(tier) = tier_of(opening.tier).filter(|_| inline_tier(opening.tier)) else {
            return problem(
                409,
                "approval-inline-off",
                "This request can't be approved from a notification",
            );
        };
        if answer.render_digest != opening.render_digest.0
            || act.render_digest != opening.render_digest
        {
            return Reply::problem(super::approve::CHANGED);
        }
        let Some(shown) = opening
            .render
            .as_deref()
            .and_then(|b| render::decode(b).ok())
            .filter(|r| crate::domain::approval::faithful(r, &request))
        else {
            return Reply::problem(super::approve::CHANGED);
        };
        // §9.14.1
        let approver = match self.approver(&kit, &key.subject, &env.ais).await {
            Ok(Some(a)) => a,
            Ok(None) => {
                return problem(
                    403,
                    "approver-instance",
                    "No device of yours signed this contribution",
                );
            }
            Err(r) => return r,
        };
        if act.act != Act::Contribution(env.class.clone())
            || act.target != p.intent
            || act.domain != p.domain
            || act.nonce != env.nonce
            || act.instance != approver.instance
            || act.party != approver.party
            || act.capacity != env.capacity
            || act.surface_profile != SDK_SURFACE_PROFILE
            || act.material_fields != render::material_fields(&shown)
            || act.expires_at <= now
            || !assurance::aas_within_ceiling(tier, act.issued_at, act.expires_at)
        {
            return problem(
                409,
                "approval-changed",
                "The answer doesn't match the request",
            );
        }
        match devices
            .approvals
            .eligibility(
                p.domain,
                &env.class,
                approver.party,
                super::approve::basis_grant(&env.basis),
            )
            .await
        {
            Ok(e) if e.eligible => {}
            Ok(_) => return problem(403, "approval-not-eligible", "You can't approve this"),
            Err(_) => return unavailable(),
        }
        // §10.2, §10.3.1, MD-11, OP-157 m.17
        let Some(assertion) = assertion else {
            return Reply::problem(ASSERTION_REQUIRED);
        };
        let (Ok(aas_bytes), Ok(statement)) = (act.to_bytes(), aas::digest(&act)) else {
            return unavailable();
        };
        // OP-156 m.3 (g)
        if crate::domain::spc::ceremony(assertion.response().client_data_json).as_deref()
            == Some("payment.get")
        {
            return assertion_rejected();
        }
        // §10.3.1, OP-157 m.17
        let verified = match self
            .assert(
                &kit,
                &key.subject,
                &statement.0,
                uv_asked(&opening.unmet),
                &assertion,
                now,
            )
            .await
        {
            Ok(v) => v,
            Err(r) => return r,
        };
        // SEC18, §8.13
        if let Err(r) = cooled(tier, verified.created_ms, now) {
            return r;
        }
        // C30, OP-157 m.17
        let used = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            let used = store::answer_invite(&mut t, &invite.id, "approved", now).await?;
            t.commit().await?;
            Ok::<_, access_store::StoreError>(used)
        };
        match used.await {
            Ok(true) => {}
            Ok(false) => return unknown_reply(),
            Err(_) => return unavailable(),
        }
        let claim = match issue_claim(
            devices,
            &kit,
            key.subject,
            statement.0,
            act.instance,
            &verified,
            now,
        )
        .await
        {
            Ok(c) => c,
            Err(r) => return r,
        };
        // §9.14.1 step 4
        let verdict = devices
            .approvals
            .contribute(Contribution {
                domain: act.domain,
                nonce: env.nonce.clone(),
                target: act.target,
                class: env.class.clone(),
                basis: env.basis,
                capacity: env.capacity,
                validity: env.validity,
                ais: env.ais.clone(),
                aas: aas_bytes,
                claim,
                pep: devices.pep.clone(),
            })
            .await;
        match committed(verdict) {
            Ok(exercise) => {
                // OP-41, OP-157 m.23
                self.spc_audit(&kit, &key.subject, "approval.inline").await;
                Reply::json(
                    200,
                    json!({
                    "decision": "approved",
                    "exercise": b64url_encode(&exercise.0),
                    "render_digest": b64url_encode(&act.render_digest.0),
                    "claim": b64url_encode(&claim.0),
                    }),
                )
            }
            Err(r) => r,
        }
    }
}

/// The requester's display name a push carries, for the invitation's text.
fn requester_name(push: &ApprovalPush) -> Option<String> {
    let requester = push.request.get("requester")?;
    let name = requester
        .get("name")
        .and_then(Value::as_str)
        .or_else(|| push.request.get("application").and_then(Value::as_str))
        .unwrap_or("A requester");
    Some(String::from(name).chars().take(200).collect())
}

fn urlencoding(s: &str) -> String {
    use std::fmt::Write as _;
    s.bytes().fold(String::new(), |mut out, b| {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // SEC26, TN-100, §13.7.3, OP-157 m.3 (m)
    #[test]
    fn a_notification_carries_an_approval_only_up_to_ct1() {
        assert!(inline_tier(tier_code(Tier::Ct0)));
        assert!(inline_tier(tier_code(Tier::Ct1)));
        assert!(!inline_tier(tier_code(Tier::Ct2)));
        assert!(!inline_tier(tier_code(Tier::Ct3)));
    }

    // OP-157 m.17
    #[test]
    fn user_verification_is_asked_only_by_an_open_term() {
        use access_kernel::combinator::{Position, Unmet};
        use access_kernel::model::{
            Binding, Consumption, Independence, ProofKind, RequirementTerm,
        };
        let unmet = |uv: Option<u64>| Unmet {
            term: RequirementTerm {
                proof_kind: ProofKind::Contribution,
                class: String::from("approve"),
                count: 1,
                binding: Binding::IntentDigest,
                freshness_ms: None,
                independence: Independence::None,
                consumption: Consumption::Reusable,
                source: None,
                assurance: uv
                    .map(|l| (String::from(access_kernel::assurance::UV), l))
                    .into_iter()
                    .collect(),
            },
            missing: 1,
            position: Position::Anchor,
            satisfiable_by_actor: false,
        };
        assert!(!uv_asked(&[]));
        assert!(!uv_asked(&[unmet(None), unmet(Some(0))]));
        assert!(uv_asked(&[unmet(None), unmet(Some(1))]));
    }

    // A-3, OP-157 m.3 (m)
    #[test]
    fn the_invitation_limit_is_429_with_a_retry_after() {
        let p = invite_limit();
        assert_eq!((p.status, p.code), (429, "approval-invite-limit"));
        assert_eq!(p.retry_after_s, Some(INVITE_WINDOW_MS / 1_000));
    }
}
