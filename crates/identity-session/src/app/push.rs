//! Push verification with number matching (OP-156 m.3 (d), §10.2.3, TN-102, IDP-4, TN-100): after
//! the first step the flow suspends on a 120 s single-use challenge that Relay carries to the
//! person's approvers; the sign-in page shows the two-digit number, which the push never carries;
//! the approver signs `{challenge, number, decision}` with its device key; the browser's next poll
//! takes the approval as the second step. Push is AAL2 at best and meets no Consequence Tier.

use std::net::IpAddr;

use access_crypto::Secret;
use access_identity_account::app::claims::emit;
use access_identity_account::domain::approver::{self, Answer, Decision, number_of};
use access_identity_account::domain::claims::{
    Bind, ClaimOrder, Content, RISK_SIGNAL, SIGNAL_TTL_MS,
};
use access_identity_account::notify::message::{Address, Body, Message, NoticeReason};
use access_identity_account::ports::AccountTx as _;
use access_identity_risk::domain::geo::GeoAnswer;
use access_identity_webauthn::ports::{CredentialRegistry, SignalSink};
use access_kernel::model::EqValue;
use access_store::push::NewPushChallenge;
use std::collections::BTreeMap;
use suiss_crypto::digest::sha256;

use super::signin::{ANONYMOUS, address};
use super::{
    Auth, FlowRef, Notifier, Resume, STEP_NOT_ALLOWED, Step, audit, encode, gone, hex, load,
    refuse, save,
};
use crate::SessionError;
use crate::domain::assurance::Factor;
use crate::domain::flow::Pending;
use crate::domain::push::{CHALLENGE_TTL_MS, Ended, HISTORY_MS, Past, factor, held};
use crate::ports::{Clock, PaymentTx as _, PushTx as _, Random, SessionDb, SessionTx as _};

const CHALLENGE_CONTEXT: &[u8] = b"access/push-challenge/v1\0";

/// The value of the `risk_signal` Claim a "This wasn't me" answer makes (OP-156 m.3 (d)).
pub const NOT_ME_SIGNAL: &str = "push_not_me";

/// The stored digest of a challenge id (CR-38).
#[must_use]
pub fn challenge_digest(challenge: &[u8; 32]) -> [u8; 32] {
    let mut m = CHALLENGE_CONTEXT.to_vec();
    m.extend_from_slice(challenge);
    sha256(&m)
}

fn only(approvers: &[access_store::push::DeviceKeyRow]) -> Option<String> {
    match approvers {
        [one] => Some(one.name.clone()),
        _ => None,
    }
}

/// Where and for what a push is sent.
#[derive(Clone, Copy)]
pub struct PushContext<'a> {
    /// The realm issuer, which the same-device proof names.
    pub issuer: &'a str,
    /// The application the person signs in to, as the push names it.
    pub application: &'a str,
}

impl core::fmt::Debug for PushContext<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PushContext")
            .field("application", &self.application)
            .finish_non_exhaustive()
    }
}

/// An approver's proof that it started this sign-in itself (in-app sign-in): its key's
/// thumbprint and its signature over [`approver::same_device_message`].
#[derive(Clone, Copy)]
pub struct SameDevice<'a> {
    /// The thumbprint.
    pub device_key: [u8; 32],
    /// The signature.
    pub signature: &'a [u8],
}

impl core::fmt::Debug for SameDevice<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SameDevice").finish_non_exhaustive()
    }
}

/// What the sign-in page shows while a push waits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushWait {
    /// The number to type into the approver.
    pub number: u8,
    /// Unix ms.
    pub expires_ms: u64,
    /// The approver's name when the account has exactly one.
    pub approver: Option<String>,
}

/// The outcome of sending a push. A decision, not an error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PushStart {
    /// Sent: the page shows the number until the end.
    Sent(PushWait),
    /// The fatigue limits hold push for `retry_after_s`; another way is offered.
    Held {
        /// Whole seconds.
        retry_after_s: u64,
        /// Which limit, for telemetry.
        reason: &'static str,
    },
    /// Refused or gone.
    Step(Step),
}

/// How a push the flow waits on ended without an approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PushEnd {
    /// Refused, or the wrong number was typed.
    Denied,
    /// "This wasn't me": the sign-in is stopped.
    NotMe,
    /// No answer in 120 s.
    Expired,
}

/// Where a flow's push stands when its browser polls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PushPoll {
    /// Still waiting.
    Waiting(PushWait),
    /// Ended without an approval; the flow is back at its second step, or stopped.
    Ended(PushEnd),
    /// No push is pending, or the approval was taken: the flow's next step.
    Step(Step),
}

/// The outcome of an approver's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answered {
    /// Approved; the flow takes it on its next poll.
    Approved,
    /// Refused.
    Denied,
    /// "This wasn't me": a risk signal and a security notice follow.
    NotMe,
    /// The number did not match; the challenge is spent.
    WrongNumber,
    /// Not a push answer.
    Malformed,
    /// No such challenge.
    Unknown,
    /// Not signed by an active approver of the challenge's account.
    Refused,
    /// Answered already.
    AlreadyAnswered,
    /// Past its 120 s.
    Expired,
}

impl<D, C, R, N, P, S> Auth<'_, D, C, R, N, P, S>
where
    D: SessionDb,
    C: Clock,
    R: Random,
    N: Notifier + Sync,
    P: CredentialRegistry + Sync,
    S: SignalSink + Sync,
{
    fn number(&self) -> Result<u8, SessionError> {
        loop {
            let mut b = [0_u8; 1];
            self.random.fill(&mut b)?;
            if let Some(n) = number_of(b[0]) {
                return Ok(n);
            }
        }
    }

    fn location(&self, ip: Option<IpAddr>) -> Option<String> {
        match self.risk.services.geo.locate(ip?) {
            GeoAnswer::Found(place) => place.country_code(),
            GeoAnswer::Unavailable => None,
        }
    }

    /// Sends a push verification for the flow's second step (OP-156 m.3 (d)): only in a realm
    /// that offers push, after the first step, to an account with an approver, inside the fatigue
    /// limits. The push names the application, the action and the coarse location, never the
    /// number.
    ///
    /// # Errors
    /// [`SessionError::Invalid`] when the realm does not offer push; [`SessionError`].
    #[expect(
        clippy::too_many_lines,
        reason = "one suspension: limits, proof, challenge, pushes"
    )]
    pub async fn send_push(
        &self,
        flow: &FlowRef<'_>,
        same_device: Option<SameDevice<'_>>,
        cx: PushContext<'_>,
        correlation: &str,
    ) -> Result<PushStart, SessionError> {
        if !self.policy.push {
            return Err(SessionError::Invalid);
        }
        let now = self.now();
        let mut tx = self.begin().await?;
        let mut l = match load(&mut tx, flow, now).await? {
            Ok(l) => l,
            Err(e) => return Ok(PushStart::Step(gone(e))),
        };
        let Some(subject) = l.state.subject.filter(|_| l.state.first_done()) else {
            return Ok(PushStart::Step(refuse(STEP_NOT_ALLOWED)));
        };
        let approvers = tx.approvers(subject).await?;
        if approvers.is_empty() {
            return Ok(PushStart::Step(refuse(STEP_NOT_ALLOWED)));
        }
        let target = self.external(subject)?;
        let history: Vec<Past> = tx
            .push_history(subject, now.saturating_sub(HISTORY_MS))
            .await?
            .into_iter()
            .map(|h| Past {
                created_ms: h.created_ms,
                expires_ms: h.expires_ms,
                answered: h.decision.as_deref().map(Ended::of).zip(h.decided_ms),
            })
            .collect();
        // OP-156 m.3 (d)
        if let Some((why, until)) = held(&history, now) {
            audit(&mut tx, "push.held", &target, &target, correlation).await?;
            tx.commit().await?;
            return Ok(PushStart::Held {
                retry_after_s: until.saturating_sub(now).div_ceil(1000).max(1),
                reason: why.reason(),
            });
        }
        let origin = match same_device {
            None => None,
            Some(proof) => {
                let message = approver::same_device_message(cx.issuer, flow.handle);
                match approvers.iter().find(|a| a.thumbprint == proof.device_key) {
                    Some(a) if approver::verify(&a.public_key, &message, proof.signature) => {
                        Some(a.id)
                    }
                    _ => return Ok(PushStart::Step(refuse(STEP_NOT_ALLOWED))),
                }
            }
        };
        let challenge = self.random32()?;
        let hash = challenge_digest(&challenge);
        let number = self.number()?;
        let expires_ms = now.saturating_add(CHALLENGE_TTL_MS);
        if l.state
            .suspend_second(Pending::Push {
                challenge: hash,
                expires_ms,
            })
            .is_err()
        {
            return Ok(PushStart::Step(refuse(STEP_NOT_ALLOWED)));
        }
        tx.insert_push_challenge(&NewPushChallenge {
            hash: &hash,
            subject,
            flow_hash: &l.row.flow_hash,
            number,
            origin_device: origin,
            created_ms: now,
            expires_ms,
        })
        .await?;
        save(&mut tx, &l, "open", Resume::Keep).await?;
        let location = self.location(self.risk.client);
        let wire = encode(&challenge);
        for a in &approvers {
            tx.notify(
                self.notifier,
                &Message {
                    subject,
                    to: Address::Device(encode(&a.thumbprint)),
                    locale: None,
                    valid_since_ms: None,
                    body: Body::PushApproval {
                        challenge: Secret::new(wire.clone()),
                        application: cx.application.chars().take(200).collect(),
                        action: String::from("Sign in"),
                        location: location.clone(),
                        expires_at_ms: expires_ms,
                    },
                },
            )
            .await?;
        }
        audit(
            &mut tx,
            "push.challenge_sent",
            &target,
            &target,
            correlation,
        )
        .await?;
        tx.commit().await?;
        Ok(PushStart::Sent(PushWait {
            number,
            expires_ms,
            approver: only(&approvers),
        }))
    }

    /// Where the flow's push stands (TN-102): an approval completes only the push step, once; a
    /// refusal or 120 s without an answer puts the flow back at its second step; "This wasn't me"
    /// stops the sign-in. A flow that waits on no push is resumed as usual.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn poll_push(
        &self,
        flow: &FlowRef<'_>,
        correlation: &str,
    ) -> Result<PushPoll, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let mut l = match load(&mut tx, flow, now).await? {
            Ok(l) => l,
            Err(e) => return Ok(PushPoll::Step(gone(e))),
        };
        let Some(Pending::Push {
            challenge,
            expires_ms,
        }) = l.state.pending.clone()
        else {
            drop(tx);
            return Ok(PushPoll::Step(self.resume(flow, correlation).await?));
        };
        let row = tx.push_challenge(&challenge).await?;
        let subject = l.state.subject.ok_or(SessionError::Corrupt)?;
        let decision = row.as_ref().and_then(|r| r.decision.clone());
        match (row, decision.as_deref()) {
            (Some(r), Some("approve")) if r.used_ms.is_none() && r.subject == subject => {
                let device = r.device.ok_or(SessionError::Corrupt)?;
                if !tx.use_push_challenge(r.id, now).await? {
                    return Err(SessionError::Conflict);
                }
                l.state.pending = None;
                // MD-11, OP-156 m.3 (e)
                let app_controlled = tx.app_factor_answer(r.id).await?
                    && tx
                        .app_factor_key(device)
                        .await?
                        .is_some_and(|k| k.hardware_attested && k.app_pin);
                let step = if app_controlled {
                    Factor::app_controlled(device, now)
                } else {
                    factor(device, now)
                };
                if l.state.record(subject, step).is_err() {
                    save(&mut tx, &l, "open", Resume::Keep).await?;
                    tx.commit().await?;
                    return Ok(PushPoll::Step(refuse(STEP_NOT_ALLOWED)));
                }
                let target = self.external(subject)?;
                audit(&mut tx, "auth.flow.resumed", &target, &target, correlation).await?;
                Ok(PushPoll::Step(self.advance(tx, l, now, correlation).await?))
            }
            (_, Some("not_me")) => {
                l.state.pending = None;
                save(&mut tx, &l, "abandoned", Resume::Clear).await?;
                tx.commit().await?;
                Ok(PushPoll::Ended(PushEnd::NotMe))
            }
            (_, Some(_)) => {
                l.state.pending = None;
                save(&mut tx, &l, "open", Resume::Keep).await?;
                tx.commit().await?;
                Ok(PushPoll::Ended(PushEnd::Denied))
            }
            (Some(r), None) if now < expires_ms => Ok(PushPoll::Waiting(PushWait {
                number: r.number,
                expires_ms,
                approver: only(&tx.approvers(subject).await?),
            })),
            _ => {
                l.state.pending = None;
                save(&mut tx, &l, "open", Resume::Keep).await?;
                audit(
                    &mut tx,
                    "auth.flow.expired",
                    ANONYMOUS,
                    ANONYMOUS,
                    correlation,
                )
                .await?;
                tx.commit().await?;
                Ok(PushPoll::Ended(PushEnd::Expired))
            }
        }
    }

    /// An approver's answer (`push-challenge.cddl`): `answer` is the deterministic CBOR it
    /// signed, `signature` its ES256 `r ‖ s`. Only an active approver of the challenge's account
    /// can answer, once, within 120 s; a wrong number spends the challenge; "This wasn't me"
    /// makes a `risk_signal` Claim and a security notice to the person (OP-156 m.3 (d)).
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn answer_push(
        &self,
        answer: &[u8],
        signature: &[u8],
        issuer: &str,
        correlation: &str,
    ) -> Result<Answered, SessionError> {
        let Ok(a) = Answer::decode(answer) else {
            return Ok(Answered::Malformed);
        };
        let now = self.now();
        let mut tx = self.begin().await?;
        let Some(row) = tx.push_challenge(&challenge_digest(&a.challenge)).await? else {
            return Ok(Answered::Unknown);
        };
        // OP-156 m.3 (d)
        let Some(device) = tx
            .approver_by_thumbprint(&a.device_key)
            .await?
            .filter(|d| d.subject == row.subject)
        else {
            return Ok(Answered::Refused);
        };
        if !approver::verify(&device.public_key, answer, signature) {
            return Ok(Answered::Refused);
        }
        if row.decision.is_some() {
            return Ok(Answered::AlreadyAnswered);
        }
        if now >= row.expires_ms {
            return Ok(Answered::Expired);
        }
        let (stored, outcome) = match a.decision {
            Decision::Approve => {
                let matches = match a.number {
                    Some(n) => n == row.number,
                    None => row.origin_device == Some(device.id),
                };
                if matches {
                    ("approve", Answered::Approved)
                } else {
                    ("wrong_number", Answered::WrongNumber)
                }
            }
            Decision::Deny => ("deny", Answered::Denied),
            Decision::NotMe => ("not_me", Answered::NotMe),
        };
        if !tx
            .decide_push_challenge(row.id, stored, now, device.id)
            .await?
        {
            return Ok(Answered::AlreadyAnswered);
        }
        // MD-11, OP-156 m.3 (e)
        if let (Answered::Approved, Some(pin_verified)) = (outcome, a.pin_verified) {
            tx.record_app_factor_answer(row.id, device.id, pin_verified)
                .await?;
        }
        tx.approver_seen(device.id).await?;
        let target = self.external(row.subject)?;
        match outcome {
            Answered::Approved => {
                audit(&mut tx, "push.approved", &target, &target, correlation).await?;
            }
            Answered::NotMe => {
                audit(&mut tx, "push.not_me", &target, &target, correlation).await?;
            }
            _ => audit(&mut tx, "push.denied", &target, &target, correlation).await?,
        }
        if outcome == Answered::NotMe {
            // OP-156 m.3 (d), §7.6 TN-O4
            emit(
                &mut tx,
                &ClaimOrder {
                    subject: row.subject,
                    class: String::from(RISK_SIGNAL),
                    at: now,
                    ttl_ms: SIGNAL_TTL_MS,
                    content: Content::Scalar(EqValue::Text(String::from(NOT_ME_SIGNAL))),
                    assurance: BTreeMap::new(),
                    bind: Bind::None,
                    line: None,
                    retract: false,
                },
            )
            .await?;
            if let Some(to) = address(tx.contact(row.subject).await?) {
                let valid_since_ms = match to {
                    Address::Email(_) => Some(tx.mailbox_since(row.subject).await?.unwrap_or(1)),
                    Address::Phone(_) | Address::Device(_) => None,
                };
                tx.notify(
                    self.notifier,
                    &Message {
                        subject: row.subject,
                        to,
                        locale: None,
                        valid_since_ms,
                        body: Body::SemanticNotice {
                            reason: NoticeReason::SecurityIntervention,
                            intent: hex(&challenge_digest(&a.challenge)),
                            link: Secret::new(format!("{issuer}/account")),
                            until_ms: None,
                        },
                    },
                )
                .await?;
            }
        }
        tx.commit().await?;
        Ok(outcome)
    }
}
