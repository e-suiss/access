//! Push verification and approvers on the hosted surface (OP-156 m.3 (d), §10.2.3): sending a push
//! for the flow's second step, an approver's signed answer, and the person's approvers on the
//! account surface (S11). There is no Access store app: an approver is any app that embeds the
//! public SDK's approver module, and none is privileged.

use access_identity_account::adapters::pg::PgAccounts;
use access_identity_account::adapters::system::SystemEntropy;
use access_identity_account::app::approver::{self, Context, Refused, Registration};
use access_identity_account::domain::login::Problem;
use access_identity_account::notify::ports::Notifier;
use access_identity_account::ports::{AccountDb as _, AccountTx as _};
use access_identity_oauth::ports::RealmEntry;
use access_identity_session::app::FlowRef;
use access_identity_session::app::push::{Answered, PushContext, PushStart, SameDevice};
use access_identity_session::ports::Clock;
use access_kernel::json::{b64url_decode, b64url_encode};
use serde_json::{Value, json};

use super::signup::STEP_UP_MAX_AGE_MS;
use super::{
    Body, Browser, Current, Hosted, INVALID_SUBMISSION, Reply, Signin, failed, flow_id, policy,
    signin,
};
use crate::domain::flow::{FlowId, Ui};
use crate::domain::frontend::rfc3339;
use crate::domain::message::{Message, TextId};
use crate::ports::{Kits, Messages, RealmKit};

/// Prefix of an approver's external id.
pub const APPROVER_PREFIX: &str = "apv";

const fn problem(status: u16, code: &'static str, title: &'static str) -> Problem {
    Problem {
        status,
        code,
        title,
        retry_after_s: None,
    }
}

const MALFORMED: Problem = problem(400, "invalid-push-answer", "That isn't a push answer");
const UNKNOWN: Problem = problem(404, "push-challenge-unknown", "No such push request");
const REFUSED: Problem = problem(
    401,
    "push-answer-refused",
    "This answer isn't signed by an approver of the account",
);
const ANSWERED: Problem = problem(
    409,
    "push-challenge-answered",
    "This push request was answered already",
);
const EXPIRED: Problem = problem(410, "push-challenge-expired", "This push request expired");
const WRONG_NUMBER: Problem = problem(
    403,
    "push-number-mismatch",
    "That number doesn't match the sign-in page. Nothing was approved.",
);
const NO_APPROVER: Problem = problem(
    404,
    "no-such-approver",
    "That approver isn't on this account",
);
const BAD_NAME: Problem = problem(
    400,
    "invalid-approver-name",
    "Give the approver a name of up to 200 characters",
);
const BAD_KEY: Problem = problem(
    400,
    "invalid-approver-key",
    "The approver's key must be an uncompressed P-256 public key",
);
const BAD_PROOF: Problem = problem(
    400,
    "approver-proof",
    "The approver's signature doesn't prove it holds the key",
);
const KNOWN: Problem = problem(409, "approver-known", "This approver is registered already");
const TOO_MANY: Problem = problem(
    409,
    "approver-limit",
    "This account has as many approvers as it can hold. Remove one first.",
);
const INACTIVE: Problem = problem(
    403,
    "account-inactive",
    "This account can't sign in right now",
);

fn unavailable() -> Reply {
    Reply::problem(Problem {
        status: 503,
        code: "unavailable",
        title: "Temporarily unavailable",
        retry_after_s: Some(1),
    })
}

fn at(ms: Option<i64>) -> Value {
    ms.and_then(|m| u64::try_from(m).ok())
        .map_or(Value::Null, |m| Value::String(rfc3339(m)))
}

/// A same-device proof as the wire carries it: the key's thumbprint and the signature, base64url.
#[derive(Clone, Copy, Debug)]
pub struct SameDeviceWire<'a> {
    /// The thumbprint.
    pub device_key: &'a str,
    /// The signature.
    pub signature: &'a str,
}

impl<K, C, M> Hosted<K, C, M>
where
    K: Kits,
    C: Clock + Sync,
    M: Messages,
{
    /// Sends the push of the flow's second step and answers with the step that shows the number.
    pub(super) async fn push<N: Notifier + Sync>(
        &self,
        auth: &Signin<'_, C, N>,
        kit: &RealmKit,
        b: &Browser<'_>,
        flow: &FlowId,
        fref: &FlowRef<'_>,
        same: Option<SameDevice<'_>>,
    ) -> Result<Reply, Reply> {
        let cx = PushContext {
            issuer: &kit.issuer,
            application: &kit.name,
        };
        match auth
            .send_push(fref, same, cx, b.correlation)
            .await
            .map_err(|e| failed(&e))?
        {
            PushStart::Sent { number, expires_ms } => Ok(Reply::ui(
                200,
                Ui::push_sent(flow.clone(), number, rfc3339(expires_ms), &policy(kit)),
            )),
            PushStart::Held {
                retry_after_s,
                reason,
            } => {
                // OP-156 m.3 (d)
                tracing::info!(
                    event = "push.fatigue.held",
                    reason,
                    "push held by the fatigue limits"
                );
                let current = self.current(auth, kit, b, fref).await?;
                let mut reply = self.render(auth, kit, flow, fref, current, 429).await?;
                if let Body::Ui(ui) = &mut reply.body {
                    let seconds = u32::try_from(retry_after_s).unwrap_or(u32::MAX);
                    ui.messages
                        .push(Message::error(TextId::PushHeld).retry_after(seconds));
                }
                reply.retry_after_s = Some(retry_after_s);
                Ok(reply)
            }
            PushStart::Step(s) => self.outcome(auth, kit, b, flow, fref, s).await,
        }
    }

    /// A submitted push step: sends the push from the second step, shows the waiting one again.
    pub(super) async fn push_step<N: Notifier + Sync>(
        &self,
        auth: &Signin<'_, C, N>,
        kit: &RealmKit,
        b: &Browser<'_>,
        flow: &FlowId,
        fref: &FlowRef<'_>,
        current: Current,
    ) -> Result<Reply, Reply> {
        match current {
            Current::Second(_) | Current::PushEnded(..) => {
                self.push(auth, kit, b, flow, fref, None).await
            }
            Current::Push(..) => self.render(auth, kit, flow, fref, current, 200).await,
            _ => Err(Reply::problem(INVALID_SUBMISSION)),
        }
    }

    /// `POST /v1/push/challenge`: sends a push for the flow's second step, from the sign-in page
    /// or, with `same`, from an approver that started the sign-in itself.
    pub async fn push_challenge(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        handle: &str,
        same: Option<SameDeviceWire<'_>>,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        signin!(self, kit, auth, Some(b.ip));
        let reply = async {
            let flow = flow_id(handle)?;
            let fref = FlowRef {
                handle,
                device: b.flow.unwrap_or_default(),
            };
            let decoded = match same {
                None => None,
                Some(w) => {
                    let key = b64url_decode(w.device_key)
                        .ok()
                        .and_then(|k| <[u8; 32]>::try_from(k).ok());
                    let sig = b64url_decode(w.signature).ok();
                    match (key, sig) {
                        (Some(k), Some(s)) => Some((k, s)),
                        _ => return Err(Reply::problem(INVALID_SUBMISSION)),
                    }
                }
            };
            let current = self.current(&auth, &kit, b, &fref).await?;
            match current {
                Current::Second(_) | Current::PushEnded(..) => {
                    let proof = decoded.as_ref().map(|(k, s)| SameDevice {
                        device_key: *k,
                        signature: s,
                    });
                    self.push(&auth, &kit, b, &flow, &fref, proof).await
                }
                Current::Done(r) => Ok(r),
                other => self.render(&auth, &kit, &flow, &fref, other, 409).await,
            }
        }
        .await
        .unwrap_or_else(|r| r);
        self.drawn(&kit, reply).await
    }

    /// `POST /v1/push/answer`: an approver's signed answer to a push (`push-challenge.cddl`).
    pub async fn push_answer(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        answer: &str,
        signature: &str,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        signin!(self, kit, auth, Some(b.ip));
        let (Ok(answer), Ok(signature)) = (b64url_decode(answer), b64url_decode(signature)) else {
            return Reply::problem(MALFORMED);
        };
        match auth
            .answer_push(&answer, &signature, &kit.issuer, b.correlation)
            .await
        {
            Ok(Answered::Approved) => Reply::json(200, json!({ "state": "approved" })),
            Ok(Answered::Denied) => Reply::json(200, json!({ "state": "denied" })),
            Ok(Answered::NotMe) => Reply::json(200, json!({ "state": "not_me" })),
            Ok(Answered::WrongNumber) => Reply::problem(WRONG_NUMBER),
            Ok(Answered::Malformed) => Reply::problem(MALFORMED),
            Ok(Answered::Unknown) => Reply::problem(UNKNOWN),
            Ok(Answered::Refused) => Reply::problem(REFUSED),
            Ok(Answered::AlreadyAnswered) => Reply::problem(ANSWERED),
            Ok(Answered::Expired) => Reply::problem(EXPIRED),
            Err(e) => failed(&e),
        }
    }

    /// `GET /v1/approvers`: the person's approvers; never a key.
    pub async fn approvers(&self, entry: &RealmEntry, b: &Browser<'_>) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let subject = match self.fresh(&kit, b, None).await {
            Ok((s, _)) => s,
            Err(r) => return r,
        };
        let read = async {
            let mut tx = PgAccounts::sealed(self.db.clone(), kit.vault())
                .begin(kit.tenant, kit.realm)
                .await?;
            let rows = approver::list(&mut tx, subject).await?;
            tx.commit().await?;
            Ok::<_, access_identity_account::AccountError>(rows)
        };
        let Ok(rows) = read.await else {
            return unavailable();
        };
        let list: Vec<Value> = rows
            .iter()
            .map(|r| {
                json!({
                    "id": kit.ids.encode(APPROVER_PREFIX, r.id).ok(),
                    "name": r.name,
                    "device_key": b64url_encode(&r.thumbprint),
                    "registered_at": at(Some(r.created_ms)),
                    "last_used_at": at(r.last_seen_ms),
                })
            })
            .collect();
        Reply::json(200, json!({ "approvers": list }))
    }

    /// `POST /v1/approvers`: registers an approver's key after a sign-in in the last 5 minutes.
    pub async fn register_approver(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        name: &str,
        public_key: &str,
        proof: &str,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let subject = match self.fresh(&kit, b, Some(STEP_UP_MAX_AGE_MS)).await {
            Ok((s, _)) => s,
            Err(r) => return r,
        };
        let (Ok(key), Ok(proof)) = (b64url_decode(public_key), b64url_decode(proof)) else {
            return Reply::problem(BAD_KEY);
        };
        let realm = kit.realm();
        let notifier = self.messages.notifier(&realm);
        let actor = kit.ids.encode("usr", subject).unwrap_or_default();
        let made = async {
            let mut tx = PgAccounts::sealed(self.db.clone(), kit.vault())
                .begin(kit.tenant, kit.realm)
                .await?;
            let cx = Context {
                actor: &actor,
                correlation: b.correlation,
                at_ms: tx.server_time().await?,
            };
            let out = approver::register(
                &mut tx,
                &SystemEntropy,
                &notifier,
                subject,
                &Registration {
                    name,
                    public_key: &key,
                    proof: &proof,
                    issuer: &kit.issuer,
                },
                cx,
            )
            .await?;
            if out.is_ok() {
                tx.commit().await?;
            }
            Ok::<_, access_identity_account::AccountError>(out)
        };
        match made.await {
            Ok(Ok(r)) => Reply::json(
                201,
                json!({
                    "id": kit.ids.encode(APPROVER_PREFIX, r.id).ok(),
                    "name": name.trim(),
                    "device_key": b64url_encode(&r.thumbprint),
                }),
            ),
            Ok(Err(Refused::Name)) => Reply::problem(BAD_NAME),
            Ok(Err(Refused::Key)) => Reply::problem(BAD_KEY),
            Ok(Err(Refused::Proof)) => Reply::problem(BAD_PROOF),
            Ok(Err(Refused::Known)) => Reply::problem(KNOWN),
            Ok(Err(Refused::TooMany)) => Reply::problem(TOO_MANY),
            Ok(Err(Refused::Inactive)) => Reply::problem(INACTIVE),
            Ok(Err(Refused::Missing)) => Reply::problem(NO_APPROVER),
            Err(_) => unavailable(),
        }
    }

    /// `POST /v1/approvers/{device}/retire`: after a sign-in in the last 5 minutes.
    pub async fn retire_approver(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        device: &str,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let subject = match self.fresh(&kit, b, Some(STEP_UP_MAX_AGE_MS)).await {
            Ok((s, _)) => s,
            Err(r) => return r,
        };
        let Ok(id) = kit.ids.decode(APPROVER_PREFIX, device) else {
            return Reply::problem(NO_APPROVER);
        };
        let actor = kit.ids.encode("usr", subject).unwrap_or_default();
        let done = async {
            let mut tx = PgAccounts::sealed(self.db.clone(), kit.vault())
                .begin(kit.tenant, kit.realm)
                .await?;
            let cx = Context {
                actor: &actor,
                correlation: b.correlation,
                at_ms: tx.server_time().await?,
            };
            let out = approver::retire(&mut tx, subject, id, cx).await?;
            if out.is_ok() {
                tx.commit().await?;
            }
            Ok::<_, access_identity_account::AccountError>(out)
        };
        match done.await {
            Ok(Ok(())) => Reply::new(204, Body::Empty),
            Ok(Err(_)) => Reply::problem(NO_APPROVER),
            Err(_) => unavailable(),
        }
    }
}
