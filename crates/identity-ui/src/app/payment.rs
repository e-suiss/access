//! Payment-class authentication on the hosted surface (OP-156 m.3 (e), (f), MD-11, IDP-4, IDP-9):
//! the SMS code of a sign-in's second step, the activation code a signed-in person asks for, and
//! the activation of an approver as the app-controlled factor: its key's hardware attestation,
//! bound to the approver key and to a challenge of the realm, and under the TR payment profile an
//! SMS activation code first.

use access_identity_account::adapters::pg::PgAccounts;
use access_identity_account::app::approver;
use access_identity_account::domain::login::Problem;
use access_identity_account::notify::ports::Notifier;
use access_identity_account::ports::{AccountDb as _, AccountTx as _};
use access_identity_oauth::ports::RealmEntry;
use access_identity_session::app::FlowRef;
use access_identity_session::app::sessions::{SessionStatus, SessionView};
use access_identity_session::app::sms::{Activation, SmsStart};
use access_identity_session::domain::assurance::AssuranceProfile;
use access_identity_session::ports::Clock;
use access_kernel::json::b64url_decode;
use access_store::audit::AuditEvent;
use serde::Deserialize;
use serde_json::json;
use suiss_crypto::digest::sha256;

use super::push::APPROVER_PREFIX;
use super::signup::{STEP_UP_MAX_AGE_MS, STEP_UP_REQUIRED};
use super::{
    Body, Browser, Current, Hosted, INVALID_SUBMISSION, Reply, SESSION_REQUIRED, Signin, failed,
    signin,
};
use crate::domain::flow::FlowId;
use crate::domain::frontend::rfc3339;
use crate::domain::message::{Message, TextId};
use crate::ports::{Kits, Messages, RealmKit};

const fn problem(status: u16, code: &'static str, title: &'static str) -> Problem {
    Problem {
        status,
        code,
        title,
        retry_after_s: None,
    }
}

const SMS_OFF: Problem = problem(
    409,
    "sms-unavailable",
    "Text message codes aren't available for this account",
);
const SMS_REFUSED: Problem = problem(
    403,
    "sms-refused",
    "Text message codes can't be used for this number right now. Use another way.",
);
const SMS_HELD: Problem = problem(
    429,
    "sms-held",
    "Too many text message codes. Try again later.",
);
const CODE_REFUSED: Problem = problem(401, "code-not-accepted", "That code isn't valid");
const NO_APPROVER: Problem = problem(
    404,
    "no-such-approver",
    "That approver isn't on this account",
);
const ACTIVATION_REQUIRED: Problem = problem(
    403,
    "activation-code-required",
    "Confirm the activation with the code we text you first",
);
const STALE: Problem = problem(400, "attestation-stale", "Ask for the attestation again");
const ATTESTATION_REFUSED: Problem = problem(
    400,
    "attestation-refused",
    "The attestation does not verify",
);
const OTHER_KEY: Problem = problem(
    400,
    "attestation-other-key",
    "The attested key is not this approver's key",
);
const UNSUPPORTED: Problem = problem(
    400,
    "attestation-format-unsupported",
    "This attestation format isn't accepted here",
);

fn unavailable() -> Reply {
    Reply::problem(Problem {
        status: 503,
        code: "unavailable",
        title: "Temporarily unavailable",
        retry_after_s: Some(1),
    })
}

/// The hardware attestation roots and App IDs an approver's key is checked against (AG-31
/// model 1, OP-156 m.3 (e)).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AppFactorRoots {
    /// Android hardware key attestation roots.
    pub android: Vec<Vec<u8>>,
    /// The Apple App Attest root.
    pub apple: Vec<Vec<u8>>,
    /// App IDs (team identifier, a dot, bundle identifier) whose App Attest keys are accepted;
    /// empty accepts none.
    pub apple_app_ids: Vec<String>,
}

impl AppFactorRoots {
    /// The roots `crates/identity-attest` embeds, and `apple_app_ids`.
    #[must_use]
    pub fn embedded(apple_app_ids: Vec<String>) -> Self {
        use access_identity_attest::domain::roots;
        Self {
            android: roots::ANDROID.iter().map(|r| r.to_vec()).collect(),
            apple: roots::APPLE_APP_ATTEST.iter().map(|r| r.to_vec()).collect(),
            apple_app_ids,
        }
    }
}

/// `POST /v1/approvers/{device}/activate`: the approver key's hardware attestation for the
/// challenge of the approver at `at`, and the SMS activation code where the profile asks for one.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationBody {
    /// The challenge's time, Unix ms; within five minutes of the trusted time.
    pub at: u64,
    /// `android-key` or `apple-app-attest`.
    pub format: String,
    /// Android: the attestation certificate chain, leaf first, DER, base64url.
    #[serde(default)]
    pub x5c: Vec<String>,
    /// Apple: the attestation object, base64url.
    #[serde(default)]
    pub attestation: Option<String>,
    /// Apple: the App ID the key was made for.
    #[serde(default)]
    pub app_id: Option<String>,
    /// The SMS activation code.
    #[serde(default)]
    pub activation_code: Option<String>,
}

/// How far the challenge's time may be from the trusted time.
pub const CHALLENGE_SKEW_MS: u64 = 5 * 60_000;

const CHALLENGE_CONTEXT: &[u8] = b"access/app-factor-attestation/v1";

/// The challenge an approver's attestation answers:
/// `SHA-256("access/app-factor-attestation/v1" ‖ 0x00 ‖ issuer ‖ 0x00 ‖ thumbprint ‖ at)`, `at`
/// in Unix ms, big-endian.
#[must_use]
pub fn attestation_challenge(issuer: &str, thumbprint: &[u8; 32], at_ms: u64) -> [u8; 32] {
    let mut m = CHALLENGE_CONTEXT.to_vec();
    m.push(0);
    m.extend_from_slice(issuer.as_bytes());
    m.push(0);
    m.extend_from_slice(thumbprint);
    m.extend_from_slice(&at_ms.to_be_bytes());
    sha256(&m)
}

const MAX_CHAIN: usize = 8;

fn bytes(text: &str, max: usize) -> Option<Vec<u8>> {
    b64url_decode(text)
        .ok()
        .filter(|b| !b.is_empty() && b.len() <= max)
}

/// The attested key of verified evidence, SEC1 uncompressed.
fn attested(
    body: &ActivationBody,
    roots: &AppFactorRoots,
    public_key: &[u8],
    challenge: &[u8; 32],
    now_s: u64,
) -> Result<Vec<u8>, Problem> {
    use access_identity_attest::domain::{android, apple};
    let refused = |e: access_identity_attest::AttestError| {
        tracing::info!(code = e.code(), "app factor attestation refused");
        ATTESTATION_REFUSED
    };
    match body.format.as_str() {
        // OP-156 m.3 (e), L21
        "android-key" => {
            if body.x5c.is_empty() || body.x5c.len() > MAX_CHAIN {
                return Err(INVALID);
            }
            let chain: Vec<Vec<u8>> = body
                .x5c
                .iter()
                .map(|c| bytes(c, 8192))
                .collect::<Option<_>>()
                .ok_or(INVALID)?;
            let anchors: Vec<&[u8]> = roots.android.iter().map(Vec::as_slice).collect();
            let a = android::verify(
                &chain,
                &anchors,
                &android::Policy {
                    challenge,
                    strongbox: false,
                    verified_boot: true,
                    locked: true,
                },
                now_s,
            )
            .map_err(refused)?;
            Ok(a.public_key)
        }
        "apple-app-attest" => {
            let app_id = body.app_id.as_deref().ok_or(INVALID)?;
            if !roots.apple_app_ids.iter().any(|a| a == app_id) {
                return Err(UNSUPPORTED);
            }
            let object = body
                .attestation
                .as_deref()
                .and_then(|o| bytes(o, 16_384))
                .ok_or(INVALID)?;
            let anchors: Vec<&[u8]> = roots.apple.iter().map(Vec::as_slice).collect();
            let a = apple::verify(
                &object,
                &anchors,
                &apple::Policy {
                    app_id,
                    key_id: &sha256(public_key),
                    client_data_hash: challenge,
                    production: true,
                },
                now_s,
            )
            .map_err(refused)?;
            Ok(a.public_key)
        }
        _ => Err(UNSUPPORTED),
    }
}

const INVALID: Problem = problem(400, "invalid-request", "Bad Request");

impl<K, C, M> Hosted<K, C, M>
where
    K: Kits,
    C: Clock + Sync,
    M: Messages,
{
    /// A submitted `send_sms` (OP-156 m.3 (f)): sends the code and shows the second step again
    /// with where it went, or why not.
    pub(super) async fn sms_step<N: Notifier + Sync>(
        &self,
        auth: &Signin<'_, C, N>,
        kit: &RealmKit,
        b: &Browser<'_>,
        flow: &FlowId,
        fref: &FlowRef<'_>,
        current: Current,
    ) -> Result<Reply, Reply> {
        if !matches!(current, Current::Second(_) | Current::PushEnded(..)) {
            return Err(Reply::problem(INVALID_SUBMISSION));
        }
        let (status, message) = match auth
            .send_sms(fref, b.correlation)
            .await
            .map_err(|e| failed(&e))?
        {
            SmsStart::Sent { last_digits, .. } => {
                let mut m = Message::info(TextId::SmsSent);
                m.text = m.text.replace("{ $last_digits }", &last_digits);
                (200, m)
            }
            SmsStart::Refused(why) => {
                tracing::info!(reason = why.reason(), "sms refused");
                (403, Message::error(TextId::SmsRefused))
            }
            SmsStart::Held { retry_after_s } => {
                let seconds = u32::try_from(retry_after_s).unwrap_or(u32::MAX);
                (
                    429,
                    Message::error(TextId::TooManyAttempts).retry_after(seconds),
                )
            }
            SmsStart::Step(s) => return self.outcome(auth, kit, b, flow, fref, s).await,
        };
        let current = self.current(auth, kit, b, fref).await?;
        let mut reply = self.render(auth, kit, flow, fref, current, status).await?;
        if let Body::Ui(ui) = &mut reply.body {
            ui.messages.push(message);
        }
        Ok(reply)
    }

    /// Whether the realm decided `idp.realm.spc`, which opens `payment` on its payment page
    /// (OP-156 m.3 (g)).
    ///
    /// # Errors
    /// The realm's kit is unavailable.
    pub async fn spc_on(&self, entry: &RealmEntry) -> Result<bool, Reply> {
        Ok(self.kit(entry).await?.auth.spc)
    }

    /// The signed-in session, authenticated in the last five minutes.
    async fn fresh_session(&self, kit: &RealmKit, b: &Browser<'_>) -> Result<SessionView, Reply> {
        signin!(self, kit, auth);
        let Some(cookie) = b.session else {
            return Err(Reply::problem(SESSION_REQUIRED));
        };
        let v = match auth.check_session(cookie).await {
            Ok(SessionStatus::Valid(v)) => *v,
            Ok(_) => return Err(Reply::problem(SESSION_REQUIRED)),
            Err(e) => return Err(failed(&e)),
        };
        let last = v.step_up_ms.unwrap_or(v.auth_time_ms).max(v.auth_time_ms);
        if self.clock.now_ms().saturating_sub(last) > STEP_UP_MAX_AGE_MS {
            return Err(Reply::problem(STEP_UP_REQUIRED));
        }
        Ok(v)
    }

    /// `POST /v1/sms/activation` (OP-156 m.3 (f)): an activation code to the signed-in
    /// person's phone number, the one SMS use the TR payment profile allows.
    pub async fn sms_activation(&self, entry: &RealmEntry, b: &Browser<'_>) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let session = match self.fresh_session(&kit, b).await {
            Ok(s) => s,
            Err(r) => return r,
        };
        signin!(self, kit, auth, Some(b.ip));
        match auth
            .send_activation_sms(session.subject, &session.id, b.correlation)
            .await
        {
            Ok(SmsStart::Sent {
                last_digits,
                expires_ms,
            }) => Reply::json(
                202,
                json!({ "last_digits": last_digits, "expires_at": rfc3339(expires_ms) }),
            ),
            Ok(SmsStart::Refused(why)) => {
                tracing::info!(reason = why.reason(), "activation sms refused");
                Reply::problem(SMS_REFUSED)
            }
            Ok(SmsStart::Held { retry_after_s }) => Reply::problem(Problem {
                retry_after_s: Some(retry_after_s),
                ..SMS_HELD
            }),
            Ok(SmsStart::Step(_)) => Reply::problem(SMS_OFF),
            Err(e) => failed(&e),
        }
    }

    /// `POST /v1/approvers/{device}/activate` (MD-11, OP-156 m.3 (e)): makes the person's approver
    /// the app-controlled factor once its key's hardware attestation verifies against the embedded
    /// roots for this approver's challenge; under the TR payment profile only after the SMS
    /// activation code. An approver so activated proves the app-controlled factor only when its
    /// answer declares the app PIN verified.
    pub async fn activate_approver(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        device: &str,
        body: &ActivationBody,
        roots: &AppFactorRoots,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let session = match self.fresh_session(&kit, b).await {
            Ok(s) => s,
            Err(r) => return r,
        };
        let Ok(id) = kit.ids.decode(APPROVER_PREFIX, device) else {
            return Reply::problem(NO_APPROVER);
        };
        let now = self.clock.now_ms();
        if now.abs_diff(body.at) > CHALLENGE_SKEW_MS {
            return Reply::problem(STALE);
        }
        let subject = session.subject;
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
        let Some(row) = rows.into_iter().find(|r| r.id == id) else {
            return Reply::problem(NO_APPROVER);
        };
        let challenge = attestation_challenge(&kit.issuer, &row.thumbprint, body.at);
        let key = match attested(body, roots, &row.public_key, &challenge, now / 1000) {
            Ok(k) => k,
            Err(p) => return Reply::problem(p),
        };
        if key != row.public_key {
            return Reply::problem(OTHER_KEY);
        }
        // OP-156 m.3 (e), (f)
        signin!(self, kit, auth, Some(b.ip));
        let profile = kit.auth.profile;
        match body.activation_code.as_deref() {
            Some(code) => match auth
                .activation_sms(subject, &session.id, code, b.correlation)
                .await
            {
                Ok(Activation::Proven) => {}
                Ok(Activation::NotAccepted) => return Reply::problem(CODE_REFUSED),
                Ok(Activation::Refused(why)) => {
                    tracing::info!(reason = why.reason(), "activation sms refused");
                    return Reply::problem(SMS_REFUSED);
                }
                Err(e) => return failed(&e),
            },
            None if profile == AssuranceProfile::TrPayment => {
                return Reply::problem(ACTIVATION_REQUIRED);
            }
            None => {}
        }
        let actor = kit.ids.encode("usr", subject).unwrap_or_default();
        let target = kit.ids.encode(APPROVER_PREFIX, id).unwrap_or_default();
        let done = async {
            let mut tx = PgAccounts::sealed(self.db.clone(), kit.vault())
                .begin(kit.tenant, kit.realm)
                .await?;
            if !tx.0.attest_app_factor_key(subject, id).await? {
                return Ok(false);
            }
            tx.audit(&AuditEvent {
                event_type: "app_factor.activated",
                actor: &actor,
                target: &target,
                correlation: b.correlation,
            })
            .await?;
            tx.commit().await?;
            Ok::<_, access_identity_account::AccountError>(true)
        };
        match done.await {
            Ok(true) => Reply::json(
                200,
                json!({
                    "id": target,
                    "hardware_attested": true,
                    "pin_policy": "app_pin",
                }),
            ),
            Ok(false) => Reply::problem(NO_APPROVER),
            Err(_) => unavailable(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-156 m.3 (e)
    #[test]
    fn the_challenge_names_the_issuer_the_key_and_the_time() {
        let c = attestation_challenge("https://a.test", &[1; 32], 5);
        assert_ne!(c, attestation_challenge("https://b.test", &[1; 32], 5));
        assert_ne!(c, attestation_challenge("https://a.test", &[2; 32], 5));
        assert_ne!(c, attestation_challenge("https://a.test", &[1; 32], 6));
    }
}
