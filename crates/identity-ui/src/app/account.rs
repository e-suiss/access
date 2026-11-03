//! The signed-in user's own surface: the current session, the session list and sign-out
//! everywhere (S10, TN-50), sign-out (§12.0.3), TOTP enrolment and recovery codes (§10.2.2,
//! TN-64) and passkey registration (§10.2.4). A session that is not live gets `401` and issues
//! nothing (G57).

use access_identity_account::domain::login::Problem;
use access_identity_oauth::ports::RealmEntry;
use access_identity_session::app::sessions::{SessionStatus, SessionView};
use access_identity_session::app::{Refusal, Step as Outcome};
use access_identity_session::domain::session::{SESSION_COOKIE, clear_cookie};
use access_identity_session::ports::Clock;
use access_identity_webauthn::app::RegistrationOutcome;
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::{Body, Browser, Hosted, Reply, SESSION_REQUIRED, credential, failed, signin};
use crate::ports::{Kits, Messages, RealmKit};

/// Opaque id prefix of a session (OP-137).
const SESSION_PREFIX: &str = "ses";

/// A registration that does not verify.
const NOT_REGISTERED: Problem = Problem {
    status: 400,
    code: "passkey-not-registered",
    title: "The passkey could not be registered",
    retry_after_s: None,
};

fn rfc3339(ms: u64) -> Value {
    i128::from(ms)
        .checked_mul(1_000_000)
        .and_then(|ns| OffsetDateTime::from_unix_timestamp_nanos(ns).ok())
        .and_then(|t| t.format(&Rfc3339).ok())
        .map_or(Value::Null, Value::String)
}

fn session_json(kit: &RealmKit, v: &SessionView, current: Option<[u8; 16]>) -> Value {
    let mut out = json!({
        "id": kit.ids.encode(SESSION_PREFIX, v.id).ok(),
        "authenticated_at": rfc3339(v.auth_time_ms),
        "expires_at": rfc3339(v.expires_ms),
        "keep_signed_in": v.keep_signed_in,
        "assurance": serde_json::to_value(&v.assurance).unwrap_or(Value::Null),
    });
    if let (Some(c), Some(map)) = (current, out.as_object_mut()) {
        map.insert("current".to_owned(), Value::Bool(c == v.id));
    }
    out
}

fn ended(status: &SessionStatus) -> Reply {
    let mut r = Reply::problem(SESSION_REQUIRED);
    if matches!(status, SessionStatus::Invalid(_)) {
        r.cookies.push(clear_cookie(SESSION_COOKIE));
    }
    r
}

fn secrets(codes: &[access_crypto::Secret<String>]) -> Value {
    Value::Array(
        codes
            .iter()
            .map(|c| Value::String(c.expose().clone()))
            .collect(),
    )
}

fn refusal(step: &Outcome) -> Reply {
    match *step {
        Outcome::Rejected(Refusal { problem, .. }) => Reply::problem(problem),
        Outcome::Throttled { retry_after_s } => Reply::problem(Problem {
            status: 429,
            code: "login-throttled",
            title: "Too many attempts",
            retry_after_s: Some(retry_after_s),
        }),
        _ => Reply::problem(super::NOT_ALLOWED),
    }
}

impl<K, C, M> Hosted<K, C, M>
where
    K: Kits,
    C: Clock + Sync,
    M: Messages,
{
    /// `GET /v1/sessions/current`.
    pub async fn current_session(&self, entry: &RealmEntry, b: &Browser<'_>) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        signin!(self, kit, auth);
        let Some(cookie) = b.session else {
            return Reply::problem(SESSION_REQUIRED);
        };
        match auth.check_session(cookie).await {
            Ok(SessionStatus::Valid(v)) => {
                let mut body = session_json(&kit, &v, None);
                if let Some(map) = body.as_object_mut() {
                    map.insert(
                        "subject".to_owned(),
                        kit.realm().external(v.subject).ok().into(),
                    );
                }
                Reply::json(200, body)
            }
            Ok(other) => ended(&other),
            Err(e) => failed(&e),
        }
    }

    /// `GET /v1/sessions`: the user's live sessions, newest first ("Signed in until …", S10).
    pub async fn sessions(&self, entry: &RealmEntry, b: &Browser<'_>) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        signin!(self, kit, auth);
        let Some(cookie) = b.session else {
            return Reply::problem(SESSION_REQUIRED);
        };
        let me = match auth.check_session(cookie).await {
            Ok(SessionStatus::Valid(v)) => v,
            Ok(other) => return ended(&other),
            Err(e) => return failed(&e),
        };
        match auth.sessions(me.subject).await {
            Ok(list) => Reply::json(
                200,
                json!({
                    "sessions": list
                        .iter()
                        .map(|v| session_json(&kit, v, Some(me.id)))
                        .collect::<Vec<_>>(),
                }),
            ),
            Err(e) => failed(&e),
        }
    }

    /// `POST /v1/sessions/current/sign-out`: ends this browser's session and clears its
    /// cookie (§12.0.3). Answered the same with or without a live session.
    pub async fn sign_out(&self, entry: &RealmEntry, b: &Browser<'_>) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        signin!(self, kit, auth);
        match auth
            .sign_out(b.session.unwrap_or_default(), b.correlation)
            .await
        {
            Ok(clear) => Reply::new(204, Body::Empty).cookie(Some(clear)),
            Err(e) => failed(&e),
        }
    }

    /// `POST /v1/sessions/sign-out-everywhere`: one `session_epoch` step ends every session
    /// and refresh family of the user, this one included (TN-50, MD-7).
    pub async fn sign_out_everywhere(&self, entry: &RealmEntry, b: &Browser<'_>) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        signin!(self, kit, auth);
        let Some(cookie) = b.session else {
            return Reply::problem(SESSION_REQUIRED);
        };
        let me = match auth.check_session(cookie).await {
            Ok(SessionStatus::Valid(v)) => v,
            Ok(other) => return ended(&other),
            Err(e) => return failed(&e),
        };
        let actor = match kit.realm().external(me.subject) {
            Ok(a) => a,
            Err(e) => return failed(&e.into()),
        };
        match auth
            .sign_out_everywhere(me.subject, &actor, b.correlation)
            .await
        {
            Ok(_) => Reply::new(204, Body::Empty).cookie(Some(clear_cookie(SESSION_COOKIE))),
            Err(e) => failed(&e),
        }
    }

    /// `POST /v1/account/totp`: starts a TOTP enrolment; the seed is shown once (§10.2.2).
    pub async fn begin_totp(&self, entry: &RealmEntry, b: &Browser<'_>, label: &str) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        signin!(self, kit, auth);
        match auth
            .begin_totp(b.session.unwrap_or_default(), &kit.name, label)
            .await
        {
            Ok(Ok(e)) => Reply::json(
                201,
                json!({
                    "enrollment": e.handle,
                    "secret": e.secret.expose(),
                    "uri": e.uri.expose(),
                }),
            ),
            Ok(Err(status)) => ended(&status),
            Err(e) => failed(&e),
        }
    }

    /// `POST /v1/account/totp/{enrollment}`: confirms with the first code. Every other session
    /// ends (TN-64); recovery codes come back once when the account had none.
    pub async fn confirm_totp(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        enrollment: &str,
        code: &str,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        signin!(self, kit, auth);
        match auth
            .confirm_totp(
                b.session.unwrap_or_default(),
                enrollment,
                code,
                b.correlation,
            )
            .await
        {
            Ok(Ok(done)) => {
                let mut body = json!({});
                if let (Some(codes), Some(map)) = (&done.recovery_codes, body.as_object_mut()) {
                    map.insert("recovery_codes".to_owned(), secrets(codes));
                }
                Reply::json(200, body)
            }
            Ok(Err(step)) => refusal(&step),
            Err(e) => failed(&e),
        }
    }

    /// `POST /v1/account/recovery-codes`: a new set, shown once; the old set stops working
    /// (TN-59).
    pub async fn recovery_codes(&self, entry: &RealmEntry, b: &Browser<'_>) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        signin!(self, kit, auth);
        match auth
            .regenerate_recovery_codes(b.session.unwrap_or_default(), b.correlation)
            .await
        {
            Ok(Ok(codes)) => Reply::json(200, json!({ "recovery_codes": secrets(&codes) })),
            Ok(Err(status)) => ended(&status),
            Err(e) => failed(&e),
        }
    }

    /// `POST /v1/account/passkeys`: starts a passkey registration (§10.2.4).
    pub async fn begin_passkey(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        name: &str,
        display_name: &str,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        signin!(self, kit, auth);
        match auth
            .begin_passkey(b.session.unwrap_or_default(), name, display_name)
            .await
        {
            Ok(Ok(reg)) => Reply::json(
                201,
                json!({ "registration": reg.handle, "options": reg.options }),
            ),
            Ok(Err(status)) => ended(&status),
            Err(e) => failed(&e),
        }
    }

    /// `POST /v1/account/passkeys/{registration}`: finishes it with the browser's
    /// `PublicKeyCredential` JSON.
    pub async fn finish_passkey(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        registration: &str,
        credential_json: &str,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        signin!(self, kit, auth);
        let Some(owned) = credential::registration(credential_json) else {
            return Reply::problem(NOT_REGISTERED);
        };
        match auth
            .finish_passkey(
                b.session.unwrap_or_default(),
                registration,
                &owned.response(),
                b.correlation,
            )
            .await
        {
            Ok(Ok(RegistrationOutcome::Registered(_))) => Reply::json(201, json!({})),
            Ok(Ok(RegistrationOutcome::Rejected(_))) => Reply::problem(NOT_REGISTERED),
            Ok(Err(step)) => refusal(&step),
            Err(e) => failed(&e),
        }
    }
}
