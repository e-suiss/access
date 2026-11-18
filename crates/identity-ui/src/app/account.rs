//! The signed-in user's own surface: the current session, the session list and sign-out
//! everywhere (S10, TN-50), sign-out (§12.0.3), TOTP enrolment and recovery codes (§10.2.2,
//! TN-64) and passkey registration (§10.2.4). A session that is not live gets `401` and issues
//! nothing (G57).

use access_identity_account::domain::login::Problem;
use access_identity_oauth::ports::EnvironmentEntry;
use access_identity_session::app::change_gate::Gate;
use access_identity_session::app::sessions::{SessionStatus, SessionView};
use access_identity_session::app::{Refusal, Step as Outcome};
use access_identity_session::domain::recovery::Restricted;
use access_identity_session::domain::session::{SESSION_COOKIE, clear_cookie};
use access_identity_session::ports::Clock;
use access_identity_webauthn::app::RegistrationOutcome;
use access_identity_webauthn::domain::Rejection;
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::{Body, Browser, Hosted, Reply, SESSION_REQUIRED, credential, failed, signin};
use crate::ports::{EnvironmentKit, Kits, Messages};

/// Opaque id prefix of a session (OP-137).
const SESSION_PREFIX: &str = "ses";

/// A registration that does not verify.
const NOT_REGISTERED: Problem = Problem {
    status: 400,
    code: "passkey-not-registered",
    title: "The passkey could not be registered",
    retry_after_s: None,
};

/// The environment's `direct` attestation policy refused the authenticator (§10.2.4, OP-159 m.3 (ll)).
const ATTESTATION_FORMAT: Problem = Problem {
    status: 422,
    code: "attestation-format",
    title: "This security key isn't accepted here",
    retry_after_s: None,
};

/// The revocation status of the authenticator's attestation could not be read, so the `direct`
/// policy refuses it (fail-closed, OP-159 m.3 (ll)).
const ATTESTATION_REVOCATION_UNKNOWN: Problem = Problem {
    status: 422,
    code: "attestation-revocation-unknown",
    title: "This security key can't be checked right now",
    retry_after_s: None,
};

/// The answer to a refused registration: honest after authentication (X34).
pub(crate) fn refused(rejection: Rejection) -> Reply {
    match rejection {
        // OP-159 m.3 (ll)
        Rejection::AttestationRevocationUnknown | Rejection::MetadataUnavailable => {
            Reply::problem(ATTESTATION_REVOCATION_UNKNOWN)
        }
        r if r.is_attestation() => Reply::problem(ATTESTATION_FORMAT),
        _ => Reply::problem(NOT_REGISTERED),
    }
}

fn rfc3339(ms: u64) -> Value {
    i128::from(ms)
        .checked_mul(1_000_000)
        .and_then(|ns| OffsetDateTime::from_unix_timestamp_nanos(ns).ok())
        .and_then(|t| t.format(&Rfc3339).ok())
        .map_or(Value::Null, Value::String)
}

fn session_json(kit: &EnvironmentKit, v: &SessionView, current: Option<[u8; 16]>) -> Value {
    let mut out = json!({
        "id": kit.ids.encode(SESSION_PREFIX, v.id).ok(),
        "authenticated_at": rfc3339(v.auth_time_ms),
        "expires_at": rfc3339(v.expires_ms),
        "keep_signed_in": v.keep_signed_in,
        "assurance": serde_json::to_value(&v.assurance).unwrap_or(Value::Null),
        // TN-33
        "device": Value::Null,
        "instance": v.instance.map(|i| access_kernel::json::b64url_encode(&i)),
        "bound": v.bound,
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

/// The answer to a sign-in method change the gate refused (TN-147).
pub(super) fn gated(gate: &Gate) -> Reply {
    match gate {
        Gate::Ended(status) => ended(status),
        Gate::StepUp => Reply::problem(super::signup::STEP_UP_REQUIRED),
        Gate::NoAddress => Reply::problem(Problem {
            status: 409,
            code: "proof-unavailable",
            title: "Add an email address or phone number to your account first",
            retry_after_s: None,
        }),
        Gate::Throttled => Reply::problem(Problem {
            status: 429,
            code: "too-many-requests",
            title: "Too many attempts",
            retry_after_s: None,
        }),
    }
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
    pub async fn current_session(&self, entry: &EnvironmentEntry, b: &Browser<'_>) -> Reply {
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
                        kit.environment().external(v.subject).ok().into(),
                    );
                }
                Reply::json(200, body)
            }
            Ok(other) => {
                let mut r = ended(&other);
                // OP-153 m.3 (y)
                r.reason = auth.signed_out_reason(cookie).await.ok().flatten();
                r
            }
            Err(e) => failed(&e),
        }
    }

    /// `GET /v1/sessions`: the user's live sessions, newest first ("Signed in until …", S10).
    pub async fn sessions(&self, entry: &EnvironmentEntry, b: &Browser<'_>) -> Reply {
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
    pub async fn sign_out(&self, entry: &EnvironmentEntry, b: &Browser<'_>) -> Reply {
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

    /// `POST /v1/login/sign-out/preview` (TN-153): whether the sign-out ticket is open for this
    /// browser's session, and where staying signed in goes; nothing is used.
    pub async fn preview_sign_out(
        &self,
        entry: &EnvironmentEntry,
        b: &Browser<'_>,
        ticket: &str,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let raw = access_kernel::json::b64url_decode(ticket)
            .ok()
            .and_then(|v| <[u8; 32]>::try_from(v).ok());
        let cookie = b
            .session
            .map(|c| access_identity_session::domain::dbsc::split_cookie(c).0)
            .and_then(|c| access_kernel::json::b64url_decode(c).ok())
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
            .map(|v| access_identity_session::domain::session::cookie_digest(&v));
        let (Some(raw), Some(cookie)) = (raw, cookie) else {
            return Reply::problem(access_identity_session::app::FLOW_GONE);
        };
        let digest = access_identity_oauth::domain::fapi::logout_ticket_digest(&raw);
        let now = self.clock.now_ms();
        let read = async {
            let mut t =
                access_store::identity::TenantTx::begin(&self.db, kit.tenant, kit.environment)
                    .await?;
            let row = t.logout_ticket(&digest, now, false).await?;
            t.commit().await?;
            Ok::<_, access_store::StoreError>(row)
        };
        match read.await {
            Ok(Some(t)) if t.cookie_hash == cookie => {
                Reply::json(200, serde_json::json!({ "cancel_to": t.cancel_uri }))
            }
            Ok(_) => Reply::problem(access_identity_session::app::FLOW_GONE),
            Err(_) => super::me::unavailable(),
        }
    }

    /// `POST /v1/sessions/sign-out-everywhere`: one `session_epoch` step ends every session
    /// and refresh family of the user, this one included (TN-50, MD-7).
    pub async fn sign_out_everywhere(&self, entry: &EnvironmentEntry, b: &Browser<'_>) -> Reply {
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
        let actor = match kit.environment().external(me.subject) {
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
    pub async fn begin_totp(
        &self,
        entry: &EnvironmentEntry,
        b: &Browser<'_>,
        label: &str,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        // TN-56
        if let Some(r) = self
            .grace_refusal(&kit, b, Restricted::SecondAuthenticator)
            .await
        {
            return r;
        }
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
                    "proof": e.proof,
                }),
            ),
            Ok(Err(gate)) => gated(&gate),
            Err(e) => failed(&e),
        }
    }

    /// `POST /v1/account/totp/{enrollment}`: confirms with the first code. Every other session
    /// ends (TN-64); recovery codes come back once when the account had none.
    pub async fn confirm_totp(
        &self,
        entry: &EnvironmentEntry,
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
                    map.insert("acknowledgement_required".to_owned(), json!(true));
                }
                Reply::json(200, body)
            }
            Ok(Err(step)) => refusal(&step),
            Err(e) => failed(&e),
        }
    }

    /// `POST /v1/account/recovery-codes`: a new set, shown once; the old set stops working
    /// (TN-59).
    pub async fn recovery_codes(&self, entry: &EnvironmentEntry, b: &Browser<'_>) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        // TN-56
        if let Some(r) = self.grace_refusal(&kit, b, Restricted::RecoveryCodes).await {
            return r;
        }
        signin!(self, kit, auth);
        match auth
            .regenerate_recovery_codes(b.session.unwrap_or_default(), b.correlation)
            .await
        {
            Ok(Ok(codes)) => Reply::json(
                200,
                json!({ "recovery_codes": secrets(&codes), "acknowledgement_required": true }),
            ),
            Ok(Err(gate)) => gated(&gate),
            Err(e) => failed(&e),
        }
    }

    /// `POST /v1/account/recovery-codes/acknowledgement`: the owner's "I saved them" for the
    /// newest set (TN-59, OP-153 m.3 (d)); `409` when no set waits for it.
    pub async fn acknowledge_recovery_codes(
        &self,
        entry: &EnvironmentEntry,
        b: &Browser<'_>,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        signin!(self, kit, auth);
        match auth
            .acknowledge_recovery_codes(b.session.unwrap_or_default(), b.correlation)
            .await
        {
            Ok(Ok(true)) => Reply::json(200, json!({ "acknowledged": true })),
            Ok(Ok(false)) => Reply::problem(Problem {
                status: 409,
                code: "nothing-to-acknowledge",
                title: "There are no new recovery codes to confirm",
                retry_after_s: None,
            }),
            Ok(Err(status)) => ended(&status),
            Err(e) => failed(&e),
        }
    }

    /// `POST /v1/account/passkeys`: starts a passkey registration (§10.2.4).
    pub async fn begin_passkey(
        &self,
        entry: &EnvironmentEntry,
        b: &Browser<'_>,
        name: &str,
        display_name: &str,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        // TN-56
        if let Some(r) = self
            .grace_refusal(&kit, b, Restricted::SecondAuthenticator)
            .await
        {
            return r;
        }
        signin!(self, kit, auth);
        match auth
            .begin_passkey(b.session.unwrap_or_default(), name, display_name)
            .await
        {
            Ok(Ok(reg)) => Reply::json(
                201,
                json!({ "registration": reg.handle, "options": reg.options, "proof": reg.proof }),
            ),
            Ok(Err(gate)) => gated(&gate),
            Err(e) => failed(&e),
        }
    }

    /// `POST /v1/account/method-proof/{flow}` (TN-147): the code from the account's address
    /// for a passkey registration or TOTP enrolment that waits for one.
    pub async fn prove_method_change(
        &self,
        entry: &EnvironmentEntry,
        b: &Browser<'_>,
        flow: &str,
        code: &str,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        signin!(self, kit, auth);
        match auth
            .prove_change(b.session.unwrap_or_default(), flow, code, b.correlation)
            .await
        {
            Ok(Ok(())) => Reply::new(204, Body::Empty),
            Ok(Err(step)) => refusal(&step),
            Err(e) => failed(&e),
        }
    }

    /// `POST /v1/account/passkeys/{registration}`: finishes it with the browser's
    /// `PublicKeyCredential` JSON.
    pub async fn finish_passkey(
        &self,
        entry: &EnvironmentEntry,
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
            Ok(Ok(RegistrationOutcome::Rejected(r))) => refused(r),
            Ok(Err(step)) => refusal(&step),
            Err(e) => failed(&e),
        }
    }
}
