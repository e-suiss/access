//! The hosted recovery surface (§12.3.2, OP-153 m.2 N2, m.4): starting and proving a recovery,
//! the rebind window, reset intents and temporary access passes, the account's recovery
//! addresses and cross-device link codes. The answers carry the state, the dates and the text
//! keys the page renders; never "full access restored" (X38, X29, TN-55).

use std::net::IpAddr;

use access_identity_account::domain::login::Problem;
use access_identity_oauth::ports::RealmEntry;
use access_identity_session::app::recovery::{
    Answer, AttemptView, Proof, Recovered, RecoverySetup, SetupChange,
};
use access_identity_session::domain::recovery::{RecoveryPath, Restricted, State, aal_name, path};
use access_identity_session::ports::Clock;
use serde_json::{Value, json};

use super::{Browser, Hosted, Reply, failed, signin};
use crate::domain::frontend::rfc3339;
use crate::domain::message::TextId;
use crate::ports::{Kits, Messages};

/// A recovery request's body (TN-106: only these fields).
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartBody {
    /// The identifier the person typed.
    pub identifier: String,
    /// The class they start with; a registered code by default.
    #[serde(default)]
    pub method: Option<String>,
}

/// One step of a recovery.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepBody {
    /// A code: a sent code or a registered recovery code.
    #[serde(default)]
    pub code: Option<String>,
    /// The account's current password, as a second proof.
    #[serde(default)]
    pub password: Option<String>,
    /// Send a code of this class.
    #[serde(default)]
    pub send: Option<String>,
    /// Open the rebind window after the waiting period.
    #[serde(default)]
    pub resume: bool,
    /// The new password in the rebind window.
    #[serde(default)]
    pub new_password: Option<String>,
}

/// The account's recovery addresses.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupBody {
    /// Recovery contacts' e-mail addresses, at most three.
    #[serde(default)]
    pub contacts: Vec<String>,
    /// Another e-mail address recovery codes go to.
    #[serde(default)]
    pub recovery_email: Option<String>,
    /// Assisted recovery; turning it off needs the acknowledgement (TN-60).
    #[serde(default = "yes")]
    pub assisted_recovery: bool,
    /// "I understand I may lose this account for good" (TN-60).
    #[serde(default)]
    pub permanent_loss_acknowledged: bool,
}

const fn yes() -> bool {
    true
}

/// The cookies the recovery surface reads besides the session.
#[derive(Clone, Copy, Debug, Default)]
pub struct RecoveryCookies<'a> {
    /// The attempt handle.
    pub attempt: Option<&'a str>,
    /// The rebind token.
    pub rebind: Option<&'a str>,
}

/// The network the start limit counts: the pseudonym of the /24 or /48 when the realm has a
/// key for it, else the prefix itself, which is hashed into the counter key and never stored.
fn network(pseudonym: Option<[u8; 32]>, ip: IpAddr) -> Vec<u8> {
    if let Some(p) = pseudonym {
        return p.to_vec();
    }
    match ip {
        IpAddr::V4(v) => v.octets().get(..3).unwrap_or_default().to_vec(),
        IpAddr::V6(v) => v.octets().get(..6).unwrap_or_default().to_vec(),
    }
}

fn text(state: State) -> TextId {
    match state {
        State::Requested | State::Throttled | State::EvidenceMet => TextId::RecoveryRequested,
        State::CoolingDown | State::RebindOpen => TextId::RecoveryCooling,
        State::Locked => TextId::RecoveryLocked,
        State::Denied | State::Closed => TextId::RecoveryDenied,
        State::GracePeriod => TextId::RecoveryComplete,
    }
}

fn view_json(v: &AttemptView) -> Value {
    let mut out = json!({
        "attempt": v.attempt,
        "state": v.state.name(),
        "method": v.path.name(),
        "required_aal": aal_name(v.required),
        "achieved_aal": v.achieved.map(aal_name),
        "evidence": v.evidence.iter().map(|e| e.name()).collect::<Vec<_>>(),
        "text": text(v.state).as_str(),
    });
    if let (Some(u), Some(m)) = (v.until_ms, out.as_object_mut()) {
        m.insert("until".into(), rfc3339(u).into());
    }
    out
}

fn answered(a: Answer, status: u16) -> Reply {
    match a {
        Answer::Done(r) => recovered(*r, status),
        Answer::Refused(p) => Reply::problem(p),
        Answer::Throttled { retry_after_s } => Reply::problem(Problem {
            status: 429,
            code: "recovery-throttled",
            title: "Too many attempts",
            retry_after_s: Some(retry_after_s),
        }),
    }
}

fn recovered(r: Recovered, status: u16) -> Reply {
    let mut body = r.view.as_ref().map_or_else(|| json!({}), view_json);
    if let Some(m) = body.as_object_mut() {
        if let Some(code) = &r.replacement {
            // OP-153 m.3 (d)
            m.insert("replacement_code".into(), code.expose().clone().into());
        }
        if let Some(after) = r.sensitive_after_ms {
            // X38, TN-55, Ek B 3656
            m.insert("sensitive_actions_after".into(), rfc3339(after).into());
            m.insert("text".into(), TextId::RecoveryComplete.as_str().into());
            m.insert("federated_links_cut".into(), r.links_cut.into());
        }
    }
    let mut reply = Reply::json(status, body);
    reply.cookies.extend(r.cookies);
    reply
}

fn setup_json(s: &RecoverySetup) -> Value {
    json!({
        "contacts": s.contacts,
        "recovery_email": s.recovery_email,
        "notice_addresses": s.notice_addresses,
        "methods": s.classes.iter().map(|c| c.name()).collect::<Vec<_>>(),
        "weakest_aal": s.weakest.map(aal_name),
        "account_aal": aal_name(s.required),
        "assisted_recovery": s.assisted,
    })
}

fn problem(p: Problem) -> Reply {
    Reply::problem(p)
}

impl<K, C, M> Hosted<K, C, M>
where
    K: Kits,
    C: Clock + Sync,
    M: Messages,
{
    /// `POST /v1/recovery`: opens an attempt; the answer is the same whether or not an account
    /// exists (OP-153 m.3 (d), CR-40).
    pub async fn start_recovery(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        body: &StartBody,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let start = match body.method.as_deref() {
            None => RecoveryPath::RegisteredCode,
            Some(m) => match path(m) {
                Some(p) => p,
                None => return problem(access_identity_session::app::recovery::RECOVERY_INVALID),
            },
        };
        signin!(self, kit, auth, Some(b.ip));
        let net = network(
            self.risk
                .ips
                .prefix(kit.tenant.as_bytes(), kit.realm.as_bytes(), b.ip),
            b.ip,
        );
        match auth
            .start_recovery(&body.identifier, start, &net, b.correlation)
            .await
        {
            Ok(a) => answered(a, 201),
            Err(e) => failed(&e),
        }
    }

    /// `GET /v1/recovery/{attempt}`.
    pub async fn recovery(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        c: RecoveryCookies<'_>,
        attempt: &str,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        signin!(self, kit, auth, Some(b.ip));
        match auth.recovery(c.attempt, attempt).await {
            Ok(a) => answered(a, 200),
            Err(e) => failed(&e),
        }
    }

    /// `POST /v1/recovery/{attempt}`: one proof or step (TN-54).
    pub async fn prove_recovery(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        c: RecoveryCookies<'_>,
        attempt: &str,
        body: &StepBody,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let proof = match (
            body.code.as_deref(),
            body.password.as_deref(),
            body.send.as_deref(),
            body.resume,
            body.new_password.as_deref(),
        ) {
            (Some(code), None, None, false, None) => Proof::Code(code),
            (None, Some(pw), None, false, None) => Proof::Password(pw),
            (None, None, Some(s), false, None) => match path(s) {
                Some(p) => Proof::Send(p),
                None => return problem(access_identity_session::app::recovery::RECOVERY_INVALID),
            },
            (None, None, None, true, None) => Proof::Continue,
            (None, None, None, false, Some(pw)) => Proof::Bind {
                password: pw,
                rebind: c.rebind,
            },
            _ => return problem(access_identity_session::app::recovery::RECOVERY_INVALID),
        };
        signin!(self, kit, auth, Some(b.ip));
        match auth
            .prove_recovery(c.attempt, attempt, proof, b.correlation)
            .await
        {
            Ok(a) => answered(a, 200),
            Err(e) => failed(&e),
        }
    }

    /// `POST /v1/recovery/intents/{token}` (TN-61, TN-62).
    pub async fn redeem_intent(&self, entry: &RealmEntry, b: &Browser<'_>, token: &str) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        signin!(self, kit, auth, Some(b.ip));
        match auth.redeem(token, b.correlation).await {
            Ok(a) => answered(a, 200),
            Err(e) => failed(&e),
        }
    }

    /// `GET /v1/account/recovery-contacts`.
    pub async fn recovery_contacts(&self, entry: &RealmEntry, b: &Browser<'_>) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        signin!(self, kit, auth);
        match auth.recovery_setup(b.session.unwrap_or_default()).await {
            Ok(Ok(s)) => Reply::json(200, setup_json(&s)),
            Ok(Err(p)) => problem(p),
            Err(e) => failed(&e),
        }
    }

    /// `PUT /v1/account/recovery-contacts`.
    pub async fn set_recovery_contacts(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        body: &SetupBody,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        signin!(self, kit, auth);
        let change = SetupChange {
            contacts: body.contacts.clone(),
            recovery_email: body.recovery_email.clone(),
            assisted: body.assisted_recovery,
            permanent_loss_acknowledged: body.permanent_loss_acknowledged,
        };
        match auth
            .set_recovery_setup(b.session.unwrap_or_default(), &change, b.correlation)
            .await
        {
            Ok(Ok(s)) => Reply::json(200, setup_json(&s)),
            Ok(Err(p)) => problem(p),
            Err(e) => failed(&e),
        }
    }

    /// `POST /v1/account/link-codes` (TN-59): shown once, never sent by e-mail.
    pub async fn create_link_code(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        with_identifier: bool,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        signin!(self, kit, auth);
        match auth
            .link_code(
                b.session.unwrap_or_default(),
                with_identifier,
                b.correlation,
            )
            .await
        {
            Ok(Ok(l)) => Reply::json(
                201,
                json!({
                    "code": l.code.expose(),
                    "bits": l.bits,
                    "expires_at": rfc3339(l.expires_ms),
                }),
            ),
            Ok(Err(p)) => problem(p),
            Err(e) => failed(&e),
        }
    }

    /// TN-56: the grace period's answer for `action`, or `None` when it lets it through.
    pub(super) async fn grace_refusal(
        &self,
        kit: &crate::ports::RealmKit,
        b: &Browser<'_>,
        action: Restricted,
    ) -> Option<Reply> {
        let cookie = b.session?;
        signin!(self, kit, auth);
        match auth.recovery_grace(cookie, action).await {
            Ok(Ok(())) => None,
            Ok(Err(p)) => Some(problem(p)),
            Err(e) => Some(failed(&e)),
        }
    }
}
