//! N5: the hosted pages' own endpoints (OP-153 m.2 N5): the theme record (TN-106), CSP
//! reports (OP-153 m.3 (t)), DBSC registration and refresh (TN-33, m.3 (y)), "End this
//! sign-in" (X36), and the S11 sign-in methods and password (TN-99, TN-68).

use access_identity_account::domain::login::Problem;
use access_identity_oauth::ports::RealmEntry;
use access_identity_session::app::dbsc::DbscRefusal;
use access_identity_session::app::sessions::SessionStatus;
use access_identity_session::app::settings::MethodRefusal;
use access_identity_session::domain::dbsc::{
    BOUND_COOKIE, CHALLENGE_HEADER, REGISTRATION_HEADER, challenge, registration, session_config,
};
use access_identity_session::domain::session::{SESSION_COOKIE, clear_cookie};
use access_identity_session::ports::Clock;
use access_kernel::json::b64url_encode;
use access_store::identity::TenantTx;
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::signup::STEP_UP_MAX_AGE_MS;
use super::{Body, Browser, Hosted, Reply, SESSION_REQUIRED, failed, issuer_path, signin};
use crate::domain::branding::Theme;
use crate::ports::{Kits, Messages, RealmKit};

/// Opaque id prefix of a session (OP-137).
const SESSION_PREFIX: &str = "ses";

/// Opaque id prefix of a sign-in method.
const METHOD_PREFIX: &str = "crd";

/// Most CSP reports a realm keeps a minute (OP-153 m.3 (t)).
pub const CSP_REPORTS_PER_MINUTE: i64 = 100;

/// How long a CSP report is kept (OP-153 m.3 (t)).
const CSP_RETENTION_MS: u64 = 30 * 86_400_000;

/// Most reports read from one request.
const MAX_REPORTS: usize = 20;

const UNAVAILABLE: Problem = Problem {
    status: 503,
    code: "unavailable",
    title: "Temporarily unavailable",
    retry_after_s: Some(1),
};

const CSP_THROTTLED: Problem = Problem {
    status: 429,
    code: "csp-reports-throttled",
    title: "Too many reports",
    retry_after_s: Some(60),
};

const BAD_REPORT: Problem = Problem {
    status: 400,
    code: "invalid-request",
    title: "Bad Request",
    retry_after_s: None,
};

const DBSC_REFUSED: Problem = Problem {
    status: 400,
    code: "dbsc-refused",
    title: "The device proof was not accepted",
    retry_after_s: None,
};

const NO_SIGN_IN: Problem = Problem {
    status: 404,
    code: "no-such-sign-in",
    title: "That sign-in isn't open",
    retry_after_s: None,
};

const LAST_METHOD: Problem = Problem {
    status: 409,
    code: "last-sign-in-method",
    title: "Add another way to sign in first",
    retry_after_s: None,
};

const NO_METHOD: Problem = Problem {
    status: 404,
    code: "no-such-method",
    title: "That sign-in method isn't on this account",
    retry_after_s: None,
};

const PASSWORD_REJECTED: Problem = Problem {
    status: 400,
    code: "password-rejected",
    title: "Choose a different password",
    retry_after_s: None,
};

fn rfc3339(ms: i64) -> Value {
    i128::from(ms)
        .checked_mul(1_000_000)
        .and_then(|ns| OffsetDateTime::from_unix_timestamp_nanos(ns).ok())
        .and_then(|t| t.format(&Rfc3339).ok())
        .map_or(Value::Null, Value::String)
}

/// The origin of the realm issuer: `https://host[:port]`.
fn origin(issuer: &str) -> &str {
    let scheme = if issuer.starts_with("http://") { 7 } else { 8 };
    let end = issuer
        .get(scheme..)
        .and_then(|r| r.find('/'))
        .map_or(issuer.len(), |i| i.saturating_add(scheme));
    issuer.get(..end).unwrap_or(issuer)
}

/// One CSP report, reduced to what is kept (OP-153 m.3 (t)).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Violation {
    pub(crate) disposition: &'static str,
    pub(crate) directive: String,
    pub(crate) blocked: String,
    pub(crate) page_path: String,
}

fn directive_of(text: &str) -> Option<String> {
    let d = text.split_whitespace().next()?.to_ascii_lowercase();
    (!d.is_empty() && d.len() <= 40 && d.bytes().all(|c| c.is_ascii_lowercase() || c == b'-'))
        .then_some(d)
}

/// The blocked resource as kept: an origin or a CSP keyword, never a full URL.
fn blocked_of(text: &str) -> String {
    let t = text.trim();
    match t {
        "inline" | "eval" | "data" | "blob" | "wasm-eval" | "trusted-types-sink" | "self" => {
            return t.to_owned();
        }
        _ => {}
    }
    let Some((scheme, rest)) = t.split_once("://") else {
        return t
            .split(':')
            .next()
            .filter(|s| s.len() <= 16 && s.bytes().all(|c| c.is_ascii_alphanumeric()))
            .unwrap_or("other")
            .to_owned();
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let out = format!("{scheme}://{host}");
    if out.len() <= 256 && !out.chars().any(char::is_control) {
        out
    } else {
        String::from("other")
    }
}

fn path_of(text: &str) -> String {
    let rest = text.split_once("://").map_or(text, |(_, r)| r);
    let path = rest
        .find('/')
        .and_then(|i| rest.get(i..))
        .unwrap_or("/")
        .split(['?', '#'])
        .next()
        .unwrap_or("/");
    if path.len() <= 256 && !path.chars().any(char::is_control) {
        path.to_owned()
    } else {
        String::from("/")
    }
}

/// The reports in a body: the Reporting API's `application/reports+json` list or a legacy
/// `application/csp-report` object (CSP3 §5).
pub(crate) fn violations(body: &[u8]) -> Option<Vec<Violation>> {
    let v: Value = serde_json::from_slice(body).ok()?;
    let one = |r: &Value, legacy: bool| -> Option<Violation> {
        let get = |a: &str, b: &str| {
            r.get(if legacy { a } else { b })
                .and_then(Value::as_str)
                .unwrap_or_default()
        };
        let directive = directive_of(get("effective-directive", "effectiveDirective"))
            .or_else(|| directive_of(get("violated-directive", "effectiveDirective")))?;
        let disposition = if get("disposition", "disposition") == "report" {
            "report"
        } else {
            "enforce"
        };
        Some(Violation {
            disposition,
            directive,
            blocked: blocked_of(get("blocked-uri", "blockedURL")),
            page_path: path_of(get("document-uri", "documentURL")),
        })
    };
    match v {
        Value::Array(list) => Some(
            list.iter()
                .filter(|r| r.get("type").and_then(Value::as_str) == Some("csp-violation"))
                .filter_map(|r| r.get("body").and_then(|b| one(b, false)))
                .take(MAX_REPORTS)
                .collect(),
        ),
        Value::Object(_) => v
            .get("csp-report")
            .and_then(|r| one(r, true))
            .map(|x| vec![x]),
        _ => None,
    }
}

fn source_pseudonym(realm: &[u8; 16], ip: std::net::IpAddr) -> [u8; 32] {
    let v6 = match ip {
        std::net::IpAddr::V4(a) => a.to_ipv6_mapped().octets(),
        std::net::IpAddr::V6(a) => a.octets(),
    };
    let prefix = access_crypto::ip_pseudonym::prefix(&v6);
    suiss_crypto::digest::sha256(
        &[
            b"access/csp-source/v1\0".as_slice(),
            realm.as_slice(),
            &prefix,
        ]
        .concat(),
    )
}

fn dbsc_refused(r: DbscRefusal) -> Reply {
    match r {
        DbscRefusal::NoSession => Reply::problem(SESSION_REQUIRED),
        DbscRefusal::DeviceMismatch => {
            let mut reply = Reply::problem(SESSION_REQUIRED)
                .cookie(Some(clear_cookie(SESSION_COOKIE)))
                .cookie(Some(clear_cookie(BOUND_COOKIE)));
            reply.reason = Some("device_mismatch");
            reply
        }
        DbscRefusal::BadProof | DbscRefusal::WrongState => Reply::problem(DBSC_REFUSED),
    }
}

impl<K, C, M> Hosted<K, C, M>
where
    K: Kits,
    C: Clock + Sync,
    M: Messages,
{
    /// The realm's theme record, checked (TN-106).
    ///
    /// # Errors
    /// The reply to send instead: no kit, or the store is unavailable.
    pub async fn theme(&self, entry: &RealmEntry) -> Result<Theme, Reply> {
        let kit = self.kit(entry).await?;
        let bytes = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            let b = access_store::idp::branding(&mut t).await?;
            t.commit().await?;
            Ok::<_, access_store::StoreError>(b)
        };
        let bytes = bytes.await.map_err(|_| Reply::problem(UNAVAILABLE))?;
        Ok(Theme::decode(bytes.as_deref()))
    }

    /// The path of the realm issuer below its host, for links and headers (§17.9.6).
    ///
    /// # Errors
    /// The reply to send instead: no kit.
    pub async fn base_path(&self, entry: &RealmEntry) -> Result<String, Reply> {
        let kit = self.kit(entry).await?;
        Ok(issuer_path(&kit.issuer).to_owned())
    }

    /// `GET /v1/login/branding` (TN-106).
    pub async fn branding(&self, entry: &RealmEntry) -> Reply {
        match self.theme(entry).await {
            Ok(t) => Reply::json(200, t.json()),
            Err(r) => r,
        }
    }

    /// `GET /v1/login/messages` (X35, XI-25, OP-153 m.22 (k)): the realm's stored texts by
    /// locale and key, rechecked as they are read; a protected key or a text with a placeholder
    /// or markup is never handed to the page.
    pub async fn message_overrides(&self, entry: &RealmEntry) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let read = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            let b = access_store::idp::locale_overrides(&mut t).await?;
            t.commit().await?;
            Ok::<_, access_store::StoreError>(b)
        };
        match read.await {
            Ok(b) => Reply::json(
                200,
                serde_json::json!({
                    "overrides": crate::domain::locale::stored_overrides(b.as_deref()),
                }),
            ),
            Err(_) => Reply::problem(UNAVAILABLE),
        }
    }

    /// `POST /csp-reports` (OP-153 m.3 (t), IDP-36): accepted with `204`, at most
    /// [`CSP_REPORTS_PER_MINUTE`] a minute per realm, kept pseudonymous for 30 days.
    pub async fn csp_report(&self, entry: &RealmEntry, b: &Browser<'_>, body: &[u8]) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let Some(list) = violations(body) else {
            return Reply::problem(BAD_REPORT);
        };
        let now = self.clock.now_ms();
        let source = source_pseudonym(kit.realm.as_bytes(), b.ip);
        let stored = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            let now_i = i64::try_from(now).unwrap_or(i64::MAX);
            let recent = t.csp_reports_since(now_i.saturating_sub(60_000)).await?;
            let room = usize::try_from(CSP_REPORTS_PER_MINUTE.saturating_sub(recent)).unwrap_or(0);
            if room == 0 {
                t.commit().await?;
                return Ok(false);
            }
            let expires = i64::try_from(now.saturating_add(CSP_RETENTION_MS)).unwrap_or(i64::MAX);
            for v in list.iter().take(room) {
                t.insert_csp_report(&access_store::sessions::CspReport {
                    received_ms: now_i,
                    expires_ms: expires,
                    disposition: v.disposition,
                    directive: &v.directive,
                    blocked: &v.blocked,
                    page_path: &v.page_path,
                    source_pseudonym: &source,
                })
                .await?;
            }
            t.commit().await?;
            Ok::<_, access_store::StoreError>(true)
        };
        match stored.await {
            Ok(true) => Reply::new(204, Body::Empty),
            Ok(false) => Reply::problem(CSP_THROTTLED),
            Err(_) => Reply::problem(UNAVAILABLE),
        }
    }

    /// The registration offer for a session that just started (TN-33, OP-153 m.3 (y)); a
    /// browser without DBSC ignores the header and keeps the plain session.
    pub(crate) async fn offer_dbsc<D, R, N, P, S>(
        &self,
        auth: &access_identity_session::app::Auth<'_, D, C, R, N, P, S>,
        kit: &RealmKit,
        session: [u8; 16],
        reply: Reply,
    ) -> Reply
    where
        D: access_identity_session::ports::SessionDb,
        R: access_identity_session::ports::Random,
        N: access_identity_account::notify::ports::Notifier + Sync,
        P: access_identity_webauthn::ports::CredentialRegistry + Sync,
        S: access_identity_webauthn::ports::SignalSink + Sync,
    {
        // OP-153 m.22 (c), m.25 (b)
        if !kit.signin.dbsc {
            return reply;
        }
        match auth.dbsc_offer(session).await {
            Ok(Some(c)) => reply.header(
                REGISTRATION_HEADER,
                registration(issuer_path(&kit.issuer), &c),
            ),
            _ => reply,
        }
    }

    /// `POST /v1/dbsc/register` (TN-33): the browser's proof ties this session to its key.
    pub async fn dbsc_register(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        proof: Option<&str>,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        signin!(self, kit, auth);
        let Some(cookie) = b.session else {
            return Reply::problem(SESSION_REQUIRED);
        };
        let Some(proof) = proof else {
            return Reply::problem(DBSC_REFUSED);
        };
        match auth.dbsc_register(cookie, proof, b.correlation).await {
            Ok(Ok(bound)) => {
                let Ok(id) = kit.ids.encode(SESSION_PREFIX, bound.session) else {
                    return Reply::problem(UNAVAILABLE);
                };
                Reply::json(
                    200,
                    session_config(&id, origin(&kit.issuer), issuer_path(&kit.issuer)),
                )
                .cookie(Some(bound.set_cookie))
            }
            Ok(Err(r)) => dbsc_refused(r),
            Err(e) => failed(&e),
        }
    }

    /// `POST /v1/dbsc/refresh` (TN-33): without a proof, a `403` with a fresh challenge; with
    /// one from the session's key, a new bound cookie. A proof from another key ends the
    /// session.
    pub async fn dbsc_refresh(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        proof: Option<&str>,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        signin!(self, kit, auth);
        let Some(cookie) = b.session else {
            return Reply::problem(SESSION_REQUIRED);
        };
        let Some(proof) = proof else {
            return match auth.dbsc_refresh_challenge(cookie).await {
                Ok(Some((id, c))) => match kit.ids.encode(SESSION_PREFIX, id) {
                    Ok(id) => {
                        Reply::new(403, Body::Empty).header(CHALLENGE_HEADER, challenge(&c, &id))
                    }
                    Err(_) => Reply::problem(UNAVAILABLE),
                },
                Ok(None) => Reply::problem(SESSION_REQUIRED),
                Err(e) => failed(&e),
            };
        };
        match auth.dbsc_refresh(cookie, proof, b.correlation).await {
            Ok(Ok(bound)) => {
                let Ok(id) = kit.ids.encode(SESSION_PREFIX, bound.session) else {
                    return Reply::problem(UNAVAILABLE);
                };
                Reply::json(
                    200,
                    session_config(&id, origin(&kit.issuer), issuer_path(&kit.issuer)),
                )
                .cookie(Some(bound.set_cookie))
            }
            Ok(Err(r)) => dbsc_refused(r),
            Err(e) => failed(&e),
        }
    }

    /// `POST /v1/sessions/{session}/end` (X36, OP-153 m.3 (y)): ends another sign-in of the
    /// person; answers with the device Instance the page then terminates with its own key.
    pub async fn end_sign_in(&self, entry: &RealmEntry, b: &Browser<'_>, session: &str) -> Reply {
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
            Ok(_) => return Reply::problem(SESSION_REQUIRED),
            Err(e) => return failed(&e),
        };
        let Ok(target) = kit.ids.decode(SESSION_PREFIX, session) else {
            return Reply::problem(NO_SIGN_IN);
        };
        match auth.end_other(&me, target, b.correlation).await {
            Ok(Some(instance)) => Reply::json(
                200,
                json!({ "instance": instance.map(|i| b64url_encode(&i)) }),
            ),
            Ok(None) => Reply::problem(NO_SIGN_IN),
            Err(e) => failed(&e),
        }
    }

    /// The live session's subject, re-authenticated within the step-up window when `fresh`.
    async fn settings_subject(
        &self,
        kit: &RealmKit,
        b: &Browser<'_>,
        fresh: bool,
    ) -> Result<[u8; 16], Reply> {
        self.fresh(kit, b, fresh.then_some(STEP_UP_MAX_AGE_MS))
            .await
            .map(|(s, _)| s)
    }

    /// `GET /v1/account/methods` (S11, TN-99, OP-148).
    pub async fn sign_in_methods(&self, entry: &RealmEntry, b: &Browser<'_>) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let subject = match self.settings_subject(&kit, b, false).await {
            Ok(s) => s,
            Err(r) => return r,
        };
        signin!(self, kit, auth);
        let rows = match auth.sign_in_methods(subject).await {
            Ok(r) => r,
            Err(e) => return failed(&e),
        };
        let pending = auth.recovery_codes_pending(subject).await.unwrap_or(false);
        let id = |r: &access_store::accounts::MethodRow| kit.ids.encode(METHOD_PREFIX, r.id).ok();
        let of = |kind: &'static str| rows.iter().filter(move |r| r.kind == kind);
        Reply::json(
            200,
            json!({
                "password": { "set": of("password").next().is_some() },
                "passkeys": of("webauthn").map(|r| json!({
                    "id": id(r),
                    "name": Value::Null,
                    "created_at": rfc3339(r.created_ms),
                    "synced": r.synced.unwrap_or(false),
                })).collect::<Vec<_>>(),
                "totp": of("totp").map(|r| json!({
                    "id": id(r),
                    "created_at": rfc3339(r.created_ms),
                })).collect::<Vec<_>>(),
                "recovery_codes": {
                    "set": of("recovery_code").next().is_some(),
                    "acknowledged": !pending,
                },
            }),
        )
    }

    /// `DELETE /v1/account/methods/{credential}` (TN-68): after a recent re-authentication,
    /// never the last method.
    pub async fn remove_sign_in_method(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        credential: &str,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let subject = match self.settings_subject(&kit, b, true).await {
            Ok(s) => s,
            Err(r) => return r,
        };
        let Ok(id) = kit.ids.decode(METHOD_PREFIX, credential) else {
            return Reply::problem(NO_METHOD);
        };
        signin!(self, kit, auth);
        match auth.remove_method(subject, id, b.correlation).await {
            Ok(Ok(())) => Reply::new(204, Body::Empty),
            Ok(Err(MethodRefusal::LastMethod)) => Reply::problem(LAST_METHOD),
            Ok(Err(_)) => Reply::problem(NO_METHOD),
            Err(e) => failed(&e),
        }
    }

    /// `PUT /v1/account/password` (§10.2.1, TN-50): after a recent re-authentication; every
    /// sign-in of the person ends, this one too, with reason `password`.
    pub async fn set_password(&self, entry: &RealmEntry, b: &Browser<'_>, new: &str) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        if !kit.auth.password {
            return Reply::problem(super::NOT_ALLOWED);
        }
        let subject = match self.settings_subject(&kit, b, true).await {
            Ok(s) => s,
            Err(r) => return r,
        };
        signin!(self, kit, auth);
        match auth.change_password(subject, new, b.correlation).await {
            Ok(Ok(())) => Reply::new(204, Body::Empty)
                .cookie(Some(clear_cookie(SESSION_COOKIE)))
                .cookie(Some(clear_cookie(BOUND_COOKIE))),
            Ok(Err(_)) => Reply::problem(PASSWORD_REJECTED),
            Err(e) => failed(&e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-153 m.3 (t)
    #[test]
    fn reports_keep_origins_not_urls() {
        let legacy = br#"{"csp-report":{"document-uri":"https://acme.example/login?x=secret",
            "violated-directive":"img-src 'self'","effective-directive":"img-src",
            "blocked-uri":"https://tracker.example/p.gif?id=42","disposition":"enforce"}}"#;
        let v = violations(legacy).unwrap();
        assert_eq!(
            v,
            [Violation {
                disposition: "enforce",
                directive: String::from("img-src"),
                blocked: String::from("https://tracker.example"),
                page_path: String::from("/login"),
            }]
        );
        let api = br#"[{"type":"csp-violation","body":{"documentURL":"https://acme.example/login",
            "effectiveDirective":"script-src-elem","blockedURL":"inline","disposition":"report"}},
            {"type":"deprecation","body":{}}]"#;
        let v = violations(api).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].blocked, "inline");
        assert_eq!(v[0].disposition, "report");
        assert!(violations(b"[1").is_none());
        assert_eq!(
            origin("https://acme.example/realms/a"),
            "https://acme.example"
        );
        assert_eq!(origin("https://acme.example"), "https://acme.example");
    }
}
