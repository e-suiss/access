//! The hosted recovery routes of the Frontend API (§12.3.2, OP-153 m.4, `frontend-v1.json`):
//! start, read and prove an attempt, redeem a reset intent or a temporary access pass, the
//! account's recovery addresses and cross-device link codes. Same-origin JSON only, as every
//! hosted write (OP-150 m.3 (r)).

#![allow(
    clippy::result_large_err,
    reason = "a refusal is the reply itself, built once per request"
)]

use std::collections::HashMap;
use std::sync::Arc;

use access_identity_oauth::ports::{Directory, Keys};
use access_identity_session::app::recovery::{REBIND_COOKIE, RECOVERY_COOKIE};
use access_identity_ui::app::recovery::{RecoveryCookies, SetupBody, StartBody, StepBody};
use access_identity_ui::ports::{Clock, Kits, Messages};
use axum::Extension;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use serde::Deserialize;
use serde::de::DeserializeOwned;

use super::web::{Jar, cookies, json_only, problem, realm, same_origin, send};
use super::{Peer, Shared};

type St<D, K, KI, C, M> = State<Arc<Shared<D, K, KI, C, M>>>;
type Params = Path<HashMap<String, String>>;

/// Longest path parameter a recovery route reads.
const MAX_PARAM: usize = 128;

fn parse<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Response> {
    serde_json::from_slice(bytes)
        .map_err(|_| problem(StatusCode::BAD_REQUEST, "invalid-request", "Bad Request"))
}

fn param<'a>(p: &'a HashMap<String, String>, name: &str) -> Result<&'a str, Response> {
    let v = p.get(name).map_or("", String::as_str);
    if v.is_empty() || v.len() > MAX_PARAM || v.chars().any(char::is_control) {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "invalid-request",
            "Bad Request",
        ));
    }
    Ok(v)
}

fn recovery_cookies(headers: &HeaderMap) -> (Option<String>, Option<String>) {
    let mut attempt = None;
    let mut rebind = None;
    for (name, value) in cookies(headers) {
        match name {
            RECOVERY_COOKIE if attempt.is_none() => attempt = Some(value.to_owned()),
            REBIND_COOKIE if rebind.is_none() => rebind = Some(value.to_owned()),
            _ => {}
        }
    }
    (attempt, rebind)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkCodeBody {
    #[serde(default)]
    with_identifier: bool,
}

macro_rules! route {
    (
        $(#[$doc:meta])*
        $name:ident($s:ident, $entry:ident, $b:ident, $p:ident, $bytes:ident, $headers:ident) $write:literal $body:block
    ) => {
        $(#[$doc])*
        pub(super) async fn $name<D, K, KI, C, M>(
            State($s): St<D, K, KI, C, M>,
            Path($p): Params,
            peer: Option<Extension<Peer>>,
            uri: Uri,
            $headers: HeaderMap,
            $bytes: Bytes,
        ) -> Response
        where
            D: Directory,
            K: Keys,
            KI: Kits,
            C: Clock + Sync,
            M: Messages,
        {
            let $entry = match realm(&$s, &$p, &uri, &$headers).await {
                Ok(e) => e,
                Err(r) => return r,
            };
            if $write && let Err(r) = same_origin(&$headers).and_then(|()| json_only(&$headers)) {
                return r;
            }
            let jar = Jar::of(&$headers, peer);
            let $b = jar.browser();
            let reply: Result<access_identity_ui::app::Reply, Response> = async { $body }.await;
            match reply {
                Ok(r) => send(r, &$headers).await,
                Err(r) => r,
            }
        }
    };
}

route! {
    /// `POST /v1/recovery` (`startRecovery`).
    start(s, entry, b, p, bytes, headers) true {
        let _ = &p;
        let body: StartBody = parse(&bytes)?;
        Ok(s.hosted.start_recovery(&entry, &b, &body).await)
    }
}

route! {
    /// `GET /v1/recovery/{attempt}` (`getRecovery`).
    get(s, entry, b, p, bytes, headers) false {
        let _ = &bytes;
        let (attempt, rebind) = recovery_cookies(&headers);
        let c = RecoveryCookies { attempt: attempt.as_deref(), rebind: rebind.as_deref() };
        Ok(s.hosted.recovery(&entry, &b, c, param(&p, "attempt")?).await)
    }
}

route! {
    /// `POST /v1/recovery/{attempt}` (`proveRecovery`).
    prove(s, entry, b, p, bytes, headers) true {
        let body: StepBody = parse(&bytes)?;
        let (attempt, rebind) = recovery_cookies(&headers);
        let c = RecoveryCookies { attempt: attempt.as_deref(), rebind: rebind.as_deref() };
        Ok(s.hosted.prove_recovery(&entry, &b, c, param(&p, "attempt")?, &body).await)
    }
}

route! {
    /// `POST /v1/recovery/intents/{token}` (`redeemResetIntent`).
    redeem(s, entry, b, p, bytes, headers) true {
        let _ = &bytes;
        Ok(s.hosted.redeem_intent(&entry, &b, param(&p, "token")?).await)
    }
}

route! {
    /// `GET /v1/account/recovery-contacts` (`getRecoveryContacts`).
    contacts(s, entry, b, p, bytes, headers) false {
        let _ = (&p, &bytes);
        Ok(s.hosted.recovery_contacts(&entry, &b).await)
    }
}

route! {
    /// `PUT /v1/account/recovery-contacts` (`setRecoveryContacts`).
    set_contacts(s, entry, b, p, bytes, headers) true {
        let _ = &p;
        let body: SetupBody = parse(&bytes)?;
        Ok(s.hosted.set_recovery_contacts(&entry, &b, &body).await)
    }
}

route! {
    /// `POST /v1/account/link-codes` (`createLinkCode`).
    link_code(s, entry, b, p, bytes, headers) true {
        let _ = &p;
        let body: LinkCodeBody = if bytes.is_empty() {
            LinkCodeBody { with_identifier: false }
        } else {
            parse(&bytes)?
        };
        Ok(s.hosted.create_link_code(&entry, &b, body.with_identifier).await)
    }
}
