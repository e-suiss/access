//! One forward-auth check from the engine's question to its answer (IDP-30 (1), (3), B22,
//! OP-156 m.3 (l)):
//!
//! 1. The proxy is a PEP its transport names; one with no live registration for the host gets
//!    `401`.
//! 2. Without a live `__Host-access-proxy` session the browser is sent to the realm's hosted
//!    sign-in (OIDC code + PKCE); the callback on the application host redeems the code once and
//!    sets the cookie.
//! 3. Every other request is a real eligibility check of the session's Party for the
//!    registration's action on the resource its path pattern names, reused from the cache for at
//!    most min(horizon, 30 s).
//! 4. An allowed request carries a 60 s application token, and the plain headers only under
//!    `idp.proxy.plain_headers`.
//!
//! Any dependency that does not answer refuses the request (MD-8, TI-9).

use std::collections::BTreeMap;

use access_kernel::intent::{ContextRefs, IntentEnvelope};
use access_kernel::json::b64url_encode;
use access_kernel::model::Window;
use suiss_crypto::digest::context_digest;

use crate::domain::answer::{
    Answer, Plain, SESSION_COOKIE, SIGN_IN_MS, STATE_COOKIE, clear_cookie, set_cookie,
};
use crate::domain::cache::{Cache, Entry, Key, MAX_TTL_MS, ttl_ms};
use crate::domain::engine::{Engine, ForwardError, Forwarded, cookie, forwarded};
use crate::domain::route::{CALLBACK_PATH, pattern, resource};
use crate::ports::{Asked, Holder, Pending, Ports, Redeemed, Registered, Unavailable};

/// Digest context of a proxy cookie as stored.
pub const COOKIE_CONTEXT: &str = "access/proxy-session/v1";

/// Digest context of a sign-in `state` as stored.
pub const STATE_CONTEXT: &str = "access/proxy-state/v1";

/// Most bases one check asks about.
pub const MAX_BASES: usize = 8;

/// How far back an intent's validity starts, ms.
const VALIDITY_SKEW_MS: u64 = 1_000;

/// What the engine asked.
pub struct Check<'a> {
    /// The engine of the path.
    pub engine: Engine,
    /// The proxy's transport identity, when its transport named one.
    pub pep: Option<&'a str>,
    /// The check request's method.
    pub method: &'a str,
    /// The path Envoy appended to the check path.
    pub suffix: Option<&'a str>,
    /// The check request's query.
    pub query: Option<&'a str>,
    /// A header of the check request.
    pub header: &'a (dyn Fn(&str) -> Option<String> + Sync),
}

/// Why the check did not decide.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// No transport identity, or none registered for the host: `401`.
    #[error("proxy-unregistered")]
    Unregistered,
    /// The forwarded request cannot be read: `400`.
    #[error("{}", .0.word())]
    Malformed(ForwardError),
    /// A dependency did not answer: `503`.
    #[error("unavailable")]
    Unavailable,
}

impl From<Unavailable> for Refusal {
    fn from(_: Unavailable) -> Self {
        Self::Unavailable
    }
}

/// A cached decision; its `Debug` never shows the application token (OP-64).
#[derive(Clone, PartialEq, Eq)]
pub enum Decided {
    /// Allowed, with its token and plain headers.
    Allow {
        /// The decision id.
        decision: String,
        /// The application token.
        token: String,
        /// The plain identity, when on.
        plain: Option<Plain>,
    },
    /// Refused.
    Deny {
        /// The decision id.
        decision: String,
    },
}

impl core::fmt::Debug for Decided {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Allow { decision, .. } => f
                .debug_struct("Allow")
                .field("decision", decision)
                .finish_non_exhaustive(),
            Self::Deny { decision } => f.debug_struct("Deny").field("decision", decision).finish(),
        }
    }
}

/// Forward-auth over `P`.
pub struct Proxy<P> {
    ports: P,
    cache: Cache<Decided>,
}

/// The digest a cookie or state is stored under.
#[must_use]
pub fn stored(context: &str, value: &str) -> [u8; 32] {
    context_digest(context, value.as_bytes()).0
}

fn query_param(query: Option<&str>, name: &str) -> Option<String> {
    query?.split('&').find_map(|p| {
        let (k, v) = p.split_once('=')?;
        let ok = !v.is_empty()
            && v.len() <= 512
            && v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~'));
        (k == name && ok).then(|| String::from(v))
    })
}

impl<P: Ports> Proxy<P> {
    /// Forward-auth over `ports`, with an empty cache.
    pub fn new(ports: P) -> Self {
        Self {
            ports,
            cache: Cache::default(),
        }
    }

    /// Its ports.
    pub const fn ports(&self) -> &P {
        &self.ports
    }

    /// Its decision cache, which the doorbell and the head watcher empty.
    pub const fn cache(&self) -> &Cache<Decided> {
        &self.cache
    }

    /// Empties the entries of every domain whose head moved past the one they were decided at;
    /// how many went. A domain whose head cannot be read is emptied (fail-closed).
    pub async fn sweep(&self) -> usize {
        let mut gone = 0usize;
        for (domain, oldest) in self.cache.domains() {
            gone = gone.saturating_add(match self.ports.head(domain).await {
                Ok(head) if head > oldest => self.cache.flush_domain(&domain, head),
                Ok(_) => 0,
                Err(Unavailable) => self.cache.flush_domain(&domain, u64::MAX),
            });
        }
        gone
    }

    fn random_text<const N: usize>(&self) -> Result<String, Unavailable> {
        let mut b = [0u8; N];
        self.ports.fill(&mut b)?;
        Ok(b64url_encode(&b))
    }

    /// Answers `check`.
    ///
    /// # Errors
    /// [`Refusal`]: the engine refuses the request.
    pub async fn check(&self, check: &Check<'_>) -> Result<Answer, Refusal> {
        let pep = check.pep.ok_or(Refusal::Unregistered)?;
        let asked = forwarded(
            check.engine,
            check.method,
            (check.suffix, check.query),
            check.header,
        )
        .map_err(Refusal::Malformed)?;
        let registered = self
            .ports
            .registered(pep, &asked.host)
            .await?
            .ok_or(Refusal::Unregistered)?;
        let cookies = (check.header)("cookie");
        if asked.path == CALLBACK_PATH {
            return self.callback(&registered, &asked, cookies.as_deref()).await;
        }
        let Some(value) = cookie(cookies.as_deref(), SESSION_COOKIE) else {
            return self.sign_in(&registered, &asked, false).await;
        };
        let session = stored(COOKIE_CONTEXT, &value);
        let r = &registered.registration;
        let Some(sid) = self
            .ports
            .session(&registered.realm, &r.name, &session)
            .await?
        else {
            return self.sign_in(&registered, &asked, true).await;
        };
        let Some(holder) = self
            .ports
            .holder(&registered.realm, &r.client_id, &sid)
            .await?
        else {
            self.cache.flush_session(&session);
            return self.sign_in(&registered, &asked, true).await;
        };
        self.decide(&registered, &asked, session, &holder).await
    }

    #[expect(clippy::too_many_lines, reason = "one decision, its steps in order")]
    async fn decide(
        &self,
        registered: &Registered<P::Realm>,
        asked: &Forwarded,
        session: [u8; 32],
        holder: &Holder,
    ) -> Result<Answer, Refusal> {
        let r = &registered.registration;
        let now = self.ports.now_ms()?;
        let deny = |decision: String, until: u64| Answer::Deny {
            decision,
            ttl_s: until.saturating_sub(now) / 1000,
        };
        let (Some(party), Some(route)) = (holder.party, pattern(&r.routes, &asked.path)) else {
            return Ok(deny(self.random_text::<16>()?, now));
        };
        let key = Key {
            session,
            app: r.name.clone(),
            method: asked.method.clone(),
            pattern: String::from(route),
        };
        if let Some(e) = self.cache.get(&key, now) {
            return Ok(match e.decided {
                Decided::Allow {
                    decision,
                    token,
                    plain,
                } => Answer::Allow {
                    decision,
                    ttl_s: e.until_ms.saturating_sub(now) / 1000,
                    token,
                    plain,
                },
                Decided::Deny { decision } => deny(decision, e.until_ms),
            });
        }
        let head = self.ports.head(holder.domain).await?;
        let resource = resource(&r.namespace, &r.name, route);
        let intent = IntentEnvelope {
            action: r.action.clone(),
            resources: vec![resource],
            params: BTreeMap::new(),
            opaque: BTreeMap::new(),
            recipient: None,
            purpose: None,
            context: ContextRefs::default(),
            provenance: BTreeMap::new(),
            validity: Window {
                from: now.saturating_sub(VALIDITY_SKEW_MS),
                until: now.saturating_add(MAX_TTL_MS),
            },
        };
        let requester = b64url_encode(session.get(..16).unwrap_or_default());
        let mut horizon = None;
        let bases = self.ports.bases(holder.domain, party, &r.action).await?;
        for b in bases.iter().take(MAX_BASES) {
            let allowed = self
                .ports
                .eligible(Asked {
                    domain: holder.domain,
                    party,
                    intent: &intent,
                    basis: &b.basis,
                    pep: &r.pep,
                    requester: requester.clone(),
                })
                .await?;
            if allowed {
                horizon = Some(b.until_ms);
                break;
            }
        }
        let decision = self.random_text::<16>()?;
        let session_end = holder.expires_ms;
        let (decided, until) = match horizon {
            Some(h) => {
                let token = self
                    .ports
                    .app_token(
                        &registered.realm,
                        &r.client_id,
                        holder,
                        (&r.audience(), &decision),
                    )
                    .await?;
                let plain = registered.plain_headers.then(|| Plain {
                    user: holder.user.clone(),
                    email: holder.email.clone(),
                });
                let until = now.saturating_add(ttl_ms(now, h.min(session_end)));
                (
                    Decided::Allow {
                        decision,
                        token,
                        plain,
                    },
                    until,
                )
            }
            None => (
                Decided::Deny { decision },
                now.saturating_add(ttl_ms(now, session_end)),
            ),
        };
        self.cache.put(
            key.clone(),
            Entry {
                decided: decided.clone(),
                domain: holder.domain,
                head,
                until_ms: until,
            },
            now,
        );
        Ok(match decided {
            Decided::Allow {
                decision,
                token,
                plain,
            } => Answer::Allow {
                decision,
                ttl_s: until.saturating_sub(now) / 1000,
                token,
                plain,
            },
            Decided::Deny { decision } => deny(decision, until),
        })
    }

    async fn sign_in(
        &self,
        registered: &Registered<P::Realm>,
        asked: &Forwarded,
        ended: bool,
    ) -> Result<Answer, Refusal> {
        let r = &registered.registration;
        let now = self.ports.now_ms()?;
        let state = self.random_text::<32>()?;
        let verifier = self.random_text::<32>()?;
        let nonce = self.random_text::<16>()?;
        let challenge = b64url_encode(&suiss_crypto::digest::sha256(verifier.as_bytes()));
        let return_to = if asked.safe() {
            format!("https://{}{}", asked.host, asked.uri())
        } else {
            format!("https://{}/", asked.host)
        };
        self.ports
            .begin(
                &registered.realm,
                &r.name,
                &stored(STATE_CONTEXT, &state),
                &Pending {
                    verifier,
                    return_to,
                },
                now.saturating_add(SIGN_IN_MS),
            )
            .await?;
        let location = self
            .ports
            .authorize_url(
                &registered.realm,
                &r.client_id,
                &r.redirect_uri(),
                (&state, &nonce, &challenge),
            )
            .await?;
        let mut cookies = vec![set_cookie(STATE_COOKIE, &state, SIGN_IN_MS / 1000)];
        if ended {
            cookies.push(clear_cookie(SESSION_COOKIE));
        }
        Ok(Answer::Redirect {
            decision: self.random_text::<16>()?,
            location,
            cookies,
        })
    }

    async fn callback(
        &self,
        registered: &Registered<P::Realm>,
        asked: &Forwarded,
        cookies: Option<&str>,
    ) -> Result<Answer, Refusal> {
        let r = &registered.registration;
        let now = self.ports.now_ms()?;
        let refused = |d: String| Answer::Deny {
            decision: d,
            ttl_s: 0,
        };
        let q = asked.query.as_deref();
        let (Some(code), Some(state), Some(bound)) = (
            query_param(q, "code"),
            query_param(q, "state"),
            cookie(cookies, STATE_COOKIE),
        ) else {
            return Ok(refused(self.random_text::<16>()?));
        };
        if asked.method != "GET" || bound != state {
            return Ok(refused(self.random_text::<16>()?));
        }
        let Some(pending) = self
            .ports
            .take(&registered.realm, &r.name, &stored(STATE_CONTEXT, &state))
            .await?
        else {
            return Ok(refused(self.random_text::<16>()?));
        };
        let Some(redeemed): Option<Redeemed> = self
            .ports
            .redeem(
                &registered.realm,
                &r.client_id,
                &r.redirect_uri(),
                (&code, &pending.verifier),
            )
            .await?
        else {
            return Ok(refused(self.random_text::<16>()?));
        };
        let value = self.random_text::<32>()?;
        self.ports
            .open(
                &registered.realm,
                &r.name,
                &stored(COOKIE_CONTEXT, &value),
                &redeemed,
            )
            .await?;
        let max_s = redeemed.expires_ms.saturating_sub(now) / 1000;
        Ok(Answer::Redirect {
            decision: self.random_text::<16>()?,
            location: pending.return_to,
            cookies: vec![
                set_cookie(SESSION_COOKIE, &value, max_s),
                clear_cookie(STATE_COOKIE),
            ],
        })
    }
}

#[cfg(test)]
mod tests;
