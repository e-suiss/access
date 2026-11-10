//! What the check answers, in each engine's terms (OP-156 m.3 (l), `proxy.cddl`
//! `proxy-decision`). Only a `200` lets a request through; every other answer is a refusal the
//! engine shows the browser as it is, or, for Nginx, turns into one.

use serde_json::json;

use super::engine::{ENVOY_REMOVE, Engine, IDENTITY_HEADER, PLAIN_HEADERS};

/// The proxy session cookie on the application host (OP-156 m.3 (l)).
pub const SESSION_COOKIE: &str = "__Host-access-proxy";

/// The cookie that binds a sign-in to the browser that began it (login CSRF).
pub const STATE_COOKIE: &str = "__Host-access-proxy-state";

/// How long a sign-in may take, ms.
pub const SIGN_IN_MS: u64 = 600_000;

/// The plain identity of an allowed request, under `idp.proxy.plain_headers`; its `Debug`
/// shows neither value (OP-64).
#[derive(Clone, PartialEq, Eq)]
pub struct Plain {
    /// `X-Access-User`.
    pub user: String,
    /// `X-Access-Email`, when known.
    pub email: Option<String>,
}

impl core::fmt::Debug for Plain {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Plain(..)")
    }
}

/// What the check decided; its `Debug` never shows the application token (OP-64).
#[derive(Clone, PartialEq, Eq)]
pub enum Answer {
    /// The request goes through with the application token.
    Allow {
        /// The decision id.
        decision: String,
        /// How long the decision may be reused, seconds.
        ttl_s: u64,
        /// The application token.
        token: String,
        /// The plain identity headers, when on.
        plain: Option<Plain>,
    },
    /// The request is refused.
    Deny {
        /// The decision id.
        decision: String,
        /// How long the refusal may be reused, seconds.
        ttl_s: u64,
    },
    /// The browser goes to `location` with `cookies` set: a sign-in, or the end of one.
    Redirect {
        /// The decision id.
        decision: String,
        /// Where to.
        location: String,
        /// `Set-Cookie` values.
        cookies: Vec<String>,
    },
}

impl core::fmt::Debug for Answer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Allow {
                decision, ttl_s, ..
            } => f
                .debug_struct("Allow")
                .field("decision", decision)
                .field("ttl_s", ttl_s)
                .finish_non_exhaustive(),
            Self::Deny { decision, ttl_s } => f
                .debug_struct("Deny")
                .field("decision", decision)
                .field("ttl_s", ttl_s)
                .finish(),
            Self::Redirect { decision, .. } => f
                .debug_struct("Redirect")
                .field("decision", decision)
                .finish_non_exhaustive(),
        }
    }
}

/// An answer on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rendered {
    /// Status.
    pub status: u16,
    /// Headers, lower-case names; a name may repeat.
    pub headers: Vec<(&'static str, String)>,
    /// The `proxy-decision` body, JSON.
    pub body: String,
}

/// A `Set-Cookie` value of a host-only, `Secure`, `HttpOnly`, `SameSite=Lax` cookie for `max_s`
/// seconds (RFC 6265bis `__Host-` prefix).
#[must_use]
pub fn set_cookie(name: &str, value: &str, max_s: u64) -> String {
    format!("{name}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_s}")
}

/// A `Set-Cookie` value that ends cookie `name`.
#[must_use]
pub fn clear_cookie(name: &str) -> String {
    set_cookie(name, "", 0)
}

/// How many `Set-Cookie` values an Nginx redirect carries: `auth_request_set` reads one
/// `$upstream_http_set_cookie`, which joins repeated headers into one unreadable value. The first
/// cookie is the one that must be set; a following one only clears a cookie that lapses anyway.
pub const NGINX_COOKIES: usize = 1;

/// `answer` as `engine` reads it.
#[must_use]
pub fn render(engine: Engine, answer: &Answer) -> Rendered {
    let mut headers = vec![("cache-control", String::from("no-store"))];
    match answer {
        Answer::Allow {
            decision,
            ttl_s,
            token,
            plain,
        } => {
            headers.push((IDENTITY_HEADER, token.clone()));
            let mut removed: Vec<&str> = Vec::new();
            match plain {
                Some(p) => {
                    headers.push((PLAIN_HEADERS[0], p.user.clone()));
                    match &p.email {
                        Some(e) => headers.push((PLAIN_HEADERS[1], e.clone())),
                        None => removed.push(PLAIN_HEADERS[1]),
                    }
                }
                None => removed.extend(PLAIN_HEADERS),
            }
            if engine == Engine::Envoy && !removed.is_empty() {
                headers.push((ENVOY_REMOVE, removed.join(",")));
            }
            Rendered {
                status: 200,
                headers,
                body: json!({
                    "outcome": "allow",
                    "decision": decision,
                    "ttl_s": ttl_s,
                    "app_token": token,
                })
                .to_string(),
            }
        }
        Answer::Deny { decision, ttl_s } => Rendered {
            status: 403,
            headers,
            body: json!({"outcome": "deny", "decision": decision, "ttl_s": ttl_s}).to_string(),
        },
        Answer::Redirect {
            decision,
            location,
            cookies,
        } => {
            headers.push(("location", location.clone()));
            let kept = if engine == Engine::Nginx {
                NGINX_COOKIES
            } else {
                cookies.len()
            };
            headers.extend(cookies.iter().take(kept).map(|c| ("set-cookie", c.clone())));
            Rendered {
                status: engine.redirect_status(),
                headers,
                body: json!({"outcome": "sign_in", "decision": decision, "ttl_s": 0}).to_string(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::assert_is_empty, reason = "test code")]

    use super::*;

    fn allow(plain: Option<Plain>) -> Answer {
        Answer::Allow {
            decision: String::from("d"),
            ttl_s: 30,
            token: String::from("t"),
            plain,
        }
    }

    fn header(r: &Rendered, name: &str) -> Vec<String> {
        r.headers
            .iter()
            .filter(|(k, _)| *k == name)
            .map(|(_, v)| v.clone())
            .collect()
    }

    // IDP-30 (3), OP-156 m.3 (l)
    #[test]
    fn an_allow_carries_the_token_and_plain_headers_only_when_on() {
        for engine in [Engine::Nginx, Engine::Traefik, Engine::Caddy, Engine::Envoy] {
            let r = render(engine, &allow(None));
            assert_eq!(r.status, 200);
            assert_eq!(header(&r, IDENTITY_HEADER), ["t"]);
            assert!(header(&r, "x-access-user").is_empty());
            let body: serde_json::Value = serde_json::from_str(&r.body).unwrap();
            assert_eq!(body["outcome"], "allow");
            assert_eq!(body["app_token"], "t");
        }
        let envoy = render(Engine::Envoy, &allow(None));
        assert_eq!(
            header(&envoy, ENVOY_REMOVE),
            ["x-access-user,x-access-email"]
        );
        let plain = Plain {
            user: String::from("u"),
            email: None,
        };
        let r = render(Engine::Envoy, &allow(Some(plain.clone())));
        assert_eq!(header(&r, "x-access-user"), ["u"]);
        assert_eq!(header(&r, ENVOY_REMOVE), ["x-access-email"]);
        assert!(header(&render(Engine::Caddy, &allow(Some(plain))), ENVOY_REMOVE).is_empty());
    }

    // IDP-30, OP-156 m.3 (l)
    #[test]
    fn a_sign_in_is_a_redirect_nginx_can_pass() {
        let a = Answer::Redirect {
            decision: String::from("d"),
            location: String::from("https://access.test/authorize?x"),
            cookies: vec![set_cookie(STATE_COOKIE, "s", 600)],
        };
        let n = render(Engine::Nginx, &a);
        assert_eq!(n.status, 401);
        assert_eq!(header(&n, "location"), ["https://access.test/authorize?x"]);
        assert_eq!(
            header(&n, "set-cookie"),
            ["__Host-access-proxy-state=s; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600"]
        );
        assert_eq!(render(Engine::Traefik, &a).status, 302);
        let back = Answer::Redirect {
            decision: String::from("d"),
            location: String::from("https://wiki.example.com/"),
            cookies: vec![
                set_cookie(SESSION_COOKIE, "v", 60),
                clear_cookie(STATE_COOKIE),
            ],
        };
        assert_eq!(
            header(&render(Engine::Nginx, &back), "set-cookie"),
            [set_cookie(SESSION_COOKIE, "v", 60)]
        );
        assert_eq!(header(&render(Engine::Caddy, &back), "set-cookie").len(), 2);
        let d = render(
            Engine::Envoy,
            &Answer::Deny {
                decision: String::from("d"),
                ttl_s: 3,
            },
        );
        assert_eq!(d.status, 403);
        assert!(header(&d, IDENTITY_HEADER).is_empty());
    }
}
