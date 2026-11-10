//! Forward-auth in this process (IDP-30, B22, OP-156 m.3 (l)): the registry and proxy sessions
//! in the store, the realm authorization server for code + PKCE and the application token, the
//! authority core's eligibility check, and the watcher that empties the decision cache once a
//! domain's head moves or the doorbell rings.

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

use access_authority_core::CoreError;
use access_authority_core::adapters::Domains;
use access_authority_core::app::Incoming;
use access_authority_core::domain::Request;
use access_authority_core::ports::{Binding, Keys, Salts};
use access_authority_sequencer::ports::Clock;
use access_identity_oauth::app::oauth::{Env, OAuth, Realm};
use access_identity_oauth::ports::dpop::Clock as _;
use access_identity_proxy::app::Proxy;
use access_identity_proxy::domain::registration::from_json;
use access_identity_proxy::ports::{
    Asked, Basis, Holder, Pending, Ports, Redeemed, Registered, Unavailable,
};
use access_kernel::combinator::{Capacity, Mode, Outcome};
use access_kernel::digest::Digest;
use access_kernel::model::{ActionRef, Id};
use access_store::Pool;
use access_store::identity::TenantTx;

/// How often the watcher reads the heads of the domains it holds decisions for.
pub(crate) const SWEEP: Duration = Duration::from_secs(1);

/// The ports of forward-auth over this process.
pub(crate) struct ServerPorts<E: Env, K, B: Binding, S: Salts, C> {
    pub(crate) router: Pool,
    pub(crate) app: Pool,
    pub(crate) oauth: Arc<OAuth<E>>,
    pub(crate) domains: Arc<Domains<K, B, S, C>>,
}

fn down<T>(_: T) -> Unavailable {
    Unavailable
}

/// RFC 3986 §2.3: everything but the unreserved characters percent-encoded.
fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

impl<E, K, B, S, C> ServerPorts<E, K, B, S, C>
where
    E: Env,
    K: Keys,
    B: Binding + Clone,
    S: Salts + Clone,
    C: Clock + Clone,
{
    async fn tx(&self, realm: &Realm) -> Result<TenantTx, Unavailable> {
        TenantTx::begin(&self.app, realm.tenant, realm.realm)
            .await
            .map_err(down)
    }
}

impl<E, K, B, S, C> Ports for ServerPorts<E, K, B, S, C>
where
    E: Env,
    K: Keys + Send + Sync + 'static,
    B: Binding + Clone + Send + Sync + 'static,
    S: Salts + Clone + Send + Sync + 'static,
    C: Clock + Clone + Send + Sync + 'static,
{
    type Realm = Realm;

    async fn registered(
        &self,
        pep: &str,
        host: &str,
    ) -> Result<Option<Registered<Realm>>, Unavailable> {
        let routes = access_store::proxy::proxy_routes(&self.router, pep, host)
            .await
            .map_err(down)?;
        let [route] = routes.as_slice() else {
            return Ok(None);
        };
        let Some(realm) = self.oauth.realm_by_slug(&route.slug).await.map_err(down)? else {
            return Ok(None);
        };
        if realm.tenant.as_bytes() != route.tenant.as_bytes()
            || realm.realm.as_bytes() != route.realm.as_bytes()
        {
            return Ok(None);
        }
        let mut t = self.tx(&realm).await?;
        let row = access_store::proxy::proxy(&mut t, &route.name)
            .await
            .map_err(down)?;
        t.commit().await.map_err(down)?;
        let Some(row) = row.filter(|r| r.live) else {
            return Ok(None);
        };
        let body: serde_json::Value = serde_json::from_str(&row.body).map_err(down)?;
        let registration = from_json(&body).map_err(down)?;
        if registration.pep != pep || registration.host != host {
            return Ok(None);
        }
        Ok(Some(Registered {
            realm,
            registration,
            plain_headers: row.plain_headers,
        }))
    }

    async fn begin(
        &self,
        realm: &Realm,
        proxy: &str,
        state: &[u8; 32],
        pending: &Pending,
        expires_ms: u64,
    ) -> Result<(), Unavailable> {
        let now = self.now_ms()?;
        let mut t = self.tx(realm).await?;
        access_store::proxy::begin_sign_in(
            &mut t,
            proxy,
            state,
            (&pending.verifier, &pending.return_to),
            (now, expires_ms),
        )
        .await
        .map_err(down)?;
        t.commit().await.map_err(down)
    }

    async fn take(
        &self,
        realm: &Realm,
        proxy: &str,
        state: &[u8; 32],
    ) -> Result<Option<Pending>, Unavailable> {
        let now = self.now_ms()?;
        let mut t = self.tx(realm).await?;
        let taken = access_store::proxy::take_sign_in(&mut t, proxy, state, now)
            .await
            .map_err(down)?;
        t.commit().await.map_err(down)?;
        Ok(taken.map(|(verifier, return_to)| Pending {
            verifier,
            return_to,
        }))
    }

    async fn open(
        &self,
        realm: &Realm,
        proxy: &str,
        cookie: &[u8; 32],
        redeemed: &Redeemed,
    ) -> Result<(), Unavailable> {
        let now = self.now_ms()?;
        let mut t = self.tx(realm).await?;
        access_store::proxy::open_session(
            &mut t,
            proxy,
            cookie,
            &redeemed.sid,
            (now, redeemed.expires_ms.max(now.saturating_add(1))),
        )
        .await
        .map_err(down)?;
        t.commit().await.map_err(down)
    }

    async fn session(
        &self,
        realm: &Realm,
        proxy: &str,
        cookie: &[u8; 32],
    ) -> Result<Option<[u8; 16]>, Unavailable> {
        let now = self.now_ms()?;
        let mut t = self.tx(realm).await?;
        let sid = access_store::proxy::session(&mut t, proxy, cookie, now)
            .await
            .map_err(down)?;
        t.commit().await.map_err(down)?;
        Ok(sid)
    }

    fn authorize_url(
        &self,
        realm: &Realm,
        client_id: &str,
        redirect_uri: &str,
        (state, nonce, challenge): (&str, &str, &str),
    ) -> impl std::future::Future<Output = Result<String, Unavailable>> + Send {
        std::future::ready(Ok(format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope=openid&state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
            OAuth::<E>::authorize_endpoint(realm),
            encode(client_id),
            encode(redirect_uri),
            encode(state),
            encode(nonce),
            encode(challenge),
        )))
    }

    async fn redeem(
        &self,
        realm: &Realm,
        client_id: &str,
        redirect_uri: &str,
        code: (&str, &str),
    ) -> Result<Option<Redeemed>, Unavailable> {
        Ok(self
            .oauth
            .proxy_redeem(realm, client_id, redirect_uri, code)
            .await
            .map_err(down)?
            .map(|g| Redeemed {
                sid: g.sid,
                expires_ms: g.expires_ms,
            }))
    }

    async fn holder(
        &self,
        realm: &Realm,
        client_id: &str,
        sid: &[u8; 16],
    ) -> Result<Option<Holder>, Unavailable> {
        Ok(self
            .oauth
            .proxy_holder(realm, client_id, sid)
            .await
            .map_err(down)?
            .map(|h| Holder {
                subject: h.subject,
                party: h.party.map(Id),
                domain: Digest(h.domain),
                expires_ms: h.expires_ms,
                user: h.sub,
                email: h.email,
            }))
    }

    async fn app_token(
        &self,
        realm: &Realm,
        client_id: &str,
        holder: &Holder,
        token: (&str, &str),
    ) -> Result<String, Unavailable> {
        self.oauth
            .app_token(realm, client_id, &holder.user, token)
            .await
            .map_err(down)
    }

    async fn bases(
        &self,
        domain: Digest,
        party: Id,
        action: &ActionRef,
    ) -> Result<Vec<Basis>, Unavailable> {
        Ok(self
            .domains
            .proxy_bases(domain, party, action)
            .await
            .map_err(down)?
            .into_iter()
            .map(|(basis, until_ms)| Basis { basis, until_ms })
            .collect())
    }

    async fn eligible(&self, asked: Asked<'_>) -> Result<bool, Unavailable> {
        let nonce = access_crypto::random::bytes::<16>().map_err(down)?;
        let inc = Incoming {
            request: Request {
                domain: asked.domain,
                mode: Mode::Check,
                nonce: nonce.to_vec(),
                intent: asked.intent.clone(),
                payload: None,
                basis: *asked.basis,
                capacity: Capacity::Own,
                proofs: Vec::new(),
                exercise: None,
                consistency: None,
            },
            ais: None,
            pep: String::from(asked.pep),
            requester: Some(asked.requester),
            explain: false,
            status: None,
            context: None,
        };
        match self.domains.eligible(&inc, asked.party).await {
            Ok(r) => Ok(r.decision.outcome == Outcome::Allow),
            Err(CoreError::Unavailable(_) | CoreError::Store(_) | CoreError::Limited) => {
                Err(Unavailable)
            }
            Err(_) => Ok(false),
        }
    }

    async fn head(&self, domain: Digest) -> Result<u64, Unavailable> {
        self.domains
            .head(domain)
            .await
            .map(|(pos, _)| pos)
            .map_err(down)
    }

    fn now_ms(&self) -> Result<u64, Unavailable> {
        self.oauth.env().clock().now().map_err(down)
    }

    fn fill(&self, out: &mut [u8]) -> Result<(), Unavailable> {
        for chunk in out.chunks_mut(32) {
            let b = access_crypto::random::bytes::<32>().map_err(down)?;
            let n = chunk.len();
            chunk.copy_from_slice(b.get(..n).ok_or(Unavailable)?);
        }
        Ok(())
    }
}

/// How long the plain header setup check waits for the upstream to answer.
pub(crate) const PROBE: Duration = Duration::from_secs(3);

/// Whether `upstream` (`http(s)://host[:port]/…`) accepts a TCP connection from here within
/// [`PROBE`] (IDP-30 (3), OP-156 m.3 (l)); nothing is sent. A URL it cannot read is reachable
/// (fail-closed: the plain headers stay off).
pub(crate) async fn reachable(upstream: &str) -> bool {
    let Some((rest, port)) = upstream
        .strip_prefix("https://")
        .map(|r| (r, 443))
        .or_else(|| upstream.strip_prefix("http://").map(|r| (r, 80)))
    else {
        return true;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let target = if authority.starts_with('[')
        || authority
            .rsplit_once(':')
            .is_some_and(|(_, p)| p.bytes().all(|b| b.is_ascii_digit()) && !p.is_empty())
    {
        String::from(authority)
    } else {
        format!("{authority}:{port}")
    };
    if authority.is_empty() || authority.contains('@') {
        return true;
    }
    matches!(
        tokio::time::timeout(PROBE, tokio::net::TcpStream::connect(target)).await,
        Ok(Ok(_))
    )
}

/// Empties the decision cache of `proxy` at each [`SWEEP`] and whenever `wake` rings, until
/// `stop` turns true (OP-156 m.3 (l)).
pub(crate) fn watch<P: Ports + 'static>(
    proxy: Arc<Proxy<P>>,
    wake: Arc<tokio::sync::Notify>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = stop.changed() => return,
                () = wake.notified() => {}
                () = tokio::time::sleep(SWEEP) => {}
            }
            let entries = proxy.sweep().await;
            if entries > 0 {
                // OP-67
                tracing::debug!(
                    event = "proxy.cache.flushed",
                    reason = "head",
                    entries,
                    "forward-auth decisions emptied"
                );
            }
        }
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::assert_is_empty, reason = "test code")]

    use super::encode;

    // IDP-30 (3), OP-156 m.3 (l)
    #[tokio::test]
    async fn an_upstream_that_answers_here_is_reachable() {
        let open = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = open.local_addr().unwrap().port();
        assert!(super::reachable(&format!("http://127.0.0.1:{port}/app")).await);
        drop(open);
        assert!(!super::reachable(&format!("http://127.0.0.1:{port}/app")).await);
        assert!(super::reachable("ftp://127.0.0.1/").await);
        assert!(super::reachable("http://user@127.0.0.1/").await);
    }

    #[test]
    fn a_query_value_is_percent_encoded_outside_the_unreserved_set() {
        assert_eq!(
            encode("https://wiki.example.com/access-proxy/v1/callback"),
            "https%3A%2F%2Fwiki.example.com%2Faccess-proxy%2Fv1%2Fcallback"
        );
        assert_eq!(encode("a-b_c.d~e"), "a-b_c.d~e");
    }
}
