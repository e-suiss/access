//! Custom domains outside the request path (OP-156 m.3 (i)): the DNS a verification reads, the
//! TLS listener's TLS-ALPN-01 answers, the pass that verifies, issues and renews through the
//! jobs table (one node per slot, OP-129 m.2), and the refresh that loads every node's SNI
//! resolver with the certificates of the verified domains and the open challenges. Without a
//! configured resolver no domain is verified; without an ACME directory no certificate is
//! ordered (TI-9).

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use access_http::tls::{DomainCert, Sni};
use access_identity_admin::domain::dns::Rtype;
use access_identity_domain::adapters::seal::{KeySeal, RealmKek};
use access_identity_domain::app::acme::Client;
use access_identity_domain::app::pass::{self, Acme, Outcome, Pass};
use access_identity_domain::ports::{
    AccountKey, AcmeHttp, Challenges, DnsProbe, Pause, Unavailable,
};
use access_store::Pool;
use access_store::StoreError;
use access_store::custom_domains::{open_challenges, served_hosts};
use access_store::identity::{RealmId, TenantId};
use access_store::jobs::{claim_kind, complete, schedule};
use access_store::tenancy::routes;
use suiss_crypto::envelope::Kek;

use crate::orgs::WebProbe;

/// The pass's job kind.
pub(crate) const KIND: &str = "custom-domains";

/// How often a node schedules and claims a pass (PD).
pub(crate) const INTERVAL: Duration = Duration::from_mins(1);

/// How often every node reloads its certificates and challenges (PD).
pub(crate) const REFRESH: Duration = Duration::from_secs(15);

const LEASE: Duration = Duration::from_mins(10);

/// DNS over the operator's DNS-over-HTTPS resolver.
pub(crate) struct Dns(pub(crate) WebProbe);

impl DnsProbe for Dns {
    async fn txt(&self, name: &str) -> Result<Vec<String>, Unavailable> {
        self.0
            .records(name, Rtype::Txt)
            .await
            .map_err(|e| Unavailable(e.0))
    }

    async fn cname(&self, name: &str) -> Result<Vec<String>, Unavailable> {
        self.0
            .records(name, Rtype::Cname)
            .await
            .map_err(|e| Unavailable(e.0))
    }
}

/// This node's TLS listener, which answers a published TLS-ALPN-01 challenge at once.
#[derive(Clone)]
pub(crate) struct Listener(pub(crate) Arc<Sni>);

impl Challenges for Listener {
    fn publish(
        &self,
        host: &str,
        digest: [u8; 32],
    ) -> impl Future<Output = Result<(), Unavailable>> + Send {
        std::future::ready(
            self.0
                .publish_challenge(host, digest)
                .map_err(|e| Unavailable(e.to_string())),
        )
    }

    fn withdraw(&self, host: &str) -> impl Future<Output = Result<(), Unavailable>> + Send {
        self.0.withdraw_challenge(host);
        std::future::ready(Ok(()))
    }
}

/// The cell's ACME account key in the identity signer (OP-156 m.3 (i)).
#[derive(Clone)]
pub(crate) struct SignerAccount(pub(crate) std::path::PathBuf);

impl SignerAccount {
    async fn ask(
        &self,
        request: access_identity_signer::acme::AcmeRequest,
    ) -> Result<access_identity_signer::acme::AcmeResponse, Unavailable> {
        use access_identity_signer::protocol::{Request, Response};
        match access_identity_signer::adapters::call(&self.0, &Request::Acme(request)).await {
            Ok(Response::Acme(a)) => Ok(a),
            Ok(Response::Error(code)) => Err(Unavailable(code)),
            Ok(_) => Err(Unavailable(String::from("signer-frame"))),
            Err(e) => Err(Unavailable(e.to_string())),
        }
    }
}

impl AccountKey for SignerAccount {
    async fn public_point(&self) -> Result<Vec<u8>, Unavailable> {
        match self
            .ask(access_identity_signer::acme::AcmeRequest::Key)
            .await?
        {
            access_identity_signer::acme::AcmeResponse::Key { point } => Ok(point),
            access_identity_signer::acme::AcmeResponse::Signed { .. } => {
                Err(Unavailable(String::from("signer-frame")))
            }
        }
    }

    async fn sign(&self, input: &[u8]) -> Result<Vec<u8>, Unavailable> {
        let request = access_identity_signer::acme::AcmeRequest::Sign {
            input: input.to_vec(),
        };
        match self.ask(request).await? {
            access_identity_signer::acme::AcmeResponse::Signed { signature } => Ok(signature),
            access_identity_signer::acme::AcmeResponse::Key { .. } => {
                Err(Unavailable(String::from("signer-frame")))
            }
        }
    }
}

/// The realm KEKs of this process.
#[derive(Clone)]
pub(crate) struct Keks(pub(crate) crate::login::RealmKeks);

impl RealmKek for Keks {
    fn kek(&self, tenant: TenantId, realm: RealmId) -> Option<Arc<dyn Kek + Send + Sync>> {
        access_identity_events::adapters::RealmKek::kek(&self.0, tenant, realm)
    }
}

fn now_s() -> Option<i64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
}

/// Loads `sni` with the certificates of every verified custom domain still valid at `now_s` and
/// with every open challenge; returns how many certificates it serves.
///
/// # Errors
/// [`StoreError`] when the realm list or the served hosts cannot be read.
pub(crate) async fn refresh<R: RealmKek>(
    (app, router): (&Pool, &Pool),
    sni: &Sni,
    keys: &KeySeal<R>,
    now_s: i64,
) -> Result<usize, StoreError> {
    let hosts = served_hosts(router).await?;
    let mut certs = Vec::new();
    if !hosts.is_empty() {
        for route in routes(router).await? {
            match pass::served(app, keys, (route.tenant, route.realm), &hosts, now_s).await {
                Ok(served) => certs.extend(served.into_iter().map(|s| DomainCert {
                    host: s.host,
                    chain: s.chain,
                    key: s.key,
                })),
                Err(error) => tracing::warn!(%error, "custom domain certificates not loaded"),
            }
        }
    }
    let n = certs.len();
    sni.set_domains(certs);
    sni.set_challenges(&open_challenges(router).await?);
    Ok(n)
}

/// The ACME side of the pass, when a directory is configured.
pub(crate) struct AcmeSetup<H, K, P> {
    /// HTTPS to the directory's origin.
    pub(crate) http: H,
    /// The account key.
    pub(crate) key: K,
    /// The pause between polls.
    pub(crate) pause: P,
    /// The directory URL.
    pub(crate) directory: String,
    /// The account contact.
    pub(crate) contact: Option<String>,
}

/// What a pass reads and writes through.
pub(crate) struct Deps<'a, D, H, K, P, C, R> {
    /// DNS.
    pub(crate) dns: &'a D,
    /// ACME, when configured.
    pub(crate) acme: Option<&'a AcmeSetup<H, K, P>>,
    /// This node's TLS-ALPN-01 answers.
    pub(crate) challenges: &'a C,
    /// The realm KEKs.
    pub(crate) keys: &'a KeySeal<R>,
}

/// Schedules this slot's pass and runs it over every live realm when this node claims it.
///
/// # Errors
/// [`StoreError`] when the jobs table or the realm list cannot be read.
pub(crate) async fn tick<D, H, K, P, C, R>(
    (app, router): (&Pool, &Pool),
    deps: Deps<'_, D, H, K, P, C, R>,
    worker: &str,
    now_s: i64,
) -> Result<Outcome, StoreError>
where
    D: DnsProbe,
    H: AcmeHttp,
    K: AccountKey,
    P: Pause,
    C: Challenges,
    R: RealmKek,
{
    let every = i64::try_from(INTERVAL.as_secs()).unwrap_or(60);
    let slot = now_s.checked_div(every).unwrap_or(0);
    schedule(
        app,
        KIND,
        &slot.to_string(),
        &format!("{KIND}:{slot}"),
        Duration::ZERO,
    )
    .await?;
    let mut out = Outcome::default();
    let p = Pass {
        app,
        dns: deps.dns,
        acme: deps.acme.map(|a| Acme {
            client: Client {
                http: &a.http,
                key: &a.key,
                pause: &a.pause,
                directory: &a.directory,
                contact: a.contact.as_deref(),
            },
        }),
        challenges: deps.challenges,
        keys: deps.keys,
    };
    for job in claim_kind(app, worker, KIND, 2, LEASE).await? {
        let mut done = true;
        for route in routes(router).await? {
            match p.realm((route.tenant, route.realm), now_s).await {
                Ok(o) => {
                    out.verified = out.verified.saturating_add(o.verified);
                    out.lapsed = out.lapsed.saturating_add(o.lapsed);
                    out.expired = out.expired.saturating_add(o.expired);
                    out.issued = out.issued.saturating_add(o.issued);
                    out.failed = out.failed.saturating_add(o.failed);
                    out.unavailable = out.unavailable.saturating_add(o.unavailable);
                }
                Err(error) => {
                    done = false;
                    tracing::warn!(%error, job = KIND, "custom domain pass failed; retried");
                }
            }
        }
        if done {
            complete(app, job.id, worker).await?;
        }
    }
    Ok(out)
}

/// Runs the pass every [`INTERVAL`] and the refresh every [`REFRESH`] until aborted.
pub(crate) async fn run<H, K, P>(
    (app, router): (Pool, Pool),
    (dns, acme): (Dns, Option<AcmeSetup<H, K, P>>),
    (sni, realm_keks): (Arc<Sni>, Keks),
    worker: String,
) where
    H: AcmeHttp,
    K: AccountKey,
    P: Pause,
{
    let keys = KeySeal(realm_keks);
    let listener = Listener(sni.clone());
    let mut refreshing = tokio::time::interval(REFRESH);
    let mut passing = tokio::time::interval(INTERVAL);
    loop {
        tokio::select! {
            _ = refreshing.tick() => {
                let Some(now) = now_s() else { continue };
                if let Err(error) = refresh((&app, &router), &sni, &keys, now).await {
                    tracing::warn!(%error, job = KIND, "custom domain certificates not refreshed");
                }
            }
            _ = passing.tick() => {
                let Some(now) = now_s() else { continue };
                let deps = Deps {
                    dns: &dns,
                    acme: acme.as_ref(),
                    challenges: &listener,
                    keys: &keys,
                };
                if let Err(error) = tick((&app, &router), deps, &worker, now).await {
                    tracing::warn!(%error, job = KIND, "custom domain pass not run");
                }
            }
        }
    }
}

/// Starts [`run`] with the configured resolver, ACME directory and the identity signer's ACME
/// account key.
pub(crate) fn spawn(
    identity: &crate::config::Identity,
    pools: (Pool, Pool),
    outbound: &access_identity_oauth::adapters::outbound::Outbound,
    (sni, acme): (
        Arc<Sni>,
        Option<access_identity_domain::adapters::https::AcmeHttps>,
    ),
    realm_keks: Keks,
    worker: String,
) -> tokio::task::JoinHandle<()> {
    let dns = Dns(WebProbe {
        outbound: outbound.clone(),
        doh: identity.org_domains.as_ref().map(|d| d.doh_url.clone()),
        rdap: None,
    });
    let setup = identity.custom_domains.as_ref();
    let acme = acme.map(|http| AcmeSetup {
        http,
        key: SignerAccount(identity.signer.clone()),
        pause: access_identity_domain::ports::TokioPause,
        directory: setup.map(|c| c.directory.clone()).unwrap_or_default(),
        contact: setup.and_then(|c| c.contact.clone()),
    });
    tokio::spawn(run(pools, (dns, acme), (sni, realm_keks), worker))
}
