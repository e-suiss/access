//! The Relay courier in this process (E42, OP-156 m.3 (c), Ek B 5393, 5401): Access's
//! messages to people leave the identity outbox for Relay, where Access is a platform tenant.
//!
//! - The tenant, the credential file and Relay's trust anchors are configuration
//!   (`[suiss.relay_platform]`); without them the server does not start.
//! - Nothing waits for Relay at start (E42 m.5): the courier reads Relay's discovery document in
//!   the background and sends only once it names this Access, the events capability and an
//!   intake on Relay's origin. Until then messages wait in the outbox.
//! - One node at a time holds the courier lease and sends (`access_ops.courier_leases`).
//! - The lag, the age of the oldest message waiting for Relay, is public at
//!   `GET /access/v1/relay-status`; past 60 s it reads as notifications delayed.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use access_crypto::Secret;
use access_crypto::opaque_id::IdKey;
use access_crypto::secret_file::SecretFile;
use access_http::internal::ReadyFlag;
use access_identity_account::adapters::system::SystemClock;
use access_identity_account::notify::courier::Courier;
use access_identity_account::notify::delivery::{Backoff, check_discovery};
use access_identity_account::notify::http::{HttpRelay, HttpRelayConfig, RelayEndpoint, discover};
use access_identity_account::notify::pg::PgCourierStore;
use access_identity_account::notify::ports::{CourierStore as _, RealmKeys};
use access_identity_events::adapters::RealmKek as _;
use access_store::Pool;
use access_store::identity::{RealmId, TenantId, TenantTx};
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use suiss_crypto::envelope::Kek;

use crate::config::Config;
use crate::login::RealmKeks;

/// The public lag route.
pub(crate) const STATUS_PATH: &str = access_http::stage11::RELAY_STATUS;

/// Past this lag notifications read as delayed (OP-156 m.3 (c), PD).
pub(crate) const DELAYED_MS: u64 = 60_000;

/// How long one Relay exchange may take (PD).
const TIMEOUT: Duration = Duration::from_secs(10);

/// How often an unconfirmed Relay is asked for its discovery document again (PD).
const DISCOVERY_RETRY: Duration = Duration::from_secs(30);

/// What the courier needs from the file system, read before the lockdown.
pub(crate) struct Prepared {
    relay: String,
    issuer: String,
    credential: PathBuf,
    tls: Arc<rustls::ClientConfig>,
}

/// Reads Relay's trust anchors and checks the credential file (E42, OP-156 m.3 (c)).
///
/// # Errors
/// No `[suiss.relay_platform]`, an unreadable or group-readable credential file, or no
/// usable trust anchor: the server does not start (TI-9).
pub(crate) fn prepare(config: &Config, system_roots: &[&str]) -> Result<Prepared, String> {
    let suiss = config.suiss.as_ref().ok_or("no suiss section")?;
    let platform = &suiss.relay_platform;
    SecretFile::load(platform.credential_file.clone())
        .map_err(|e| format!("suiss.relay_platform.credential_file: {e}"))?;
    let pem = match &platform.ca_file {
        Some(f) => std::fs::read(f).map_err(|e| format!("{}: {e}", f.display()))?,
        None => system_roots
            .iter()
            .find_map(|f| std::fs::read(f).ok())
            .ok_or("no trust anchors for Relay")?,
    };
    let tls = access_http::tls::client_config(&pem).map_err(|e| e.to_string())?;
    Ok(Prepared {
        relay: suiss.relay.clone(),
        issuer: config.issuer.clone().ok_or("no issuer")?,
        credential: platform.credential_file.clone(),
        tls,
    })
}

/// What the lockdown must leave open for the courier: the credential file's directory, for its
/// rotation, and Relay's port.
pub(crate) fn lockdown_needs(config: &Config) -> (Option<PathBuf>, Option<u16>) {
    let Some(suiss) = config.suiss.as_ref() else {
        return (None, None);
    };
    let dir = suiss
        .relay_platform
        .credential_file
        .parent()
        .map(Path::to_path_buf);
    let port = suiss
        .relay
        .strip_prefix("https://")
        .and_then(|rest| rest.split('/').next())
        .map(|authority| {
            authority
                .rsplit_once(':')
                .and_then(|(_, p)| p.parse().ok())
                .unwrap_or(443)
        });
    (dir, port)
}

/// The realms' KEKs the courier unwraps subject keys with.
pub(crate) struct Keks(pub(crate) RealmKeks);

impl RealmKeys for Keks {
    fn kek(
        &self,
        tenant: TenantId,
        realm: RealmId,
        kek_id: &str,
    ) -> Option<Arc<dyn Kek + Send + Sync>> {
        self.0.kek(tenant, realm).filter(|k| k.id() == kek_id)
    }
}

/// The running courier.
pub(crate) struct Running {
    stop: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
    notices: tokio::task::JoinHandle<()>,
}

impl Running {
    /// Finishes the send in flight, gives the lease up and stops.
    pub(crate) async fn stop(self) {
        let _ = self.stop.send(true);
        let _ = self.task.await;
        let _ = self.notices.await;
    }
}

async fn confirmed(p: &Prepared, stop: &mut tokio::sync::watch::Receiver<bool>) -> Option<String> {
    loop {
        if *stop.borrow() {
            return None;
        }
        let why = match discover(&p.relay, p.tls.clone(), TIMEOUT).await {
            Ok(doc) => match check_discovery(&doc, &p.relay, &p.issuer) {
                Ok(url) => return Some(url),
                Err(e) => e.to_string(),
            },
            Err(e) => e.to_string(),
        };
        tracing::warn!(reason = %why, "relay not confirmed; messages wait in the outbox");
        let _ = tokio::time::timeout(DISCOVERY_RETRY, stop.changed()).await;
    }
}

/// Starts the courier and the security notice courier as `holder` over the outbox reader, the
/// application pool and the router pool; `alive` is unset when the courier ends other than by
/// [`Running::stop`].
pub(crate) fn start(
    prepared: Prepared,
    (reader, app, router): (Pool, Pool, Pool),
    keks: RealmKeks,
    ids: [u8; 32],
    holder: String,
    alive: &ReadyFlag,
) -> Running {
    let (stop, stopped) = tokio::sync::watch::channel(false);
    // OP-156 m.3 (c)
    let notices = tokio::spawn(notices_run(
        NoticePools {
            app: app.clone(),
            router,
            reader: reader.clone(),
        },
        keks.clone(),
        ids,
        holder.clone(),
        stopped.clone(),
    ));
    let ended = alive.clone();
    let task = tokio::spawn(async move {
        let mut until = stopped.clone();
        let Some(url) = confirmed(&prepared, &mut until).await else {
            return;
        };
        let relay = RelayEndpoint::parse(&url)
            .map_err(|e| e.to_string())
            .and_then(|endpoint| {
                HttpRelay::new(HttpRelayConfig {
                    endpoint,
                    tls: prepared.tls.clone(),
                    token_file: prepared.credential.clone(),
                    timeout: TIMEOUT,
                })
                .map_err(|e| e.to_string())
            });
        let relay = match relay {
            Ok(r) => r,
            Err(error) => {
                tracing::error!(%error, "relay courier cannot start");
                ended.set(false);
                return;
            }
        };
        tracing::info!("relay confirmed; the courier starts");
        let courier = Courier::new(
            PgCourierStore { reader, app },
            relay,
            Keks(keks),
            SystemClock,
            IdKey::new(Secret::new(ids)),
            Backoff::default(),
        );
        courier.run(&holder, &stopped).await;
        if !*stopped.borrow() {
            ended.set(false);
        }
    });
    Running {
        stop,
        task,
        notices,
    }
}

/// Starts the couriers of `prepared`, when there is one, under a fresh holder name.
///
/// # Errors
/// No randomness for the holder name.
pub(crate) fn spawn(
    prepared: Option<Prepared>,
    pools: &crate::Pools,
    keks: &RealmKeks,
    ids: [u8; 32],
    alive: &ReadyFlag,
) -> Result<Option<Running>, String> {
    prepared
        .map(|p| {
            Ok(start(
                p,
                (
                    pools.outbox_reader.clone(),
                    pools.app.clone(),
                    pools.router.clone(),
                ),
                keks.clone(),
                ids,
                format!("relay/{}", crate::holder()?),
                alive,
            ))
        })
        .transpose()
}

/// `GET /access/v1/relay-status` over the courier's store (OP-156 m.3 (c), §8.13).
pub(crate) fn routes(reader: Pool, app: Pool) -> axum::Router {
    axum::Router::new()
        .route(STATUS_PATH, axum::routing::get(status))
        .with_state(Arc::new(PgCourierStore { reader, app }))
}

/// The status body: the lag, `null` when nothing waits, and whether it reads as delayed.
#[must_use]
pub(crate) fn body(lag_ms: Option<u64>) -> serde_json::Value {
    json!({
        "relay_lag_ms": lag_ms,
        "notifications_delayed": lag_ms.is_some_and(|l| l > DELAYED_MS),
    })
}

async fn status(State(store): State<Arc<PgCourierStore>>) -> Response {
    match store.lag_ms().await {
        Ok(lag) => {
            if let Some(l) = lag.filter(|l| *l > DELAYED_MS) {
                tracing::warn!(
                    event = "relay.courier.lag",
                    lag_ms = l,
                    "relay notifications delayed"
                );
            }
            let mut r = Json(body(lag)).into_response();
            r.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            r
        }
        Err(error) => {
            tracing::warn!(%error, "relay lag unavailable");
            access_http::problem::codes::UNAVAILABLE
                .problem()
                .into_response()
        }
    }
}

/// The security notice courier's lease consumer (Ek B 5294).
pub(crate) const NOTICES: &str = "relay-notices";

/// How often the notice courier reads the authority outboxes (PD).
const NOTICE_INTERVAL: Duration = Duration::from_secs(2);

/// Authority events read per domain and step (PD).
const NOTICE_BATCH: u32 = 100;

/// The notice courier's pools and keys.
pub(crate) struct NoticePools {
    /// `access_app`.
    pub(crate) app: Pool,
    /// `access_router`, for the live realms.
    pub(crate) router: Pool,
    /// `access_outbox_reader`, for the lease.
    pub(crate) reader: Pool,
}

/// One step over every live realm's governing domain: each security-relevant authority event
/// past the notice cursor becomes a notice to the person whose Party it concerns (OP-156 m.3
/// (c), Ek B 5294); returns the notices queued.
///
/// # Errors
/// A store failure; the cursor has not passed an event whose notice is not queued.
pub(crate) async fn notices_step<K: access_identity_events::adapters::RealmKek>(
    pools: &NoticePools,
    keks: &K,
    ids: &IdKey,
) -> Result<u32, String> {
    use access_identity_account::adapters::system::SystemEntropy;
    use access_identity_account::notify::notices::{queue, security_event};
    use access_internal_api::events::Event;
    use access_store::scope::DomainId;
    let e = |x: access_store::StoreError| x.to_string();
    let mut queued = 0_u32;
    for r in access_store::tenancy::routes(&pools.router)
        .await
        .map_err(e)?
    {
        let mut t = TenantTx::begin(&pools.app, r.tenant, r.realm)
            .await
            .map_err(e)?;
        let g = access_store::idp::governance(&mut t).await.map_err(e)?;
        t.commit().await.map_err(e)?;
        let Some(g) = g else { continue };
        let domain = DomainId::from_bytes(*g.domain.as_bytes());
        let Some(kek) = keks.kek(r.tenant, r.realm) else {
            continue;
        };
        // OP-157 m.3 (h), §12.3.8 (4)
        let mut s = TenantTx::begin(&pools.app, r.tenant, r.realm)
            .await
            .map_err(e)?;
        access_identity_account::app::breakglass::sweep(
            &mut s,
            (&*kek, ids),
            &SystemEntropy,
            &SystemClock,
            &r.issuer,
            access_identity_account::ports::Clock::now_ms(&SystemClock),
        )
        .await
        .map_err(|x| x.to_string())?;
        // OP-157 m.3 (f), (g), §8.16
        support_sweep(&mut s, (&*kek, ids), &r.slug).await?;
        s.commit().await.map_err(e)?;
        let at = access_store::relay::notice_cursor(&pools.app, &domain)
            .await
            .map_err(e)?;
        let rows = access_store::authority::read_outbox(&pools.app, &domain, at, NOTICE_BATCH)
            .await
            .map_err(e)?;
        let Some(last) = rows.last().map(|o| (o.pos, o.idx)) else {
            continue;
        };
        let mut t = TenantTx::begin(&pools.app, r.tenant, r.realm)
            .await
            .map_err(e)?;
        // OP-156 m.3 (c)
        let open = t.security_notices_enabled().await.map_err(e)?;
        for row in &rows {
            let Ok(ev) = Event::from_bytes(&row.event) else {
                continue;
            };
            // OP-157 m.3 (h), TN-71
            if ev.kind == access_internal_api::events::Kind::BreakglassUsed {
                if breakglass_used(&mut t, (&*kek, ids), &ev, (&r.slug, &r.issuer)).await? {
                    queued = queued.saturating_add(1);
                }
                continue;
            }
            // OP-157 m.3 (f), SI-21
            if support_revoked(&mut t, (&*kek, ids), &ev, &r.slug).await? {
                queued = queued.saturating_add(1);
                continue;
            }
            // OP-157 m.3 (h), §12.3.8 (5)
            breakglass_departed(&mut t, (&*kek, ids), &ev, &r.issuer).await?;
            if !open {
                continue;
            }
            let Some((event, party)) = security_event(&ev) else {
                continue;
            };
            let Some(subject) = access_store::idp::party_subject(&mut t, &party)
                .await
                .map_err(e)?
            else {
                continue;
            };
            let sent = queue(
                &mut t,
                (&*kek, ids),
                &SystemEntropy,
                &SystemClock,
                subject,
                event,
                (&r.slug, &r.issuer),
                ev.at,
            )
            .await
            .map_err(|x| x.to_string())?;
            if sent.is_some() {
                queued = queued.saturating_add(1);
            }
        }
        t.commit().await.map_err(e)?;
        access_store::relay::advance_notice_cursor(&pools.app, &domain, last)
            .await
            .map_err(e)?;
    }
    Ok(queued)
}

/// Ends the realm's support access past its end and shreds its expired support artifacts
/// (OP-157 m.3 (f), (g)).
async fn support_sweep(
    t: &mut TenantTx,
    (kek, ids): (&(dyn suiss_crypto::envelope::Kek + Send + Sync), &IdKey),
    slug: &str,
) -> Result<(), String> {
    use access_identity_account::adapters::system::SystemEntropy;
    let now = access_identity_account::ports::Clock::now_ms(&SystemClock);
    let ended = access_identity_account::app::support::sweep(
        t,
        (kek, ids),
        (&SystemEntropy, &SystemClock),
        now,
        slug,
    )
    .await
    .map_err(|x| x.to_string())?;
    for row in &ended {
        access_identity_ui::app::support::announce(t, ids, row, ("ended", now))
            .await
            .map_err(|x| x.to_string())?;
    }
    Ok(())
}

/// When `ev` revokes a support Grant, the support access it gave ends and the person is told
/// (OP-157 m.3 (f), SI-21); whether it did.
async fn support_revoked(
    t: &mut TenantTx,
    (kek, ids): (&(dyn suiss_crypto::envelope::Kek + Send + Sync), &IdKey),
    ev: &access_internal_api::events::Event,
    slug: &str,
) -> Result<bool, String> {
    use access_identity_account::adapters::system::SystemEntropy;
    use access_internal_api::events::{Kind, Subject};
    let (Kind::AuthorityRevoked, Subject::Grant(g)) = (ev.kind, ev.subject) else {
        return Ok(false);
    };
    let Some(row) = access_identity_account::app::support::revoked(
        t,
        (kek, ids),
        (&SystemEntropy, &SystemClock),
        (g.0, ev.at),
        slug,
    )
    .await
    .map_err(|x| x.to_string())?
    else {
        return Ok(false);
    };
    access_identity_ui::app::support::announce(t, ids, &row, ("revoked", ev.at))
        .await
        .map_err(|x| x.to_string())?;
    Ok(true)
}

/// The acting organization of a break-glass use: the Party's own organization, or the first
/// organization its account belongs to; `None` when it has neither.
async fn acting_org(
    t: &mut TenantTx,
    actor: &[u8; 16],
) -> Result<Option<access_store::orgs::OrgRow>, String> {
    let e = |x: access_store::StoreError| x.to_string();
    if let Some(org) = t.org_by_party(*actor).await.map_err(e)? {
        return Ok(Some(org));
    }
    let Some(subject) = access_store::idp::party_subject(t, actor)
        .await
        .map_err(e)?
    else {
        return Ok(None);
    };
    Ok(t.orgs_of(subject)
        .await
        .map_err(e)?
        .into_iter()
        .next()
        .map(|(o, _)| o))
}

/// Delivers one `breakglass.used` authority event in `t`: the record for its review, the
/// critical audit row, the subject's notice whatever the realm's notice setting, the on-call
/// alarm and the `breakglass.used` webhook (OP-157 m.3 (h), (aa), TN-71); whether it was new.
async fn breakglass_used(
    t: &mut TenantTx,
    (kek, ids): (&(dyn suiss_crypto::envelope::Kek + Send + Sync), &IdKey),
    ev: &access_internal_api::events::Event,
    (slug, issuer): (&str, &str),
) -> Result<bool, String> {
    use access_identity_account::adapters::system::SystemEntropy;
    use access_identity_account::app::breakglass::{Used, deliver};
    use access_internal_api::events::{Detail, Source, Subject};
    let e = |x: access_store::StoreError| x.to_string();
    let (
        Subject::Party(party),
        Source::Exercise(exercise),
        Detail::Breakglass {
            grant,
            actor,
            approvals,
            until,
            drill,
        },
    ) = (ev.subject, ev.source, &ev.detail)
    else {
        return Ok(false);
    };
    let subject = access_store::idp::party_subject(t, &party.0)
        .await
        .map_err(e)?;
    let org = acting_org(t, &actor.0).await?;
    let used = Used {
        exercise: exercise.0,
        grant: grant.0,
        actor: actor.0,
        party: party.0,
        subject,
        approvals: *approvals,
        at_ms: ev.at,
        until_ms: *until,
        drill: *drill,
        organization: org.as_ref().map_or(slug, |o| o.display_name.as_str()),
    };
    let done = deliver(t, (kek, ids), &SystemEntropy, &SystemClock, &used, issuer)
        .await
        .map_err(|x| x.to_string())?;
    if let (true, Some(s), Some(o), Some(realm)) = (done.recorded, subject, org, t.realm()) {
        let id = access_crypto::random::bytes::<32>().map_err(|_| "random")?;
        let account = ids
            .encode(access_identity_account::app::SUBJECT_PREFIX, s)
            .map_err(|x| x.to_string())?;
        let event = access_identity_events::domain::catalog::IdentityEvent::breakglass_used(
            id,
            realm.as_bytes(),
            (
                &account,
                &access_kernel::json::b64url_encode(&exercise.0),
                &o.id,
            ),
            (u32::try_from(*approvals).unwrap_or(u32::MAX), *until),
            ev.at,
        );
        access_identity_events::app::emit(t, &event)
            .await
            .map_err(|x| x.to_string())?;
    }
    Ok(done.noticed)
}

/// When a departing Party's account is a break-glass account, its Grants must be rotated: the
/// critical audit row and the on-call alarm (OP-157 m.3 (h), §12.3.8 (5)).
async fn breakglass_departed(
    t: &mut TenantTx,
    (kek, ids): (&(dyn suiss_crypto::envelope::Kek + Send + Sync), &IdKey),
    ev: &access_internal_api::events::Event,
    issuer: &str,
) -> Result<(), String> {
    use access_identity_account::adapters::system::SystemEntropy;
    use access_identity_account::app::breakglass::CONSOLE_PATH;
    use access_identity_account::notify::message::{Body, BreakglassAlarm};
    use access_identity_account::notify::notices::queue_body;
    use access_internal_api::events::{Detail, Kind, ReasonClass, Subject};
    let e = |x: access_store::StoreError| x.to_string();
    let (
        Kind::PartyDisabled,
        Subject::Party(party),
        Detail::Disabled {
            reason: ReasonClass::Departed,
        },
    ) = (ev.kind, ev.subject, &ev.detail)
    else {
        return Ok(());
    };
    let Some(subject) = access_store::idp::party_subject(t, &party.0)
        .await
        .map_err(e)?
    else {
        return Ok(());
    };
    if !t.is_breakglass_account(&subject).await.map_err(e)? {
        return Ok(());
    }
    let account = ids
        .encode(access_identity_account::app::SUBJECT_PREFIX, subject)
        .map_err(|x| x.to_string())?;
    t.audit(&access_store::audit::AuditEvent {
        event_type: "breakglass.rotation_required",
        actor: "authority",
        target: &account,
        correlation: "-",
    })
    .await
    .map_err(e)?;
    let link = format!("{}{CONSOLE_PATH}", issuer.trim_end_matches('/'));
    for to in t.breakglass_on_call().await.map_err(e)? {
        if to == subject {
            continue;
        }
        let body = Body::BreakglassAlarm {
            alarm: BreakglassAlarm::RotationRequired,
            account: account.clone(),
            link: Secret::new(link.clone()),
            at_ms: ev.at,
        };
        queue_body(t, (kek, ids), &SystemEntropy, &SystemClock, to, body)
            .await
            .map_err(|x| x.to_string())?;
    }
    Ok(())
}

/// Runs [`notices_step`] as `holder` while it holds the notice lease, until `stop`.
pub(crate) async fn notices_run(
    pools: NoticePools,
    keks: RealmKeks,
    ids: [u8; 32],
    holder: String,
    stop: tokio::sync::watch::Receiver<bool>,
) {
    use access_identity_account::notify::lease::TTL;
    let ids = IdKey::new(Secret::new(ids));
    let mut stop = stop;
    let mut held: Option<access_store::relay::CourierLease> = None;
    while !*stop.borrow() {
        held =
            match access_store::relay::acquire_courier_lease(&pools.reader, NOTICES, &holder, TTL)
                .await
            {
                Ok(l) => l,
                Err(error) => {
                    tracing::warn!(%error, "relay notice lease failed");
                    None
                }
            };
        if held.is_some()
            && let Err(error) = notices_step(&pools, &keks, &ids).await
        {
            tracing::warn!(%error, "relay notice step failed");
        }
        let _ = tokio::time::timeout(NOTICE_INTERVAL, stop.changed()).await;
    }
    if let Some(l) = held
        && let Err(error) = access_store::relay::release_courier_lease(&pools.reader, &l).await
    {
        tracing::warn!(%error, "relay notice lease release failed");
    }
}

#[cfg(test)]
mod tests;
