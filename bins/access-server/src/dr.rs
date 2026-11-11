//! `access-server dr-promote` (OP-29, HL-31, §16.7.1, §17.4.8, OP-158 m.3 (r)): run once on a
//! cell promoted from its async DR copy, before it serves.
//!
//! - It refuses unless every live realm of the cell declared the async DR profile
//!   (`idp.realm.dr_profile`): a realm without one is never served from an async copy.
//! - It raises every realm's `session_epoch` floor, so every session and refresh family issued
//!   before the promote ends and everyone signs in again; writes in the loss window (password,
//!   MFA changes) may be lost, as each realm's declared RPO says.
//! - It records the promote, after which no authority domain is led until it continues under a
//!   fence proof with its last head covered (§17.4.1 item 2, FA-13): the async copy is never
//!   promoted into a domain's lineage by itself.
//! - It records a restore generation, so the server stays closed until `access-server reshred`
//!   has applied the shred journal again (OP-42).

use access_store::Pool;
use access_store::identity::TenantTx;

/// One realm the promote served again, with its declared RPO.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct Realm {
    /// Its slug.
    pub(crate) slug: String,
    /// The declared recovery point objective, seconds; above zero.
    pub(crate) rpo_s: u64,
    /// Subjects whose sessions and refresh families the epoch floor ended.
    pub(crate) signed_out: u64,
}

/// What the promote did.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct Promoted {
    /// The promote's generation.
    pub(crate) generation: u64,
    /// The restore generation the re-shred must answer.
    pub(crate) restore: u64,
    /// Every live realm, each with its declared RPO.
    pub(crate) realms: Vec<Realm>,
}

fn now_ms() -> Result<i64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .ok_or_else(|| String::from("no wall clock"))
}

/// Promotes the cell's async DR copy for the identity plane (OP-29).
///
/// # Errors
/// Why it refused; nothing is recorded when a realm declares no profile.
pub(crate) async fn promote(app: &Pool, router: &Pool) -> Result<Promoted, String> {
    let routes = access_store::tenancy::routes(router)
        .await
        .map_err(|e| e.to_string())?;
    let profiles = access_store::cells::dr_profiles(app)
        .await
        .map_err(|e| e.to_string())?;
    let mut declared = Vec::with_capacity(routes.len());
    for r in &routes {
        let rpo = profiles
            .iter()
            .find(|(t, realm, _)| t == r.tenant.as_bytes() && realm == r.realm.as_bytes())
            .and_then(|(_, _, rpo)| *rpo);
        let Some(rpo_s) = rpo else {
            return Err(format!(
                "realm {} declares no async DR profile; the promoted copy stays closed (OP-29)",
                r.slug
            ));
        };
        declared.push((r, rpo_s));
    }
    let n = u32::try_from(routes.len()).map_err(|_| String::from("too many realms"))?;
    let generation = access_store::cells::mark_dr_promoted(app, n)
        .await
        .map_err(|e| e.to_string())?;
    let floor = now_ms()?;
    let mut realms = Vec::with_capacity(declared.len());
    for (r, rpo_s) in declared {
        let mut t = TenantTx::begin(app, r.tenant, r.realm)
            .await
            .map_err(|e| e.to_string())?;
        let signed_out = t
            .raise_epoch_floor(floor)
            .await
            .map_err(|e| e.to_string())?;
        t.commit().await.map_err(|e| e.to_string())?;
        realms.push(Realm {
            slug: r.slug.clone(),
            rpo_s,
            signed_out,
        });
    }
    let restore = access_store::restore::mark_restored(app)
        .await
        .map_err(|e| e.to_string())?;
    let target = format!("dr:{generation}");
    access_store::operational::record_operational(
        app,
        &access_store::operational::OperationalEvent {
            occurred_at_ms: u64::try_from(floor).unwrap_or(0),
            tenant: None,
            domain: None,
            event_type: "failover.promoted",
            actor: "dr-promote",
            target: &target,
            reason: "async-dr",
            correlation: "dr-promote",
        },
    )
    .await
    .map_err(|e| e.to_string())?;
    tracing::warn!(
        event = "restore.reshred.pending",
        generation = restore,
        "the async DR copy was promoted; re-shred before serving (OP-29, OP-42)"
    );
    Ok(Promoted {
        generation,
        restore,
        realms,
    })
}
