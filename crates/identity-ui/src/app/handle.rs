//! Handles on the Frontend API (E56, OP-156 m.4 Q20): the person claims a Suiss subdomain or a
//! domain they own as a human-readable name beside their DID. A Suiss handle is verified at once,
//! since Access answers both directions; a handle of the person's own domain is verified once its
//! host answers `/.well-known/access-handle` with the DID. A handle is shown, and listed in the
//! DID document, only once verified; it is an identifier, never authority, and is never handed
//! to anyone else.

use access_identity_account::domain::login::Problem;
use access_identity_oauth::ports::RealmEntry;
use access_store::audit::AuditEvent;
use access_store::identity::TenantTx;
use access_store::idp;
use serde::Deserialize;
use serde_json::{Value, json};

use super::did::did_of;
use super::me::unavailable;
use super::signup::STEP_UP_MAX_AGE_MS;
use super::{Body, Browser, Hosted, Reply};
use crate::domain::handle::{Handle, Verdict, verify};
use crate::ports::{Clock, HandleHosts, Kits, Messages, RealmKit};

/// The opaque id prefix of a handle.
pub const HANDLE_PREFIX: &str = "hdl";

/// `POST /v1/me/handles`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandleClaim {
    /// The handle.
    pub handle: String,
}

const fn problem(status: u16, code: &'static str, title: &'static str) -> Problem {
    Problem {
        status,
        code,
        title,
        retry_after_s: None,
    }
}

const BAD: Problem = problem(400, "handle-invalid", "That isn't a name that can be used");
const TAKEN: Problem = problem(409, "handle-taken", "That name can't be used");
const NO_PARTY: Problem = problem(409, "handle-party", "Add this device first");
const UNKNOWN: Problem = problem(404, "handle-unknown", "There is no such name");
const NOT_VERIFIED: Problem = problem(
    409,
    "handle-not-verified",
    "Your site doesn't point back to you yet",
);

/// The base a Suiss handle of the realm is a subdomain of: the issuer's host, with the realm's
/// slug in front for a path issuer.
#[must_use]
pub fn suiss_base(issuer: &str) -> Option<String> {
    let rest = issuer.strip_prefix("https://")?.trim_end_matches('/');
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    let host = host.split(':').next()?.to_ascii_lowercase();
    match path.rsplit('/').next().filter(|s| !s.is_empty()) {
        Some(slug) => Some(format!("{}.{host}", slug.to_ascii_lowercase())),
        None => Some(host),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{x:02x}"));
        s
    })
}

impl<K, C, M> Hosted<K, C, M>
where
    K: Kits,
    C: Clock + Sync,
    M: Messages,
{
    async fn handle_party(&self, kit: &RealmKit, subject: [u8; 16]) -> Result<[u8; 16], Reply> {
        let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm)
            .await
            .map_err(|_| unavailable())?;
        let p = idp::subject_party(&mut t, &subject)
            .await
            .map_err(|_| unavailable())?;
        t.commit().await.map_err(|_| unavailable())?;
        p.ok_or_else(|| Reply::problem(NO_PARTY))
    }

    async fn record_handle(
        &self,
        kit: &RealmKit,
        (subject, id): ([u8; 16], [u8; 16]),
        event: &'static str,
        correlation: &str,
    ) -> Result<bool, Reply> {
        let actor = kit.ids.encode("usr", subject).unwrap_or_default();
        let done = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            let new = t.handle_event(subject, id, event).await?;
            if new {
                t.audit(&AuditEvent {
                    event_type: if event == "verified" {
                        "handle.verified"
                    } else {
                        "handle.retired"
                    },
                    actor: &actor,
                    target: &hex(&id),
                    correlation,
                })
                .await?;
            }
            t.commit().await?;
            Ok::<_, access_store::StoreError>(new)
        };
        done.await.map_err(|_| unavailable())
    }

    /// `GET /v1/me/handles`: the person's handles, each with whether it is shown.
    pub async fn handles(&self, entry: &RealmEntry, b: &Browser<'_>) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let subject = match self.fresh(&kit, b, None).await {
            Ok((s, _)) => s,
            Err(r) => return r,
        };
        let read = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            let rows = t.handles(Some(subject), None).await?;
            t.commit().await?;
            Ok::<_, access_store::StoreError>(rows)
        };
        let Ok(rows) = read.await else {
            return unavailable();
        };
        let list: Vec<Value> = rows
            .iter()
            .filter(|r| !r.retired)
            .map(|r| {
                json!({
                    "id": kit.ids.encode(HANDLE_PREFIX, r.id).ok(),
                    "handle": r.handle,
                    "kind": r.kind,
                    "did": r.did,
                    "state": if r.verified { "verified" } else { "pending" },
                    "shown": r.verified,
                })
            })
            .collect();
        Reply::json(200, json!({ "handles": list }))
    }

    /// `POST /v1/me/handles` (E56 (2)): after a sign-in in the last 5 minutes. A Suiss handle is
    /// verified at once; one of the person's own domain waits for its host.
    pub async fn claim_handle(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        claim: &HandleClaim,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let subject = match self.fresh(&kit, b, Some(STEP_UP_MAX_AGE_MS)).await {
            Ok((s, _)) => s,
            Err(r) => return r,
        };
        let (Some(handle), Some(base)) = (Handle::parse(&claim.handle), suiss_base(&kit.issuer))
        else {
            return Reply::problem(BAD);
        };
        let suiss = handle.under(&base);
        if suiss
            && handle
                .as_str()
                .strip_suffix(&base)
                .is_some_and(|label| label.trim_end_matches('.').contains('.'))
        {
            return Reply::problem(BAD);
        }
        if !suiss && handle.as_str().ends_with(&base) {
            return Reply::problem(BAD);
        }
        let party = match self.handle_party(&kit, subject).await {
            Ok(p) => p,
            Err(r) => return r,
        };
        let Some(did) = did_of(&kit.issuer, &party) else {
            return unavailable();
        };
        let kind = if suiss { "suiss" } else { "own" };
        let actor = kit.ids.encode("usr", subject).unwrap_or_default();
        let made = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            let id = t
                .claim_handle((subject, party), handle.as_str(), &did, kind)
                .await?;
            if let Some(id) = id {
                t.audit(&AuditEvent {
                    event_type: "handle.claimed",
                    actor: &actor,
                    target: &hex(&id),
                    correlation: b.correlation,
                })
                .await?;
            }
            t.commit().await?;
            Ok::<_, access_store::StoreError>(id)
        };
        let id = match made.await {
            Ok(Some(id)) => id,
            Ok(None) => return Reply::problem(TAKEN),
            Err(_) => return unavailable(),
        };
        // E56 (2)
        if suiss
            && let Err(r) = self
                .record_handle(&kit, (subject, id), "verified", b.correlation)
                .await
        {
            return r;
        }
        Reply::json(
            201,
            json!({
                "id": kit.ids.encode(HANDLE_PREFIX, id).ok(),
                "handle": handle.as_str(),
                "kind": kind,
                "did": did,
                "state": if suiss { "verified" } else { "pending" },
                "shown": suiss,
                "well_known": handle.well_known_url(),
            }),
        )
    }

    /// `POST /v1/me/handles/{handle}/verify` (E56 (2)): asks the handle's host for the DID; the
    /// claim is the DID's side.
    pub async fn verify_handle<H: HandleHosts>(
        &self,
        hosts: &H,
        entry: &RealmEntry,
        b: &Browser<'_>,
        id: &str,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let subject = match self.fresh(&kit, b, None).await {
            Ok((s, _)) => s,
            Err(r) => return r,
        };
        let Ok(id) = kit.ids.decode(HANDLE_PREFIX, id) else {
            return Reply::problem(UNKNOWN);
        };
        let read = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            let rows = t.handles(Some(subject), None).await?;
            t.commit().await?;
            Ok::<_, access_store::StoreError>(rows)
        };
        let Ok(rows) = read.await else {
            return unavailable();
        };
        let Some(row) = rows.into_iter().find(|r| r.id == id && !r.retired) else {
            return Reply::problem(UNKNOWN);
        };
        let Some(handle) = Handle::parse(&row.handle) else {
            return Reply::problem(UNKNOWN);
        };
        if !row.verified {
            let answer = hosts.well_known(handle.as_str()).await;
            let claimed = json!({ "id": row.did, "alsoKnownAs": [handle.also_known_as()] });
            if verify(&handle, &row.did, answer.as_deref(), &claimed) != Verdict::Verified {
                return Reply::problem(NOT_VERIFIED);
            }
            if let Err(r) = self
                .record_handle(&kit, (subject, id), "verified", b.correlation)
                .await
            {
                return r;
            }
        }
        Reply::json(200, json!({ "state": "verified", "shown": true }))
    }

    /// `POST /v1/me/handles/{handle}/retire`: the handle is no longer shown and never handed to
    /// anyone else.
    pub async fn retire_handle(&self, entry: &RealmEntry, b: &Browser<'_>, id: &str) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let subject = match self.fresh(&kit, b, None).await {
            Ok((s, _)) => s,
            Err(r) => return r,
        };
        let Ok(id) = kit.ids.decode(HANDLE_PREFIX, id) else {
            return Reply::problem(UNKNOWN);
        };
        match self
            .record_handle(&kit, (subject, id), "retired", b.correlation)
            .await
        {
            Ok(true) => Reply::new(204, Body::Empty),
            Ok(false) => Reply::problem(UNKNOWN),
            Err(r) => r,
        }
    }

    /// The verified, not retired handles of `party`, as the DID document lists them in
    /// `alsoKnownAs` (E56 (2)).
    pub(super) async fn shown_handles(
        &self,
        kit: &RealmKit,
        party: [u8; 16],
    ) -> Result<Vec<String>, Reply> {
        let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm)
            .await
            .map_err(|_| unavailable())?;
        let rows = t
            .handles(None, Some(party))
            .await
            .map_err(|_| unavailable())?;
        t.commit().await.map_err(|_| unavailable())?;
        Ok(rows
            .iter()
            .filter(|r| r.verified && !r.retired)
            .filter_map(|r| Handle::parse(&r.handle).map(|h| h.also_known_as()))
            .collect())
    }
}

/// The router's reads of the Suiss handles (E56 (2)).
#[derive(Clone, Debug)]
pub struct RouterHandles(pub access_store::Pool);

impl crate::ports::HandleDirectory for RouterHandles {
    async fn did_of_host(
        &self,
        host: &str,
    ) -> Result<Option<String>, access_identity_oauth::ports::Unavailable> {
        access_store::handles::suiss_handle_did(&self.0, host)
            .await
            .map_err(|_| access_identity_oauth::ports::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // E56 (2)
    #[test]
    fn a_suiss_handle_is_a_subdomain_of_the_realms_own_base() {
        assert_eq!(
            suiss_base("https://access.test/realms/acme").as_deref(),
            Some("acme.access.test")
        );
        assert_eq!(
            suiss_base("https://acme.suiss.app/").as_deref(),
            Some("acme.suiss.app")
        );
        assert_eq!(suiss_base("http://acme.example"), None);
    }
}
