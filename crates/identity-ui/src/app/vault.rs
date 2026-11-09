//! Connected accounts for agents and the token release on the realm's surface (§8.8, §8.9,
//! AS-M15, OP-154 m.3 (t)): the person lists, connects and disconnects accounts with their
//! session; a registered executor asks for a release with its transport identity. No answer
//! ever carries a token except a release, and agents have no route here (§11.13).

use access_identity_account::domain::login::Problem;
use access_identity_oauth::ports::RealmEntry;
use access_identity_session::domain::flow::device_digest;
use access_identity_session::domain::session::{FLOW_COOKIE, set_cookie};
use access_identity_session::ports::Clock;
use access_identity_vault::app::{
    Connect, ConnectionView, Keys, ReleaseRequest, Vault, VaultError,
};
use access_identity_vault::domain::release::Refusal;
use access_identity_vault::ports::{Exercises, ProviderHttp, Random, SocialSecrets};
use access_kernel::codec::Canonical as _;
use access_kernel::intent::IntentEnvelope;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::tier::Tier;
use serde_json::{Value, json};

use super::{Body, Browser, Hosted, Reply};
use crate::ports::{Kits, Messages, RealmKit};

/// Longest base64url intent a release accepts.
pub const MAX_INTENT: usize = 16 * 1024;

fn problem(status: u16, code: &'static str, title: &'static str) -> Reply {
    Reply::problem(Problem {
        status,
        code,
        title,
        retry_after_s: (status == 503).then_some(1),
    })
}

fn refused(e: VaultError) -> Reply {
    match e {
        VaultError::Refused(r) => refusal(r),
        VaultError::NoResource => problem(
            404,
            "vault-resource-unknown",
            "That service isn't available here",
        ),
        VaultError::NoConnection => {
            problem(404, "vault-connection-unknown", "No such connected account")
        }
        VaultError::ConsentRequired => problem(
            409,
            "vault-consent-required",
            "Approve this app first, then connect the account",
        ),
        VaultError::NoParty => problem(409, "vault-no-party", "Set up this device first"),
        VaultError::Scope => problem(
            400,
            "vault-scope",
            "That access isn't offered for this service",
        ),
        VaultError::Upstream => problem(
            502,
            "vault-upstream-refused",
            "The service didn't connect the account",
        ),
        VaultError::FlowGone => {
            problem(400, "vault-flow-gone", "That connection attempt has ended")
        }
        VaultError::Unavailable => problem(503, "unavailable", "Temporarily unavailable"),
    }
}

fn refusal(r: Refusal) -> Reply {
    problem(r.status(), r.code(), "The token was not released")
}

fn keys(kit: &RealmKit) -> Keys<'_> {
    Keys {
        tenant: kit.tenant,
        realm: kit.realm,
        kek: &*kit.kek,
        ids: &kit.ids,
        issuer: &kit.issuer,
    }
}

/// The callback the upstream redirects to: the connections list with the OAuth answer.
fn redirect_uri(kit: &RealmKit) -> String {
    format!("{}/v1/account/vault/connections", kit.issuer)
}

fn connection_id(s: &str) -> Option<[u8; 16]> {
    b64url_decode(s)
        .ok()
        .and_then(|b| <[u8; 16]>::try_from(b).ok())
}

const fn tier_name(t: Tier) -> &'static str {
    match t {
        Tier::Ct0 => "ct0",
        Tier::Ct1 => "ct1",
        Tier::Ct2 => "ct2",
        Tier::Ct3 => "ct3",
    }
}

fn view(v: &ConnectionView) -> Value {
    json!({
        "connection": b64url_encode(&v.row.id),
        "resource": v.row.resource,
        "upstream": v.upstream,
        "client_id": v.row.client_id,
        "scopes": v.row.scopes,
        "status": v.row.status,
        "created_ms": v.row.created_ms,
        "status_ms": v.row.status_ms,
        "used": v.releases.iter().map(|r| json!({
            "exercise": b64url_encode(&r.exercise),
            "agent": r.actor.map(|a| b64url_encode(&a)),
            "delivery": r.path,
            "tier": r.tier,
            "released_ms": r.released_ms,
        })).collect::<Vec<_>>(),
    })
}

/// The OAuth answer the upstream redirected back with.
#[derive(Clone, Copy, Debug)]
pub struct Callback<'a> {
    /// `code`, when it connected.
    pub code: Option<&'a str>,
    /// `state`.
    pub state: &'a str,
}

/// What `POST /v1/account/vault/connections` asks.
#[derive(Clone, Debug)]
pub struct StartBody {
    /// The Resource.
    pub resource: String,
    /// The agent client.
    pub client_id: String,
    /// The scopes, when not all of the Resource's.
    pub scopes: Option<Vec<String>>,
}

impl<K: Kits, C: Clock + Sync, M: Messages> Hosted<K, C, M> {
    async fn vault_kit(&self, entry: &RealmEntry) -> Result<std::sync::Arc<RealmKit>, Reply> {
        self.kit(entry).await
    }

    /// `GET /v1/account/vault/connections` (§8.8, §8.9): the person's connected accounts and
    /// what used each (which agent, which Exercise, which path); never a token. With the
    /// upstream's OAuth answer it is the connect callback: the account is connected and the
    /// browser goes back to the account pages.
    pub async fn vault_connections<H, S, X, R>(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        callback: Option<Callback<'_>>,
        vault: &Vault<H, S, X, R>,
    ) -> Reply
    where
        H: ProviderHttp,
        S: SocialSecrets,
        X: Exercises,
        R: Random,
    {
        let kit = match self.vault_kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let (subject, _) = match self.fresh(&kit, b, None).await {
            Ok(s) => s,
            Err(r) => return r,
        };
        let k = keys(&kit);
        let now = self.clock.now_ms();
        if let Some(cb) = callback {
            let Some(device) = b
                .flow
                .and_then(|f| b64url_decode(f).ok())
                .and_then(|d| <[u8; 32]>::try_from(d).ok())
            else {
                return refused(VaultError::FlowGone);
            };
            let device = device_digest(&device);
            let Some(code) = cb.code else {
                if vault
                    .abandon(&self.db, &k, &device, cb.state, now)
                    .await
                    .is_err()
                {
                    tracing::warn!("vault connect attempt not closed");
                }
                let to = format!("{}/account?vault_error=vault-upstream-refused", kit.issuer);
                return Reply::new(303, Body::Redirect(to));
            };
            let done = vault
                .finish(
                    &self.db,
                    &k,
                    (subject, &device),
                    (code, cb.state),
                    &redirect_uri(&kit),
                    now,
                )
                .await;
            let to = match done {
                Ok(id) => format!("{}/account?connected={}", kit.issuer, b64url_encode(&id)),
                Err(e) => format!("{}/account?vault_error={e}", kit.issuer),
            };
            return Reply::new(303, Body::Redirect(to));
        }
        match vault.connections(&self.db, &k, subject).await {
            Ok(list) => Reply::json(
                200,
                json!({ "connections": list.iter().map(view).collect::<Vec<_>>() }),
            ),
            Err(e) => refused(e),
        }
    }

    /// `GET /v1/account/agent-connections` (S11, OP-154 m.3 (e), (t)): the person's connected
    /// accounts and their agents, each with its name, kind, status, whether the person sponsors
    /// it and which of the person's accounts it used; never a token, never authority.
    pub async fn agent_connections<H, S, X, R>(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        vault: &Vault<H, S, X, R>,
    ) -> Reply
    where
        H: ProviderHttp,
        S: SocialSecrets,
        X: Exercises,
        R: Random,
    {
        let kit = match self.vault_kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let (subject, _) = match self.fresh(&kit, b, None).await {
            Ok(s) => s,
            Err(r) => return r,
        };
        match vault
            .agent_connections(&self.db, &keys(&kit), subject)
            .await
        {
            Ok(a) => Reply::json(
                200,
                json!({
                    "agents": a.agents.iter().map(|v| json!({
                        "agent": b64url_encode(&v.agent.party),
                        "name": v.agent.display_name,
                        "kind": v.agent.kind,
                        "status": v.agent.status,
                        "sponsor": v.sponsor,
                        "connections": v.connections.iter().map(|c| b64url_encode(c)).collect::<Vec<_>>(),
                        "last_used_ms": v.last_used_ms,
                    })).collect::<Vec<_>>(),
                    "connections": a.connections.iter().map(view).collect::<Vec<_>>(),
                }),
            ),
            Err(e) => refused(e),
        }
    }

    /// `GET /v1/account/vault/connections/{connection}`: one connected account; never a token.
    pub async fn vault_connection<H, S, X, R>(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        connection: &str,
        vault: &Vault<H, S, X, R>,
    ) -> Reply
    where
        H: ProviderHttp,
        S: SocialSecrets,
        X: Exercises,
        R: Random,
    {
        let kit = match self.vault_kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let (subject, _) = match self.fresh(&kit, b, None).await {
            Ok(s) => s,
            Err(r) => return r,
        };
        let Some(id) = connection_id(connection) else {
            return refused(VaultError::NoConnection);
        };
        match vault.connections(&self.db, &keys(&kit), subject).await {
            Ok(list) => list.iter().find(|v| v.row.id == id).map_or_else(
                || refused(VaultError::NoConnection),
                |v| Reply::json(200, view(v)),
            ),
            Err(e) => refused(e),
        }
    }

    /// `POST /v1/account/vault/connections` (AS-M15): the upstream URL that connects the
    /// account, only after the person's AAS for the client.
    pub async fn start_vault_connection<H, S, X, R>(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        ask: &StartBody,
        vault: &Vault<H, S, X, R>,
    ) -> Reply
    where
        H: ProviderHttp,
        S: SocialSecrets,
        X: Exercises,
        R: Random,
    {
        let kit = match self.vault_kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let (subject, _) = match self.fresh(&kit, b, None).await {
            Ok(s) => s,
            Err(r) => return r,
        };
        let (device, fresh) = match b.flow.and_then(|f| b64url_decode(f).ok()) {
            Some(d) if d.len() == 32 => (<[u8; 32]>::try_from(d).unwrap_or([0; 32]), false),
            _ => match access_crypto::random::bytes::<32>() {
                Ok(d) => (d, true),
                Err(_) => return refused(VaultError::Unavailable),
            },
        };
        let redirect = redirect_uri(&kit);
        let ask = Connect {
            resource: &ask.resource,
            client_id: &ask.client_id,
            scopes: ask.scopes.clone(),
            redirect_uri: &redirect,
        };
        match vault
            .start(
                &self.db,
                &keys(&kit),
                (subject, &device_digest(&device)),
                &ask,
                self.clock.now_ms(),
            )
            .await
        {
            Ok((id, url)) => Reply::json(
                200,
                json!({ "connection": b64url_encode(&id), "redirect_to": url }),
            )
            .cookie(fresh.then(|| set_cookie(FLOW_COOKIE, &b64url_encode(&device), None))),
            Err(e) => refused(e),
        }
    }

    /// `DELETE /v1/account/vault/connections/{connection}`: the connection ends, its tokens
    /// are shredded and revoked upstream where it can be; nothing is deleted (OP-73).
    pub async fn disconnect_vault_connection<H, S, X, R>(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        connection: &str,
        vault: &Vault<H, S, X, R>,
    ) -> Reply
    where
        H: ProviderHttp,
        S: SocialSecrets,
        X: Exercises,
        R: Random,
    {
        let kit = match self.vault_kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let (subject, _) = match self.fresh(&kit, b, None).await {
            Ok(s) => s,
            Err(r) => return r,
        };
        let Some(id) = connection_id(connection) else {
            return refused(VaultError::NoConnection);
        };
        match vault
            .disconnect(&self.db, &keys(&kit), subject, id, self.clock.now_ms())
            .await
        {
            Ok(()) => Reply::json(
                200,
                json!({ "connection": connection, "status": "disconnected" }),
            ),
            Err(e) => refused(e),
        }
    }

    /// `POST /v1/vault/releases` (G59, U65, U66, EI-26, OP-154 m.3 (t)): the release a
    /// registered executor asks for, `pep` being its transport identity. The answer names the
    /// path and how long the token may be used, and says the upstream token's content is not
    /// guaranteed (N-54).
    pub async fn release_vault_token<H, S, X, R>(
        &self,
        entry: &RealmEntry,
        pep: Option<&str>,
        body: &Value,
        vault: &Vault<H, S, X, R>,
    ) -> Reply
    where
        H: ProviderHttp,
        S: SocialSecrets,
        X: Exercises,
        R: Random,
    {
        // §11.13, Ek B 4627
        if pep.is_none() {
            return refusal(Refusal::Unauthenticated);
        }
        let Some(req) = release_request(body) else {
            return problem(400, "invalid-request", "Bad Request");
        };
        let kit = match self.vault_kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let now = self.clock.now_ms();
        match vault.release(&self.db, &keys(&kit), pep, &req, now).await {
            Ok(r) => Reply::json(
                200,
                json!({
                    "access_token": r.token.expose(),
                    "token_type": r.token_type,
                    "delivery": r.admitted.path.name(),
                    "use_until_ms": r.admitted.use_until,
                    "expires_in": r.admitted.use_until.saturating_sub(now) / 1000,
                    "tier": tier_name(r.admitted.tier),
                    "exercise": b64url_encode(&req.exercise),
                    "content": "not-guaranteed",
                }),
            )
            .header("cache-control", String::from("no-store")),
            Err(e) => refused(e),
        }
    }
}

fn bytes32(v: &Value, k: &str) -> Option<[u8; 32]> {
    let s = v.get(k)?.as_str()?;
    <[u8; 32]>::try_from(b64url_decode(s).ok()?).ok()
}

/// A release body: `domain`, `exercise` (base64url digests), `intent` (base64url
/// deterministic CBOR of the intent envelope), `connection` and `delivery` (`executor` or
/// `agent`); nothing else.
fn release_request(v: &Value) -> Option<ReleaseRequest> {
    let o = v.as_object()?;
    if o.keys().any(|k| {
        !matches!(
            k.as_str(),
            "domain" | "exercise" | "intent" | "connection" | "delivery"
        )
    }) {
        return None;
    }
    let intent = o
        .get("intent")?
        .as_str()
        .filter(|s| s.len() <= MAX_INTENT)?;
    let intent = IntentEnvelope::from_bytes(&b64url_decode(intent).ok()?).ok()?;
    let agent = match o.get("delivery").and_then(Value::as_str) {
        None | Some("executor") => false,
        Some("agent") => true,
        Some(_) => return None,
    };
    Some(ReleaseRequest {
        domain: bytes32(v, "domain")?,
        exercise: bytes32(v, "exercise")?,
        intent,
        connection: connection_id(o.get("connection")?.as_str()?)?,
        agent,
    })
}
