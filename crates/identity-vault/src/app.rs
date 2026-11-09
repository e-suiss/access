//! The vault's use cases (OP-63): connecting an account after the person's consent to the
//! client (AS-M15), refreshing it under a lease, disconnecting it, and releasing a token only
//! against an allowed Exercise (G59, U66). Upstream calls never run inside a database
//! transaction.

use access_crypto::Secret;
use access_crypto::opaque_id::IdKey;
use access_identity_account::app::Realm;
use access_identity_account::app::sealing;
use access_identity_federation::domain::token::pkce_challenge;
use access_kernel::intent::{IntentEnvelope, intent_digest};
use access_kernel::json::b64url_encode;
use access_kernel::tier::Tier;
use access_store::accounts::SealedSecret;
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::vault::{
    ConnectionRow, NewConnection, NewRelease, NewTokenSet, ReleaseRow, TokenSetRow,
};
use access_store::{Pool, StoreError};
use suiss_crypto::envelope::Kek;

use crate::domain::catalog::Catalog;
use crate::domain::release::{
    Admitted, Asked, Held, Path, Refusal, TokenFacts, admit, refresh_first,
};
use crate::domain::resource::Resource;
use crate::domain::tokens::{
    TokenError, TokenSet, authorization_url, code_form, refresh_form, revoke_form,
};
use crate::ports::{Exercises, ProviderHttp, Random, SocialSecrets};

/// How long a connect attempt waits on the upstream's redirect back.
pub const ATTEMPT_TTL_MS: u64 = 600_000;

/// How long one refresh may hold its lease.
pub const REFRESH_LEASE_MS: u64 = 30_000;

/// How long the reconnect prompt stays worth acting on.
pub const PROMPT_TTL_MS: u64 = 7 * 86_400_000;

/// Most releases a connection view lists.
pub const VIEW_RELEASES: u32 = 20;

/// The vault's services for one process.
pub struct Vault<H, S, X, R> {
    /// The shipped upstream catalog.
    pub catalog: Catalog,
    /// HTTPS to upstreams, SSRF-guarded.
    pub http: H,
    /// The realms' client secrets.
    pub secrets: S,
    /// The authority plane's allowed Exercises.
    pub exercises: X,
    /// Randomness.
    pub random: R,
}

/// One realm's keys, as the vault needs them.
#[derive(Clone, Copy)]
pub struct Keys<'a> {
    /// Tenant.
    pub tenant: TenantId,
    /// Realm.
    pub realm: RealmId,
    /// The realm KEK that wraps subject DEKs.
    pub kek: &'a (dyn Kek + Send + Sync),
    /// The cell's id key.
    pub ids: &'a IdKey,
    /// The realm's issuer, for the links it sends.
    pub issuer: &'a str,
}

impl Keys<'_> {
    fn realm(&self) -> Realm<'_> {
        Realm {
            tenant: self.tenant,
            realm: self.realm,
            kek: self.kek,
            ids: self.ids,
        }
    }

    async fn begin(&self, db: &Pool) -> Result<TenantTx, VaultError> {
        Ok(TenantTx::begin(db, self.tenant, self.realm).await?)
    }
}

/// What a vault call came to when it did not succeed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum VaultError {
    /// A release was refused.
    #[error("{0}")]
    Refused(Refusal),
    /// No enabled Resource by that name.
    #[error("vault-resource-unknown")]
    NoResource,
    /// No such connection of this person.
    #[error("vault-connection-unknown")]
    NoConnection,
    /// The person has given that client no consent with their AAS (AS-M15).
    #[error("vault-consent-required")]
    ConsentRequired,
    /// The person's account has no Party yet: a device must be set up first.
    #[error("vault-no-party")]
    NoParty,
    /// A scope the Resource does not hold.
    #[error("vault-scope")]
    Scope,
    /// The upstream refused the code exchange.
    #[error("vault-upstream-refused")]
    Upstream,
    /// The connect attempt is unknown, used, expired or another browser's.
    #[error("vault-flow-gone")]
    FlowGone,
    /// The store, a key, the upstream or the authority plane did not answer.
    #[error("unavailable")]
    Unavailable,
}

impl From<StoreError> for VaultError {
    fn from(_: StoreError) -> Self {
        Self::Unavailable
    }
}

impl From<access_identity_account::AccountError> for VaultError {
    fn from(_: access_identity_account::AccountError) -> Self {
        Self::Unavailable
    }
}

impl From<Refusal> for VaultError {
    fn from(r: Refusal) -> Self {
        Self::Refused(r)
    }
}

/// A connect request (S11 "Connected accounts for agents").
#[derive(Clone, Debug)]
pub struct Connect<'a> {
    /// The Resource.
    pub resource: &'a str,
    /// The agent client the account is for.
    pub client_id: &'a str,
    /// The scopes to ask for; all of the Resource's when `None`.
    pub scopes: Option<Vec<String>>,
    /// Where the upstream redirects back.
    pub redirect_uri: &'a str,
}

/// A release request (`POST /v1/vault/releases`).
#[derive(Clone, Debug)]
pub struct ReleaseRequest {
    /// The domain whose Exercise it is.
    pub domain: [u8; 32],
    /// The allowed Exercise.
    pub exercise: [u8; 32],
    /// The intent it was allowed for.
    pub intent: IntentEnvelope,
    /// The connection.
    pub connection: [u8; 16],
    /// Whether path (b) is asked for.
    pub agent: bool,
}

/// A released token. `Debug` never shows it; nothing serialises it on its own (AG-40 (7)).
pub struct Released {
    /// The upstream access token.
    pub token: Secret<String>,
    /// Its `token_type`.
    pub token_type: String,
    /// What was admitted.
    pub admitted: Admitted,
}

impl core::fmt::Debug for Released {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Released")
            .field("token", &"[redacted]")
            .field("admitted", &self.admitted)
            .finish_non_exhaustive()
    }
}

/// One connection as the person or the registry sees it: never a token.
#[derive(Clone, Debug)]
pub struct ConnectionView {
    /// The connection.
    pub row: ConnectionRow,
    /// The upstream's name.
    pub upstream: Option<String>,
    /// Its newest releases, newest first: which Exercise, for which agent, on which path.
    pub releases: Vec<ReleaseRow>,
}

fn kind_of(connection: &[u8; 16]) -> String {
    format!("vault-token-set:{}", b64url_encode(connection))
}

fn hash(text: &str) -> [u8; 32] {
    suiss_crypto::digest::sha256(text.as_bytes())
}

async fn audit(
    t: &mut TenantTx,
    event_type: &str,
    actor: &str,
    connection: &[u8; 16],
    correlation: &str,
) -> Result<(), VaultError> {
    t.audit(&access_store::audit::AuditEvent {
        event_type,
        actor,
        target: &b64url_encode(connection),
        correlation,
    })
    .await?;
    Ok(())
}

fn enabled(row: Option<access_store::vault::ResourceRow>) -> Option<(u64, Resource)> {
    let row = row?;
    let r = Resource::from_bytes(row.definition.as_deref()?).ok()?;
    Some((row.version, r))
}

fn sealed_of(row: &TokenSetRow) -> Option<SealedSecret> {
    let (wrapped_dek, nonce, ciphertext) = row.sealed.clone()?;
    Some(SealedSecret {
        kek_id: row.kek_id.clone(),
        wrapped_dek,
        nonce,
        ciphertext,
        pepper_version: None,
    })
}

/// Seals `set` under the person's subject DEK as the connection's next `TokenSet` (OP-73: the
/// person's erasure shreds it with every credential).
async fn seal_in(
    t: &mut TenantTx,
    keys: &Keys<'_>,
    c: &ConnectionRow,
    set: &TokenSet,
    now: u64,
) -> Result<u64, VaultError> {
    let realm = keys.realm();
    let subject = t
        .subject(c.subject, false)
        .await?
        .ok_or(VaultError::NoConnection)?;
    let dek = sealing::subject_key(&realm, &subject)?;
    let s = sealing::seal(
        &realm,
        &dek,
        &c.subject,
        &kind_of(&c.id),
        set.to_sealed_text().as_bytes(),
    )?;
    Ok(t.put_vault_token_set(
        c.id,
        &NewTokenSet {
            kek_id: &s.kek_id,
            wrapped_dek: &s.wrapped_dek,
            nonce: &s.nonce,
            ciphertext: &s.ciphertext,
            access_expires_ms: set.expires_at,
            refreshable: set.refresh_token.is_some(),
            now_ms: now,
        },
    )
    .await?)
}

async fn open(
    t: &mut TenantTx,
    keys: &Keys<'_>,
    c: &ConnectionRow,
    row: &TokenSetRow,
) -> Result<Option<TokenSet>, VaultError> {
    let Some(sealed) = sealed_of(row) else {
        return Ok(None);
    };
    let realm = keys.realm();
    let subject = t
        .subject(c.subject, false)
        .await?
        .ok_or(VaultError::NoConnection)?;
    let dek = sealing::subject_key(&realm, &subject)?;
    let text = sealing::open(&realm, &dek, &c.subject, &kind_of(&c.id), &sealed)?;
    Ok(TokenSet::from_sealed_text(text.expose()).ok())
}

/// What one release reads before it decides.
struct Read {
    connection: Option<ConnectionRow>,
    resource: Option<Resource>,
    open: bool,
    token: Option<TokenSetRow>,
}

impl<H: ProviderHttp, S: SocialSecrets, X: Exercises, R: Random> Vault<H, S, X, R> {
    async fn read(
        &self,
        db: &Pool,
        keys: &Keys<'_>,
        connection: [u8; 16],
    ) -> Result<Read, VaultError> {
        let mut t = keys.begin(db).await?;
        let c = t.vault_connection(connection).await?;
        let resource = match &c {
            Some(c) => enabled(t.vault_resource(&c.resource).await?).map(|(_, r)| r),
            None => None,
        };
        let open = t.vault_release_open().await?;
        let token = t.vault_token_set(connection).await?;
        t.commit().await?;
        Ok(Read {
            connection: c,
            resource,
            open,
            token,
        })
    }

    /// `POST /v1/vault/releases` (G59, U65, U66, EI-26, OP-154 m.3 (t)): the token of
    /// `req.connection` for the PEP `caller`, only against the allowed Exercise `req.exercise`
    /// of `req.domain`, once. A token about to expire is refreshed first and the same check
    /// runs again; the release record is written with its audit row.
    ///
    /// # Errors
    /// [`VaultError::Refused`]; [`VaultError::Unavailable`].
    pub async fn release(
        &self,
        db: &Pool,
        keys: &Keys<'_>,
        caller: Option<&str>,
        req: &ReleaseRequest,
        now: u64,
    ) -> Result<Released, VaultError> {
        if caller.is_none() {
            return Err(Refusal::Unauthenticated.into());
        }
        let digest = intent_digest(&req.intent).map_err(|_| Refusal::NoExercise)?;
        let allowed = self
            .exercises
            .allowed(req.domain, req.exercise, &req.intent)
            .await
            .map_err(|_| VaultError::Unavailable)?;
        let asked = Asked {
            caller,
            intent: &req.intent,
            agent: req.agent,
        };
        let mut read = self.read(db, keys, req.connection).await?;
        let mut refreshed = false;
        loop {
            let c = read.connection.as_ref().ok_or(Refusal::NotConnected)?;
            let held = Held {
                status: &c.status,
                party: c.party,
                resource: read.resource.as_ref(),
            };
            let facts = TokenFacts {
                expires_at: read.token.as_ref().and_then(|r| r.access_expires_ms),
                revocable: read
                    .resource
                    .as_ref()
                    .is_some_and(|r| r.upstream.revocation_endpoint.is_some()),
            };
            // U66
            let admitted = admit(&asked, allowed.as_ref(), &held, (read.open, facts), now)?;
            let row = read.token.as_ref().ok_or(Refusal::NotConnected)?;
            if !refreshed && row.refreshable && refresh_first(row.access_expires_ms, now) {
                self.refresh(db, keys, req.connection, now).await?;
                refreshed = true;
                read = self.read(db, keys, req.connection).await?;
                continue;
            }
            if row.access_expires_ms.is_some_and(|e| e <= now) {
                return Err(Refusal::NeedsReconnect.into());
            }
            return self
                .record(
                    db,
                    keys,
                    (c, row),
                    (req, &digest.0),
                    (caller, allowed.as_ref()),
                    admitted,
                    now,
                )
                .await;
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the release record names everything the decision rested on"
    )]
    async fn record(
        &self,
        db: &Pool,
        keys: &Keys<'_>,
        (c, row): (&ConnectionRow, &TokenSetRow),
        (req, intent): (&ReleaseRequest, &[u8; 32]),
        (caller, allowed): (Option<&str>, Option<&crate::domain::release::Allowed>),
        admitted: Admitted,
        now: u64,
    ) -> Result<Released, VaultError> {
        let pep = caller.ok_or(Refusal::Unauthenticated)?;
        let a = allowed.ok_or(Refusal::NoExercise)?;
        let mut t = keys.begin(db).await?;
        let set = open(&mut t, keys, c, row)
            .await?
            .ok_or(Refusal::NotConnected)?;
        let tier = match admitted.tier {
            Tier::Ct0 => 0,
            Tier::Ct1 => 1,
            Tier::Ct2 => 2,
            Tier::Ct3 => 3,
        };
        // G59, EI-26, Ek B 4504
        let first = t
            .insert_vault_release(&NewRelease {
                domain: &req.domain,
                exercise: &req.exercise,
                position: a.position,
                intent,
                actor: a.actor,
                connection: c.id,
                token_set_version: row.version,
                pep,
                path: admitted.path.name(),
                tier,
                use_until_ms: admitted.use_until,
                now_ms: now,
            })
            .await?;
        if !first {
            return Err(Refusal::AlreadyUsed.into());
        }
        audit(
            &mut t,
            match admitted.path {
                Path::Executor => "vault.released.executor",
                Path::Agent => "vault.released.agent",
            },
            pep,
            &c.id,
            &b64url_encode(&req.exercise),
        )
        .await?;
        t.commit().await?;
        Ok(Released {
            token: set.access_token,
            token_type: set.token_type,
            admitted,
        })
    }

    /// Refreshes the connection's tokens under its lease (OP-154 m.3 (t)). A refused refresh
    /// marks the connection `needs_reconnect`, shreds its tokens and tells the person through
    /// Relay; nothing falls back. Another holder's running lease is left alone.
    ///
    /// # Errors
    /// [`VaultError::Unavailable`] when the upstream or a key did not answer.
    pub async fn refresh(
        &self,
        db: &Pool,
        keys: &Keys<'_>,
        connection: [u8; 16],
        now: u64,
    ) -> Result<(), VaultError> {
        let mut t = keys.begin(db).await?;
        if !t
            .lease_vault_refresh(connection, now, now.saturating_add(REFRESH_LEASE_MS))
            .await?
        {
            t.commit().await?;
            return Ok(());
        }
        let c = t
            .vault_connection(connection)
            .await?
            .ok_or(VaultError::NoConnection)?;
        let resource = enabled(t.vault_resource(&c.resource).await?).map(|(_, r)| r);
        let row = t.vault_token_set(connection).await?;
        let set = match &row {
            Some(row) => open(&mut t, keys, &c, row).await?,
            None => None,
        };
        t.commit().await?;
        let (Some(resource), Some(set)) = (resource, set) else {
            return self.lapse(db, keys, &c, now).await;
        };
        let Some(refresh_token) = set.refresh_token.clone() else {
            return self.lapse(db, keys, &c, now).await;
        };
        let secret = self
            .secrets
            .secret(&resource.client_secret_ref)
            .await
            .map_err(|_| VaultError::Unavailable)?;
        let url = resource
            .upstream
            .refresh_endpoint
            .as_deref()
            .unwrap_or(&resource.upstream.token_endpoint);
        let form = refresh_form(
            (&resource.client_id, secret.expose()),
            refresh_token.expose(),
        );
        let Ok((status, body)) = self.http.post_form(url, &form).await else {
            let mut t = keys.begin(db).await?;
            t.set_vault_connection(connection, "active", None, now)
                .await?;
            t.commit().await?;
            return Err(VaultError::Unavailable);
        };
        let next = TokenSet::from_answer(
            (status, &body),
            &resource.upstream,
            Some(&refresh_token),
            now,
        );
        match next {
            Ok(next) => {
                let mut t = keys.begin(db).await?;
                seal_in(&mut t, keys, &c, &next, now).await?;
                t.set_vault_connection(connection, "active", None, now)
                    .await?;
                audit(&mut t, "vault.refreshed", "vault", &c.id, "refresh").await?;
                t.commit().await?;
                Ok(())
            }
            Err(TokenError::Refused | TokenError::Malformed) => self.lapse(db, keys, &c, now).await,
        }
    }

    /// The connection lapsed: `needs_reconnect`, its tokens shredded, the person told through
    /// Relay (OP-154 m.3 (t)).
    async fn lapse(
        &self,
        db: &Pool,
        keys: &Keys<'_>,
        c: &ConnectionRow,
        now: u64,
    ) -> Result<(), VaultError> {
        let mut t = keys.begin(db).await?;
        if t.set_vault_connection(c.id, "needs_reconnect", None, now)
            .await?
        {
            t.shred_vault_token_sets(c.id, now).await?;
            audit(&mut t, "vault.needs_reconnect", "vault", &c.id, "refresh").await?;
            let name = enabled(t.vault_resource(&c.resource).await?)
                .map_or_else(|| c.resource.clone(), |(_, r)| r.upstream.display_name);
            prompt(&mut t, keys, c.subject, &name, now).await?;
        }
        t.commit().await?;
        Ok(())
    }

    /// Refreshes every active connection of the realm whose token expires within the refresh
    /// window, at most `limit`; returns how many it tried.
    ///
    /// # Errors
    /// [`VaultError::Unavailable`] when the store did not answer.
    pub async fn refresh_due(
        &self,
        db: &Pool,
        keys: &Keys<'_>,
        now: u64,
        limit: u32,
    ) -> Result<usize, VaultError> {
        let mut t = keys.begin(db).await?;
        let due = t
            .vault_refresh_due(
                now.saturating_add(crate::domain::release::REFRESH_AHEAD_MS),
                limit,
            )
            .await?;
        t.commit().await?;
        for c in &due {
            if let Err(e) = self.refresh(db, keys, *c, now).await {
                tracing::warn!(error = %e, "vault refresh failed");
            }
        }
        Ok(due.len())
    }

    /// `POST /v1/account/vault/connections` (AS-M15, §8.8, §8.9): opens a pending connection
    /// and returns it with the upstream's authorization URL, only after the person's AAS for
    /// `ask.client_id` (a live consent record of theirs for that client).
    ///
    /// # Errors
    /// [`VaultError`].
    pub async fn start(
        &self,
        db: &Pool,
        keys: &Keys<'_>,
        (subject, device): ([u8; 16], &[u8; 32]),
        ask: &Connect<'_>,
        now: u64,
    ) -> Result<([u8; 16], String), VaultError> {
        let mut t = keys.begin(db).await?;
        let (version, resource) =
            enabled(t.vault_resource(ask.resource).await?).ok_or(VaultError::NoResource)?;
        let scopes: Vec<String> = match &ask.scopes {
            Some(s) if s.iter().all(|x| resource.scopes.contains(x)) && s.len() <= 64 => s.clone(),
            Some(_) => return Err(VaultError::Scope),
            None => resource.scopes.iter().cloned().collect(),
        };
        // AS-M15, OP-154 m.8 (d)
        if t.vault_client_consent(subject, ask.client_id)
            .await?
            .is_none()
        {
            return Err(VaultError::ConsentRequired);
        }
        let party = access_store::idp::subject_party(&mut t, &subject)
            .await?
            .ok_or(VaultError::NoParty)?;
        let id = t
            .insert_vault_connection(&NewConnection {
                subject,
                party,
                resource: &resource.name,
                resource_version: version,
                client_id: ask.client_id,
                scopes: &scopes,
                now_ms: now,
            })
            .await?;
        let mut r = [0; 64];
        self.random
            .fill(&mut r)
            .map_err(|_| VaultError::Unavailable)?;
        let (s, v) = r.split_at(32);
        let state = b64url_encode(s);
        let verifier = b64url_encode(v);
        t.insert_vault_attempt(
            (&hash(&state), device),
            id,
            &verifier,
            (now, now.saturating_add(ATTEMPT_TTL_MS)),
        )
        .await?;
        audit(
            &mut t,
            "vault.connect_started",
            &b64url_encode(&subject),
            &id,
            ask.client_id,
        )
        .await?;
        t.commit().await?;
        let url = authorization_url(
            &resource.upstream,
            (&resource.client_id, ask.redirect_uri),
            &scopes,
            (&state, &pkce_challenge(&verifier)),
        );
        Ok((id, url))
    }

    /// The upstream's redirect back: the attempt this browser opened is used once, the code
    /// exchanged in the back end, and the `TokenSet` sealed under the person's key.
    ///
    /// # Errors
    /// [`VaultError`].
    pub async fn finish(
        &self,
        db: &Pool,
        keys: &Keys<'_>,
        (subject, device): ([u8; 16], &[u8; 32]),
        (code, state): (&str, &str),
        redirect_uri: &str,
        now: u64,
    ) -> Result<[u8; 16], VaultError> {
        let mut t = keys.begin(db).await?;
        let (id, verifier) = t
            .take_vault_attempt(&hash(state), device, now)
            .await?
            .ok_or(VaultError::FlowGone)?;
        let c = t
            .vault_connection(id)
            .await?
            .filter(|c| c.subject == subject && c.status == "pending")
            .ok_or(VaultError::FlowGone)?;
        let resource = enabled(t.vault_resource_at(&c.resource, c.resource_version).await?)
            .map(|(_, r)| r)
            .ok_or(VaultError::NoResource)?;
        t.commit().await?;
        let secret = self
            .secrets
            .secret(&resource.client_secret_ref)
            .await
            .map_err(|_| VaultError::Unavailable)?;
        let form = code_form(
            &resource.upstream,
            (&resource.client_id, secret.expose()),
            redirect_uri,
            code,
            &verifier,
        );
        let answer = self
            .http
            .post_form(&resource.upstream.token_endpoint, &form)
            .await
            .map_err(|_| VaultError::Unavailable)?;
        let set = TokenSet::from_answer((answer.0, &answer.1), &resource.upstream, None, now);
        let mut t = keys.begin(db).await?;
        let Ok(set) = set else {
            t.set_vault_connection(id, "disconnected", None, now)
                .await?;
            audit(&mut t, "vault.connect_refused", "upstream", &id, "connect").await?;
            t.commit().await?;
            return Err(VaultError::Upstream);
        };
        seal_in(&mut t, keys, &c, &set, now).await?;
        let granted: Option<Vec<String>> = set.scope.as_ref().map(|s| {
            s.split([' ', ','])
                .filter(|x| !x.is_empty())
                .take(64)
                .map(String::from)
                .collect()
        });
        t.set_vault_connection(id, "active", granted.as_deref(), now)
            .await?;
        for old in t.vault_connections_of(subject).await? {
            let same = old.id != id
                && old.resource == c.resource
                && old.client_id == c.client_id
                && old.status == "needs_reconnect";
            if same
                && t.set_vault_connection(old.id, "disconnected", None, now)
                    .await?
            {
                t.shred_vault_token_sets(old.id, now).await?;
            }
        }
        audit(
            &mut t,
            "vault.connected",
            &b64url_encode(&subject),
            &id,
            &c.client_id,
        )
        .await?;
        t.commit().await?;
        Ok(id)
    }

    /// The upstream answered with an error: the attempt is used and its pending connection
    /// ends; nothing was connected.
    ///
    /// # Errors
    /// [`VaultError`].
    pub async fn abandon(
        &self,
        db: &Pool,
        keys: &Keys<'_>,
        device: &[u8; 32],
        state: &str,
        now: u64,
    ) -> Result<(), VaultError> {
        let mut t = keys.begin(db).await?;
        if let Some((id, _)) = t.take_vault_attempt(&hash(state), device, now).await? {
            t.set_vault_connection(id, "disconnected", None, now)
                .await?;
            audit(&mut t, "vault.connect_refused", "upstream", &id, "connect").await?;
        }
        t.commit().await?;
        Ok(())
    }

    /// `DELETE /v1/account/vault/connections/{connection}`: the connection ends, its tokens are
    /// shredded (OP-73) and, where the upstream has an RFC 7009 endpoint, revoked there.
    ///
    /// # Errors
    /// [`VaultError`].
    pub async fn disconnect(
        &self,
        db: &Pool,
        keys: &Keys<'_>,
        subject: [u8; 16],
        connection: [u8; 16],
        now: u64,
    ) -> Result<(), VaultError> {
        let mut t = keys.begin(db).await?;
        let c = t
            .vault_connection(connection)
            .await?
            .filter(|c| c.subject == subject && c.status != "disconnected")
            .ok_or(VaultError::NoConnection)?;
        let resource = enabled(t.vault_resource(&c.resource).await?).map(|(_, r)| r);
        let set = match t.vault_token_set(connection).await? {
            Some(row) => open(&mut t, keys, &c, &row).await?,
            None => None,
        };
        t.set_vault_connection(connection, "disconnected", None, now)
            .await?;
        t.shred_vault_token_sets(connection, now).await?;
        audit(
            &mut t,
            "vault.disconnected",
            &b64url_encode(&subject),
            &c.id,
            "disconnect",
        )
        .await?;
        t.commit().await?;
        if let (Some(r), Some(set)) = (resource, set)
            && let Some(url) = &r.upstream.revocation_endpoint
            && let Ok(secret) = self.secrets.secret(&r.client_secret_ref).await
        {
            let form = revoke_form((&r.client_id, secret.expose()), &set);
            if self.http.post_form(url, &form).await.is_err() {
                tracing::warn!("upstream revocation did not answer");
            }
        }
        Ok(())
    }

    /// The person's connections, each with its upstream and newest releases; never a token
    /// (§8.8, §8.9: "used by which agent under which delegation").
    ///
    /// # Errors
    /// [`VaultError::Unavailable`].
    pub async fn connections(
        &self,
        db: &Pool,
        keys: &Keys<'_>,
        subject: [u8; 16],
    ) -> Result<Vec<ConnectionView>, VaultError> {
        let mut t = keys.begin(db).await?;
        let rows = t.vault_connections_of(subject).await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let upstream = enabled(t.vault_resource(&row.resource).await?)
                .map(|(_, r)| r.upstream.display_name);
            let releases = t.vault_releases_of(row.id, VIEW_RELEASES).await?;
            out.push(ConnectionView {
                row,
                upstream,
                releases,
            });
        }
        t.commit().await?;
        Ok(out)
    }
}

/// Tells the person through Relay that a connection must be connected again (OP-154 m.3 (t)).
async fn prompt(
    t: &mut TenantTx,
    keys: &Keys<'_>,
    subject: [u8; 16],
    name: &str,
    now: u64,
) -> Result<(), VaultError> {
    use access_identity_account::adapters::system::{SystemClock, SystemEntropy};
    use access_identity_account::notify::message::{Address, Body, Message, Prompt};
    use access_identity_account::notify::notifier::OutboxNotifier;
    use access_identity_account::notify::ports::Notifier as _;
    let Some((kind, stored)) = t.contact(subject).await? else {
        return Ok(());
    };
    let Some(value) =
        access_identity_account::app::vault::reveal_with_kek(t, keys.kek, subject, &stored).await?
    else {
        return Ok(());
    };
    let to = if kind == "phone" {
        Address::Phone(value)
    } else {
        Address::Email(value)
    };
    let valid_since_ms = match to {
        Address::Email(_) => Some(
            t.mailbox_since(subject)
                .await?
                .and_then(|v| u64::try_from(v).ok())
                .unwrap_or(1)
                .max(1),
        ),
        Address::Phone(_) => None,
    };
    let realm = keys.realm();
    let name: String = name.chars().take(200).collect();
    OutboxNotifier::new(&realm, &SystemEntropy, &SystemClock)
        .notify(
            t,
            &Message {
                subject,
                to,
                locale: None,
                valid_since_ms,
                body: Body::Prompt {
                    prompt: Prompt::AgentConnectionNeedsReconnect,
                    link: Secret::new(format!("{}/account", keys.issuer)),
                    name,
                    expires_at_ms: now.saturating_add(PROMPT_TTL_MS),
                },
            },
        )
        .await
        .map_err(|_| VaultError::Unavailable)?;
    Ok(())
}
