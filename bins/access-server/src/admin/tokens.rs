//! Management read tokens in this process (TN-130, TN-27, OP-151 m.3 (c)): the environment AS's RFC
//! 8693 exchange reads the authority plane's live Instance keys through [`PlaneHolders`]; the
//! management API verifies a presented token with [`ManagementTokens`]: the issuing environment's
//! signature, the DPoP proof for this method and URI by the bound key, used once, and that
//! nothing it was issued under has ended: the Instance is still live in the environment's domain, and
//! a console session's token needs that session live and its account's `session_epoch`
//! unchanged (OP-21). The console BFF's tokens are issued here too, bound to the BFF's DPoP key
//! of the session and naming the session's device Instance (TN-128).

use access_crypto::AwsLcBackend;
use access_crypto::dpop::replay_key;
use access_crypto::jose::JwsAlg;
use access_http::api::domain::Surface as ApiSurface;
use access_http::api::ports::{Presented, ReadToken, ReadTokens, Unavailable};
use access_http::console::ports::{ConsoleSession, IssuedRead, SessionInstance};
use access_identity_oauth::adapters::dpop::PgReplayCache;
use access_identity_oauth::adapters::{PgDirectory, SignerKeys};
use access_identity_oauth::domain::dpop::DpopProfile;
use access_identity_oauth::domain::jwt::environment_key_set;
use access_identity_oauth::domain::management::{
    CONSOLE_CLIENT, READ_TTL_MS, ReadClaims, ReadFacts, Surface, read_claims, read_token_claims,
    unverified_audience,
};
use access_identity_oauth::domain::tokens::ACCESS_TYP;
use access_identity_oauth::ports::dpop::ReplayCache as _;
use access_identity_oauth::ports::oauth::{Held, ManagementHolders, TokenSigner as _};
use access_identity_oauth::ports::{Directory as _, EnvironmentEntry};
use access_identity_session::domain::console::ABSOLUTE_MS;
use access_kernel::digest::Digest;
use access_kernel::json::b64url_encode;
use access_kernel::verify::cose::PublicKey;
use access_kernel::verify::dpop::{ProofRules, verify_proof};
use access_store::Pool;
use access_store::console::{self, ConsoleSessionRow};
use access_store::identity::TenantTx;
use suiss_crypto::digest::sha256;
use suiss_crypto::secret::Secret;

use super::WallClock;
use super::environment::LiveKeys;
use access_http::api::ports::Clock as _;

const DAY_MS: u64 = 86_400_000;

/// The authority plane's live Instance keys, for the environment AS's management read token exchange,
/// and the platform environment's slug (`suiss.platform_environment`, OP-151 m.2 M2): only its Instances get
/// `access-admin:platform` tokens; without one none do (MD-8).
pub(crate) struct PlaneHolders<P>(pub(crate) P, pub(crate) Option<String>);

impl<P: LiveKeys + 'static> ManagementHolders for PlaneHolders<P> {
    fn instance_key(&self, domain: [u8; 32], kid: [u8; 32]) -> Held<'_, Option<PublicKey>> {
        Box::pin(async move {
            self.0
                .live_key(Digest(domain), kid)
                .await
                .map_err(|_| access_identity_oauth::ports::Unavailable)
        })
    }

    fn platform(&self, environment: &EnvironmentEntry) -> Held<'_, bool> {
        let yes = self.1.as_deref() == Some(environment.slug.as_str());
        Box::pin(async move { Ok(yes) })
    }
}

/// Verifies and issues management read tokens over the environment directory, the identity signer,
/// the application pool and the authority plane's keys.
pub(crate) struct ManagementTokens<P> {
    pub(crate) directory: PgDirectory,
    pub(crate) signer: SignerKeys,
    pub(crate) app: Pool,
    pub(crate) plane: P,
    pub(crate) dpop: DpopProfile,
    /// The platform environment's slug, whose tokens read the platform surface (OP-151 m.2 M2).
    pub(crate) platform: Option<String>,
}

fn down<E>(_: E) -> Unavailable {
    Unavailable
}

/// What a token was issued under, as it stands now.
enum Standing {
    Live,
    Ended,
}

impl<P: LiveKeys> ManagementTokens<P> {
    async fn environment_of(
        &self,
        surface: &Surface,
    ) -> Result<Option<EnvironmentEntry>, Unavailable> {
        match surface {
            Surface::Environment(slug) => self.directory.by_slug(slug).await.map_err(down),
            // OP-151 m.2 M2
            Surface::Platform => match self.platform.as_deref() {
                Some(slug) => self.directory.by_slug(slug).await.map_err(down),
                None => Ok(None),
            },
        }
    }

    async fn governing(
        &self,
        environment: &EnvironmentEntry,
    ) -> Result<Option<Digest>, Unavailable> {
        let mut t = TenantTx::begin(&self.app, environment.tenant, environment.environment)
            .await
            .map_err(down)?;
        let g = access_store::idp::governance(&mut t).await.map_err(down)?;
        t.commit().await.map_err(down)?;
        Ok(g.map(|g| Digest(*g.domain.as_bytes())))
    }

    async fn epoch(
        &self,
        environment: &EnvironmentEntry,
        subject: [u8; 16],
    ) -> Result<Option<i64>, Unavailable> {
        let mut t = TenantTx::begin(&self.app, environment.tenant, environment.environment)
            .await
            .map_err(down)?;
        let s = t.subject(subject, false).await.map_err(down)?;
        t.commit().await.map_err(down)?;
        Ok(s.filter(|s| s.status == "active").map(|s| s.session_epoch))
    }

    /// OP-21, TN-130: the Instance is live, and a console session's token needs that session
    /// live, within its absolute end, holding that Instance, its account's epoch unchanged.
    async fn standing(
        &self,
        environment: &EnvironmentEntry,
        c: &ReadClaims,
        now: u64,
    ) -> Result<Standing, Unavailable> {
        let Some(domain) = self.governing(environment).await? else {
            return Ok(Standing::Ended);
        };
        if self.plane.live_key(domain, c.instance).await?.is_none() {
            return Ok(Standing::Ended);
        }
        let Some(sid) = c.console_session else {
            return Ok(Standing::Live);
        };
        let Some(s) = console::by_id(&self.app, &sid).await.map_err(down)? else {
            return Ok(Standing::Ended);
        };
        let held = s
            .instance
            .as_ref()
            .is_some_and(|(kid, _)| *kid == c.instance);
        let open = s.ended_ms.is_none() && s.created_ms.saturating_add(ABSOLUTE_MS) > now;
        // OP-159 m.47 (g), TN-142
        if open && s.environment != environment.environment {
            let administered = self.administered(&s, environment, c.instance).await?;
            let epoch = self.epoch_of(s.tenant, s.environment, s.subject).await?;
            if !administered || c.rev.is_none() || epoch != c.rev {
                return Ok(Standing::Ended);
            }
            return Ok(Standing::Live);
        }
        let live = open && s.environment == environment.environment && held;
        if !live || c.rev.is_none() || self.epoch(environment, s.subject).await? != c.rev {
            return Ok(Standing::Ended);
        }
        Ok(Standing::Live)
    }

    /// The account's `session_epoch` in `(tenant, environment)` while it is active.
    async fn epoch_of(
        &self,
        tenant: access_store::identity::TenantId,
        environment: access_store::identity::EnvironmentId,
        subject: [u8; 16],
    ) -> Result<Option<i64>, Unavailable> {
        let mut t = TenantTx::begin(&self.app, tenant, environment)
            .await
            .map_err(down)?;
        let s = t.subject(subject, false).await.map_err(down)?;
        t.commit().await.map_err(down)?;
        Ok(s.filter(|s| s.status == "active").map(|s| s.session_epoch))
    }

    /// Whether the console session `s` holds `instance` in the domain of `environment`, an
    /// environment its management environment administers, with a `tenant_administration` line
    /// there that has not ended (OP-159 m.47 (f), (g), TN-142).
    async fn administered(
        &self,
        s: &ConsoleSessionRow,
        environment: &EnvironmentEntry,
        instance: [u8; 32],
    ) -> Result<bool, Unavailable> {
        if environment.tenant != s.tenant {
            return Ok(false);
        }
        let Some(domain) = self.governing(environment).await? else {
            return Ok(false);
        };
        let d = access_store::scope::DomainId::from_bytes(domain.0);
        let held = access_store::tenant_admin::session_instances(&self.app, &s.id)
            .await
            .map_err(down)?
            .into_iter()
            .find(|i| i.domain == d && i.kid == instance);
        let Some(held) = held else {
            return Ok(false);
        };
        let mut t = TenantTx::begin_tenant(&self.app, s.tenant)
            .await
            .map_err(down)?;
        let consumers = access_store::environment_binding::consumed_by(&mut t, &d)
            .await
            .map_err(down)?;
        t.commit().await.map_err(down)?;
        if !consumers.contains(&s.environment) {
            return Ok(false);
        }
        let mut t = TenantTx::begin(&self.app, s.tenant, s.environment)
            .await
            .map_err(down)?;
        let line = access_store::tenant_admin::line_of_party(&mut t, &d, &held.party)
            .await
            .map_err(down)?;
        t.commit().await.map_err(down)?;
        Ok(
            line.is_some_and(|(l, admin)| admin.live && l.ended_ms.is_none())
                && self.plane.live_key(domain, instance).await?.is_some(),
        )
    }

    /// A read token on the environment surface of `slug`, an environment the console session
    /// `row`'s management environment administers, signed by that environment's own key for the
    /// session's Instance in its domain and bound to the BFF's DPoP key `jkt` (OP-159 m.47 (g),
    /// TN-142); `sub` is the administrator's alias there, never an account of it (TNI-14).
    pub(crate) async fn issue_administered(
        &self,
        row: &ConsoleSessionRow,
        slug: &str,
        instance: &SessionInstance,
        jkt: [u8; 32],
    ) -> Result<Option<IssuedRead>, Unavailable> {
        let now = WallClock.now_ms()?;
        let surface = Surface::Environment(String::from(slug));
        let Some(environment) = self.environment_of(&surface).await? else {
            return Ok(None);
        };
        if row.ended_ms.is_some()
            || row.created_ms.saturating_add(ABSOLUTE_MS) <= now
            || !self.administered(row, &environment, instance.kid).await?
        {
            return Ok(None);
        }
        let Some(rev) = self
            .epoch_of(row.tenant, row.environment, row.subject)
            .await?
        else {
            return Ok(None);
        };
        let alg = self.alg(&environment).await?;
        let jti = b64url_encode(&access_crypto::random::bytes::<16>().map_err(down)?);
        let mut alias = environment.environment.as_bytes().to_vec();
        alias.extend_from_slice(&row.subject);
        let sub = format!(
            "adm_{}",
            b64url_encode(
                &suiss_crypto::digest::context_digest("access/tenant-admin-sub/v1", &alias).0[..16]
            )
        );
        let claims = read_token_claims(
            &ReadFacts {
                issuer: environment.issuer.as_str(),
                surface: &surface,
                sub: &sub,
                client_id: CONSOLE_CLIENT,
                instance: instance.kid,
                jkt,
                console_session: Some(row.id),
                rev: Some(rev),
                now_ms: now,
                ttl_ms: READ_TTL_MS,
            },
            &jti,
        );
        let token = self
            .signer
            .sign(environment.environment, alg, ACCESS_TYP, &claims, now)
            .await
            .map_err(down)?;
        Ok(Some(IssuedRead {
            token: Secret::new(token.into_bytes()),
            expires_ms: now.saturating_add(READ_TTL_MS),
        }))
    }

    /// A read token on `surface` for the console session `row` and its device Instance, bound
    /// to the BFF's DPoP key `jkt` of the session; `None` when the session, its account or its
    /// Instance is not live, or when `surface` is the platform's and the session is not in the
    /// platform environment (OP-151 m.2 M2, OP-159 m.41).
    pub(crate) async fn issue_console(
        &self,
        row: &ConsoleSessionRow,
        instance: &SessionInstance,
        jkt: [u8; 32],
        surface: ApiSurface,
    ) -> Result<Option<IssuedRead>, Unavailable> {
        let now = WallClock.now_ms()?;
        if row.ended_ms.is_some()
            || row.created_ms.saturating_add(ABSOLUTE_MS) <= now
            || row.instance.as_ref().map(|(kid, _)| kid) != Some(&instance.kid)
        {
            return Ok(None);
        }
        // OP-159 m.41, TN-119
        let surface = match surface {
            ApiSurface::Environment => Surface::Environment(row.slug.clone()),
            ApiSurface::Platform => Surface::Platform,
        };
        let Some(environment) = self.environment_of(&surface).await? else {
            return Ok(None);
        };
        if environment.environment != row.environment {
            return Ok(None);
        }
        let Some(rev) = self.epoch(&environment, row.subject).await? else {
            return Ok(None);
        };
        if self
            .plane
            .live_key(Digest(row.domain), instance.kid)
            .await?
            .is_none()
        {
            return Ok(None);
        }
        let alg = self.alg(&environment).await?;
        let jti = b64url_encode(&access_crypto::random::bytes::<16>().map_err(down)?);
        let claims = read_token_claims(
            &ReadFacts {
                issuer: environment.issuer.as_str(),
                surface: &surface,
                sub: &row.account,
                client_id: CONSOLE_CLIENT,
                instance: instance.kid,
                jkt,
                console_session: Some(row.id),
                rev: Some(rev),
                now_ms: now,
                ttl_ms: READ_TTL_MS,
            },
            &jti,
        );
        let token = self
            .signer
            .sign(environment.environment, alg, ACCESS_TYP, &claims, now)
            .await
            .map_err(down)?;
        Ok(Some(IssuedRead {
            token: Secret::new(token.into_bytes()),
            expires_ms: now.saturating_add(READ_TTL_MS),
        }))
    }

    async fn alg(&self, environment: &EnvironmentEntry) -> Result<JwsAlg, Unavailable> {
        let mut t = TenantTx::begin(&self.app, environment.tenant, environment.environment)
            .await
            .map_err(down)?;
        let s = access_store::idp::settings(&mut t).await.map_err(down)?;
        t.commit().await.map_err(down)?;
        Ok(match s.as_ref().map(|s| s.jose_alg.as_str()) {
            Some("Ed25519") => JwsAlg::Ed25519,
            _ => JwsAlg::Es256,
        })
    }
}

/// The console BFF's read tokens (TN-128, TN-130): issued for a session's device Instance.
pub(crate) struct ConsoleGrants<P>(pub(crate) std::sync::Arc<ManagementTokens<P>>);

impl<P: LiveKeys + 'static> access_http::console::ports::ReadGrants for ConsoleGrants<P> {
    async fn issue(
        &self,
        session: &ConsoleSession,
        instance: &SessionInstance,
        jkt: [u8; 32],
        surface: ApiSurface,
    ) -> Result<Option<IssuedRead>, Unavailable> {
        let Some(row) = console::by_id(&self.0.app, &session.id)
            .await
            .map_err(down)?
        else {
            return Ok(None);
        };
        self.0.issue_console(&row, instance, jkt, surface).await
    }

    async fn issue_in(
        &self,
        session: &ConsoleSession,
        environment: &str,
        instance: &SessionInstance,
        jkt: [u8; 32],
    ) -> Result<Option<IssuedRead>, Unavailable> {
        let Some(row) = console::by_id(&self.0.app, &session.id)
            .await
            .map_err(down)?
        else {
            return Ok(None);
        };
        self.0
            .issue_administered(&row, environment, instance, jkt)
            .await
    }
}

impl<P: LiveKeys + 'static> ReadTokens for ManagementTokens<P> {
    async fn verify(&self, p: Presented<'_>) -> Result<Option<ReadToken>, Unavailable> {
        let Some(surface) = unverified_audience(p.token).and_then(|a| Surface::of(&a)) else {
            return Ok(None);
        };
        let Some(environment) = self.environment_of(&surface).await? else {
            return Ok(None);
        };
        let jwks = self
            .signer
            .jwks(environment.environment)
            .await
            .map_err(down)?;
        let keys = environment_key_set(jwks.as_bytes()).map_err(down)?;
        let Ok(claims) = read_claims(p.token, &keys, environment.issuer.as_str()) else {
            return Ok(None);
        };
        // TN-27, RFC 9449 §7
        let [proof] = p.proofs else {
            return Ok(None);
        };
        let now = WallClock.now_ms()?;
        let rules = ProofRules {
            method: p.method,
            uri: p.uri,
            allowed: self.dpop.allowed(),
            now,
            lifetime_ms: self.dpop.lifetime_ms(),
            skew_ms: self.dpop.skew_ms(),
            access_token: Some(p.token),
            bound_jkt: Some(&claims.jkt),
        };
        let Ok(proof) = verify_proof(&AwsLcBackend, proof, &rules) else {
            return Ok(None);
        };
        let day = u32::try_from(proof.iat / DAY_MS).map_err(down)?;
        let first = PgReplayCache::new(
            self.app.clone(),
            environment.tenant,
            environment.environment,
        )
        .first_use(day, replay_key(&proof.htm, &proof.htu, &proof.jti))
        .await
        .map_err(down)?;
        if !first {
            return Ok(None);
        }
        if matches!(
            self.standing(&environment, &claims, now).await?,
            Standing::Ended
        ) {
            return Ok(None);
        }
        Ok(Some(ReadToken {
            audience: claims.aud,
            scopes: claims.scopes,
            subject: claims.sub,
            issued_at_ms: claims.iat_ms,
            expires_at_ms: claims.exp_ms,
            id: sha256(p.token.as_bytes()),
        }))
    }
}
