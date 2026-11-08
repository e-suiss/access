//! Management read tokens in this process (TN-130, TN-27, OP-151 m.3 (c)): the realm AS's RFC
//! 8693 exchange reads the authority plane's live Instance keys through [`PlaneHolders`]; the
//! management API verifies a presented token with [`ManagementTokens`]: the issuing realm's
//! signature, the DPoP proof for this method and URI by the bound key, used once, and that
//! nothing it was issued under has ended: the Instance is still live in the realm's domain, and
//! a console session's token needs that session live and its account's `session_epoch`
//! unchanged (OP-21). The console BFF's tokens are issued here too, bound to the BFF's DPoP key
//! of the session and naming the session's device Instance (TN-128).

use access_crypto::AwsLcBackend;
use access_crypto::dpop::replay_key;
use access_crypto::jose::JwsAlg;
use access_http::api::ports::{Presented, ReadToken, ReadTokens, Unavailable};
use access_http::console::ports::{ConsoleSession, IssuedRead, SessionInstance};
use access_identity_oauth::adapters::dpop::PgReplayCache;
use access_identity_oauth::adapters::{PgDirectory, SignerKeys};
use access_identity_oauth::domain::dpop::DpopProfile;
use access_identity_oauth::domain::jwt::realm_key_set;
use access_identity_oauth::domain::management::{
    CONSOLE_CLIENT, READ_TTL_MS, ReadClaims, ReadFacts, Surface, read_claims, read_token_claims,
    unverified_audience,
};
use access_identity_oauth::domain::tokens::ACCESS_TYP;
use access_identity_oauth::ports::dpop::ReplayCache as _;
use access_identity_oauth::ports::oauth::{Held, ManagementHolders, TokenSigner as _};
use access_identity_oauth::ports::{Directory as _, RealmEntry};
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
use super::realm::LiveKeys;
use access_http::api::ports::Clock as _;

const DAY_MS: u64 = 86_400_000;

/// The authority plane's live Instance keys, for the realm AS's management read token exchange,
/// and the platform realm's slug (`suiss.platform_realm`, OP-151 m.2 M2): only its Instances get
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

    fn platform(&self, realm: &RealmEntry) -> Held<'_, bool> {
        let yes = self.1.as_deref() == Some(realm.slug.as_str());
        Box::pin(async move { Ok(yes) })
    }
}

/// Verifies and issues management read tokens over the realm directory, the identity signer,
/// the application pool and the authority plane's keys.
pub(crate) struct ManagementTokens<P> {
    pub(crate) directory: PgDirectory,
    pub(crate) signer: SignerKeys,
    pub(crate) app: Pool,
    pub(crate) plane: P,
    pub(crate) dpop: DpopProfile,
    /// The platform realm's slug, whose tokens read the platform surface (OP-151 m.2 M2).
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
    async fn realm_of(&self, surface: &Surface) -> Result<Option<RealmEntry>, Unavailable> {
        match surface {
            Surface::Realm(slug) => self.directory.by_slug(slug).await.map_err(down),
            // OP-151 m.2 M2
            Surface::Platform => match self.platform.as_deref() {
                Some(slug) => self.directory.by_slug(slug).await.map_err(down),
                None => Ok(None),
            },
        }
    }

    async fn governing(&self, realm: &RealmEntry) -> Result<Option<Digest>, Unavailable> {
        let mut t = TenantTx::begin(&self.app, realm.tenant, realm.realm)
            .await
            .map_err(down)?;
        let g = access_store::idp::governance(&mut t).await.map_err(down)?;
        t.commit().await.map_err(down)?;
        Ok(g.map(|g| Digest(*g.domain.as_bytes())))
    }

    async fn epoch(
        &self,
        realm: &RealmEntry,
        subject: [u8; 16],
    ) -> Result<Option<i64>, Unavailable> {
        let mut t = TenantTx::begin(&self.app, realm.tenant, realm.realm)
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
        realm: &RealmEntry,
        c: &ReadClaims,
        now: u64,
    ) -> Result<Standing, Unavailable> {
        let Some(domain) = self.governing(realm).await? else {
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
        let live = s.ended_ms.is_none()
            && s.created_ms.saturating_add(ABSOLUTE_MS) > now
            && s.realm == realm.realm
            && held;
        if !live || c.rev.is_none() || self.epoch(realm, s.subject).await? != c.rev {
            return Ok(Standing::Ended);
        }
        Ok(Standing::Live)
    }

    /// A read token for the console session `row` and its device Instance, bound to the BFF's
    /// DPoP key `jkt` of the session; `None` when the session, its account or its Instance is
    /// not live.
    pub(crate) async fn issue_console(
        &self,
        row: &ConsoleSessionRow,
        instance: &SessionInstance,
        jkt: [u8; 32],
    ) -> Result<Option<IssuedRead>, Unavailable> {
        let now = WallClock.now_ms()?;
        if row.ended_ms.is_some()
            || row.created_ms.saturating_add(ABSOLUTE_MS) <= now
            || row.instance.as_ref().map(|(kid, _)| kid) != Some(&instance.kid)
        {
            return Ok(None);
        }
        let surface = Surface::Realm(row.slug.clone());
        let Some(realm) = self.realm_of(&surface).await? else {
            return Ok(None);
        };
        if realm.realm != row.realm {
            return Ok(None);
        }
        let Some(rev) = self.epoch(&realm, row.subject).await? else {
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
        let alg = self.alg(&realm).await?;
        let jti = b64url_encode(&access_crypto::random::bytes::<16>().map_err(down)?);
        let claims = read_token_claims(
            &ReadFacts {
                issuer: realm.issuer.as_str(),
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
            .sign(realm.realm, alg, ACCESS_TYP, &claims, now)
            .await
            .map_err(down)?;
        Ok(Some(IssuedRead {
            token: Secret::new(token.into_bytes()),
            expires_ms: now.saturating_add(READ_TTL_MS),
        }))
    }

    async fn alg(&self, realm: &RealmEntry) -> Result<JwsAlg, Unavailable> {
        let mut t = TenantTx::begin(&self.app, realm.tenant, realm.realm)
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
    ) -> Result<Option<IssuedRead>, Unavailable> {
        let Some(row) = console::by_id(&self.0.app, &session.id)
            .await
            .map_err(down)?
        else {
            return Ok(None);
        };
        self.0.issue_console(&row, instance, jkt).await
    }
}

impl<P: LiveKeys + 'static> ReadTokens for ManagementTokens<P> {
    async fn verify(&self, p: Presented<'_>) -> Result<Option<ReadToken>, Unavailable> {
        let Some(surface) = unverified_audience(p.token).and_then(|a| Surface::of(&a)) else {
            return Ok(None);
        };
        let Some(realm) = self.realm_of(&surface).await? else {
            return Ok(None);
        };
        let jwks = self.signer.jwks(realm.realm).await.map_err(down)?;
        let keys = realm_key_set(jwks.as_bytes()).map_err(down)?;
        let Ok(claims) = read_claims(p.token, &keys, realm.issuer.as_str()) else {
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
        let first = PgReplayCache::new(self.app.clone(), realm.tenant, realm.realm)
            .first_use(day, replay_key(&proof.htm, &proof.htu, &proof.jti))
            .await
            .map_err(down)?;
        if !first {
            return Ok(None);
        }
        if matches!(self.standing(&realm, &claims, now).await?, Standing::Ended) {
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
