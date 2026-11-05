//! Authority token projections (§9.9, CMP-7): an access token the realm's authorization
//! server asks for is a `projection.issue` commit of its holder, and only its ALLOW makes a
//! token (§9.9 "her token issuance bir karardır"). The token is the RFC 9068 `at+jwt` whose
//! authority is the RAR `authorization_details` of the contract the decision made (§9.13.5),
//! signed by the domain's operational key in the authority signer (§9.9.3 rule 7), bound to
//! the holder key (PI-11), for one resource server (RFC 8707). A refresh is a new decision in
//! the same family (§9.9.3 rule 6, L19).

use std::collections::BTreeMap;

use access_authority_sequencer::ports::Clock;
use access_crypto::projection::{
    AccessTokenProjection, Authority as RarAuthority, PartyPseudonym, PartyRefs,
    access_token_claims,
};
use access_internal_api::projections::{MAX_TOKEN_BYTES, SIGNER_UNAVAILABLE, TOKEN_TOO_LARGE};
use access_kernel::codec::Canonical as _;
use access_kernel::combinator::Outcome;
use access_kernel::digest::Digest;
use access_kernel::intent::IntentEnvelope;
use access_kernel::json::{Json, b64url_decode, b64url_encode};
use access_kernel::meta::Payload;
use access_kernel::model::Id;
use access_kernel::pap::Pap;
use access_kernel::tier::Tier;
use access_kernel::verify::projection::Confirmation;
use access_store::projections::{Family, family as read_family, open_family};
use access_store::scope::DomainId;

use super::{Domains, Led, open_keyring, signer_reason};
use crate::CoreError;
use crate::app::{Incoming, Response};
use crate::ports::{Binding, Keys, Salts};

/// Longest horizon of an exact-intent token, from its decision (§9.9.1, §9.9.3 rule 4).
pub const INTENT_HORIZON_MS: u64 = 5 * 60 * 1000;

/// Longest horizon of a bounds token, from its decision: the top of the 5–15 minute range
/// (§9.9.3 rule 4, MD-7, PD).
pub const BOUNDS_HORIZON_MS: u64 = 15 * 60 * 1000;

/// The claim that names a token's refresh family (P50).
pub const FAMILY_CLAIM: &str = "family";

/// Label of the digest of a token's `ValidityContract` (`access_contract`).
pub const CONTRACT_LABEL: &str = "access/validity-contract/v1";

/// What the token carries (§9.9.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenAuthority {
    /// A bounds token: the contract's bounds, `kind = bounds`.
    Bounds,
    /// An exact-intent token for this intent, `kind = intent`.
    Intent(Box<IntentEnvelope>),
}

/// A token the authorization server asks for.
#[derive(Clone, Debug)]
pub struct TokenOrder {
    /// The holder's `projection.issue` commit.
    pub incoming: Incoming,
    /// The authorization server's issuer identifier.
    pub issuer: String,
    /// The OAuth client.
    pub client_id: String,
    /// The one resource server (RFC 8707).
    pub audience: String,
    /// The holder binding.
    pub confirmation: Confirmation,
    /// What it carries.
    pub authority: TokenAuthority,
    /// The family of a refresh.
    pub family: Option<[u8; 16]>,
}

/// A signed token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    /// The compact JWS.
    pub jws: String,
    /// The `projection.issue` `ExerciseID`.
    pub exercise: Digest,
    /// Position of its decision record.
    pub position: u64,
    /// Digest of its `ValidityContract` under [`CONTRACT_LABEL`].
    pub contract: Digest,
    /// `exp`: the contract's horizon, ms.
    pub expires_at: u64,
    /// Its refresh family.
    pub family: [u8; 16],
}

/// What a [`TokenOrder`] came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Projected {
    /// Allowed, committed and signed.
    Issued(Token),
    /// Decided, not allowed: the response with its decision.
    Decided(Box<Response>),
    /// No token, by stable code; nothing was decided unless the code says so.
    Refused(&'static str),
}

/// Parties as the token names them: a reference the core made stays as it is, a Party of the
/// exact intent becomes its reference (MD-10).
struct Refs(BTreeMap<Id, Id>);

impl PartyRefs for Refs {
    fn pseudonym(&self, party: &Id) -> Option<PartyPseudonym> {
        let r = self.0.get(party).unwrap_or(party);
        PartyPseudonym::new(&b64url_encode(&r.0)).ok()
    }
}

/// Why an order is refused before anything is decided.
fn precheck(order: &TokenOrder, tier: Option<Tier>, now: u64) -> Option<&'static str> {
    let Some(Payload::ProjectionIssue {
        bounds, audience, ..
    }) = &order.incoming.request.payload
    else {
        return Some("projection-payload");
    };
    // §9.9.3 rule 1
    if order.audience.is_empty() || !audience.contains(&order.audience) {
        return Some("invalid-target");
    }
    let actions = &bounds.authority.actions;
    if actions.exact.is_empty() || !actions.prefix.is_empty() {
        return Some("projection-authority");
    }
    let (cap, ceiling) = match &order.authority {
        TokenAuthority::Bounds => (BOUNDS_HORIZON_MS, Tier::Ct1),
        TokenAuthority::Intent(i) => {
            if actions.exact.len() != 1 || !actions.exact.contains(&i.action) {
                return Some("projection-authority");
            }
            (INTENT_HORIZON_MS, Tier::Ct2)
        }
    };
    // §9.9.3 rule 4: CT2+ only as exact intent, CT3 never
    match tier {
        None => return Some("projection-authority"),
        Some(t) if t > ceiling => return Some("projection-tier"),
        Some(_) => {}
    }
    let horizon = bounds.constraints.validity.until;
    if horizon <= now || horizon.saturating_sub(now) > cap {
        return Some("projection-horizon");
    }
    None
}

impl<K: Keys, B: Binding + Clone, S: Salts + Clone, C: Clock + Clone> Domains<K, B, S, C> {
    /// Decides `order` as its holder's `projection.issue` commit and, when it is allowed, signs
    /// the token (§9.9, P17): a token that cannot be checked first (wrong payload, resource,
    /// horizon or tier, a revoked family) is refused before anything is recorded.
    ///
    /// # Errors
    /// [`CoreError`] as [`Domains::exercise`].
    pub async fn project(&self, order: &TokenOrder) -> Result<Projected, CoreError> {
        if let Some(code) = self.refusal(order).await? {
            return Ok(Projected::Refused(code));
        }
        let r = self.exercise(&order.incoming).await?;
        if r.decision.outcome != Outcome::Allow {
            return Ok(Projected::Decided(Box::new(r)));
        }
        let (Some(pap), Some(exercise), Some(position), false) =
            (&r.pap, r.exercise, r.record, r.replayed)
        else {
            return Ok(Projected::Refused("replayed"));
        };
        let pap = Pap::from_bytes(pap).map_err(|_| CoreError::Protocol("pap"))?;
        let family = match self.family_of(order, &pap, &exercise).await? {
            Ok(f) => f,
            Err(code) => return Ok(Projected::Refused(code)),
        };
        let contract = pap
            .validity
            .to_bytes()
            .map(|b| Digest(suiss_crypto::digest::context_digest(CONTRACT_LABEL, &b).0))
            .map_err(|_| CoreError::Protocol("validity"))?;
        Ok(match self.signed(order, &pap, &exercise, family).await? {
            Ok(jws) => Projected::Issued(Token {
                jws,
                exercise,
                position,
                contract,
                expires_at: pap.validity.horizon,
                family,
            }),
            Err(code) => Projected::Refused(code),
        })
    }

    /// Why `order` cannot become a token, known before any decision: a refresh of a family that
    /// is unknown, revoked or another client's (§9.9.3 rule 6), or [`precheck`].
    async fn refusal(&self, order: &TokenOrder) -> Result<Option<&'static str>, CoreError> {
        let domain = order.incoming.request.domain;
        if let Some(f) = &order.family {
            match read_family(&self.setup.app, &DomainId::from_bytes(domain.0), f).await? {
                None => return Ok(Some("family-unknown")),
                Some(row) if row.revoked_pos.is_some() => return Ok(Some("family-revoked")),
                Some(row) if row.client_id != order.client_id => {
                    return Ok(Some("family-mismatch"));
                }
                Some(_) => {}
            }
        }
        let mut guard = self.leading(domain).await?;
        let Some(led) = guard.as_mut() else {
            return Err(CoreError::Unavailable("leader"));
        };
        let now = led
            .clock
            .now()
            .await
            .map_err(|_| CoreError::Unavailable("time"))?;
        let tier = match (&order.incoming.request.payload, &order.authority) {
            (Some(Payload::ProjectionIssue { bounds, .. }), TokenAuthority::Bounds) => {
                led.core
                    .projected_tier(&bounds.authority.actions.exact, None, now)
                    .await?
            }
            (Some(Payload::ProjectionIssue { .. }), TokenAuthority::Intent(i)) => {
                led.core
                    .projected_tier(&std::collections::BTreeSet::new(), Some(i), now)
                    .await?
            }
            _ => None,
        };
        Ok(precheck(order, tier, now))
    }

    /// The family of an allowed projection: the refreshed one, held by the same Instance, or a
    /// new one named by the first 16 bytes of its `ExerciseID` (P50).
    async fn family_of(
        &self,
        order: &TokenOrder,
        pap: &Pap,
        exercise: &Digest,
    ) -> Result<Result<[u8; 16], &'static str>, CoreError> {
        let id = DomainId::from_bytes(order.incoming.request.domain.0);
        if let Some(f) = order.family {
            let row = read_family(&self.setup.app, &id, &f)
                .await?
                .ok_or(CoreError::Protocol("family"))?;
            return Ok(if row.holder == pap.holder.instance.0 {
                Ok(f)
            } else {
                Err("family-mismatch")
            });
        }
        let mut f = [0; 16];
        f.copy_from_slice(exercise.0.get(..16).ok_or(CoreError::Protocol("family"))?);
        let family = Family {
            family: f,
            client_id: order.client_id.clone(),
            holder: pap.holder.instance.0,
            root_exercise: exercise.0,
            status: None,
            revoked_pos: None,
        };
        open_family(&self.setup.sequencer, &id, &family).await?;
        Ok(Ok(f))
    }

    /// The signed token of an allowed projection, or the stable code that stopped it: no
    /// signer, a token over [`MAX_TOKEN_BYTES`], the signer's refusal.
    async fn signed(
        &self,
        order: &TokenOrder,
        pap: &Pap,
        exercise: &Digest,
        family: [u8; 16],
    ) -> Result<Result<String, &'static str>, CoreError> {
        let domain = order.incoming.request.domain;
        let Some(path) = self.setup.signer.clone() else {
            return Ok(Err(SIGNER_UNAVAILABLE));
        };
        let mut guard = self.leading(domain).await?;
        let Some(led) = guard.as_mut() else {
            return Err(CoreError::Unavailable("leader"));
        };
        let actor = led.core.instance_ref(&pap.holder.instance).await?;
        let refs = match &order.authority {
            TokenAuthority::Intent(i) => Refs(led.core.intent_refs(i)?),
            TokenAuthority::Bounds => Refs(BTreeMap::new()),
        };
        let projection = AccessTokenProjection {
            issuer: &order.issuer,
            domain: &domain,
            projection_exercise: exercise,
            actor_party: &actor,
            capacity: pap.capacity,
            validity: &pap.validity,
            authority: match &order.authority {
                TokenAuthority::Bounds => RarAuthority::Bounds,
                TokenAuthority::Intent(i) => RarAuthority::Intent(i),
            },
            audience: &order.audience,
            client_id: &order.client_id,
            confirmation: order.confirmation,
            iat: pap.iat,
        };
        let Ok(Json::Object(mut claims)) = access_token_claims(&projection, &refs) else {
            return Ok(Err("projection-authority"));
        };
        // P50: the family a revocation ends, read back by introspection
        claims.push((
            String::from(FAMILY_CLAIM),
            Json::Str(b64url_encode(&family)),
        ));
        let claims = Json::Object(claims);
        let claims = access_crypto::jose::output::to_string(&claims);
        // OP-150 m.3 (s)
        if claims.len() > MAX_TOKEN_BYTES {
            return Ok(Err(TOKEN_TOO_LARGE));
        }
        Ok(
            match sign_token(&path, led, domain, claims.into_bytes(), pap.iat).await {
                Ok(jws) if jws.len() > MAX_TOKEN_BYTES => Err(TOKEN_TOO_LARGE),
                other => other,
            },
        )
    }
}

impl<K: Keys, B: Binding + Clone, S: Salts + Clone, C: Clock + Clone> Domains<K, B, S, C> {
    /// Revokes the refresh family `family` of `domain` at the domain's head (§9.9.3 rule 6,
    /// P50): its later refreshes are refused before any decision. `true` the first time;
    /// `false` for a family already revoked or unknown.
    ///
    /// # Errors
    /// [`CoreError::Store`].
    pub async fn revoke_family(&self, domain: Digest, family: [u8; 16]) -> Result<bool, CoreError> {
        let id = DomainId::from_bytes(domain.0);
        let head = access_store::authority::read_head(&self.setup.app, &id).await?;
        Ok(
            access_store::projections::revoke_family(&self.setup.sequencer, &id, &family, head.pos)
                .await?,
        )
    }

    /// The refresh family `family` of `domain`.
    ///
    /// # Errors
    /// [`CoreError::Store`].
    pub async fn family(
        &self,
        domain: Digest,
        family: [u8; 16],
    ) -> Result<Option<Family>, CoreError> {
        Ok(read_family(&self.setup.app, &DomainId::from_bytes(domain.0), &family).await?)
    }

    /// The state of the access token `token` of `domain` at least at the domain's head (RFC
    /// 7662, MD-8, §9.9.3 rule 5): active when the domain's operational key signed it under
    /// usage `token`, its horizon has not passed and its family is not revoked.
    ///
    /// # Errors
    /// [`CoreError::Unavailable`] without the metadata; [`CoreError::Store`].
    pub async fn introspect(
        &self,
        domain: Digest,
        token: &str,
        now: u64,
    ) -> Result<(bool, Option<String>, u64), CoreError> {
        let (head, _) = self.head(domain).await?;
        let metadata = self
            .metadata(domain)
            .await
            .ok_or(CoreError::Unavailable("signer"))?;
        let declared = access_kernel::verify::cose::parse_sign1(&metadata)
            .ok()
            .and_then(|m| m.payload)
            .and_then(|p| access_kernel::verify::key_scope::DomainMetadata::from_bytes(&p).ok())
            .ok_or(CoreError::Unavailable("metadata"))?;
        let mut keys = access_kernel::verify::cose::KeySet::default();
        for k in declared.operational_keys.iter().filter(|k| {
            k.usage
                .contains(&access_kernel::verify::key_scope::KeyUsage::Token)
        }) {
            if keys.insert(k.kid, k.key.clone()).is_ok() {
                keys.allowed.insert(k.alg);
            }
        }
        let Ok(v) = access_kernel::verify::jws::verify_compact(
            &access_crypto::AwsLcBackend,
            token,
            &keys,
            access_kernel::verify::projection::ACCESS_TOKEN_TYP,
            access_kernel::verify::jws::Origin::Native,
        ) else {
            return Ok((false, None, head));
        };
        let Ok(claims) =
            access_kernel::json::parse(&v.payload, access_kernel::verify::jws::MAX_PAYLOAD)
        else {
            return Ok((false, None, head));
        };
        let live = claims
            .get("exp")
            .and_then(Json::as_int)
            .and_then(|e| u64::try_from(e).ok())
            .and_then(|e| e.checked_mul(1000))
            .is_some_and(|e| e > now);
        let family = claims
            .get(FAMILY_CLAIM)
            .and_then(Json::as_str)
            .and_then(|f| b64url_decode(f).ok())
            .and_then(|f| <[u8; 16]>::try_from(f).ok());
        let Some(family) = family.filter(|_| live) else {
            return Ok((false, None, head));
        };
        let revoked = self
            .family(domain, family)
            .await?
            .is_none_or(|f| f.revoked_pos.is_some());
        if revoked {
            return Ok((false, None, head));
        }
        Ok((true, String::from_utf8(v.payload).ok(), head))
    }

    /// The domain's latest committed position and its `recorded_at` (G51).
    ///
    /// # Errors
    /// [`CoreError::Store`].
    pub async fn head(&self, domain: Digest) -> Result<(u64, u64), CoreError> {
        let h =
            access_store::authority::read_head(&self.setup.app, &DomainId::from_bytes(domain.0))
                .await?;
        Ok((h.pos, h.recorded_at))
    }
}

/// Asks the signer at `path` to sign an access token, opening the domain's keyring first. An
/// unreachable signer is [`SIGNER_UNAVAILABLE`]: there is no other signing path (§16.7.1).
async fn sign_token<B: Binding, S: Salts, C>(
    path: &std::path::Path,
    led: &mut Led<B, S, C>,
    domain: Digest,
    claims: Vec<u8>,
    at: u64,
) -> Result<String, &'static str> {
    use access_authority_signer::adapters::call;
    use access_authority_signer::protocol::{Request as SignRequest, Response as SignResponse};
    if !led.signer_open {
        led.signer_open = open_keyring(path, domain).await;
    }
    match call(path, &SignRequest::SignToken { domain, claims, at }).await {
        Ok(SignResponse::Token { jws, .. }) => Ok(jws),
        Ok(SignResponse::Error(code)) => Err(signer_reason(&code)),
        Ok(_) => Err("signer-error"),
        Err(_) => Err(SIGNER_UNAVAILABLE),
    }
}
