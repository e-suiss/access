//! The in-process seam for authority token projections (OP-62, OP-150 m.2, §9.9): the realm's
//! authorization server asks, the authority core of this process decides the holder's
//! `projection.issue` commit and the authority signer signs the token. The identity plane never
//! signs an authority token (§9.9.3 rule 7).

use access_authority_core::CoreError;
use access_authority_core::adapters::{Projected, TokenAuthority, TokenOrder};
use access_authority_core::app::Incoming;
use access_authority_core::domain::Request;
use access_authority_core::ports::{Binding, Keys, Salts};
use access_authority_sequencer::ports::Clock;
use access_internal_api::epochs::{AuthorityPosition, Epochs, KeyEpoch};
use access_internal_api::idp::Unavailable;
use access_internal_api::projections::{
    Confirmation, Introspection, IssuedToken, Projections, SIGNER_UNAVAILABLE, TokenKind,
    TokenProjection, TokenProjectionRequest,
};
use access_kernel::codec::Canonical as _;
use access_kernel::combinator::{Mode, Outcome};
use access_kernel::digest::Digest;
use access_kernel::meta::Payload;
use access_kernel::verify::projection::Confirmation as Cnf;

use super::Plane;

fn refused(code: &str) -> TokenProjection {
    TokenProjection::Refused {
        code: String::from(code),
    }
}

/// The core's order for `r`, or the stable code that refuses it.
pub(crate) fn order(r: TokenProjectionRequest) -> Result<TokenOrder, &'static str> {
    let payload = Payload::from_bytes(&r.payload).map_err(|_| "projection-payload")?;
    // §9.9.3 rule 1: one resource, never a default one
    let [audience] = <[String; 1]>::try_from(r.resources).map_err(|_| "invalid-target")?;
    let authority = match (r.kind, r.target) {
        (TokenKind::Bounds, None) => TokenAuthority::Bounds,
        (TokenKind::Intent, Some(t)) => TokenAuthority::Intent(Box::new(t)),
        _ => return Err("projection-authority"),
    };
    Ok(TokenOrder {
        incoming: Incoming {
            request: Request {
                domain: r.domain,
                mode: Mode::Commit,
                nonce: r.nonce,
                intent: r.intent,
                payload: Some(payload),
                basis: r.basis,
                capacity: r.capacity,
                proofs: Vec::new(),
                exercise: None,
                consistency: None,
            },
            ais: Some(r.ais),
            pep: r.pep,
            explain: false,
        },
        issuer: r.issuer,
        client_id: r.client_id,
        audience,
        confirmation: match r.confirmation {
            Confirmation::DpopJkt(j) => Cnf::Jkt(j),
            Confirmation::MtlsX5t(x) => Cnf::X5tS256(x),
        },
        authority,
        family: r.family,
    })
}

/// The answer of a [`Projected`]; an unreachable signer is [`Unavailable`] (K17: 503).
pub(crate) fn answer(p: Projected) -> Result<TokenProjection, Unavailable> {
    Ok(match p {
        Projected::Issued(t) => TokenProjection::Issued(IssuedToken {
            token: t.jws,
            exercise: t.exercise,
            position: t.position,
            contract: t.contract,
            expires_at: t.expires_at,
            status: None,
            family: t.family,
        }),
        Projected::Decided(r) if r.decision.outcome == Outcome::RequireAction => {
            TokenProjection::RequireAction {
                decision: r.decision,
                position: r.record,
            }
        }
        Projected::Decided(r) => TokenProjection::Denied {
            decision: r.decision,
            position: r.record,
        },
        Projected::Refused(code) if code == SIGNER_UNAVAILABLE => {
            return Err(Unavailable(String::from(code)));
        }
        Projected::Refused(code) => refused(code),
    })
}

fn failed(e: &CoreError) -> Result<TokenProjection, Unavailable> {
    match e {
        CoreError::Unavailable(_) | CoreError::Store(_) | CoreError::Sequencer(_) => {
            Err(Unavailable(e.to_string()))
        }
        other => Ok(refused(other.code())),
    }
}

impl<K, B, S, C> Projections for Plane<K, B, S, C>
where
    K: Keys + Send + Sync + 'static,
    B: Binding + Clone + Send + Sync + 'static,
    S: Salts + Clone + Send + Sync + 'static,
    C: Clock + Clone + Send + Sync + 'static,
{
    async fn issue(&self, request: TokenProjectionRequest) -> Result<TokenProjection, Unavailable> {
        let order = match order(request) {
            Ok(o) => o,
            Err(code) => return Ok(refused(code)),
        };
        match self.domains.project(&order).await {
            Ok(p) => answer(p),
            Err(e) => failed(&e),
        }
    }

    async fn introspect(
        &self,
        domain: Digest,
        token: String,
    ) -> Result<Introspection, Unavailable> {
        let now = self
            .clock
            .clone()
            .now()
            .await
            .map_err(|e| Unavailable(e.to_string()))?;
        let (active, claims, as_of) = self
            .domains
            .introspect(domain, &token, now)
            .await
            .map_err(|e| Unavailable(e.to_string()))?;
        Ok(Introspection {
            active,
            claims,
            as_of,
        })
    }

    async fn revoke_family(&self, domain: Digest, family: [u8; 16]) -> Result<bool, Unavailable> {
        self.domains
            .revoke_family(domain, family)
            .await
            .map_err(|e| Unavailable(e.to_string()))
    }
}

impl<K, B, S, C> Epochs for Plane<K, B, S, C>
where
    K: Keys + Send + Sync + 'static,
    B: Binding + Clone + Send + Sync + 'static,
    S: Salts + Clone + Send + Sync + 'static,
    C: Clock + Clone + Send + Sync + 'static,
{
    async fn head(&self, domain: Digest) -> Result<AuthorityPosition, Unavailable> {
        let (position, recorded_at) = self
            .domains
            .head(domain)
            .await
            .map_err(|e| Unavailable(e.to_string()))?;
        Ok(AuthorityPosition {
            domain,
            position,
            recorded_at,
        })
    }

    async fn key_epoch(
        &self,
        domain: Digest,
        kid: [u8; 32],
    ) -> Result<Option<KeyEpoch>, Unavailable> {
        let metadata = self
            .domains
            .metadata(domain)
            .await
            .ok_or_else(|| Unavailable(String::from(SIGNER_UNAVAILABLE)))?;
        let declared = access_kernel::verify::cose::parse_sign1(&metadata)
            .ok()
            .and_then(|m| m.payload)
            .and_then(|p| access_kernel::verify::key_scope::DomainMetadata::from_bytes(&p).ok())
            .ok_or_else(|| Unavailable(String::from("metadata")))?;
        Ok(declared
            .operational_keys
            .iter()
            .find(|k| k.kid == kid)
            .map(|k| KeyEpoch {
                owner: access_internal_api::epochs::KeyOwner::Domain(domain),
                kid,
                valid_from: k.valid_from,
                valid_until: k.valid_until,
            }))
    }
}

#[cfg(test)]
mod tests;
