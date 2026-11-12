//! Placement of domains, realms and tenants in cells (§17.1.4, §17.4.9, CMP-26, OP-30, TI-17,
//! T28, TN-9, OP-158 m.3 (o)): the Placement Directory routes a request to the cell that leads
//! it and is never a decision input. A domain moves between cells only by the source's seal and
//! the target's replayed acceptance (W7's cell move); its placement changes after the target
//! accepted. The silo move takes every domain of a tenant to a cell of its own; no data is
//! replicated between cells.

use std::path::Path;

use access_authority_sequencer::cell::{self, MoveError};
use access_kernel::digest::Digest;
use access_kernel::verify::key_scope::{Declarations, Durability, Residency};
use access_store::Pool;
use access_store::placement::{self, Placed, Subject};
use access_store::scope::DomainId;

/// One cell's databases, as a move reaches them.
#[derive(Clone, Copy)]
pub struct CellDb<'a> {
    /// The cell's name in the placement grammar.
    pub name: &'a str,
    /// `access_sequencer`.
    pub sequencer: &'a Pool,
    /// `access_app`.
    pub app: &'a Pool,
}

/// Why a placement change did not happen.
#[derive(Debug, thiserror::Error)]
pub enum PlacementError {
    /// The cell move was refused; the domain stays where it was sealed.
    #[error("cell move: {0}")]
    Move(#[from] MoveError),
    /// The source cell does not hold the domain or tenant.
    #[error("not in the source cell")]
    NotHere,
    /// The store refused.
    #[error("store: {0}")]
    Store(#[from] access_store::StoreError),
}

/// Where a request for a subject goes (TI-17).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Route {
    /// This cell serves it, or decides that it does not.
    Here,
    /// Another cell serves it.
    Elsewhere(String),
}

/// The route of a subject `placed` in, as `this` cell reads it: only a placement in another cell
/// sends a request away; no placement, or a directory that cannot answer, leaves it here, where
/// the commit path decides (TI-17).
#[must_use]
pub fn route<E>(this: &str, placed: &Result<Option<Placed>, E>) -> Route {
    match placed {
        Ok(Some(p)) if p.cell != this => Route::Elsewhere(p.cell.clone()),
        _ => Route::Here,
    }
}

/// Moves `domain` from `source` to `target` (§17.4.1 item 1, T28): seals it on the source,
/// accepts the replayed image on the target, then records the placement in both cells. Returns
/// the accepted epoch.
///
/// # Errors
/// [`PlacementError`]; a refused acceptance leaves the domain sealed on the source and placed
/// there, closed until it is accepted.
pub async fn move_domain(
    source: CellDb<'_>,
    target: CellDb<'_>,
    domain: Digest,
    (holder, at_ms): (&str, u64),
) -> Result<u64, PlacementError> {
    let id = DomainId::from_bytes(domain.0);
    let tenant = placement::domain_tenant(source.app, &id)
        .await?
        .ok_or(PlacementError::NotHere)?;
    let sealed = access_store::cells::cell_head(source.sequencer, &id)
        .await?
        .is_some_and(|h| h.sealed_at.is_some());
    if !sealed {
        cell::seal(source.sequencer, source.app, domain, holder).await?;
    }
    let epoch = cell::accept(source.sequencer, target.sequencer, target.app, domain).await?;
    let dedicated = placement::cell_profile(target.app)
        .await?
        .is_some_and(|p| p.dedicated_to == Some(tenant));
    for app in [source.app, target.app] {
        placement::place_tenant(
            app,
            tenant,
            &Subject::Domain(domain.0),
            (target.name, dedicated),
            at_ms,
        )
        .await?;
    }
    Ok(epoch)
}

/// What a silo move did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Siloed {
    /// Each domain moved, with its accepted epoch.
    pub domains: Vec<(Digest, u64)>,
}

/// Moves every authority domain of `tenant` to `target`, a cell of its own (TN-9, §12.1.1,
/// OP-158 m.3 (o)): the tenant is adopted there with its id, each domain is sealed and accepted,
/// and the tenant's placement names the target in both cells. A realm follows its governing
/// domain's cell. The identity plane's rows of the tenant move by the logical transfer path
/// (HL-32), not here.
///
/// # Errors
/// [`PlacementError`]; a domain already moved is skipped, so the move can be run again.
pub async fn silo(
    source: CellDb<'_>,
    target: CellDb<'_>,
    tenant: [u8; 16],
    (holder, at_ms): (&str, u64),
) -> Result<Siloed, PlacementError> {
    let domains = placement::tenant_domains(source.app, tenant).await?;
    if domains.is_empty() {
        return Err(PlacementError::NotHere);
    }
    placement::adopt_tenant(target.app, tenant, target.name).await?;
    let dedicated = placement::cell_profile(target.app)
        .await?
        .is_some_and(|p| p.dedicated_to == Some(tenant));
    let mut out = Siloed::default();
    for id in domains {
        let domain = Digest(*id.as_bytes());
        let here = access_store::cells::cell_head(target.sequencer, &id).await?;
        if here.is_some() {
            continue;
        }
        let epoch = move_domain(source, target, domain, (holder, at_ms)).await?;
        out.domains.push((domain, epoch));
    }
    for app in [source.app, target.app] {
        placement::place_tenant(
            app,
            tenant,
            &Subject::Tenant(tenant),
            (target.name, dedicated),
            at_ms,
        )
        .await?;
    }
    Ok(out)
}

/// What `domain`'s binding-signed Domain Metadata declares, from the authority signer at
/// `signer` (OP-158 m.3 (b)).
///
/// # Errors
/// The signer's stable refusal code, `signer-unreachable` or `signer-metadata`.
pub async fn declared(signer: &Path, domain: Digest) -> Result<Declarations, String> {
    use access_authority_signer::adapters::call;
    use access_authority_signer::protocol::{Request, Response};
    use access_kernel::codec::Canonical as _;
    let cose = match call(signer, &Request::Metadata(domain)).await {
        Ok(Response::Metadata(m)) => m,
        Ok(Response::Error(code)) => return Err(code),
        Ok(_) => return Err(String::from("signer-frame")),
        Err(_) => return Err(String::from("signer-unreachable")),
    };
    access_kernel::verify::cose::parse_sign1(&cose)
        .ok()
        .and_then(|s| s.payload)
        .and_then(|p| access_kernel::verify::key_scope::DomainMetadata::from_bytes(&p).ok())
        .map(|m| m.declared)
        .ok_or_else(|| String::from("signer-metadata"))
}

/// `declared` with a cell's `durability` and `residency` (HL-40, T28).
#[must_use]
pub fn with_cell(
    mut declared: Declarations,
    durability: Durability,
    residency: Option<Residency>,
) -> Declarations {
    declared.durability = Some(durability);
    declared.residency = residency;
    declared
}

/// Publishes a cell's `durability` and `residency` in `domain`'s Domain Metadata through the
/// authority signer at `signer`, keeping every other declaration (HL-40, OP-158 m.3 (p)): a
/// single-node cell says so, and nothing it declares about itself grants a SEC23
/// acknowledgement without a declared replica and an independent witness. Returns whether the
/// metadata changed.
///
/// # Errors
/// The signer's stable refusal code, `signer-unreachable` or `signer-metadata`.
pub async fn declare_cell(
    signer: &Path,
    domain: Digest,
    (durability, residency): (Durability, Option<Residency>),
    canonical: &access_kernel::meta::RootSets,
) -> Result<bool, String> {
    use access_authority_signer::adapters::call;
    use access_authority_signer::protocol::{Request, Response};
    let declared = declared(signer, domain).await?;
    // OP-159 m.3 (j), m.16 (e)
    let wanted = crate::app::reanchor::canonical_only(
        &with_cell(declared.clone(), durability, residency),
        canonical,
    );
    if wanted == declared {
        return Ok(false);
    }
    match call(
        signer,
        &Request::Declare {
            domain,
            declared: Box::new(wanted),
        },
    )
    .await
    {
        Ok(Response::Opened) => Ok(true),
        Ok(Response::Error(code)) => Err(code),
        Ok(_) => Err(String::from("signer-frame")),
        Err(_) => Err(String::from("signer-unreachable")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn placed(cell: &str) -> Placed {
        Placed {
            cell: String::from(cell),
            dedicated: false,
            version: 1,
        }
    }

    // TI-17, CMP-26
    #[test]
    fn ti_17_only_a_placement_elsewhere_routes_away() {
        assert_eq!(
            route::<()>("cell-a", &Ok(Some(placed("cell-b")))),
            Route::Elsewhere(String::from("cell-b"))
        );
        assert_eq!(
            route::<()>("cell-a", &Ok(Some(placed("cell-a")))),
            Route::Here
        );
        assert_eq!(route::<()>("cell-a", &Ok(None)), Route::Here);
        assert_eq!(route("cell-a", &Err(())), Route::Here);
    }
}
