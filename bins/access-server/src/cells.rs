//! This process's cell (§17.4.9, CMP-26, OP-30, HL-40, OP-158 m.3 (o), (p)): the profile its
//! configuration declares (name, region, residency class, durability, the tenant a dedicated
//! cell serves), recorded in the database at start; the Placement Directory as the domain routes
//! read it; and what every domain led here publishes in its Domain Metadata about this cell's
//! durability and residency.

use std::collections::BTreeMap;
use std::path::Path;

use access_http::placement::{Directory, Elsewhere, Lookup, Unanswered};
use access_kernel::digest::Digest;
use access_kernel::verify::key_scope::{DrClass, Durability, Residency};
use access_store::Pool;
use access_store::placement::{self, CellProfile, Subject};

use crate::config::{self, Config};

/// The profile `config` declares for this cell.
pub(crate) fn profile(config: &Config) -> CellProfile {
    let own = config.cells.own();
    CellProfile {
        cell: config.cells.name().to_owned(),
        region: own.and_then(|c| c.region.clone()),
        class: own.map_or_else(|| String::from("regional"), |c| c.class.clone()),
        durability: match config.database.as_ref().map(|d| d.durability) {
            Some(config::Durability::SingleNode) => String::from("single-node"),
            _ => String::from("replicated"),
        },
        dedicated_to: own
            .and_then(|c| c.dedicated_to.as_deref())
            .and_then(config::uuid_bytes),
    }
}

/// Records `profile` as this cell's, when it changed (OP-158 m.3 (o)).
///
/// # Errors
/// The store's refusal, as text.
pub(crate) async fn declare(app: &Pool, profile: &CellProfile) -> Result<(), String> {
    let changed = placement::declare_cell(app, profile)
        .await
        .map_err(|e| format!("cell profile: {e}"))?;
    tracing::info!(
        cell = %profile.cell,
        durability = %profile.durability,
        changed,
        "cell profile (OP-158 m.3 (o), (p))"
    );
    Ok(())
}

/// The durability and residency a domain led by a cell of `profile` declares (HL-40, T28).
pub(crate) fn declared_of(profile: &CellProfile) -> (Durability, Option<Residency>) {
    let durability = if profile.durability == "single-node" {
        Durability::SingleNode
    } else {
        Durability::Replicated
    };
    let class = if profile.class == "multi-region-sync" {
        DrClass::MultiRegionSync
    } else {
        DrClass::Regional
    };
    (
        durability,
        profile
            .region
            .clone()
            .map(|region| Residency::new(region, class)),
    )
}

/// `declared` with this cell's durability and residency.
#[cfg(test)]
fn with_cell(
    declared: access_kernel::verify::key_scope::Declarations,
    profile: &CellProfile,
) -> access_kernel::verify::key_scope::Declarations {
    let (durability, residency) = declared_of(profile);
    access_authority_core::app::placement::with_cell(declared, durability, residency)
}

/// Publishes this cell's durability and residency in `domain`'s Domain Metadata through the
/// authority signer at `signer`, keeping every other declaration (HL-40, OP-158 m.3 (p)).
/// Returns whether the metadata changed.
///
/// # Errors
/// The signer's refusal, as text.
pub(crate) async fn declare_domain(
    signer: &Path,
    domain: Digest,
    profile: &CellProfile,
) -> Result<bool, String> {
    let (durability, residency) = declared_of(profile);
    access_authority_core::app::placement::declare_cell(signer, domain, durability, residency).await
}

/// The Placement Directory as the domain routes read it (TI-17): a domain placed in another
/// cell is answered there; the cells' URLs come from the configuration.
pub(crate) struct PgDirectory {
    app: Pool,
    this: String,
    urls: BTreeMap<String, Option<String>>,
}

impl PgDirectory {
    /// Over `app` for the cells of `config`.
    pub(crate) fn new(app: Pool, config: &Config) -> Self {
        Self {
            app,
            this: config.cells.name().to_owned(),
            urls: config
                .cells
                .cell
                .iter()
                .map(|c| (c.name.clone(), c.url.clone()))
                .collect(),
        }
    }

    /// Over `app` for cell `this` with the cells' `urls`.
    #[cfg(test)]
    pub(crate) fn of(app: Pool, this: &str, urls: &[(&str, &str)]) -> Self {
        Self {
            app,
            this: this.to_owned(),
            urls: urls
                .iter()
                .map(|(n, u)| ((*n).to_owned(), Some((*u).to_owned())))
                .collect(),
        }
    }
}

impl Directory for PgDirectory {
    fn elsewhere(&self, domain: [u8; 32]) -> Lookup<'_> {
        Box::pin(async move {
            let placed = placement::cell_of(&self.app, &Subject::Domain(domain))
                .await
                .map_err(|_| Unanswered);
            match access_authority_core::app::placement::route(&self.this, &placed) {
                access_authority_core::app::placement::Route::Here => placed.map(|_| None),
                access_authority_core::app::placement::Route::Elsewhere(cell) => {
                    Ok(Some(Elsewhere {
                        url: self.urls.get(&cell).cloned().flatten(),
                        cell,
                    }))
                }
            }
        })
    }
}

#[cfg(test)]
mod tests;
