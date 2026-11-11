//! The realm KEK rotation job (OP-138, OP-144, OP-158 m.3 (y)): a new KEK generation is made in
//! the token, every subject DEK under the old one is re-wrapped to it inside the token, and the
//! rotation record counts what moved. A run that stops resumes from the rows still under the
//! old KEK; the old KEK stays in the token, so nothing it wraps is ever unreadable.

use access_store::Pool;
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::kek::Rotation;

use crate::login::{RealmKeks, kek_id_at, kek_label_at, realm_keks};

/// Subject DEKs re-wrapped per transaction (PD).
pub(crate) const BATCH: u32 = 256;

/// What a run did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Run {
    /// The rotation as it stands after the run.
    pub(crate) rotation: Rotation,
    /// DEKs this run moved.
    pub(crate) moved: u64,
}

/// Why a run stopped.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RotationError {
    /// The token refused.
    #[error("hsm: {0}")]
    Hsm(String),
    /// The database refused.
    #[error(transparent)]
    Store(#[from] access_store::StoreError),
}

fn generation_of(realm: &[u8; 16], kek_id: &str) -> Option<u32> {
    (1..=64).find(|g| kek_id_at(realm, *g) == kek_id)
}

/// Starts a rotation of the realm's KEK, or resumes the open one, and runs it to its end at
/// most `batches` batches of `batch` keys long. Calling it again resumes.
///
/// # Errors
/// [`RotationError`]; what was committed before stays counted.
pub(crate) async fn rotate(
    keks: &RealmKeks,
    app: &Pool,
    (tenant, realm): (TenantId, RealmId),
    batch: u32,
    batches: u32,
) -> Result<Run, RotationError> {
    let id = *realm.as_bytes();
    let mut t = TenantTx::begin(app, tenant, realm).await?;
    let open = t.kek_rotation().await?.filter(|r| !r.finished);
    let rotation = if let Some(open) = open {
        t.commit().await?;
        open
    } else {
        let current = realm_keks(keks.token(), &id)
            .map_err(RotationError::Hsm)?
            .first()
            .map_or(1, |(g, _)| *g);
        let next = current.saturating_add(1);
        keks.token()
            .generate_kek(&kek_label_at(&id, next))
            .map_err(|e| RotationError::Hsm(e.to_string()))?;
        let (from, to) = (kek_id_at(&id, current), kek_id_at(&id, next));
        t.open_kek_rotation(&from, &to).await?;
        t.commit().await?;
        keks.reload(&id);
        Rotation {
            from_kek: from,
            to_kek: to,
            rewrapped: 0,
            finished: false,
        }
    };
    let from_gen = generation_of(&id, &rotation.from_kek)
        .ok_or_else(|| RotationError::Hsm(rotation.from_kek.clone()))?;
    let to_gen = generation_of(&id, &rotation.to_kek)
        .ok_or_else(|| RotationError::Hsm(rotation.to_kek.clone()))?;
    let hsm = |g| {
        keks.token()
            .kek(&kek_label_at(&id, g))
            .map_err(|e| RotationError::Hsm(e.to_string()))
    };
    let (from, to) = (hsm(from_gen)?, hsm(to_gen)?);
    let mut moved = 0_u64;
    for _ in 0..batches.max(1) {
        let mut t = TenantTx::begin(app, tenant, realm).await?;
        let found = t.wrapped_by_kek(&rotation.from_kek, batch).await?;
        let mut here = 0_u64;
        for key in &found {
            // OP-138
            let rewrapped = from
                .rewrap(&key.wrapped, &to)
                .map_err(|e| RotationError::Hsm(e.code().to_owned()))?;
            if t.rewrap_subject_dek(key, (&rotation.from_kek, &rotation.to_kek), &rewrapped)
                .await?
            {
                here = here.saturating_add(1);
            }
        }
        let done = u32::try_from(found.len()).unwrap_or(u32::MAX) < batch;
        t.count_kek_rotation(&rotation.to_kek, here, done).await?;
        t.commit().await?;
        moved = moved.saturating_add(here);
        if done {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
            // OP-41, OP-138
            access_store::operational::record_operational(
                app,
                &access_store::operational::OperationalEvent {
                    event_type: "kek.rotated",
                    occurred_at_ms: now,
                    tenant: Some(*tenant.as_bytes()),
                    domain: None,
                    actor: "access-server:rotate-kek",
                    target: &rotation.to_kek,
                    reason: "",
                    correlation: &rotation.from_kek,
                },
            )
            .await?;
            tracing::info!(
                to = %rotation.to_kek,
                rewrapped = rotation.rewrapped.saturating_add(moved),
                "realm KEK rotated (OP-138)"
            );
            break;
        }
    }
    let mut t = TenantTx::begin(app, tenant, realm).await?;
    let now = t.kek_rotation().await?.unwrap_or(rotation);
    t.commit().await?;
    Ok(Run {
        rotation: now,
        moved,
    })
}
