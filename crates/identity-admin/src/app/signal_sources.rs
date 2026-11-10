//! `idp.signal.*` changes written under their committed ALLOW (OP-156 m.3 (r)), and the signal
//! sources as administrators read them. A source only names an issuer: its Claims count once
//! the domain accepts them with its own Acceptance (E38). A retired name is never reused
//! (OP-73).

use access_identity_signals::domain::source::{Source, SourceChange, issuer_id};
use access_store::identity::TenantTx;
use access_store::idp::Bound;
use access_store::signals::{NewSignalSource, SignalSourceRow};
use serde_json::{Value as Json, json};

use crate::AdminError;
use crate::domain::Invalid;

/// What must hold now for `change`: a new name was never used; a retired source is live.
///
/// # Errors
/// [`Invalid`]; [`AdminError`].
pub(crate) async fn current(t: &mut TenantTx, change: &SourceChange) -> Result<(), AdminError> {
    let rows = t.signal_sources().await?;
    match change {
        SourceChange::Register(s) => {
            if rows.iter().any(|r| r.name == s.name) {
                return Err(Invalid::SignalSourceExists.into());
            }
        }
        SourceChange::Retire(name) => {
            if !rows.iter().any(|r| r.name == *name && r.live) {
                return Err(Invalid::NoSignalSource.into());
            }
        }
    }
    Ok(())
}

fn new(s: &Source) -> NewSignalSource<'_> {
    NewSignalSource {
        name: &s.name,
        live: true,
        kind: s.kind.name(),
        provider: &s.provider,
        issuer: &s.issuer,
        format: s.format.name(),
        transmitter: s.transmitter.as_deref(),
        expected_interval_s: s.expected_interval_s,
    }
}

/// Writes `change` under `bound`.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn write(
    t: &mut TenantTx,
    bound: &Bound,
    change: &SourceChange,
) -> Result<bool, AdminError> {
    match change {
        SourceChange::Register(s) => t.put_signal_source(bound, &new(s)).await?,
        SourceChange::Retire(name) => {
            let row: SignalSourceRow = t
                .signal_sources()
                .await?
                .into_iter()
                .find(|r| r.name == *name)
                .ok_or(Invalid::NoSignalSource)?;
            t.put_signal_source(
                bound,
                &NewSignalSource {
                    name: &row.name,
                    live: false,
                    kind: &row.kind,
                    provider: &row.provider,
                    issuer: &row.issuer,
                    format: &row.format,
                    transmitter: row.transmitter.as_deref(),
                    expected_interval_s: row.expected_interval_s,
                },
            )
            .await?;
        }
    }
    Ok(true)
}

/// The signal sources as administrators read them, each with its decision position. A source
/// heard over SSF shows its transmitter's delay (§8.13); `delayed_since` is filled by the
/// caller from the transmitters it knows.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn list(
    t: &mut TenantTx,
    key: Option<&str>,
) -> Result<Vec<(Json, u64)>, AdminError> {
    Ok(t.signal_sources()
        .await?
        .into_iter()
        .filter(|r| key.is_none_or(|k| k == r.name))
        .map(|r| {
            let class = access_identity_signals::domain::source::Kind::parse(&r.kind)
                .map_or("", access_identity_signals::domain::source::Kind::class);
            (
                json!({
                    "name": r.name,
                    "kind": r.kind,
                    "class": class,
                    "provider": r.provider,
                    "issuer": issuer_id(&r.issuer),
                    "format": r.format,
                    "transmitter": r.transmitter,
                    "expected_interval_s": r.expected_interval_s,
                    "status": if r.live { "live" } else { "retired" },
                    "version": r.version,
                }),
                r.position,
            )
        })
        .collect())
}
