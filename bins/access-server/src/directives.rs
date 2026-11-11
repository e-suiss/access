//! The cell's operator break-glass directives (OP-46, G63, OP-157 m.3 (j)): `access-breakglass`
//! leaves signed files in `ops/directives/`; this process reads them every second and carries
//! out what they add up to. The wholesale `session_epoch` floor moves every subject whose epoch
//! last moved before it, so every session and refresh family issued before it ends. A leader
//! marked unhealthy gives its leases up and takes none; the fence goes on. A file that does not
//! verify under the cell's directive key, or names another cell, is ignored. Nothing here makes
//! an authority decision or writes authority state; each directive applied is one operational
//! audit row (`operator.directive`, OP-39).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use access_crypto::breakglass::{Directive, DirectiveState, hex, unhex};
use access_store::Pool as PgPool;
use access_store::identity::TenantTx;
use access_store::operational::{OperationalEvent, record_operational};

use crate::ServerDomains;
use crate::config::Breakglass;

/// How often the directory is read (OP-157 m.3 (j)).
pub(crate) const EVERY: Duration = Duration::from_secs(1);

/// The largest directive file read.
const MAX_FILE: u64 = 4096;

/// The cell's directive directory and key.
pub(crate) struct Reader {
    cell: String,
    dir: PathBuf,
    key: Vec<u8>,
}

impl Reader {
    /// From the `[breakglass]` section.
    ///
    /// # Errors
    /// The directive key is not 32 bytes of hex, or the cell is unnamed.
    pub(crate) fn new(c: &Breakglass) -> Result<Self, &'static str> {
        let key = unhex(&c.directive_key)
            .filter(|k| k.len() == 32)
            .ok_or("breakglass.directive_key must be 64 hex digits")?;
        if c.cell.is_empty() {
            return Err("breakglass.cell must name the cell");
        }
        Ok(Self {
            cell: c.cell.clone(),
            dir: c.directives.clone(),
            key,
        })
    }

    /// Every directive in the directory that verifies and names this cell, and how many files
    /// did not.
    pub(crate) fn read(&self) -> (Vec<Directive>, usize) {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return (Vec::new(), 0);
        };
        let mut good = Vec::new();
        let mut bad = 0_usize;
        for path in entries.filter_map(|e| e.ok().map(|e| e.path())) {
            if path.extension().is_none_or(|x| x != "cbor") {
                continue;
            }
            let verified = std::fs::metadata(&path)
                .ok()
                .filter(|m| m.is_file() && m.len() <= MAX_FILE)
                .and_then(|_| std::fs::read(&path).ok())
                .and_then(|b| Directive::verify(&b, &self.key).ok())
                .filter(|d| d.cell == self.cell);
            match verified {
                Some(d) => good.push(d),
                None => bad = bad.saturating_add(1),
            }
        }
        (good, bad)
    }
}

/// What this process has carried out so far.
#[derive(Debug, Default)]
pub(crate) struct Applied {
    floor_ms: u64,
    recorded: u64,
    refused: usize,
}

/// Moves every realm's subjects to the floor; true once all of them are there.
async fn raise_floor(app: &PgPool, router: &PgPool, floor_ms: u64) -> bool {
    let Ok(floor) = i64::try_from(floor_ms) else {
        return false;
    };
    let Ok(realms) = access_store::tenancy::routes(router).await else {
        return false;
    };
    let mut all = true;
    for r in realms {
        let moved = async {
            let mut t = TenantTx::begin(app, r.tenant, r.realm).await?;
            let n = t.raise_epoch_floor(floor).await?;
            t.commit().await?;
            Ok::<u64, access_store::StoreError>(n)
        }
        .await;
        match moved {
            Ok(n) if n > 0 => tracing::warn!(
                event = "operator.epoch_floor.raised",
                subjects = n,
                "operator epoch floor ended sessions"
            ),
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(%error, "operator epoch floor not applied yet");
                all = false;
            }
        }
    }
    all
}

/// One round: reads the directives and carries out their state.
pub(crate) async fn tick(
    reader: &Reader,
    domains: &ServerDomains,
    app: &PgPool,
    router: &PgPool,
    applied: &mut Applied,
) -> DirectiveState {
    let (directives, refused) = reader.read();
    if refused != applied.refused {
        // §17.8.2
        tracing::error!(
            event = "operator.directive.refused",
            files = refused,
            "a break-glass directive file does not verify; it is ignored"
        );
        applied.refused = refused;
    }
    let state = DirectiveState::fold(&directives);
    domains.stand_down(state.leader_unhealthy).await;
    if let Some(floor) = state.epoch_floor_ms
        && floor > applied.floor_ms
        && raise_floor(app, router, floor).await
    {
        applied.floor_ms = floor;
    }
    let mut fresh: Vec<&Directive> = directives
        .iter()
        .filter(|d| d.seq > applied.recorded)
        .collect();
    fresh.sort_by_key(|d| d.seq);
    for d in fresh {
        let target = format!("directive:{}", d.seq);
        let actor = format!("operator:{}", reader.cell);
        let op = d.op.name();
        let op = if op.len() <= 64 {
            op
        } else {
            String::from("flag")
        };
        let correlation = hex(&d.document);
        // OP-157 m.3 (k), SA-51, TI-18
        let row = OperationalEvent {
            occurred_at_ms: d.at_ms,
            tenant: None,
            domain: None,
            event_type: "operator.directive",
            actor: &actor,
            target: &target,
            reason: &op,
            correlation: &correlation,
        };
        if record_operational(app, &row).await.is_err() {
            break;
        }
        applied.recorded = d.seq;
    }
    state
}

/// Runs [`tick`] every second until the task is aborted.
pub(crate) async fn run(reader: Reader, domains: Arc<ServerDomains>, app: PgPool, router: PgPool) {
    let mut applied = Applied::default();
    let mut every = tokio::time::interval(EVERY);
    let mut last = DirectiveState::default();
    loop {
        every.tick().await;
        let state = tick(&reader, &domains, &app, &router, &mut applied).await;
        if state != last {
            tracing::warn!(
                event = "operator.directive.state",
                seq = state.seq,
                leader_unhealthy = state.leader_unhealthy,
                flags = state.flags.len(),
                "operator break-glass directives in force"
            );
            last = state;
        }
    }
}
