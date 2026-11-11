//! The provider's rebuild-diff and replay of every domain this process leads (§16.5, RT9,
//! TI-1, TI-16, TI-RT1, TI-RT4, G32, G33, OP-158 m.3 (i)). Each domain's records are replayed
//! with the open evaluator as they are committed, from a verified snapshot or Genesis:
//! - the folded state is compared with the live state: a difference is a fold notice, the
//!   leader gives the domain up and no process leads it until the state is rebuilt from the
//!   log (sev-1);
//! - a decision that does not replay is declared as a re-evaluation notice for the root and the
//!   Security Party; nothing stops (G32) and no restriction is written.
//!
//! A snapshot is taken every [`SNAPSHOT_EVERY`] records.

use std::collections::HashMap;
use std::time::Duration;

use access_authority_core::app::{divergence, snapshot};
use access_authority_sequencer::ports::NoteSigner;
use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_kernel::record::RecordEnvelope;
use access_store::Pool;
use access_store::scope::DomainId;
use access_verifier::replay::{Kind, Replay};

/// How often the led domains are replayed (PD; the periodic fold of FA-14).
pub(crate) const INTERVAL: Duration = Duration::from_secs(60);

/// Records between snapshots (PD).
pub(crate) const SNAPSHOT_EVERY: u64 = 10_000;

/// The evaluator identity the provider writes into its divergence sets.
pub(crate) const EVALUATOR: &str = concat!("access-server/", env!("CARGO_PKG_VERSION"));

/// Records one replay step reads at a time.
const STEP: u64 = 4_096;

/// What one step did for one domain.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Stepped {
    /// Records replayed.
    pub(crate) replayed: u64,
    /// The folded state is not the live state: commits stopped.
    pub(crate) fold: bool,
    /// Decisions newly declared as not replaying.
    pub(crate) declared: u32,
    /// A snapshot was taken.
    pub(crate) snapshot: bool,
}

/// One domain's replay, kept between steps.
pub(crate) struct Replayer {
    replay: Replay,
    next: u64,
    declared: usize,
    snapshot: u64,
}

async fn start(app: &Pool, domain: Digest, head: u64) -> Result<Replayer, String> {
    // TI-RT4
    let (replay, next, snapshot) = match snapshot::verified_before(app, domain, head)
        .await
        .map_err(|e| e.to_string())?
    {
        Some((state, pos)) => {
            let next = pos.saturating_add(1);
            (Replay::resume(domain, state, next), next, pos)
        }
        None => (Replay::new(), 0, 0),
    };
    Ok(Replayer {
        replay,
        next,
        declared: 0,
        snapshot,
    })
}

/// Replays `domain` up to its head and compares; `replayers` keeps its replay.
///
/// # Errors
/// A store or fold failure, as text; the next step tries again.
pub(crate) async fn step<S: NoteSigner + Sync>(
    domains: &crate::ServerDomains,
    (app, signer): (&Pool, &S),
    replayers: &mut HashMap<Digest, Replayer>,
    domain: Digest,
    now: u64,
) -> Result<Stepped, String> {
    let e = |x: access_store::StoreError| x.to_string();
    let id = DomainId::from_bytes(domain.0);
    let head = access_store::authority::read_head(app, &id)
        .await
        .map_err(e)?
        .pos;
    let r = match replayers.remove(&domain) {
        Some(r) => r,
        None => start(app, domain, head).await?,
    };
    let mut r = r;
    let mut out = Stepped::default();
    let from = r.next;
    while r.next <= head {
        let to = r.next.saturating_add(STEP).saturating_sub(1).min(head);
        for row in access_store::authority::read_log(app, &id, r.next, to)
            .await
            .map_err(e)?
        {
            let env = RecordEnvelope::from_bytes(&row.envelope).map_err(|x| x.to_string())?;
            let d = env.disclose(|_| true).map_err(|x| x.to_string())?;
            r.replay.push(&d, true).map_err(|x| x.to_string())?;
            out.replayed = out.replayed.saturating_add(1);
        }
        r.next = to.saturating_add(1);
    }
    let stored = access_store::authority::state(app, &id).await.map_err(e)?;
    let differing = match r.replay.state() {
        Some(state) => divergence::differing(state, &stored),
        None => Vec::new(),
    };
    let fold_item = r.replay.items().iter().any(|i| i.kind == Kind::Fold);
    if !differing.is_empty() || fold_item {
        // RT9, TI-16
        let diff = divergence::Diff { head, differing };
        divergence::declare_fold(app, domain, &diff, now)
            .await
            .map_err(|x| x.to_string())?;
        domains.halt(domain).await;
        out.fold = true;
        return Ok(out);
    }
    let items = r.replay.items();
    if items.len() > r.declared
        && let Some(set) = r.replay.set((from.min(head), head), EVALUATOR, now)
    {
        let fresh: Vec<_> = items.iter().skip(r.declared).collect();
        let bytes = set.to_bytes().map_err(|x| x.to_string())?;
        let first = fresh.first().map_or(head, |i| i.position);
        let declared = divergence::declare(
            app,
            domain,
            &divergence::Declared {
                source: "rebuild-diff",
                by: None,
                range: (0, head),
                items: u32::try_from(fresh.len()).unwrap_or(u32::MAX),
                first,
                set: &bytes,
            },
            now,
        )
        .await
        .map_err(|x| x.to_string())?;
        if declared.is_some() {
            out.declared = u32::try_from(fresh.len()).unwrap_or(u32::MAX);
        }
        r.declared = items.len();
    }
    if head.saturating_sub(r.snapshot) >= SNAPSHOT_EVERY {
        match snapshot::take(app, signer, domain, now).await {
            Ok(s) => {
                r.snapshot = s.pos;
                out.snapshot = true;
            }
            Err(error) => tracing::warn!(%error, "snapshot not taken"),
        }
    }
    replayers.insert(domain, r);
    Ok(out)
}

fn wall_ms() -> u64 {
    use access_identity_account::ports::Clock as _;
    access_identity_account::adapters::system::SystemClock.now_ms()
}

/// Replays every led domain each [`INTERVAL`].
pub(crate) async fn run<S: NoteSigner + Sync>(
    domains: std::sync::Arc<crate::ServerDomains>,
    app: Pool,
    signer: S,
) {
    let mut replayers = HashMap::new();
    let mut every = tokio::time::interval(INTERVAL);
    every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        every.tick().await;
        let now = wall_ms();
        for domain in domains.led() {
            if let Err(error) = step(&domains, (&app, &signer), &mut replayers, domain, now).await {
                tracing::warn!(%error, "replay step not done");
            }
        }
    }
}

/// The `declareDivergence` route's keeper: a replica agent's signed set counts only under the
/// key the domain declares for that replica (G32, OP-158 m.3 (h)).
pub(crate) struct Declarations {
    /// The domains, for their declared replicas.
    pub(crate) domains: std::sync::Arc<crate::ServerDomains>,
    /// `access_app`.
    pub(crate) app: Pool,
}

impl access_http::divergence::Declare for Declarations {
    async fn declare(
        &self,
        domain: Digest,
        set: Vec<u8>,
    ) -> Result<Option<u64>, access_authority_core::CoreError> {
        use access_authority_core::CoreError;
        let bad = || CoreError::Protocol("divergence-set");
        let signed =
            access_verifier::replay::SignedSet::verify(&suiss_crypto::sig::PureBackend, &set)
                .map_err(|_| bad())?;
        if signed.set.domain != domain {
            return Err(bad());
        }
        let key = suiss_crypto::cose::PublicKey::Ed25519(signed.key);
        let replica = self
            .domains
            .declared(domain)
            .await
            .replicas
            .into_iter()
            .find(|r| r.key == key)
            .ok_or(CoreError::Protocol("replica-unknown"))?;
        let head = access_store::authority::read_head(&self.app, &DomainId::from_bytes(domain.0))
            .await?
            .pos;
        let (from, to) = signed.set.range;
        if to > head {
            return Err(bad());
        }
        let first = signed
            .set
            .items
            .iter()
            .map(|i| i.position)
            .min()
            .ok_or_else(bad)?;
        divergence::declare(
            &self.app,
            domain,
            &divergence::Declared {
                source: "replica",
                by: Some(&replica.name),
                range: (from, to),
                items: u32::try_from(signed.set.items.len()).unwrap_or(u32::MAX),
                first,
                set: &set,
            },
            wall_ms(),
        )
        .await
    }
}
