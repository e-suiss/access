//! The allowlist and re-anchor side of a domain's algorithm routes (§15.16, CR-45 RA-6, OP-159
//! m.3 (e), (f), (g), m.9 (h)): the signer's allowlist, the CT3 time-lock kept in the store, the
//! re-anchor before a retirement and the `algorithm_retired` notice.

use std::path::PathBuf;

use access_authority_core::app::reanchor::{Status, retire_gate};
use access_authority_sequencer::witness::Target;
use access_crypto::opaque_id::IdKey;
use access_http::algorithms::{Admission, AlgorithmError, Algorithms, Reanchored};
use access_kernel::digest::Digest;
use access_kernel::verify::ml_dsa::is_ml_dsa;
use access_store::Pool;
use access_store::pq_checkpoint::Reason;
use access_store::scope::DomainId;
use suiss_crypto::cose::Algorithm;

use crate::login::RealmKeks;

/// The CT3 time-lock of an admission (OP-159 m.3 (e), m.9 (h)).
pub(crate) const LOCK_MS: u64 = access_kernel::meta::CT3_DELAY_DEFAULT_S * 1_000;

/// How long after its time-lock a request still admits (PD).
pub(crate) const LAPSE_MS: u64 = 7 * 24 * 60 * 60 * 1_000;

/// Where the notice of a retirement is queued.
pub(crate) struct Notify {
    /// `access_router`, for the live realms.
    pub(crate) router: Pool,
    /// The realm KEKs.
    pub(crate) keks: RealmKeks,
    /// The opaque id key.
    pub(crate) ids: IdKey,
}

/// The signer, the store and the witnesses.
pub(crate) struct PgAlgorithms {
    /// The authority signer's socket.
    pub(crate) socket: PathBuf,
    /// `access_app`.
    pub(crate) app: Pool,
    /// `access_sequencer`.
    pub(crate) sequencer: Pool,
    /// The witnesses.
    pub(crate) targets: Vec<Target>,
    /// The notice side; none where no notice is sent.
    pub(crate) notify: Option<Notify>,
}

fn signer_error(code: &str) -> AlgorithmError {
    match code {
        "algorithm-profile-conflict" => AlgorithmError::Conflict,
        "reanchor-required" => AlgorithmError::ReanchorRequired,
        "pq-key-unavailable" => AlgorithmError::PqKeyUnavailable,
        "signer-unknown-domain" => AlgorithmError::Unknown,
        _ => AlgorithmError::Unavailable,
    }
}

/// The wall clock, Unix ms.
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

/// The algorithm's JOSE name.
const fn name(alg: Algorithm) -> &'static str {
    match alg {
        Algorithm::Ed25519 => "EdDSA",
        Algorithm::Esp256 => "ESP256",
        Algorithm::Es256 => "ES256",
        Algorithm::MlDsa44 => "ML-DSA-44",
        Algorithm::MlDsa65 => "ML-DSA-65",
        Algorithm::MlDsa87 => "ML-DSA-87",
    }
}

impl PgAlgorithms {
    async fn allowlist(
        &self,
        domain: Digest,
        alg: Algorithm,
        retire: bool,
    ) -> Result<(), AlgorithmError> {
        access_authority_core::adapters::allowlist(&self.socket, domain, alg, retire)
            .await
            .map_err(|code| signer_error(&code))
    }

    async fn audit(&self, domain: Digest, event: &'static str, target: &str, now: u64) {
        let _ = access_store::operational::record_operational(
            &self.app,
            &access_store::operational::OperationalEvent {
                event_type: event,
                occurred_at_ms: now,
                tenant: None,
                domain: Some(domain.0),
                actor: "provider",
                target,
                reason: "",
                correlation: "",
            },
        )
        .await;
    }
}

impl Algorithms for PgAlgorithms {
    // OP-159 m.3 (e), (r), m.9 (h)
    async fn admit(
        &self,
        domain: Digest,
        alg: Algorithm,
        now: u64,
    ) -> Result<Admission, AlgorithmError> {
        let m = crate::checkpoints::pq::metadata(&self.socket, domain)
            .await
            .ok_or(AlgorithmError::Unknown)?;
        if m.algorithms.contains(&alg) {
            return Ok(Admission::Admitted);
        }
        access_kernel::meta::admit_algorithm(&m.declared, alg)
            .map_err(|_| AlgorithmError::Conflict)?;
        let id = DomainId::from_bytes(domain.0);
        let since = now.saturating_sub(LOCK_MS.saturating_add(LAPSE_MS));
        let asked = access_store::algorithm_admission::latest(&self.app, &id, alg.cose(), since)
            .await
            .map_err(|_| AlgorithmError::Unavailable)?;
        let Some(asked) = asked else {
            access_store::algorithm_admission::request(&self.sequencer, &id, alg.cose(), now)
                .await
                .map_err(|_| AlgorithmError::Unavailable)?;
            return Ok(Admission::Locked(now.saturating_add(LOCK_MS)));
        };
        let opens = asked.saturating_add(LOCK_MS);
        if now < opens {
            return Ok(Admission::Locked(opens));
        }
        self.allowlist(domain, alg, false).await?;
        self.audit(domain, "algorithm.admitted", &alg.cose().to_string(), now)
            .await;
        Ok(Admission::Admitted)
    }

    // CR-45 RA-6, OP-159 m.3 (g)
    async fn reanchor(
        &self,
        domain: Digest,
        retirement: bool,
        now: u64,
    ) -> Result<Reanchored, AlgorithmError> {
        let reason = if retirement {
            Reason::Retirement
        } else {
            Reason::Request
        };
        let out = crate::checkpoints::pq::run(
            (&self.socket, &self.app, &self.sequencer),
            domain,
            &self.targets,
            reason,
            now,
        )
        .await
        .map_err(|code| match code {
            "reanchor-no-pq-witness" => AlgorithmError::NoPqWitness,
            "pq-key-unavailable" => AlgorithmError::PqKeyUnavailable,
            "checkpoint-not-witnessed" => AlgorithmError::NotWitnessed,
            _ => AlgorithmError::Unavailable,
        })?;
        Ok(match out {
            Status::Pending => Reanchored::Pending,
            Status::Anchored(r) => Reanchored::Anchored {
                size: r.size,
                time: r.time,
                witnesses: r.witnesses,
            },
        })
    }

    // §15.16 step (c), RA-6, OP-159 m.3 (f), m.13 (f)
    async fn retirable(
        &self,
        domain: Digest,
        alg: Algorithm,
        now: u64,
    ) -> Result<u64, AlgorithmError> {
        let m = crate::checkpoints::pq::metadata(&self.socket, domain)
            .await
            .ok_or(AlgorithmError::Unknown)?;
        if is_ml_dsa(alg) || !m.algorithms.contains(&alg) {
            return Err(AlgorithmError::Conflict);
        }
        let head = access_store::authority::read_head(&self.app, &DomainId::from_bytes(domain.0))
            .await
            .map_err(|_| AlgorithmError::Unavailable)?;
        let last = m.declared.pq_reanchor.as_ref();
        retire_gate(last, head.pos.saturating_add(1), now)
            .map_err(|_| AlgorithmError::ReanchorRequired)?;
        // CR-18, OP-159 m.3 (d)
        if !m.algorithms.iter().any(|a| is_ml_dsa(*a))
            || !m
                .binding
                .values()
                .any(|b| b.superseded.is_none() && is_ml_dsa(b.alg))
        {
            return Err(AlgorithmError::PqKeyUnavailable);
        }
        last.map(|r| r.size).ok_or(AlgorithmError::ReanchorRequired)
    }

    // §15.16 step (b), OP-159 m.3 (f)
    async fn retire(
        &self,
        domain: Digest,
        (alg, exercise, size): (Algorithm, Digest, u64),
        now: u64,
    ) -> Result<(), AlgorithmError> {
        self.allowlist(domain, alg, true).await?;
        let target = format!(
            "{}@{size}:{}",
            alg.cose(),
            access_kernel::json::b64url_encode(&exercise.0)
        );
        self.audit(domain, "algorithm.retired", &target, now).await;
        if let Some(n) = &self.notify
            && let Err(error) = crate::relay::algorithm_retired(
                (&self.app, &n.router),
                (&n.keks, &n.ids),
                &DomainId::from_bytes(domain.0),
                (name(alg), size, now),
            )
            .await
        {
            tracing::warn!(%error, "algorithm_retired notice not queued");
        }
        Ok(())
    }
}
