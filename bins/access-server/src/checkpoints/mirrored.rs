//! Mirror before witness (T21, TI-13, OP-158 m.3 (f)): a checkpoint of a domain that declares
//! replicas goes to its witnesses only once a declared replica acknowledged holding it, so no
//! independent cosignature, and so no SEC23 acknowledgement, ever covers records no replica
//! holds. A domain that declares no replica has nothing to wait for; its SEC23 commits are never
//! acknowledged.

use access_authority_core::app::mirror::replicas;
use access_kernel::digest::Digest;
use access_kernel::verify::key_scope::Declarations;
use access_store::Pool;
use access_store::scope::DomainId;

use super::publish::Publisher;

/// No declared replica holds a checkpoint within the wait (TI-13).
const AUDIT_EVENT_LAGGING: &str = "replica.lagging";

/// How often the wait looks at the acks another process took.
const POLL: std::time::Duration = std::time::Duration::from_millis(100);

/// `witnesses` when a declared replica of `domain` holds `size` records within the ack wait,
/// or when none is declared; otherwise no witness at all for this checkpoint.
pub(super) async fn first(
    app: &Pool,
    domain: Digest,
    declared: &Declarations,
    size: u64,
    witnesses: Publisher,
) -> Publisher {
    if declared.replicas.is_empty() {
        return witnesses;
    }
    let names: Vec<String> = declared.replicas.iter().map(|r| r.name.clone()).collect();
    let id = DomainId::from_bytes(domain.0);
    let wait = access_authority_sequencer::witness::ACK_WAIT;
    let held = replicas()
        .wait(domain, size, (wait, POLL), || async {
            access_store::mirror::acked(app, &id, &names)
                .await
                .map_or(0, |all| all.iter().map(|(_, s)| *s).max().unwrap_or(0))
        })
        .await;
    match held {
        Ok(_) => witnesses,
        Err(acked) => {
            tracing::warn!(
                size,
                acked,
                "no declared replica holds the checkpoint; it is not sent to witnesses (TI-13)"
            );
            let target = format!("size:{size}");
            let lagging = access_store::operational::record_operational(
                app,
                &access_store::operational::OperationalEvent {
                    event_type: AUDIT_EVENT_LAGGING,
                    occurred_at_ms: super::wall_ms(),
                    tenant: None,
                    domain: Some(domain.0),
                    actor: "provider",
                    target: &target,
                    reason: "not-mirrored",
                    correlation: "",
                },
            )
            .await;
            if let Err(error) = lagging {
                tracing::warn!(%error, "replica lag audit row not kept");
            }
            Publisher {
                targets: Vec::new(),
                sinks: witnesses.sinks,
            }
        }
    }
}
