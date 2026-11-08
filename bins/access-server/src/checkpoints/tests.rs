#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use access_authority_signer::adapters::call as authority_call;
use access_authority_signer::protocol::{
    Request as AuthorityRequest, Response as AuthorityResponse,
};
use access_identity_audit::domain::verify;
use access_identity_signer::cell::operational_origin;
use access_identity_signer::protocol::{Request, Response};
use access_store::audit::{AuditEvent, last_checkpoint};
use access_store::authority::{
    CommitBatch, HeadRow, LogRecord, acquire_lease, commit_batch, read_head,
};
use access_store::authority_checkpoint::latest;
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::operational::{
    OperationalEvent, last_operational_checkpoint, record_operational,
};
use access_store::testing::{TestDb, fresh};
use suiss_crypto::envelope::SoftKek;
use suiss_crypto::note::{Checkpoint, parse_note};

use super::*;

const T: TenantId = TenantId::from_bytes([0x31; 16]);
const R: RealmId = RealmId::from_bytes([0x32; 16]);

/// A real identity signer with its cell key open, on a socket of its own.
fn identity_signer(name: &str) -> PathBuf {
    use access_identity_signer::adapters::{DirVault, SealedFactory, now_ms, serve};
    let dir = std::env::temp_dir().join(format!("acp-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut service = access_identity_signer::service::Service::start(
        SealedFactory::new(SoftKek::new("identity-kek", [9; 32])),
        DirVault::new(&dir),
        suiss_crypto::rotation::Policy::REALM,
    )
    .unwrap();
    service.open_cell("cell-f5").unwrap();
    let path = dir.join("s.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let uid = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&dir).unwrap());
    tokio::spawn(serve(
        listener,
        Arc::new(Mutex::new(service)),
        vec![uid],
        now_ms,
    ));
    path
}

struct SoftBinding;

impl access_authority_signer::ports::Bindings for SoftBinding {
    fn binding(
        &mut self,
        _: &Digest,
    ) -> Result<Box<dyn suiss_crypto::signer::Signer + Send>, suiss_crypto::signer::SignError> {
        static DOC: std::sync::OnceLock<suiss_crypto::secret::Secret<Vec<u8>>> =
            std::sync::OnceLock::new();
        let doc = DOC.get_or_init(|| {
            suiss_crypto::signer::SoftSigner::generate_ed25519()
                .unwrap()
                .1
        });
        Ok(Box::new(
            suiss_crypto::signer::SoftSigner::ed25519_from_pkcs8(doc)?,
        ))
    }
}

const NOW: u64 = 1_800_000_000_000;

fn now() -> u64 {
    NOW
}

/// A real authority signer with `d`'s keyring open and its first key active.
async fn authority_signer(name: &str, d: Digest) -> PathBuf {
    use access_authority_signer::adapters::{DirVault, SealedFactory, serve};
    let dir = std::env::temp_dir().join(format!("acp-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let policy = suiss_crypto::rotation::Policy {
        publish_lead_ms: 0,
        ..suiss_crypto::rotation::Policy::AUTHORITY
    };
    let service = Arc::new(Mutex::new(
        access_authority_signer::service::Service::start(
            SealedFactory::new(SoftKek::new("kek", [4; 32])),
            SoftBinding,
            DirVault::new(&dir),
            policy,
            NOW,
        )
        .unwrap(),
    ));
    let socket = dir.join("a.sock");
    let uid = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&dir).unwrap());
    tokio::spawn(serve(
        tokio::net::UnixListener::bind(&socket).unwrap(),
        Arc::clone(&service),
        vec![uid],
        now,
    ));
    let open = AuthorityRequest::Open(Box::new(access_authority_signer::domain::default_template(
        d,
    )));
    assert_eq!(
        authority_call(&socket, &open).await.unwrap(),
        AuthorityResponse::Opened
    );
    for _ in 0..2 {
        service.lock().unwrap().tick(NOW, 1);
    }
    socket
}

async fn write_rows(db: &TestDb) {
    let mut t = TenantTx::begin(&db.app, T, R).await.unwrap();
    t.audit(&AuditEvent {
        event_type: "session.revoked",
        actor: "adm_1",
        target: "usr_1",
        correlation: "req_1",
    })
    .await
    .unwrap();
    t.commit().await.unwrap();
    record_operational(
        &db.app,
        &OperationalEvent {
            occurred_at_ms: 1_000,
            tenant: Some([0x31; 16]),
            domain: Some([0xd0; 32]),
            event_type: "audit.read",
            actor: "inst:x",
            target: "record:1",
            reason: "explain",
            correlation: "req_2",
        },
    )
    .await
    .unwrap();
}

// A-1, OP-38, OP-44, OP-150 m.3 (h), CR-23: a written identity audit row and a written
// operational row each reach a checkpoint signed by the identity signer's cell
// `audit-checkpoint` key through the server's checkpointer, under their own origins
#[tokio::test]
async fn an_audit_row_reaches_a_signed_checkpoint() {
    let db = fresh().await.unwrap();
    let socket = identity_signer("audit");
    let signer = SignerNotes(socket.clone());
    // CR-23, G42: nothing is appended while the signer is down
    let down = SignerNotes(socket.with_file_name("absent.sock"));
    write_rows(&db).await;
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let t = audit_tick(&db.checkpointer, "a", &down, NOW).await;
        assert_eq!((t.identity, t.operational), (0, 0));
        // the watermark is cluster-wide (OP-131 m.4): rows count once every older transaction ends
        let t = audit_tick(&db.checkpointer, "a", &signer, NOW).await;
        assert_eq!(t.failed, 0);
        let identity = last_checkpoint(&db.checkpointer).await.unwrap();
        let operational = last_operational_checkpoint(&db.checkpointer).await.unwrap();
        if let (Some(i), Some(o)) = (identity, operational) {
            let Ok(Response::CellKey { origin, vkey }) =
                access_identity_signer::adapters::call(&socket, &Request::CellKey).await
            else {
                panic!("cell key");
            };
            assert_eq!(i.size, 1);
            assert_eq!(o.size, 1);
            assert_eq!(
                verify(&access_crypto::AwsLcBackend, &i, &origin, &vkey).unwrap(),
                NOW
            );
            let op = operational_origin(&origin).unwrap();
            assert_eq!(
                verify(&access_crypto::AwsLcBackend, &o, &op, &vkey).unwrap(),
                NOW
            );
            break;
        }
        assert!(Instant::now() < deadline, "no checkpoint after 20 s");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // nothing new ended: a second tick appends nothing
    let again = audit_tick(&db.checkpointer, "a", &signer, NOW + 1).await;
    assert_eq!(again, AuditTick::default());
}

// OP-152 m.5 (k), OP-38, OP-44: one writer per cell audit chain; a second replica's checkpointer
// stays on standby while the first holds both chains' leases, and signs nothing
#[tokio::test]
async fn only_the_lease_holding_replica_signs_the_cell_chains() {
    let db = fresh().await.unwrap();
    let signer = SignerNotes(identity_signer("lease"));
    write_rows(&db).await;
    let first = audit_tick(&db.checkpointer, "a", &signer, NOW).await;
    assert_eq!((first.standby, first.failed), (0, 0));
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let other = audit_tick(&db.checkpointer, "b", &signer, NOW).await;
        assert_eq!(
            other,
            AuditTick {
                standby: 2,
                ..AuditTick::default()
            }
        );
        let t = audit_tick(&db.checkpointer, "a", &signer, NOW).await;
        assert_eq!((t.standby, t.failed), (0, 0));
        if last_checkpoint(&db.checkpointer).await.unwrap().is_some() {
            break;
        }
        assert!(Instant::now() < deadline, "no checkpoint after 20 s");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let other = audit_tick(&db.checkpointer, "b", &signer, NOW + 1).await;
    assert_eq!(
        other,
        AuditTick {
            standby: 2,
            ..AuditTick::default()
        }
    );
}

/// A domain whose head is at position 1, with the Genesis versions the server writes.
async fn domain(db: &TestDb) -> Digest {
    use access_kernel::record::{Header, Opened, RecordKind};
    use suiss_crypto::dcbor::Value;
    let versions = Value::Map(vec![
        (Value::text("core"), Value::Unsigned(1)),
        (Value::text("meta_schema"), Value::Unsigned(1)),
    ]);
    let envelope = RecordEnvelope {
        header: Header {
            domain: None,
            pos: 0,
            kind: RecordKind::Genesis,
            recorded_at: NOW - 10,
            prev: None,
        },
        fields: std::collections::BTreeMap::from([(
            String::from("versions"),
            Opened {
                value: versions,
                salt: [3; 32],
            },
        )]),
    };
    let d = envelope.domain().unwrap();
    let id = DomainId::from_bytes(d.0);
    let genesis = LogRecord {
        pos: 0,
        kind: "genesis",
        recorded_at: NOW - 10,
        leaf_hash: envelope.leaf_hash().unwrap(),
        envelope: access_kernel::codec::Canonical::to_bytes(&envelope).unwrap(),
    };
    access_store::authority::create_domain(&db.sequencer, &id, [0x31; 16], &genesis, &[])
        .await
        .unwrap();
    let (lease, head) = acquire_lease(&db.sequencer, &id, "a", Duration::from_secs(10))
        .await
        .unwrap();
    let leaf = [0x81; 32];
    let batch = CommitBatch {
        epoch: lease.epoch,
        after: head.pos,
        records: vec![LogRecord {
            pos: 1,
            kind: "claim",
            recorded_at: NOW - 5,
            leaf_hash: leaf,
            envelope: vec![0xa1, 1],
        }],
        head: HeadRow {
            pos: 1,
            epoch: lease.epoch,
            leaf_hash: leaf,
            recorded_at: NOW - 5,
            frontier: vec![suiss_ledger::merkle::node_hash(&head.leaf_hash, &leaf)],
        },
        nonces: vec![],
        outbox: vec![],
        proofs: vec![],
        reads: vec![],
        writes: vec![],
        draws: vec![],
        single_use: vec![],
        effects: vec![],
    };
    commit_batch(&db.sequencer, &id, [0x31; 16], &batch)
        .await
        .unwrap();
    d
}

// A-1, CMP-6, T16, T20, OP-143 m.10: the committed head of a led domain is signed by the
// authority signer under usage `checkpoint` and appended with its key excerpt; a quiet domain
// gets a new one at the next cadence (heartbeat) though its head did not move
#[tokio::test]
async fn a_led_domain_gets_signed_checkpoints() {
    let db = fresh().await.unwrap();
    let d = domain(&db).await;
    let socket = authority_signer("domain", d).await;
    let (heads, signer) = (PgHeads(db.app.clone()), SocketSigner::new(socket));
    let first = domain_checkpoint((&heads, &signer), (&db.app, &db.sequencer), d, NOW)
        .await
        .unwrap();
    let head = read_head(&db.app, &DomainId::from_bytes(d.0))
        .await
        .unwrap();
    assert_eq!(first.size, head.pos + 1);
    assert_ne!(first.excerpt.len(), 0);
    let body = Checkpoint::parse(&parse_note(&first.note).unwrap().body).unwrap();
    assert_eq!((body.size, body.root), (first.size, first.root));
    assert_eq!(
        access_authority_sequencer::checkpoint::extensions(&body)
            .unwrap()
            .issued_at,
        NOW
    );
    let later = NOW + 60_000;
    domain_checkpoint((&heads, &signer), (&db.app, &db.sequencer), d, later)
        .await
        .unwrap();
    let stored = latest(&db.app, &DomainId::from_bytes(d.0))
        .await
        .unwrap()
        .unwrap();
    assert_eq!((stored.issued_at, stored.size), (later, first.size));
}
