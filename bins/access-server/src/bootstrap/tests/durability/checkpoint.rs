#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

//! Real `access-witness` processes against this server's checkpointer on real Postgres and a
//! real authority signer (OP-158 m.5, OP-153 m.3 (gg)): cosigning with consistency proofs,
//! independence, out-of-cycle and coalesced checkpoints, the fail-closed path when a witness is
//! killed, the witnesses' own state on disk, gossip and equivocation, and the time cross-check.

use std::path::Path;
use std::process::Command;

use access_authority_sequencer::witness::{Target, board, time_check};
use access_product_twin::witness::Witness;
use access_store::authority::Lease;
use access_store::witness::{cosigns, equivocations, witnessed_through};
use suiss_ledger::checkpoint::cadence::Cadence;
use suiss_ledger::merkle::Frontier;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use access_authority_sequencer::adapters::{PgHeads, SocketSigner, SourcesClock};
use access_authority_sequencer::ports::NoteSigner as DomainSigner;
use access_authority_signer::adapters::call as authority_call;
use access_authority_signer::protocol::{
    Request as AuthorityRequest, Response as AuthorityResponse,
};
use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_kernel::record::RecordEnvelope;
use access_store::authority::{CommitBatch, HeadRow, LogRecord, acquire_lease, commit_batch};
use access_store::scope::DomainId;
use access_store::testing::{TestDb, fresh};
use suiss_crypto::envelope::SoftKek;
use suiss_crypto::note::{Checkpoint, parse_note};

use crate::checkpoints::domain_step;
use crate::checkpoints::publish::{Publisher, gossip};

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

fn wall() -> u64 {
    access_authority_signer::adapters::now_ms()
}

/// A binary of this target directory, built when it is missing.
fn bin(package: &str, name: &str) -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let dir = exe.parent().and_then(Path::parent).unwrap().to_path_buf();
    let bin = dir.join(name);
    if !bin.exists() {
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let status = Command::new(cargo)
            .args(["build", "-p", package, "--bin", name])
            .status()
            .unwrap();
        assert!(status.success(), "{name} did not build");
    }
    assert!(bin.exists(), "no {name} at {}", bin.display());
    bin
}

fn witness_bin() -> PathBuf {
    bin("access-witness", "access-witness")
}

/// The declared witness `w` of `operator`, for a provider run by Suiss.
fn target(w: &Witness, operator: &str) -> Target {
    Target::new(&w.url, &w.vkey, operator, "Suiss").unwrap()
}

/// A domain this test leads, with real timestamps.
struct Log {
    id: DomainId,
    domain: Digest,
    lease: Lease,
    frontier: Frontier,
    leaf: [u8; 32],
}

impl Log {
    async fn create(db: &TestDb) -> Self {
        use access_kernel::record::{Header, Opened, RecordKind};
        use suiss_crypto::dcbor::Value;
        let versions = Value::Map(vec![
            (Value::text("core"), Value::Unsigned(1)),
            (Value::text("meta_schema"), Value::Unsigned(1)),
        ]);
        let at = wall() - 60_000;
        let envelope = RecordEnvelope {
            header: Header {
                domain: None,
                pos: 0,
                kind: RecordKind::Genesis,
                recorded_at: at,
                prev: None,
            },
            fields: std::collections::BTreeMap::from([(
                String::from("versions"),
                Opened {
                    value: versions,
                    salt: suiss_crypto::digest::sha256(&at.to_be_bytes()),
                },
            )]),
        };
        let domain = envelope.domain().unwrap();
        let id = DomainId::from_bytes(domain.0);
        let leaf = envelope.leaf_hash().unwrap();
        let genesis = LogRecord {
            pos: 0,
            kind: "genesis",
            recorded_at: at,
            leaf_hash: leaf,
            envelope: access_kernel::codec::Canonical::to_bytes(&envelope).unwrap(),
        };
        access_store::authority::create_domain(&db.sequencer, &id, [0x31; 16], &genesis, &[])
            .await
            .unwrap();
        let (lease, _) = acquire_lease(&db.sequencer, &id, "w2", Duration::from_secs(600))
            .await
            .unwrap();
        let mut frontier = Frontier::default();
        frontier.push(leaf).unwrap();
        Self {
            id,
            domain,
            lease,
            frontier,
            leaf,
        }
    }

    async fn push(&mut self, db: &TestDb, n: u64, recorded_at: u64) {
        let mut records = Vec::new();
        let after = self.frontier.size() - 1;
        for i in 0..n {
            let pos = after + 1 + i;
            let mut seed = self.domain.0.to_vec();
            seed.extend_from_slice(&pos.to_be_bytes());
            let leaf = suiss_crypto::digest::sha256(&seed);
            self.frontier.push(leaf).unwrap();
            self.leaf = leaf;
            records.push(LogRecord {
                pos,
                kind: "claim",
                recorded_at,
                leaf_hash: leaf,
                envelope: vec![0xa1, 1],
            });
        }
        let pos = self.frontier.size() - 1;
        let batch = CommitBatch {
            epoch: self.lease.epoch,
            after,
            records,
            head: HeadRow {
                pos,
                epoch: self.lease.epoch,
                leaf_hash: self.leaf,
                recorded_at,
                frontier: self.frontier.nodes().to_vec(),
            },
            nonces: vec![],
            outbox: vec![],
            proofs: vec![],
            reads: vec![],
            writes: vec![],
            draws: vec![],
            single_use: vec![],
            beside: vec![],
            effects: vec![],
        };
        commit_batch(&db.sequencer, &self.id, [0x31; 16], &batch)
            .await
            .unwrap();
    }

    fn size(&self) -> u64 {
        self.frontier.size()
    }

    /// Appends one real claim record with an `artifacts` field and a withheld `secret`.
    async fn push_record(&mut self, db: &TestDb, artifact: [u8; 32], recorded_at: u64) {
        use access_kernel::record::{Header, Opened, RecordKind};
        use suiss_crypto::dcbor::Value;
        let pos = self.frontier.size();
        let salt = |n: &str| {
            let mut s = self.leaf.to_vec();
            s.extend_from_slice(n.as_bytes());
            suiss_crypto::digest::sha256(&s)
        };
        let envelope = RecordEnvelope {
            header: Header {
                domain: Some(self.domain),
                pos,
                kind: RecordKind::Claim,
                recorded_at,
                prev: Some(Digest(self.leaf)),
            },
            fields: std::collections::BTreeMap::from([
                (
                    String::from("artifacts"),
                    Opened {
                        value: Value::Array(vec![Value::Bytes(artifact.to_vec())]),
                        salt: salt("artifacts"),
                    },
                ),
                (
                    String::from("secret"),
                    Opened {
                        value: Value::text("lineage stays closed"),
                        salt: salt("secret"),
                    },
                ),
            ]),
        };
        let leaf = envelope.leaf_hash().unwrap();
        let after = pos - 1;
        self.frontier.push(leaf).unwrap();
        self.leaf = leaf;
        let batch = CommitBatch {
            epoch: self.lease.epoch,
            after,
            records: vec![LogRecord {
                pos,
                kind: "claim",
                recorded_at,
                leaf_hash: leaf,
                envelope: access_kernel::codec::Canonical::to_bytes(&envelope).unwrap(),
            }],
            head: HeadRow {
                pos,
                epoch: self.lease.epoch,
                leaf_hash: leaf,
                recorded_at,
                frontier: self.frontier.nodes().to_vec(),
            },
            nonces: vec![],
            outbox: vec![],
            proofs: vec![],
            reads: vec![],
            writes: vec![],
            draws: vec![],
            single_use: vec![],
            beside: vec![],
            effects: vec![],
        };
        commit_batch(&db.sequencer, &self.id, [0x31; 16], &batch)
            .await
            .unwrap();
    }
}

/// A real authority signer on the wall clock with `d`'s keyring open.
async fn wall_signer(
    name: &str,
    d: Digest,
    declared: access_kernel::verify::key_scope::Declarations,
) -> PathBuf {
    use access_authority_signer::adapters::{DirVault, SealedFactory, now_ms, serve};
    let dir = std::env::temp_dir().join(format!("acw-{name}-{}", std::process::id()));
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
            now_ms(),
        )
        .unwrap(),
    ));
    let socket = dir.join("a.sock");
    let uid = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&dir).unwrap());
    tokio::spawn(serve(
        tokio::net::UnixListener::bind(&socket).unwrap(),
        Arc::clone(&service),
        vec![uid],
        now_ms,
    ));
    let mut template = access_authority_signer::domain::default_template(d);
    template.declared = declared;
    let open = AuthorityRequest::Open(Box::new(template));
    assert_eq!(
        authority_call(&socket, &open).await.unwrap(),
        AuthorityResponse::Opened
    );
    for _ in 0..2 {
        service.lock().unwrap().tick(now_ms(), 1);
    }
    socket
}

/// The binding key the test signer's binding store holds.
fn binding_key(d: Digest) -> [u8; 32] {
    use access_authority_signer::ports::Bindings as _;
    let suiss_crypto::cose::PublicKey::Ed25519(k) = SoftBinding.binding(&d).unwrap().public_key()
    else {
        panic!("ed25519 binding");
    };
    k
}

/// The Domain Metadata declarations naming `witnesses` with their operators and the domain's
/// independence statement, and the default MMD (OP-158 m.6 (e)).
fn declare(witnesses: &[(&Witness, &str, bool)]) -> access_kernel::verify::key_scope::Declarations {
    let mut d = access_authority_signer::domain::declared_default();
    for (w, operator, independent) in witnesses {
        let (name, rest) = w.vkey.split_once('+').unwrap();
        let b64 = rest.split_once('+').unwrap().1;
        let raw = suiss_crypto::note::base64_decode(b64).unwrap();
        let key: [u8; 32] = raw[1..].try_into().unwrap();
        d.witnesses
            .push(access_kernel::verify::key_scope::Witness::new(
                name.to_owned(),
                suiss_crypto::cose::PublicKey::Ed25519(key),
                suiss_crypto::cose::Algorithm::Ed25519,
                (*operator).to_owned(),
                *independent,
            ));
    }
    d
}

// CMP-6, T16, T17, SEC23, SI-12, B13, U9, HL-7, TI-RT2, OP-38, OP-158 m.3 (c), (d), (k)
#[tokio::test(flavor = "multi_thread")]
#[allow(
    clippy::too_many_lines,
    reason = "one walkthrough of the witness protocol"
)]
async fn real_witnesses_cosign_fence_off_a_dead_one_and_expose_equivocation() {
    let db = fresh().await.unwrap();
    let mut log = Log::create(&db).await;
    let d = log.domain;
    log.push(&db, 1, wall() - 30_000).await;
    let key = binding_key(d);
    let root = std::env::temp_dir().join(format!("aw-proc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let mut independent = Witness::start(
        &witness_bin(),
        &root,
        ("w-independent", "Example Witness Ltd"),
        d.0,
        key,
    )
    .unwrap();
    let own = Witness::start(&witness_bin(), &root, ("w-own", "Suiss"), d.0, key).unwrap();
    // OP-158 m.6 (e)
    let declared = declare(&[
        (&independent, "Example Witness Ltd", true),
        (&own, "Suiss", false),
    ]);
    let socket = wall_signer("witnesses", d, declared).await;
    let (heads, signer) = (PgHeads(db.app.clone()), SocketSigner::new(socket));
    let sink = root.join("sink");
    let mut publisher = Publisher {
        targets: vec![
            target(&independent, "Example Witness Ltd"),
            target(&own, "Suiss"),
        ],
        sinks: vec![sink.clone()],
    };
    let pools = (&db.app, &db.sequencer);
    let mut cadence = Cadence::default();

    // T16
    let (row, out) = domain_step(
        (&heads, &signer, &publisher),
        pools,
        (d, &mut cadence),
        wall(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(row.size, 2);
    assert_eq!((out.cosigned, out.independent), (2, 1), "{out:?}");
    // SI-12, B13
    let kept = cosigns(&db.app, &log.id, row.size, &row.root)
        .await
        .unwrap();
    assert_eq!(kept.iter().filter(|c| c.independent).count(), 1);
    assert_eq!(witnessed_through(&db.app, &log.id).await.unwrap(), 2);
    assert_eq!(board().witnessed(&d), 2);
    assert_eq!(independent.cosigned(d.0).unwrap(), [2]);
    assert_eq!(
        std::fs::read_dir(sink.join(access_kernel::json::b64url_encode(&d.0)))
            .unwrap()
            .count(),
        2
    );
    // TI-RT2
    assert_eq!(time_check(), Ok(()));
    assert!(
        domain_step(
            (&heads, &signer, &publisher),
            pools,
            (d, &mut cadence),
            wall()
        )
        .await
        .unwrap()
        .is_none(),
        "nothing due before the interval"
    );

    // OP-38, SEC23
    log.push(&db, 3, wall() - 20_000).await;
    board().want(d, 4);
    board().want(d, log.size());
    let (row, out) = domain_step(
        (&heads, &signer, &publisher),
        pools,
        (d, &mut cadence),
        wall(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!((row.size, out.independent), (5, 1), "{out:?}");
    assert_eq!(board().wanted(&d), None);
    assert_eq!(board().wait(d, 5, Duration::from_millis(10)).await, Ok(5));

    // SEC23
    independent.kill().unwrap();
    log.push(&db, 2, wall() - 10_000).await;
    let (row, out) = domain_step(
        (&heads, &signer, &publisher),
        pools,
        (d, &mut Cadence::default().resume(5, 0)),
        wall(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        (row.size, out.cosigned, out.independent),
        (7, 1, 0),
        "{out:?}"
    );
    assert_eq!(witnessed_through(&db.app, &log.id).await.unwrap(), 5);
    assert_eq!(
        board().wait(d, 7, Duration::from_millis(200)).await,
        Err(5),
        "ack pending without an independent cosignature"
    );

    independent.restart().unwrap();
    publisher.targets[0] = target(&independent, "Example Witness Ltd");
    let (row, out) = domain_step(
        (&heads, &signer, &publisher),
        pools,
        (d, &mut Cadence::default().resume(7, 0)),
        wall(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!((row.size, out.independent), (7, 1), "{out:?}");
    assert_eq!(board().wait(d, 7, Duration::from_millis(10)).await, Ok(7));
    assert_eq!(independent.cosigned(d.0).unwrap(), [2, 5, 7]);

    // U9, HL-7
    let elsewhere = root.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let third = Witness::start(
        &witness_bin(),
        &elsewhere,
        ("w-third", "Other Witness Ltd"),
        d.0,
        key,
    )
    .unwrap();
    let real = access_store::witness::checkpoint_of_size(&db.app, &log.id, 7)
        .await
        .unwrap()
        .unwrap();
    let mut body = Checkpoint::parse(&parse_note(&real.note).unwrap().body).unwrap();
    body.root = suiss_crypto::digest::sha256(b"another tree");
    let text = body.to_body().unwrap();
    let noted = DomainSigner::sign_note(
        &signer,
        d,
        text.clone(),
        access_authority_sequencer::checkpoint::extensions(&body)
            .unwrap()
            .issued_at,
    )
    .await
    .unwrap();
    let forged = format!("{text}\n{}", noted.line);
    let third_target = target(&third, "Other Witness Ltd");
    access_authority_sequencer::witness::add_checkpoint(
        &third_target,
        &d,
        (None, &[]),
        &forged,
        &noted.excerpt,
    )
    .await
    .unwrap();
    let real_body = Checkpoint::parse(&parse_note(&real.note).unwrap().body).unwrap();
    let refused = access_authority_sequencer::witness::add_checkpoint(
        &publisher.targets[1],
        &d,
        (Some((7, real_body.root)), &[]),
        &forged,
        &noted.excerpt,
    )
    .await;
    assert_eq!(
        refused,
        Err(access_authority_sequencer::witness::WitnessError::Said(
            suiss_ledger::checkpoint::witness::Refused::Inconsistent,
            409
        ))
    );
    assert_eq!(own.refused(d.0).unwrap(), 1);
    let monitored = Publisher {
        targets: vec![target(&independent, "Example Witness Ltd"), third_target],
        sinks: vec![],
    };
    assert!(gossip(&monitored, pools, d, wall()).await >= 1);
    assert!(equivocations(&db.app, &log.id).await.unwrap() >= 1);
    let monitor = root.join("monitor.conf");
    std::fs::write(
        &monitor,
        format!(
            "domain {}\nwitness {} {}\nwitness {} {}\n",
            access_kernel::json::b64url_encode(&d.0),
            independent.url,
            independent.vkey,
            third.url,
            third.vkey
        ),
    )
    .unwrap();
    let out = Command::new(witness_bin())
        .args(["monitor", monitor.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3), "{out:?}");
    let printed = String::from_utf8_lossy(&out.stdout);
    assert!(
        printed.contains("equivocation size 7") && printed.contains("\nproof "),
        "{printed}"
    );

    // U11
    let mut own = own;
    own.fence(d.0, 7).unwrap();
    publisher.targets[1] = target(&own, "Suiss");

    // TI-RT2
    log.push(&db, 1, wall() + 120_000).await;
    let (row, out) = domain_step(
        (&heads, &signer, &publisher),
        pools,
        (d, &mut Cadence::default().resume(7, 0)),
        wall(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        (row.size, out.independent, out.cosigned),
        (8, 1, 1),
        "{out:?}"
    );
    assert!(
        out.failed.iter().any(|(url, e)| *url == own.url
            && *e
                == access_authority_sequencer::witness::WitnessError::Said(
                    suiss_ledger::checkpoint::witness::Refused::Fenced,
                    403
                )),
        "{out:?}"
    );
    assert_eq!(own.cosigned(d.0).unwrap(), [2, 5, 7, 7]);
    assert_eq!(
        time_check(),
        Err(suiss_ledger::time::TimeError::AheadOfWitness)
    );
    let mut clock = SourcesClock::new(db.sequencer.clone());
    assert!(matches!(
        access_authority_sequencer::ports::Clock::now(&mut clock).await,
        Err(access_authority_sequencer::SequencerError::Time(
            suiss_ledger::time::TimeError::AheadOfWitness
        ))
    ));
    assert!(clock.sources().await.is_ok());
    drop((own, third));
    let _ = std::fs::remove_dir_all(&root);
}

/// The log's `vkey` from a checkpoint's key excerpt.
pub(super) fn log_vkey(origin: &str, excerpt: &[u8]) -> String {
    let sign1 = suiss_crypto::cose::parse_sign1(excerpt).unwrap();
    let ex =
        access_kernel::verify::key_scope::KeyExcerpt::from_bytes(sign1.payload.as_deref().unwrap())
            .unwrap();
    let suiss_crypto::cose::PublicKey::Ed25519(k) = ex.key.key else {
        panic!("ed25519");
    };
    suiss_crypto::note::Verifier::ed25519(origin, k)
        .unwrap()
        .to_vkey()
}

async fn http(router: axum::Router, uri: &str, pep: bool) -> (axum::http::StatusCode, Vec<u8>) {
    use tower::ServiceExt as _;
    let mut req = axum::http::Request::get(uri)
        .body(axum::body::Body::empty())
        .unwrap();
    if pep {
        req.extensions_mut()
            .insert(access_http::adp::adapters::Pep("pep-w2".into()));
    }
    let r = router.oneshot(req).await.unwrap();
    let status = r.status();
    let body = axum::body::to_bytes(r.into_body(), 1 << 22).await.unwrap();
    (status, body.to_vec())
}

fn verify(args: &[&str]) -> (bool, String) {
    let out = Command::new(bin("esuiss-access-verify", "access-verify"))
        .args(args)
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

// T19, §17.6.1 rule 5, U21, U49, TI-RT5, P18, U9, HL-7
#[tokio::test(flavor = "multi_thread")]
#[allow(
    clippy::too_many_lines,
    reason = "one walkthrough of the bundle and its checks"
)]
async fn a_witnessed_bundle_opens_only_artifacts_and_dates_the_record() {
    let db = fresh().await.unwrap();
    let mut log = Log::create(&db).await;
    let d = log.domain;
    let artifact = suiss_crypto::digest::sha256(&wall().to_be_bytes());
    log.push_record(&db, artifact, wall() - 30_000).await;
    log.push_record(
        &db,
        suiss_crypto::digest::sha256(&artifact),
        wall() - 20_000,
    )
    .await;
    let key = binding_key(d);
    let root = std::env::temp_dir().join(format!("aw-bundle-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let witness = Witness::start(
        &witness_bin(),
        &root,
        ("w-only", "Example Witness Ltd"),
        d.0,
        key,
    )
    .unwrap();
    let socket = wall_signer(
        "bundle",
        d,
        declare(&[(&witness, "Example Witness Ltd", true)]),
    )
    .await;
    let (heads, signer) = (PgHeads(db.app.clone()), SocketSigner::new(socket));
    let target = target(&witness, "Example Witness Ltd");
    let publisher = Publisher {
        targets: vec![target.clone()],
        sinks: vec![],
    };
    let pools = (&db.app, &db.sequencer);
    let (row, out) = domain_step(
        (&heads, &signer, &publisher),
        pools,
        (d, &mut Cadence::default()),
        wall(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!((row.size, out.independent), (3, 1), "{out:?}");
    let router = || {
        access_http::transparency::router(crate::transparency::PgCheckpoints {
            app: db.app.clone(),
            witnesses: vec![target.clone()],
        })
    };
    let origin = access_authority_sequencer::checkpoint::origin(&d);

    // §9.16, P32
    let (status, body) = http(
        router(),
        &format!("/access/v1/domains/{origin}/checkpoints"),
        false,
    )
    .await;
    assert_eq!(status, 200);
    let listing: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(listing["witnessed_through"], 3);
    assert_eq!(listing["claims"]["equivocation_detectable"], false);
    let note = listing["checkpoint"]["note"].as_str().unwrap().to_owned();
    let vkey = log_vkey(&origin, &row.excerpt);
    // U49
    let note_file = root.join("checkpoint.note");
    std::fs::write(&note_file, &note).unwrap();
    let (ok, text) = verify(&[
        "checkpoint",
        "--note",
        note_file.to_str().unwrap(),
        "--origin",
        &origin,
        "--log",
        &vkey,
        "--cosigners",
        &witness.vkey,
    ]);
    assert!(ok && text.contains("size: 3"), "{text}");

    // K15
    let (status, tile) = http(
        router(),
        &format!("/access/v1/domains/{origin}/tile/0/000.p/3"),
        false,
    )
    .await;
    assert_eq!(status, 200);
    let hashes: Vec<[u8; 32]> = tile.chunks(32).map(|c| c.try_into().unwrap()).collect();
    let mut rebuilt = Frontier::default();
    for h in &hashes {
        rebuilt.push(*h).unwrap();
    }
    assert_eq!(rebuilt.root(), row.root);
    assert_eq!(
        http(
            router(),
            &format!("/access/v1/domains/{origin}/tile/0/000.p/4"),
            false
        )
        .await
        .0,
        404
    );
    // T19
    let uri = format!("/access/v1/domains/{origin}/checkpoints/3/inclusion/1");
    assert_eq!(http(router(), &uri, false).await.0, 401);
    assert_eq!(
        http(
            router(),
            &format!("/access/v1/domains/{origin}/checkpoints/9/inclusion/1"),
            true
        )
        .await
        .0,
        409
    );
    let (status, bundle) = http(router(), &uri, true).await;
    assert_eq!(status, 200);
    let bundle_file = root.join("bundle.cbor");
    std::fs::write(&bundle_file, &bundle).unwrap();
    let decoded =
        suiss_crypto::dcbor::decode(&bundle, suiss_crypto::dcbor::Limits::CEILING).unwrap();
    let Some(suiss_crypto::dcbor::Value::Bytes(disclosure)) = decoded.get("record") else {
        panic!("record");
    };
    let disclosure = access_kernel::record::Disclosure::from_bytes(disclosure).unwrap();
    assert_eq!(disclosure.opened.keys().collect::<Vec<_>>(), ["artifacts"]);
    assert!(disclosure.withheld.contains_key("secret"));

    // U21
    let now_s = wall() / 1000;
    let existed = |before: u64| {
        verify(&[
            "existed",
            "--bundle",
            bundle_file.to_str().unwrap(),
            "--origin",
            &origin,
            "--log",
            &vkey,
            "--cosigners",
            &witness.vkey,
            "--before",
            &before.to_string(),
        ])
    };
    let (ok, text) = existed(now_s + 5);
    assert!(
        ok && text.contains("pos: 1") && text.contains("opened: artifacts"),
        "{text}"
    );
    let (ok, text) = existed(now_s - 3_600);
    assert!(!ok && text.contains("reject: after"), "{text}");

    // TI-RT5, P18
    let metadata = DomainSigner::metadata(&signer, d).await.unwrap();
    let metadata_file = root.join("metadata.cose");
    std::fs::write(&metadata_file, &metadata).unwrap();
    let fresh = |now: u64| {
        verify(&[
            "fresh",
            "--metadata",
            metadata_file.to_str().unwrap(),
            "--note",
            note_file.to_str().unwrap(),
            "--origin",
            &origin,
            "--log",
            &vkey,
            "--cosigners",
            &witness.vkey,
            "--now",
            &now.to_string(),
        ])
    };
    let (ok, text) = fresh(wall());
    assert!(ok, "{text}");
    let (ok, text) = fresh(wall() + 2 * 3_600_000);
    assert!(!ok && text.contains("stale"), "{text}");
    drop(witness);
    let _ = std::fs::remove_dir_all(&root);
}
