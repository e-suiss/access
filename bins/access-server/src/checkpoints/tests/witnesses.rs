//! Real `access-witness` processes against this server's checkpointer on real Postgres and a
//! real authority signer (OP-158 m.5, OP-153 m.3 (gg)): cosigning with consistency proofs,
//! independence, out-of-cycle and coalesced checkpoints, the fail-closed path when a witness is
//! killed, the witnesses' own state on disk, gossip and equivocation, and the time cross-check.

use std::io::BufRead as _;
use std::path::Path;
use std::process::{Child, Command, Stdio};

use access_authority_sequencer::witness::{Target, board, time_check};
use access_kernel::verify::key_scope::DomainMetadata;
use access_store::authority::Lease;
use access_store::witness::{cosigns, equivocations, witnessed_through};
use suiss_ledger::checkpoint::cadence::Cadence;
use suiss_ledger::merkle::Frontier;

use super::*;
use crate::checkpoints::publish::{Publisher, gossip};

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

struct Witness {
    child: Child,
    url: String,
    vkey: String,
    config: PathBuf,
    state: PathBuf,
}

impl Witness {
    fn keygen(root: &Path, name: &str) -> (PathBuf, String) {
        let key = root.join(format!("{name}.pk8"));
        let out = Command::new(witness_bin())
            .args(["keygen", key.to_str().unwrap(), name])
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        let text = String::from_utf8(out.stdout).unwrap();
        (key, text.trim().strip_prefix("vkey ").unwrap().to_owned())
    }

    fn start(root: &Path, name: &str, operator: &str, domain: Digest, binding: [u8; 32]) -> Self {
        let (key, vkey) = Self::keygen(root, name);
        let state = root.join(format!("{name}-state"));
        let config = root.join(format!("{name}.conf"));
        std::fs::write(
            &config,
            format!(
                "name {name}\nkey {}\nstate {}\nlisten 127.0.0.1:0\noperator {operator}\nlog {} {}\n",
                key.display(),
                state.display(),
                access_kernel::json::b64url_encode(&domain.0),
                access_kernel::json::b64url_encode(&binding),
            ),
        )
        .unwrap();
        Self::spawn(config, state, vkey)
    }

    fn spawn(config: PathBuf, state: PathBuf, vkey: String) -> Self {
        let mut child = Command::new(witness_bin())
            .args(["serve", config.to_str().unwrap()])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = std::io::BufReader::new(stdout).read_line(&mut line);
            let _ = tx.send(line);
        });
        let line = rx.recv_timeout(Duration::from_secs(30)).unwrap();
        let addr = line.trim().strip_prefix("listening ").unwrap().to_owned();
        Self {
            child,
            url: format!("http://{addr}"),
            vkey,
            config,
            state,
        }
    }

    /// SIGKILL, then the same configuration and state again on a new port.
    fn kill(&mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }

    fn restart(self) -> Self {
        let text = std::fs::read_to_string(&self.config).unwrap();
        std::fs::write(&self.config, text).unwrap();
        Self::spawn(self.config.clone(), self.state.clone(), self.vkey.clone())
    }

    fn target(&self, operator: &str) -> Target {
        Target::new(&self.url, &self.vkey, operator, "Suiss").unwrap()
    }

    fn chain(&self, domain: Digest) -> String {
        std::fs::read_to_string(self.state.join(format!(
            "{}.chain",
            access_kernel::json::b64url_encode(&domain.0)
        )))
        .unwrap_or_default()
    }
}

impl Drop for Witness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
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
            effects: vec![],
        };
        commit_batch(&db.sequencer, &self.id, [0x31; 16], &batch)
            .await
            .unwrap();
    }
}

/// A real authority signer on the wall clock with `d`'s keyring open.
async fn wall_signer(name: &str, d: Digest) -> PathBuf {
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
    let open = AuthorityRequest::Open(Box::new(access_authority_signer::domain::default_template(
        d,
    )));
    assert_eq!(
        authority_call(&socket, &open).await.unwrap(),
        AuthorityResponse::Opened
    );
    for _ in 0..2 {
        service.lock().unwrap().tick(now_ms(), 1);
    }
    socket
}

/// The binding key the signer's Domain Metadata names.
async fn binding(signer: &SocketSigner, d: Digest) -> [u8; 32] {
    let bytes = DomainSigner::metadata(signer, d).await.unwrap();
    let sign1 = suiss_crypto::cose::parse_sign1(&bytes).unwrap();
    let md = DomainMetadata::from_bytes(sign1.payload.as_deref().unwrap()).unwrap();
    let key = md.binding.values().next().unwrap();
    let suiss_crypto::cose::PublicKey::Ed25519(k) = key.key else {
        panic!("ed25519 binding");
    };
    k
}

// CMP-6, T16, T17, SEC23, SI-12, B13, U9, HL-7, TI-RT2, OP-38, OP-158 m.3 (c), (d), (k);
// Ek B 5839, 5840, 5842, 5843, 5844, 5845, 5893, 6082, 6106
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
    let socket = wall_signer("witnesses", d).await;
    let (heads, signer) = (PgHeads(db.app.clone()), SocketSigner::new(socket));
    let key = binding(&signer, d).await;
    let root = std::env::temp_dir().join(format!("aw-proc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let mut independent = Witness::start(&root, "w-independent", "Example Witness Ltd", d, key);
    let own = Witness::start(&root, "w-own", "Suiss", d, key);
    let sink = root.join("sink");
    let mut publisher = Publisher {
        targets: vec![
            independent.target("Example Witness Ltd"),
            own.target("Suiss"),
        ],
        sinks: vec![sink.clone()],
    };
    let pools = (&db.app, &db.sequencer);
    let mut cadence = Cadence::default();

    // T16: the first checkpoint, cosigned by both from size 0
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
    // SI-12, B13, 6082: the provider operator's own witness does not count
    let kept = cosigns(&db.app, &log.id, row.issued_at).await.unwrap();
    assert_eq!(kept.iter().filter(|c| c.independent).count(), 1);
    assert_eq!(witnessed_through(&db.app, &log.id).await.unwrap(), 2);
    assert_eq!(board().witnessed(&d), 2);
    assert!(independent.chain(d).contains(" cosigned 2 "));
    assert_eq!(
        std::fs::read_dir(sink.join(access_kernel::json::b64url_encode(&d.0)))
            .unwrap()
            .count(),
        2
    );
    // TI-RT2: records older than the cosignature leave the gate open
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

    // OP-38, SEC23: two waiting commits, one out-of-cycle checkpoint with a consistency proof
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

    // SEC23 fail closed: the independent witness is killed; the own one alone is no ack
    independent.kill();
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

    // the witness comes back from its own state and cosigns from its base
    let independent = independent.restart();
    publisher.targets[0] = independent.target("Example Witness Ltd");
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
    let chain = independent.chain(d);
    assert!(
        chain.contains(" cosigned 5 ") && chain.contains(" cosigned 7 "),
        "{chain}"
    );

    // U9, HL-7: the provider shows a third witness another tree of the same size
    let elsewhere = root.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let third = Witness::start(&elsewhere, "w-third", "Other Witness Ltd", d, key);
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
    let metadata = DomainSigner::metadata(&signer, d).await.unwrap();
    let third_target = third.target("Other Witness Ltd");
    access_authority_sequencer::witness::add_checkpoint(
        &third_target,
        (0, &[]),
        &forged,
        &noted.excerpt,
        &metadata,
    )
    .await
    .unwrap();
    // the honest witnesses refuse it: the own one keeps it as evidence in its chain
    let refused = access_authority_sequencer::witness::add_checkpoint(
        &publisher.targets[1],
        (7, &[]),
        &forged,
        &noted.excerpt,
        &metadata,
    )
    .await;
    assert_eq!(
        refused,
        Err(access_authority_sequencer::witness::WitnessError::Conflict(
            7
        ))
    );
    assert!(own.chain(d).contains(" equivocation "));
    // gossip: the server's monitor keeps signed evidence
    let monitored = Publisher {
        targets: vec![independent.target("Example Witness Ltd"), third_target],
        sinks: vec![],
    };
    assert!(gossip(&monitored, pools, d, wall()).await >= 1);
    assert!(equivocations(&db.app, &log.id).await.unwrap() >= 1);
    // and the open monitor of the witness binary finds it too
    let out = Command::new(witness_bin())
        .args([
            "monitor",
            &access_kernel::json::b64url_encode(&d.0),
            &independent.url,
            &independent.vkey,
            &third.url,
            &third.vkey,
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stdout).contains("equivocation size 7"));

    // TI-RT2, 6106: a record newer than the witness's clock closes the commit gate
    log.push(&db, 1, wall() + 120_000).await;
    domain_step(
        (&heads, &signer, &publisher),
        pools,
        (d, &mut Cadence::default().resume(7, 0)),
        wall(),
    )
    .await
    .unwrap()
    .unwrap();
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
fn log_vkey(origin: &str, excerpt: &[u8]) -> String {
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

// T19, §17.6.1 rule 5, U21, U49, TI-RT5, P18, U9, HL-7; Ek B 5779, 5829, 5834, 5846, 5849,
// 5893, 5945, 6074
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines, reason = "one walkthrough of the bundle and its checks")]
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
    let socket = wall_signer("bundle", d).await;
    let (heads, signer) = (PgHeads(db.app.clone()), SocketSigner::new(socket));
    let key = binding(&signer, d).await;
    let root = std::env::temp_dir().join(format!("aw-bundle-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let witness = Witness::start(&root, "w-only", "Example Witness Ltd", d, key);
    let target = witness.target("Example Witness Ltd");
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

    // §9.16, P32, 6074: anyone may copy the witnessed checkpoint; one witness claims nothing
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
    // U49: the cosigned checkpoint verifies with the witness keys alone
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

    // T19: a PEP gets the bundle of position 1, `artifacts` open and nothing else
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
    let Some(suiss_crypto::dcbor::Value::Bytes(disclosure)) = decoded.get("disclosure") else {
        panic!("disclosure");
    };
    let disclosure = access_kernel::record::Disclosure::from_bytes(disclosure).unwrap();
    assert_eq!(disclosure.opened.keys().collect::<Vec<_>>(), ["artifacts"]);
    assert!(disclosure.withheld.contains_key("secret"));

    // U21: it existed by the witness's cosignature, and not before it
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

    // TI-RT5, P18, 5945: the metadata is fresh by the cosignature, not by its own iat
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
