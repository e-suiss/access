//! Token Status Lists against a real PostgreSQL and an in-process authority signer: a family
//! takes an entry, its revocation sets it, the publisher signs the list with the position it
//! reflects, and a verifier reads the bit under the domain's `status-list` key.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::time::Duration;

use access_authority_core::status::adapters::{PgLists, SignerSocket, open_family};
use access_authority_core::status::{CAPACITY, Publisher, list_uri};
use access_kernel::digest::Digest;
use access_kernel::status::{CWT_CONTENT_TYPE, ListToken, StatusRef, lookup};
use access_kernel::verify::PureBackend;
use access_kernel::verify::cose::verify_sign1;
use access_kernel::verify::key_scope::{DomainMetadata, KeyUsage, operational_key};
use access_store::authority::{
    CommitBatch, HeadRow, LogRecord, acquire_lease, commit_batch, create_domain,
};
use access_store::projections::{Family, family, revoke_family};
use access_store::scope::DomainId;
use access_store::status::{latest, lists, open_family_with_entry};
use access_store::testing::{TestDb, fresh};

const TENANT: [u8; 16] = [0x01, 0x9a, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 9];
const NOW: u64 = 10_000;
const API: &str = "https://api.example";

/// A domain whose head is at position 3, recorded at `NOW + 5 s`.
async fn domain(db: &TestDb, seed: u8) -> Digest {
    let d = DomainId::from_bytes([seed; 32]);
    let genesis = LogRecord {
        pos: 0,
        kind: "genesis",
        recorded_at: NOW,
        leaf_hash: [seed; 32],
        envelope: vec![0xa0],
    };
    create_domain(&db.sequencer, &d, TENANT, &genesis, &[])
        .await
        .unwrap();
    let (lease, head) = acquire_lease(&db.sequencer, &d, "a", Duration::from_secs(10))
        .await
        .unwrap();
    let records = (1..=3)
        .map(|pos| LogRecord {
            pos,
            kind: "claim",
            recorded_at: NOW + 5_000,
            leaf_hash: [0x80 + u8::try_from(pos).unwrap(); 32],
            envelope: vec![0xa1, u8::try_from(pos).unwrap()],
        })
        .collect();
    let batch = CommitBatch {
        epoch: lease.epoch,
        after: head.pos,
        records,
        head: HeadRow {
            pos: 3,
            epoch: lease.epoch,
            leaf_hash: [0x83; 32],
            recorded_at: NOW + 5_000,
            frontier: vec![[0x83; 32]],
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
    commit_batch(&db.sequencer, &d, TENANT, &batch)
        .await
        .unwrap();
    Digest([seed; 32])
}

fn fam(n: u8) -> Family {
    Family {
        family: [n; 16],
        client_id: String::from("cli_x"),
        holder: [4; 16],
        root_exercise: [n; 32],
        status: None,
        revoked_pos: None,
    }
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

type SignerService = std::sync::Arc<
    std::sync::Mutex<
        access_authority_signer::service::Service<
            access_authority_signer::adapters::SealedFactory<suiss_crypto::envelope::SoftKek>,
            SoftBinding,
            access_authority_signer::adapters::DirVault,
        >,
    >,
>;

/// An in-process signer on a socket of its own, at `NOW`, with `d`'s keyring open and its
/// first key active.
async fn start_signer(name: &str, d: Digest) -> (std::path::PathBuf, SignerService) {
    use access_authority_signer::adapters::{DirVault, SealedFactory, call, serve};
    use access_authority_signer::protocol::{Request, Response};
    let dir = std::env::temp_dir().join(format!("access-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let policy = suiss_crypto::rotation::Policy {
        publish_lead_ms: 0,
        ..suiss_crypto::rotation::Policy::AUTHORITY
    };
    let service = std::sync::Arc::new(std::sync::Mutex::new(
        access_authority_signer::service::Service::start(
            SealedFactory::new(suiss_crypto::envelope::SoftKek::new("kek", [4; 32])),
            SoftBinding,
            DirVault::new(&dir),
            policy,
            NOW,
        )
        .unwrap(),
    ));
    let socket = dir.join("signer.sock");
    let _ = std::fs::remove_file(&socket);
    let uid = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&dir).unwrap());
    tokio::spawn(serve(
        tokio::net::UnixListener::bind(&socket).unwrap(),
        std::sync::Arc::clone(&service),
        vec![uid],
        || NOW,
    ));
    let open = Request::Open(Box::new(access_authority_signer::domain::default_template(
        d,
    )));
    assert_eq!(call(&socket, &open).await.unwrap(), Response::Opened);
    for _ in 0..2 {
        service.lock().unwrap().tick(NOW, 1);
    }
    (socket, service)
}

/// The domain's Domain Metadata from the signer, verified under the binding key.
async fn metadata(socket: &std::path::Path, d: Digest) -> DomainMetadata {
    use access_authority_signer::ports::Bindings as _;
    use access_authority_signer::protocol::{Request, Response};
    let Response::Metadata(bytes) =
        access_authority_signer::adapters::call(socket, &Request::Metadata(d))
            .await
            .unwrap()
    else {
        panic!("metadata");
    };
    let binding_key = SoftBinding.binding(&d).unwrap().public_key();
    let mut trusted = access_kernel::verify::cose::KeySet::default();
    trusted
        .insert(
            access_kernel::verify::key_scope::thumbprint(&binding_key),
            binding_key,
        )
        .unwrap();
    trusted
        .allowed
        .insert(access_kernel::verify::cose::Algorithm::Ed25519);
    access_kernel::verify::key_scope::verify_metadata(&PureBackend, &bytes, &trusted).unwrap()
}

// OP-150 m.3 (a), (s), (l), §11.20, T24, L2-STL-1, L2-STL-2, L2-STL-3: families take
// consecutive entries of one list; a revoked family's bit is set in the list the publisher signs
// under the status-list key, whose iat is the reflected position's recorded_at and whose as_of is
// that position; publishing again at the same head signs nothing
#[tokio::test]
async fn a_revoked_family_is_set_in_the_signed_list() {
    let db = fresh().await.unwrap();
    let d = domain(&db, 31).await;
    let (socket, _service) = start_signer("status-list", d).await;
    let mut entries = Vec::new();
    for n in 1..=3 {
        entries.push(
            open_family(&db.sequencer, API, d, &fam(n))
                .await
                .unwrap()
                .unwrap(),
        );
    }
    let uri = list_uri(API, &d, 0);
    assert_eq!(
        entries,
        vec![(uri.clone(), 0), (uri.clone(), 1), (uri.clone(), 2)]
    );
    assert_eq!(
        open_family(&db.sequencer, API, d, &fam(2)).await.unwrap(),
        None
    );
    let scope = DomainId::from_bytes(d.0);
    assert_eq!(
        family(&db.app, &scope, &[2; 16])
            .await
            .unwrap()
            .unwrap()
            .status,
        Some((uri.clone(), 1))
    );
    assert!(
        revoke_family(&db.sequencer, &scope, &[2; 16], 2)
            .await
            .unwrap()
    );

    let lists_ = PgLists {
        app: db.app.clone(),
        sequencer: db.sequencer.clone(),
    };
    let publisher = Publisher::new(lists_, SignerSocket(socket.clone()));
    let signed = publisher.publish(d, NOW).await.unwrap();
    assert_eq!(signed.len(), 1);
    assert_eq!(signed[0].as_of, 3);
    assert_eq!(publisher.publish(d, NOW).await.unwrap(), Vec::new());

    let p = latest(&db.app, &scope, &uri).await.unwrap().unwrap();
    assert_eq!((p.seq, p.applied_pos, p.iat_ms), (0, 3, NOW + 5_000));
    let md = metadata(&socket, d).await;
    let unverified = access_kernel::verify::cose::parse_sign1(&p.token)
        .unwrap()
        .payload
        .unwrap();
    let iat = ListToken::from_bytes(&unverified).unwrap().iat * 1_000;
    let key = operational_key(
        &PureBackend,
        &md,
        &d,
        p.excerpt.as_deref().unwrap(),
        KeyUsage::StatusList,
        iat,
    )
    .unwrap();
    let verified = verify_sign1(&PureBackend, &p.token, &key.key_set(), CWT_CONTENT_TYPE).unwrap();
    let t = ListToken::from_bytes(&verified.payload).unwrap();
    assert_eq!((t.uri.as_str(), t.as_of, t.iat), (uri.as_str(), 3, 15));
    let raw = miniz_oxide::inflate::decompress_to_vec_zlib(&t.lst).unwrap();
    assert_eq!(raw.len(), usize::try_from(CAPACITY / 8).unwrap());
    let set = |idx| {
        lookup(
            &t,
            &raw,
            &StatusRef {
                idx,
                uri: uri.clone(),
            },
        )
        .unwrap()
    };
    assert!(!set(0));
    assert!(set(1));
    assert!(!set(2));
}

// §11.20, OP-150 m.3 (a): a full list is followed by the next one, and concurrent openings
// never share an entry
#[tokio::test]
async fn entries_are_unique_and_lists_roll_over() {
    let db = fresh().await.unwrap();
    let d = domain(&db, 32).await;
    let scope = DomainId::from_bytes(d.0);
    let mut tasks = Vec::new();
    for n in 1..=9_u8 {
        let pool = db.sequencer.clone();
        tasks.push(tokio::spawn(async move {
            open_family_with_entry(&pool, &DomainId::from_bytes(d.0), &fam(n), 4, |k| {
                list_uri(API, &d, k)
            })
            .await
            .unwrap()
            .unwrap()
        }));
    }
    let mut got = Vec::new();
    for t in tasks {
        got.push(t.await.unwrap());
    }
    got.sort();
    let mut want: Vec<(String, u64)> = (0..9)
        .map(|i: u64| (list_uri(API, &d, i / 4), i % 4))
        .collect();
    want.sort();
    assert_eq!(got, want);
    let all = lists(&db.app, &scope).await.unwrap();
    assert_eq!(
        all.iter()
            .map(|l| (l.list_no, l.allocated))
            .collect::<Vec<_>>(),
        vec![(0, 4), (1, 4), (2, 1)]
    );
}

// §9.9.3 k.6, P50, §9.16, OP-150 m.3 (a): ending a holder revokes its live families once, sets
// their entries and gives one projection-invalidated event per family, keyed by the family's
// first projection.issue; another holder's family is untouched
#[tokio::test]
async fn ending_a_holder_invalidates_its_families_once() {
    use access_authority_core::status::adapters::revoke_holder;
    use access_internal_api::events::{Kind, Source, Subject};
    let db = fresh().await.unwrap();
    let d = domain(&db, 33).await;
    let scope = DomainId::from_bytes(d.0);
    for n in 1..=3 {
        let mut f = fam(n);
        if n == 3 {
            f.holder = [8; 16];
        }
        open_family(&db.sequencer, API, d, &f).await.unwrap();
    }
    let source = Source::Exercise(Digest([0xee; 32]));
    let events = revoke_holder(&db.sequencer, d, &[4; 16], (2, source, NOW))
        .await
        .unwrap();
    assert_eq!(
        events
            .iter()
            .map(|e| (e.kind, e.subject, e.source, e.at))
            .collect::<Vec<_>>(),
        vec![
            (
                Kind::ProjectionInvalidated,
                Subject::Projection(Digest([1; 32])),
                source,
                NOW
            ),
            (
                Kind::ProjectionInvalidated,
                Subject::Projection(Digest([2; 32])),
                source,
                NOW
            ),
        ]
    );
    assert_eq!(
        revoke_holder(&db.sequencer, d, &[4; 16], (3, source, NOW))
            .await
            .unwrap(),
        Vec::new()
    );
    let snap = access_store::status::snapshot(&db.app, &scope, &list_uri(API, &d, 0))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(snap.revoked, vec![0, 1]);
    assert_eq!(
        family(&db.app, &scope, &[3; 16])
            .await
            .unwrap()
            .unwrap()
            .revoked_pos,
        None
    );
}
