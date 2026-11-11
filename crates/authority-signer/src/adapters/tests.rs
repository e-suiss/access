//! The adapters over a temporary directory and an in-process KEK.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};

use access_kernel::verify::key_scope::{KeyUsage, SpecVersions};
use suiss_crypto::envelope::SoftKek;
use suiss_crypto::rotation::Policy;

use super::*;
use crate::domain::Template;

struct Soft(Secret<Vec<u8>>);

impl Bindings for Soft {
    fn binding(&mut self, _: &Digest) -> Result<Box<dyn Signer + Send>, SignError> {
        Ok(Box::new(SoftSigner::ed25519_from_pkcs8(&self.0)?))
    }
}

fn template() -> Template {
    Template {
        domain: Digest([7; 32]),
        genesis: Digest([8; 32]),
        algorithms: BTreeSet::from([Algorithm::Ed25519]),
        operational_alg: Algorithm::Ed25519,
        operational_window_max_ms: 86_400_000,
        min_versions: SpecVersions::default(),
        adopted: SpecVersions::default(),
        caps: None,
        hybrid: None,
        discovery: None,
        declared: crate::domain::declared_default(),
    }
}

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("access-signer-{name}-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

// CR-21 m.3
#[test]
fn sealed_keys_open_only_under_their_kek() {
    let mut factory = SealedFactory::new(SoftKek::new("kek-1", [1; 32]));
    let g = factory.generate(Algorithm::Ed25519).unwrap();
    let loaded = factory.load(Algorithm::Ed25519, &g.sealed).unwrap();
    assert_eq!(loaded.public_key(), g.signer.public_key());
    let mut other = SealedFactory::new(SoftKek::new("kek-2", [2; 32]));
    assert!(other.load(Algorithm::Ed25519, &g.sealed).is_err());
}

// CMP-22, OP-143 m.4
#[tokio::test]
async fn the_socket_serves_declared_callers() {
    let dir = temp("vault");
    let (_, doc) = SoftSigner::generate_ed25519().unwrap();
    let policy = Policy {
        publish_lead_ms: 0,
        ..Policy::AUTHORITY
    };
    let service = Service::start(
        SealedFactory::new(SoftKek::new("kek-1", [1; 32])),
        Soft(doc),
        DirVault::new(&dir),
        policy,
        now_ms(),
    )
    .unwrap();
    let service = Arc::new(Mutex::new(service));
    let path = dir.join("signer.sock");
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).unwrap();
    let uid = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&dir).unwrap());
    tokio::spawn(serve(listener, Arc::clone(&service), vec![uid], now_ms));
    assert_eq!(
        call(&path, &Request::Open(Box::new(template())))
            .await
            .unwrap(),
        Response::Opened
    );
    for _ in 0..2 {
        service.lock().unwrap().tick(now_ms(), 1);
    }
    let Response::Metadata(m) = call(&path, &Request::Metadata(Digest([7; 32])))
        .await
        .unwrap()
    else {
        panic!("metadata");
    };
    assert_ne!(m, Vec::<u8>::new());
    let signed = call(
        &path,
        &Request::Sign {
            domain: Digest([7; 32]),
            usage: KeyUsage::Receipt,
            content_type: String::from("application/x"),
            payload: vec![1],
            at: now_ms(),
        },
    )
    .await
    .unwrap();
    assert!(matches!(signed, Response::Signed { .. }), "{signed:?}");
    assert_eq!(DirVault::new(&dir).all().unwrap().len(), 1);
}

type Started = Arc<Mutex<Service<SealedFactory<SoftKek>, Soft, DirVault>>>;

fn started(dir: &Path) -> Started {
    let (_, doc) = SoftSigner::generate_ed25519().unwrap();
    let service = Service::start(
        SealedFactory::new(SoftKek::new("kek-1", [1; 32])),
        Soft(doc),
        DirVault::new(dir),
        Policy::AUTHORITY,
        now_ms(),
    )
    .unwrap();
    Arc::new(Mutex::new(service))
}

// CMP-22, OP-143 m.4 (c)
#[tokio::test]
async fn undeclared_callers_get_no_answer() {
    let dir = temp("undeclared");
    let path = dir.join("signer.sock");
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).unwrap();
    let uid = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&dir).unwrap());
    tokio::spawn(serve(
        listener,
        started(&dir),
        vec![uid.wrapping_add(1)],
        now_ms,
    ));
    let answer = call(&path, &Request::Open(Box::new(template()))).await;
    assert!(answer.is_err(), "{answer:?}");
    assert_eq!(DirVault::new(&dir).all().unwrap(), Vec::<Vec<u8>>::new());
}

// CR-21, CMP-22
#[tokio::test]
async fn peer_credentials_name_the_connecting_process() {
    let dir = temp("peer");
    let path = dir.join("peer.sock");
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).unwrap();
    let uid = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&path).unwrap());
    let _client = UnixStream::connect(&path).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let cred = server.peer_cred().unwrap();
    assert_eq!(cred.uid(), uid);
    assert_eq!(cred.pid(), Some(i32::try_from(std::process::id()).unwrap()));
}

static FRAME_SENT: AtomicBool = AtomicBool::new(false);
static READ_EARLY: AtomicBool = AtomicBool::new(false);

fn watched_clock() -> u64 {
    if !FRAME_SENT.load(Ordering::SeqCst) {
        READ_EARLY.store(true, Ordering::SeqCst);
    }
    now_ms()
}

// CR-25, CMP-22a
#[tokio::test]
async fn the_clock_is_read_after_the_frame() {
    let dir = temp("clock");
    let service = started(&dir);
    let (mut server, mut client) = UnixStream::pair().unwrap();
    let answering =
        tokio::spawn(
            async move { answer(&mut server, &service, watched_clock, READ_TIMEOUT).await },
        );
    tokio::task::yield_now().await;
    FRAME_SENT.store(true, Ordering::SeqCst);
    let frame = protocol::encode_request_traced(&Request::Metadata(Digest([7; 32])), None).unwrap();
    client.write_all(&frame).await.unwrap();
    answering.await.unwrap().unwrap();
    let mut header = [0_u8; 4];
    client.read_exact(&mut header).await.unwrap();
    assert!(!READ_EARLY.load(Ordering::SeqCst));
}

// CMP-22a
#[tokio::test]
async fn a_silent_caller_times_out() {
    let dir = temp("silent");
    let service = started(&dir);
    let (mut server, mut client) = UnixStream::pair().unwrap();
    client.write_all(&[0, 0]).await.unwrap();
    let answered = answer(&mut server, &service, now_ms, Duration::from_millis(20)).await;
    assert_eq!(
        answered.map_err(|e| e.kind()),
        Err(std::io::ErrorKind::TimedOut)
    );
}

struct HeapPages(Vec<u8>);

impl suiss_crypto::signer::KeyPages for HeapPages {
    fn expose(&self, f: &mut dyn FnMut(&[u8])) {
        f(&self.0);
    }
}

// SAI-45, CR-34, OP-158
#[test]
fn a_paged_factory_signs_from_protected_pages_and_fails_closed_when_full() {
    let room = Arc::new(std::sync::atomic::AtomicUsize::new(2));
    let left = Arc::clone(&room);
    let pager: Arc<Pager> = Arc::new(move |doc: &[u8]| {
        let had = left.load(Ordering::SeqCst);
        (had > 0).then(|| {
            left.store(had - 1, Ordering::SeqCst);
            Box::new(HeapPages(doc.to_vec())) as Box<dyn suiss_crypto::signer::KeyPages>
        })
    });
    let mut factory = SealedFactory::new(SoftKek::new("kek-1", [1; 32])).with_pager(pager);
    let g = factory.generate(Algorithm::Ed25519).unwrap();
    let loaded = factory.load(Algorithm::Ed25519, &g.sealed).unwrap();
    assert_eq!(loaded.public_key(), g.signer.public_key());
    assert_eq!(loaded.sign(b"m").unwrap(), g.signer.sign(b"m").unwrap());
    assert_eq!(room.load(Ordering::SeqCst), 0);
    assert!(factory.generate(Algorithm::Esp256).is_err());
    assert!(factory.generate(Algorithm::MlDsa65).is_err());
}
