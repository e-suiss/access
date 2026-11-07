use suiss_crypto::envelope::SoftKek;
use suiss_crypto::rotation::Policy;

use super::*;
use crate::app::Keyring;

// CR-21 m.3: a sealed realm key loads back under the same KEK and not under another
#[test]
fn sealed_keys_open_only_under_their_kek() {
    let mut factory = SealedFactory::new(SoftKek::new("realm-kek-1", [1; 32]));
    for alg in [JwsAlg::Es256, JwsAlg::Ed25519] {
        let g = factory.generate(alg).unwrap();
        let loaded = factory.load(alg, &g.sealed).unwrap();
        assert_eq!(loaded.public_key(), g.signer.public_key());
        let mut other = SealedFactory::new(SoftKek::new("realm-kek-2", [2; 32]));
        assert!(other.load(alg, &g.sealed).is_err());
    }
}

// CR-23: a restarted signer loads its sealed keys back and signs on with the same key
#[test]
fn a_restart_signs_with_the_same_key() {
    let mut factory = SealedFactory::new(SoftKek::new("realm-kek-1", [1; 32]));
    let mut ring = Keyring::new(JwsAlg::Es256, Policy::REALM).unwrap();
    let mut now = 0;
    while now <= Policy::REALM.publish_lead_ms + 60_000 {
        let _ = ring.tick(&mut factory, now, now);
        now += 60_000;
    }
    let before = ring.sign("at+jwt", b"{}", now).unwrap();
    let mut restored =
        Keyring::restore(JwsAlg::Es256, Policy::REALM, ring.saved(), &mut factory).unwrap();
    assert_eq!(restored.jwks(), ring.jwks());
    let after = restored.sign("at+jwt", b"{}", now).unwrap();
    assert_eq!(after.kid, before.kid);
}

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ais-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::create_dir_all(&dir);
    dir
}

type Shared = Arc<Mutex<Service<SealedFactory<SoftKek>, DirVault>>>;

fn listening(dir: &Path, offset: u32) -> (PathBuf, Shared) {
    let service = Service::start(
        SealedFactory::new(SoftKek::new("realm-kek-1", [1; 32])),
        DirVault::new(dir),
        Policy::REALM,
    )
    .unwrap();
    let service = Arc::new(Mutex::new(service));
    let path = dir.join("s.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let uid = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(dir).unwrap());
    tokio::spawn(serve(
        listener,
        Arc::clone(&service),
        vec![uid.wrapping_add(offset)],
        now_ms,
    ));
    (path, service)
}

// CMP-22b, OP-143 m.9 (e): a declared caller opens a realm over the socket and reads its JWKS;
// the vault keeps one file per realm
#[tokio::test]
async fn the_socket_serves_realm_keys() {
    let dir = temp("serve");
    let (path, _) = listening(&dir, 0);
    let realm = Realm([4; 16]);
    assert_eq!(call(&path, &Request::Ping).await.unwrap(), Response::Pong);
    let open = Request::Open {
        realm,
        alg: JwsAlg::Es256,
    };
    assert_eq!(call(&path, &open).await.unwrap(), Response::Opened);
    let Response::Jwks(doc) = call(&path, &Request::Jwks(realm)).await.unwrap() else {
        panic!("jwks");
    };
    assert!(doc.contains(r#""use":"sig""#), "{doc}");
    assert_eq!(DirVault::new(&dir).all().unwrap().len(), 1);
}

// CMP-22: a caller whose user id is not declared is closed unanswered
#[tokio::test]
async fn undeclared_callers_get_no_answer() {
    let dir = temp("undeclared");
    let (path, _) = listening(&dir, 1);
    assert!(call(&path, &Request::Ping).await.is_err());
}

// OP-150, CMP-22b: the cell key is served over the socket and kept in its own vault file, apart
// from the realm files
#[tokio::test]
async fn the_socket_serves_the_cell_key() {
    let dir = temp("cell");
    let (path, service) = listening(&dir, 0);
    service.lock().unwrap().open_cell("cell-a").unwrap();
    let Response::CellKey { origin, vkey } = call(&path, &Request::CellKey).await.unwrap() else {
        panic!("cell key");
    };
    assert_eq!(origin, "cell-a/identity-audit");
    assert!(vkey.starts_with("cell-a/identity-audit+"), "{vkey}");
    assert!(DirVault::new(&dir).cell().unwrap().is_some());
    assert_eq!(DirVault::new(&dir).all().unwrap().len(), 0);
}

// CMP-22b: a caller that never sends its frame is closed after the read timeout instead of
// holding a connection task forever
#[tokio::test]
async fn a_silent_caller_times_out() {
    let dir = temp("silent");
    let service = Service::start(
        SealedFactory::new(SoftKek::new("realm-kek-1", [1; 32])),
        DirVault::new(&dir),
        Policy::REALM,
    )
    .unwrap();
    let service = Arc::new(Mutex::new(service));
    let (mut server, mut client) = UnixStream::pair().unwrap();
    client.write_all(&[0, 0]).await.unwrap();
    let answered = answer(&mut server, &service, now_ms, Duration::from_millis(20)).await;
    assert_eq!(
        answered.map_err(|e| e.kind()),
        Err(std::io::ErrorKind::TimedOut)
    );
}
