use suiss_crypto::envelope::SoftKek;
use suiss_crypto::rotation::Policy;

use super::*;
use crate::app::Keyring;

// CR-21 m.3
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

// CR-23
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

// CMP-22b, OP-143 m.9 (e)
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

// CMP-22
#[tokio::test]
async fn undeclared_callers_get_no_answer() {
    let dir = temp("undeclared");
    let (path, _) = listening(&dir, 1);
    assert!(call(&path, &Request::Ping).await.is_err());
}

// OP-150, CMP-22b
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

// CMP-22b
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

/// A fresh `SoftHSM` token of this test process with a KEK (OP-69).
fn hsm_store() -> suiss_crypto::pkcs11::KeyStore {
    let label = format!("shutdown-{}", std::process::id());
    let out = suiss_crypto::pkcs11::token_tests::init_softhsm_token(
        None,
        &label,
        "1234-test-only",
        "5678-test-only",
    )
    .unwrap();
    assert!(out.status.success(), "{out:?}");
    let module = [
        std::env::var("SUISS_PKCS11_MODULE").unwrap_or_default(),
        String::from("/opt/homebrew/lib/softhsm/libsofthsm2.so"),
        String::from("/usr/lib/softhsm/libsofthsm2.so"),
        String::from("/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"),
        String::from("/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so"),
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.is_file())
    .unwrap();
    suiss_crypto::pkcs11::KeyStore::open(
        &module,
        &label,
        &Secret::new(String::from("1234-test-only")),
    )
    .unwrap()
}

// OP-94, OP-158
#[tokio::test(flavor = "multi_thread")]
async fn a_stopped_signer_closes_its_token_in_order() {
    let dir = temp("shutdown");
    let store = hsm_store();
    let kek = store.generate_kek("access/identity/kek").unwrap();
    let service =
        Service::start(SealedFactory::new(kek), DirVault::new(&dir), Policy::REALM).unwrap();
    let service = Arc::new(Mutex::new(service));
    let path = dir.join("s.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let uid = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&dir).unwrap());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let serving = tokio::spawn(serve_until(
        listener,
        Arc::clone(&service),
        vec![uid],
        now_ms,
        async move {
            let _ = stopped.await;
        },
    ));
    let open = Request::Open {
        realm: Realm([6; 16]),
        alg: JwsAlg::Es256,
    };
    assert_eq!(call(&path, &open).await.unwrap(), Response::Opened);
    assert_eq!(store.open_handles(), 1);
    stop.send(()).unwrap();
    tokio::time::timeout(DRAIN, serving)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(call(&path, &Request::Ping).await.is_err());
    let finalizer = store.finalizer();
    assert!(matches!(
        finalizer.finalize(),
        Err(suiss_crypto::pkcs11::HsmError::Busy(2))
    ));
    drop(service);
    assert_eq!(store.open_handles(), 0);
    store.finalize().unwrap();
}
