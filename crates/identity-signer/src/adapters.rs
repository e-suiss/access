//! Adapters of the identity signer's ports: a key factory that creates realm keys in the
//! signer process and seals each one under the realm's KEK (CR-21 m.3, T31), a directory
//! vault keyed by realm, and the Unix domain socket server and client (CMP-22b).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use access_crypto::jose::JwsAlg;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{UnixListener, UnixStream};

use crate::ports::{Vault, VaultError};
use crate::protocol::{self, Realm, Request, Response};
use crate::service::Service;
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::envelope::{Dek, Kek, Sealed, open_body, seal_body};
use suiss_crypto::secret::Secret;
use suiss_crypto::signer::{PagedSigner, Pager, SignError, Signer, SoftSigner};

use crate::ports::{Generated, KeyFactory};

/// Binds the sealed key to what it is for; distinct from the authority's operational keys.
const SEAL_CONTEXT: &[u8] = b"access/identity-signer/realm-key";

/// Binds a sealed `rsa-id` key to its purpose (OP-155 m.3 (k)).
const RSA_ID_CONTEXT: &[u8] = b"access/identity-signer/rsa-id";

/// Binds a sealed SAML key to its purpose (OP-155 m.3 (d)).
const SAML_CONTEXT: &[u8] = b"access/identity-signer/saml";

/// Creates realm keys on aws-lc-rs and seals each PKCS#8 document under its own DEK, wrapped
/// by the realm's KEK; the plaintext never leaves memory (CR-21 m.3).
pub struct SealedFactory<K> {
    kek: K,
    pager: Option<Arc<Pager>>,
}

impl<K: Kek> SealedFactory<K> {
    /// A factory sealing under `kek`.
    pub const fn new(kek: K) -> Self {
        Self { kek, pager: None }
    }

    /// This factory keeping each opened realm key's document only in `pager`'s protected
    /// memory (CR-34, SAI-45, OP-158 m.3 (y)).
    #[must_use]
    pub fn with_pager(mut self, pager: Arc<Pager>) -> Self {
        self.pager = Some(pager);
        self
    }

    fn signer(
        &self,
        alg: JwsAlg,
        doc: &Secret<Vec<u8>>,
    ) -> Result<Box<dyn Signer + Send>, SignError> {
        let ed25519 = alg == JwsAlg::Ed25519;
        Ok(match (&self.pager, alg) {
            (Some(pager), _) => Box::new(PagedSigner::new(ed25519, doc, pager.as_ref())?),
            (None, JwsAlg::Es256) => Box::new(SoftSigner::p256_from_pkcs8(doc)?),
            (None, JwsAlg::Ed25519) => Box::new(SoftSigner::ed25519_from_pkcs8(doc)?),
        })
    }
}

impl<K: Kek> SealedFactory<K> {
    fn seal(&self, context: &[u8], doc: &[u8]) -> Result<Vec<u8>, SignError> {
        let dek = Dek::generate().map_err(|_| SignError::Random)?;
        let wrapped = self.kek.wrap(&dek).map_err(|_| SignError::Key)?;
        let sealed = seal_body(dek, context, doc).map_err(|_| SignError::Key)?;
        let v = Value::Map(vec![
            (Value::text("kek"), Value::text(self.kek.id())),
            (Value::text("wrapped"), Value::Bytes(wrapped)),
            (Value::text("nonce"), Value::Bytes(sealed.nonce.to_vec())),
            (Value::text("ciphertext"), Value::Bytes(sealed.ciphertext)),
        ]);
        dcbor::encode(&v, Limits::CEILING).map_err(|_| SignError::Encode)
    }

    fn open(&self, context: &[u8], sealed: &[u8]) -> Result<Secret<Vec<u8>>, SignError> {
        let v = dcbor::decode(sealed, Limits::CEILING).map_err(|_| SignError::Key)?;
        let bytes = |k: &str| match v.get(k) {
            Some(Value::Bytes(b)) => Ok(b.clone()),
            _ => Err(SignError::Key),
        };
        let dek = self
            .kek
            .unwrap(&bytes("wrapped")?)
            .map_err(|_| SignError::Key)?;
        let body = Sealed {
            nonce: bytes("nonce")?.try_into().map_err(|_| SignError::Key)?,
            ciphertext: bytes("ciphertext")?,
        };
        let doc = open_body(&dek, context, &body).map_err(|_| SignError::Key)?;
        Ok(Secret::new(doc.to_vec()))
    }
}

impl<K: Kek> KeyFactory for SealedFactory<K> {
    // MD-6, OP-155 m.3 (k)
    fn generate_rsa_id(&mut self) -> Result<(access_crypto::rsa_id::RsaIdKey, Vec<u8>), SignError> {
        let (key, doc) = access_crypto::rsa_id::RsaIdKey::generate().map_err(|_| SignError::Key)?;
        Ok((key, self.seal(RSA_ID_CONTEXT, &doc)?))
    }

    fn load_rsa_id(&mut self, sealed: &[u8]) -> Result<access_crypto::rsa_id::RsaIdKey, SignError> {
        let doc = self.open(RSA_ID_CONTEXT, sealed)?;
        access_crypto::rsa_id::RsaIdKey::from_pkcs8(doc.expose()).map_err(|_| SignError::Key)
    }

    fn seal_document(&mut self, doc: &Secret<Vec<u8>>) -> Result<Vec<u8>, SignError> {
        self.seal(SAML_CONTEXT, doc.expose())
    }

    fn open_document(&mut self, sealed: &[u8]) -> Result<Secret<Vec<u8>>, SignError> {
        self.open(SAML_CONTEXT, sealed)
    }

    fn generate(&mut self, alg: JwsAlg) -> Result<Generated, SignError> {
        let (_, doc) = match alg {
            JwsAlg::Es256 => SoftSigner::generate_p256()?,
            JwsAlg::Ed25519 => SoftSigner::generate_ed25519()?,
        };
        let signer = self.signer(alg, &doc)?;
        let dek = Dek::generate().map_err(|_| SignError::Random)?;
        let wrapped = self.kek.wrap(&dek).map_err(|_| SignError::Key)?;
        let sealed = seal_body(dek, SEAL_CONTEXT, doc.expose()).map_err(|_| SignError::Key)?;
        let v = Value::Map(vec![
            (Value::text("kek"), Value::text(self.kek.id())),
            (Value::text("wrapped"), Value::Bytes(wrapped)),
            (Value::text("nonce"), Value::Bytes(sealed.nonce.to_vec())),
            (Value::text("ciphertext"), Value::Bytes(sealed.ciphertext)),
        ]);
        Ok(Generated {
            signer,
            sealed: dcbor::encode(&v, Limits::CEILING).map_err(|_| SignError::Encode)?,
        })
    }

    fn load(&mut self, alg: JwsAlg, sealed: &[u8]) -> Result<Box<dyn Signer + Send>, SignError> {
        let v = dcbor::decode(sealed, Limits::CEILING).map_err(|_| SignError::Key)?;
        let bytes = |k: &str| match v.get(k) {
            Some(Value::Bytes(b)) => Ok(b.clone()),
            _ => Err(SignError::Key),
        };
        let dek = self
            .kek
            .unwrap(&bytes("wrapped")?)
            .map_err(|_| SignError::Key)?;
        let body = Sealed {
            nonce: bytes("nonce")?.try_into().map_err(|_| SignError::Key)?,
            ciphertext: bytes("ciphertext")?,
        };
        let doc = open_body(&dek, SEAL_CONTEXT, &body).map_err(|_| SignError::Key)?;
        self.signer(alg, &Secret::new(doc.to_vec()))
    }
}

fn hex(realm: &Realm) -> String {
    realm
        .0
        .iter()
        .fold(String::with_capacity(32), |mut out, b| {
            let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{b:02x}"));
            out
        })
}

/// One file per realm in a directory only the identity signer reads and writes; a write
/// replaces the file atomically, so a dropped key's sealed material is gone with the old file
/// (OP-73).
pub struct DirVault {
    dir: PathBuf,
}

impl DirVault {
    /// A vault in `dir`.
    #[must_use]
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
        }
    }
}

impl Vault for DirVault {
    fn all(&mut self) -> Result<Vec<Vec<u8>>, VaultError> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(&self.dir).map_err(|_| VaultError)? {
            let path = e.map_err(|_| VaultError)?.path();
            if path.extension().is_some_and(|x| x == "cbor") {
                out.push(std::fs::read(&path).map_err(|_| VaultError)?);
            }
        }
        Ok(out)
    }

    fn put(&mut self, realm: &Realm, bytes: &[u8]) -> Result<(), VaultError> {
        let name = hex(realm);
        let tmp = self.dir.join(format!("{name}.tmp"));
        std::fs::write(&tmp, bytes).map_err(|_| VaultError)?;
        std::fs::rename(&tmp, self.dir.join(format!("{name}.cbor"))).map_err(|_| VaultError)
    }

    fn cell(&mut self) -> Result<Option<Vec<u8>>, VaultError> {
        match std::fs::read(self.dir.join(CELL_FILE)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(VaultError),
        }
    }

    fn put_cell(&mut self, bytes: &[u8]) -> Result<(), VaultError> {
        let tmp = self.dir.join("cell.tmp");
        std::fs::write(&tmp, bytes).map_err(|_| VaultError)?;
        std::fs::rename(&tmp, self.dir.join(CELL_FILE)).map_err(|_| VaultError)
    }

    fn issuer(&mut self, realm: &Realm) -> Result<Option<Vec<u8>>, VaultError> {
        match std::fs::read(self.dir.join(issuer_file(realm))) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(VaultError),
        }
    }

    fn put_issuer(&mut self, realm: &Realm, bytes: &[u8]) -> Result<(), VaultError> {
        let tmp = self.dir.join(format!("{}.issuer.tmp", hex(realm)));
        std::fs::write(&tmp, bytes).map_err(|_| VaultError)?;
        std::fs::rename(&tmp, self.dir.join(issuer_file(realm))).map_err(|_| VaultError)
    }

    fn rsa_id(&mut self, realm: &Realm) -> Result<Option<Vec<u8>>, VaultError> {
        match std::fs::read(self.dir.join(rsa_id_file(realm))) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(VaultError),
        }
    }

    fn put_rsa_id(&mut self, realm: &Realm, bytes: &[u8]) -> Result<(), VaultError> {
        let tmp = self.dir.join(format!("{}.rsa-id.tmp", hex(realm)));
        std::fs::write(&tmp, bytes).map_err(|_| VaultError)?;
        std::fs::rename(&tmp, self.dir.join(rsa_id_file(realm))).map_err(|_| VaultError)
    }

    fn saml(&mut self, realm: &Realm) -> Result<Option<Vec<u8>>, VaultError> {
        match std::fs::read(self.dir.join(saml_file(realm))) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(VaultError),
        }
    }

    fn put_saml(&mut self, realm: &Realm, bytes: &[u8]) -> Result<(), VaultError> {
        let tmp = self.dir.join(format!("{}.saml.tmp", hex(realm)));
        std::fs::write(&tmp, bytes).map_err(|_| VaultError)?;
        std::fs::rename(&tmp, self.dir.join(saml_file(realm))).map_err(|_| VaultError)
    }

    fn ssh(&mut self, realm: &Realm) -> Result<Option<Vec<u8>>, VaultError> {
        match std::fs::read(self.dir.join(ssh_file(realm))) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(VaultError),
        }
    }

    fn put_ssh(&mut self, realm: &Realm, bytes: &[u8]) -> Result<(), VaultError> {
        let tmp = self.dir.join(format!("{}.ssh-ca.tmp", hex(realm)));
        std::fs::write(&tmp, bytes).map_err(|_| VaultError)?;
        std::fs::rename(&tmp, self.dir.join(ssh_file(realm))).map_err(|_| VaultError)
    }
}

/// A realm's `rsa-id` key file; not `.cbor`, so it is never read as a realm key set.
fn rsa_id_file(realm: &Realm) -> String {
    format!(
        "{}.{}.key",
        hex(realm),
        crate::purpose::KeyPurpose::RsaId.label()
    )
}

/// A realm's SAML key file; not `.cbor`, so it is never read as a realm key set.
fn saml_file(realm: &Realm) -> String {
    format!("{}.{}.key", hex(realm), crate::saml::LABEL)
}

/// A realm's SSH CA key file; not `.cbor`, so it is never read as a realm key set.
fn ssh_file(realm: &Realm) -> String {
    format!("{}.{}.key", hex(realm), crate::ssh::LABEL)
}

/// A realm's Claim issuer key file; not `.cbor`, so it is never read as a realm key set.
fn issuer_file(realm: &Realm) -> String {
    format!("{}.{}.key", hex(realm), crate::issuer::LABEL)
}

/// The cell key's file; not `.cbor`, so it is never read as a realm.
const CELL_FILE: &str = "audit-checkpoint.key";

/// Milliseconds since the Unix epoch.
#[must_use]
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// A random draw for a new key's jitter.
#[must_use]
pub fn draw() -> u64 {
    access_crypto::random::bytes::<8>().map_or(0, u64::from_le_bytes)
}

/// How long a caller may take to send its whole request frame (CMP-22b).
pub const READ_TIMEOUT: Duration = Duration::from_secs(5);

async fn read_frame(stream: &mut UnixStream) -> Result<Result<Vec<u8>, ()>, std::io::Error> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).await?;
    let Ok(len) = protocol::frame_len(header) else {
        return Ok(Err(()));
    };
    let mut body = vec![0_u8; len];
    stream.read_exact(&mut body).await?;
    Ok(Ok(body))
}

/// CR-28: the service runs on the blocking pool, since its key store calls (PKCS#11, KMS) block;
/// a stuck HSM session holds a blocking thread, never the runtime's request tasks. A caller that
/// does not send its frame within `deadline` is closed unanswered.
async fn answer<F, V>(
    stream: &mut UnixStream,
    service: &Arc<Mutex<Service<F, V>>>,
    clock: fn() -> u64,
    deadline: Duration,
) -> Result<(), std::io::Error>
where
    F: KeyFactory + Send + 'static,
    V: Vault + Send + 'static,
{
    let frame = tokio::time::timeout(deadline, read_frame(stream))
        .await
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
    let response = match frame {
        Ok(body) => {
            match protocol::decode_request_traced(&body) {
                Ok((request, traceparent)) => {
                    let service = Arc::clone(service);
                    // OP-67 m.1
                    let span = tracing::info_span!("signer.request");
                    if let Some(parent) = traceparent
                        .as_deref()
                        .and_then(access_telemetry::trace::TraceParent::parse)
                    {
                        access_telemetry::trace::adopt(&span, parent, None);
                    }
                    tokio::task::spawn_blocking(move || {
                        let _entered = span.entered();
                        service
                            .lock()
                            .map_or(Response::Error(String::from("signer-poisoned")), |mut s| {
                                s.handle(request, clock(), draw())
                            })
                    })
                    .await
                    .unwrap_or_else(|_| Response::Error(String::from("signer-poisoned")))
                }
                Err(_) => Response::Error(String::from("signer-frame")),
            }
        }
        Err(()) => Response::Error(String::from("signer-frame")),
    };
    let out =
        protocol::encode_response(&response).map_err(|_| std::io::Error::other("signer-frame"))?;
    stream.write_all(&out).await
}

/// Serves requests on `listener`, one per connection, from callers whose user id is in
/// `allowed` (CMP-22: UDS and peer credentials); others are closed unanswered. `clock` gives
/// the signer's time in milliseconds.
///
/// # Errors
/// The listener fails.
pub async fn serve<F, V>(
    listener: UnixListener,
    service: Arc<Mutex<Service<F, V>>>,
    allowed: Vec<u32>,
    clock: fn() -> u64,
) -> Result<(), std::io::Error>
where
    F: KeyFactory + Send + 'static,
    V: Vault + Send + 'static,
{
    serve_until(listener, service, allowed, clock, std::future::pending()).await
}

/// Longest wait for the requests in flight once the signer stops accepting (OP-94).
pub const DRAIN: Duration = Duration::from_secs(10);

/// [`serve`] until `stop` resolves; then it stops accepting, lets the requests in flight
/// finish for at most [`DRAIN`] and returns, so the caller can drop the keys and close the
/// token in order (OP-94, OP-158 m.3 (y)).
///
/// # Errors
/// The listener fails.
pub async fn serve_until<F, V, S>(
    listener: UnixListener,
    service: Arc<Mutex<Service<F, V>>>,
    allowed: Vec<u32>,
    clock: fn() -> u64,
    stop: S,
) -> Result<(), std::io::Error>
where
    F: KeyFactory + Send + 'static,
    V: Vault + Send + 'static,
    S: std::future::Future<Output = ()>,
{
    let mut inflight = tokio::task::JoinSet::new();
    let mut stop = std::pin::pin!(stop);
    loop {
        tokio::select! {
            () = &mut stop => break,
            Some(_) = inflight.join_next(), if !inflight.is_empty() => {}
            accepted = listener.accept() => {
                let (mut stream, _) = accepted?;
                let admitted = stream.peer_cred().is_ok_and(|c| allowed.contains(&c.uid()));
                if !admitted {
                    continue;
                }
                let service = Arc::clone(&service);
                inflight.spawn(async move {
                    let _ = answer(&mut stream, &service, clock, READ_TIMEOUT).await;
                });
            }
        }
    }
    drop(listener);
    let drained = tokio::time::timeout(DRAIN, async {
        while inflight.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        inflight.shutdown().await;
    }
    Ok(())
}

/// Sends one request to the identity signer at `path` (CMP-15.x to CMP-22b).
///
/// # Errors
/// The socket fails or the answer is not a frame.
pub async fn call(path: &Path, request: &Request) -> Result<Response, std::io::Error> {
    let watch = access_telemetry::metrics::Stopwatch::start();
    let answered = exchange(path, request).await;
    // §13.9, §17.8.2
    let outcome = match &answered {
        Ok(Response::Error(reason)) => {
            tracing::warn!(
                event = "signer.refused",
                outcome = "refused",
                plane = "identity",
                %reason,
                "the signer refused a request"
            );
            "refused"
        }
        Ok(_) => "ok",
        Err(_) => "error",
    };
    access_telemetry::signals::SIGNER_CALL.record_duration(watch.elapsed(), ["identity", outcome]);
    answered
}

async fn exchange(path: &Path, request: &Request) -> Result<Response, std::io::Error> {
    let mut stream = UnixStream::connect(path).await?;
    // OP-67 m.1
    let traceparent = access_telemetry::trace::current_header();
    let frame = protocol::encode_request_traced(request, traceparent.as_deref())
        .map_err(|_| std::io::Error::other("signer-frame"))?;
    stream.write_all(&frame).await?;
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).await?;
    let len = protocol::frame_len(header).map_err(|_| std::io::Error::other("signer-frame"))?;
    let mut body = vec![0_u8; len];
    stream.read_exact(&mut body).await?;
    protocol::decode_response(&body).map_err(|_| std::io::Error::other("signer-frame"))
}

#[cfg(test)]
mod tests;
