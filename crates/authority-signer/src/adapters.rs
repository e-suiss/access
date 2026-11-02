//! Adapters of the signer's ports: a key factory that seals each operational key under the KEK
//! (CR-21 m.3), the HSM's binding keys (CR-29), a directory vault, and the Unix domain socket
//! server that admits only declared callers (CMP-22).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use access_kernel::digest::Digest;
use suiss_crypto::cose::Algorithm;
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::envelope::{Dek, Kek, Sealed, open_body, seal_body};
use suiss_crypto::secret::Secret;
use suiss_crypto::signer::{SignError, Signer, SoftSigner};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{UnixListener, UnixStream};

use crate::ports::{Bindings, Generated, KeyFactory, Vault, VaultError};
use crate::protocol::{self, Request, Response};
use crate::service::Service;

/// Binds the sealed key to what it is for.
const SEAL_CONTEXT: &[u8] = b"access/signer/operational-key";

/// Creates operational keys in the signer process and seals each PKCS#8 document under its own
/// DEK, wrapped by the KEK; the plaintext never leaves memory (CR-21 m.3).
pub struct SealedFactory<K> {
    kek: K,
}

impl<K: Kek> SealedFactory<K> {
    /// A factory sealing under `kek`.
    pub const fn new(kek: K) -> Self {
        Self { kek }
    }
}

impl<K: Kek> KeyFactory for SealedFactory<K> {
    fn generate(&mut self, alg: Algorithm) -> Result<Generated, SignError> {
        let (signer, doc): (Box<dyn Signer + Send>, _) = match alg {
            Algorithm::Ed25519 => {
                let (s, d) = SoftSigner::generate_ed25519()?;
                (Box::new(s), d)
            }
            Algorithm::Esp256 | Algorithm::Es256 => {
                let (s, d) = SoftSigner::generate_p256()?;
                (Box::new(s), d)
            }
            _ => return Err(SignError::Algorithm),
        };
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

    fn load(&mut self, alg: Algorithm, sealed: &[u8]) -> Result<Box<dyn Signer + Send>, SignError> {
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
        let doc = Secret::new(doc.to_vec());
        Ok(match alg {
            Algorithm::Ed25519 => Box::new(SoftSigner::ed25519_from_pkcs8(&doc)?),
            Algorithm::Esp256 | Algorithm::Es256 => Box::new(SoftSigner::p256_from_pkcs8(&doc)?),
            _ => return Err(SignError::Algorithm),
        })
    }
}

fn hex(domain: &Digest) -> String {
    domain
        .0
        .iter()
        .fold(String::with_capacity(64), |mut out, b| {
            let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{b:02x}"));
            out
        })
}

/// The HSM label of a domain's binding key.
#[must_use]
pub fn binding_label(domain: &Digest) -> String {
    format!("access/binding/{}", hex(domain))
}

/// Binding keys in the HSM, one per domain; a domain's first `open` creates it (CR-29).
pub struct HsmBindings {
    store: suiss_crypto::pkcs11::KeyStore,
}

impl HsmBindings {
    /// Binding keys in `store`.
    #[must_use]
    pub const fn new(store: suiss_crypto::pkcs11::KeyStore) -> Self {
        Self { store }
    }
}

impl Bindings for HsmBindings {
    fn binding(&mut self, domain: &Digest) -> Result<Box<dyn Signer + Send>, SignError> {
        let label = binding_label(domain);
        let signer = match self.store.signer(&label) {
            Ok(s) => s,
            Err(_) => self
                .store
                .generate_ed25519(&label)
                .map_err(|_| SignError::Key)?,
        };
        Ok(Box::new(signer))
    }
}

/// One file per domain in a directory only the signer reads and writes; a write replaces the
/// file atomically, so a dropped key's sealed material is gone with the old file (OP-73).
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

    fn put(&mut self, domain: &Digest, bytes: &[u8]) -> Result<(), VaultError> {
        let name = hex(domain);
        let tmp = self.dir.join(format!("{name}.tmp"));
        std::fs::write(&tmp, bytes).map_err(|_| VaultError)?;
        std::fs::rename(&tmp, self.dir.join(format!("{name}.cbor"))).map_err(|_| VaultError)
    }
}

/// Milliseconds since the Unix epoch.
#[must_use]
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

async fn answer<F, B, V>(
    stream: &mut UnixStream,
    service: &Mutex<Service<F, B, V>>,
    now: u64,
) -> Result<(), std::io::Error>
where
    F: KeyFactory,
    B: Bindings,
    V: Vault,
{
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).await?;
    let response = match protocol::frame_len(header) {
        Ok(len) => {
            let mut body = vec![0_u8; len];
            stream.read_exact(&mut body).await?;
            match protocol::decode_request(&body) {
                Ok(request) => service
                    .lock()
                    .map_or(Response::Error(String::from("signer-poisoned")), |mut s| {
                        s.handle(request, now)
                    }),
                Err(_) => Response::Error(String::from("signer-frame")),
            }
        }
        Err(_) => Response::Error(String::from("signer-frame")),
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
pub async fn serve<F, B, V>(
    listener: UnixListener,
    service: Arc<Mutex<Service<F, B, V>>>,
    allowed: Vec<u32>,
    clock: fn() -> u64,
) -> Result<(), std::io::Error>
where
    F: KeyFactory + Send + 'static,
    B: Bindings + Send + 'static,
    V: Vault + Send + 'static,
{
    loop {
        let (mut stream, _) = listener.accept().await?;
        let admitted = stream.peer_cred().is_ok_and(|c| allowed.contains(&c.uid()));
        if !admitted {
            continue;
        }
        let service = Arc::clone(&service);
        tokio::spawn(async move {
            let _ = answer(&mut stream, &service, clock()).await;
        });
    }
}

/// Sends one request to the signer at `path` (CMP-7 to CMP-22a).
///
/// # Errors
/// The socket fails or the answer is not a frame.
pub async fn call(path: &Path, request: &Request) -> Result<Response, std::io::Error> {
    let mut stream = UnixStream::connect(path).await?;
    let frame =
        protocol::encode_request(request).map_err(|_| std::io::Error::other("signer-frame"))?;
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
