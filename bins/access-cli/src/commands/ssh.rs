//! `access-cli ssh login`: a short-lived OpenSSH certificate for a fresh Ed25519 key (IDP-32,
//! OP-156 m.3 (o)). The person signs in in the browser with a passkey or MFA through the
//! realm's code flow (PKCE, RFC 8252 loopback redirect, DPoP bound to the Instance key); the
//! realm drafts the certificate's `projection.issue` from the person's `ssh.login` Grant; the
//! command checks that the draft names the key and server group it asked for, signs the AIS
//! with the Instance key and gets the certificate. The key and certificate go to `ssh-agent`
//! with the certificate's lifetime, or to a `0600` file. Nothing is kept beyond that.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use access_identity_oauth::domain::authority::{TokenExercise, encode_exercise};
use access_identity_ssh::domain::cert::Certificate;
use access_identity_ssh::domain::holder::{AGENT_SUCCESS, add_identity, private_key_file};
use access_identity_ssh::domain::key::Ed25519Public;
use access_identity_ssh::domain::schema;
use access_kernel::ais::Statement;
use access_kernel::codec::Canonical as _;
use access_kernel::combinator::{Capacity, Mode};
use access_kernel::digest::Digest;
use access_kernel::intent::{IntentEnvelope, intent_digest};
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::meta::{ExerciseBasis, HoldingRef, Payload};
use access_kernel::model::{Bound, EqValue, Id, ResourceSelector};
use access_sdk::auth::dpop::{ProofFor, proof};
use clap::{Args, Subcommand};
use serde_json::{Value, json};
use suiss_crypto::secret::Secret;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::{KeyArgs, note, out};
use crate::client::{Env as _, System};
use crate::exit::{self, Code};
use crate::http::{Https, Request, Transport as _};
use crate::keys::{InstanceKey, KeySource, Pkcs11Uri};

/// `ssh` arguments.
#[derive(Debug, Args)]
pub(crate) struct SshArgs {
    #[command(subcommand)]
    pub(crate) verb: Verb,
}

/// What to do.
#[derive(Debug, Subcommand)]
pub(crate) enum Verb {
    /// Signs in in the browser and gets a certificate for a fresh key.
    Login(LoginArgs),
}

/// `ssh login` arguments.
#[derive(Debug, Args)]
pub(crate) struct LoginArgs {
    /// The realm issuer, `https://host[:port]/realms/<slug>` or the realm's own host.
    #[arg(long, value_name = "URL")]
    pub(crate) issuer: String,
    /// PEM file of the CA the issuer chains to.
    #[arg(long, value_name = "PATH")]
    pub(crate) ca: PathBuf,
    /// The realm's public client for the command line, with a loopback redirect URI.
    #[arg(long, value_name = "ID")]
    pub(crate) client_id: String,
    #[command(flatten)]
    pub(crate) key: KeyArgs,
    /// The server group.
    #[arg(long, value_name = "NAME")]
    pub(crate) host_group: String,
    /// A principal (server user name) to ask for; every one the Grant names when none is given.
    #[arg(long = "principal", value_name = "NAME")]
    pub(crate) principals: Vec<String>,
    /// The lifetime in seconds; 8 hours for a person, 15 minutes for an agent by default.
    #[arg(long, value_name = "SECONDS")]
    pub(crate) lifetime: Option<u64>,
    /// An agent's Party (base64url) the certificate is for; its Instance key is `--key-file`.
    #[arg(long, value_name = "PARTY")]
    pub(crate) agent: Option<String>,
    /// Writes the key to this file (`0600`) and the certificate to `<file>-cert.pub` instead of
    /// adding both to the `ssh-agent` at `SSH_AUTH_SOCK`.
    #[arg(long, value_name = "PATH")]
    pub(crate) out: Option<PathBuf>,
    /// How long to wait for the browser sign-in, seconds.
    #[arg(long, value_name = "SECONDS", default_value_t = 300)]
    pub(crate) wait: u64,
}

/// Why the command failed.
#[derive(Debug, thiserror::Error)]
enum SshError {
    #[error("{0}")]
    Usage(String),
    #[error("{0}")]
    Config(String),
    #[error("{0}")]
    Failed(String),
    #[error("{0}")]
    Refused(String),
}

impl SshError {
    const fn code(&self) -> Code {
        match self {
            Self::Usage(_) => exit::USAGE,
            Self::Config(_) => exit::CONFIG,
            Self::Failed(_) => exit::FAILED,
            Self::Refused(_) => exit::REMOTE,
        }
    }
}

fn failed<E: core::fmt::Display>(what: &str) -> impl Fn(E) -> SshError + '_ {
    move |e| SshError::Failed(format!("{what}: {e}"))
}

/// Runs `ssh`.
pub(crate) async fn run(args: SshArgs) -> Code {
    match args.verb {
        Verb::Login(a) => match Box::pin(login(&a)).await {
            Ok(text) => out(&text),
            Err(e) => {
                note(&format!("access-cli: {e}"));
                e.code()
            }
        },
    }
}

fn form_encode(s: &str, o: &mut String) {
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            o.push(char::from(b));
        } else {
            let _ = write!(o, "%{b:02X}");
        }
    }
}

fn form(pairs: &[(&str, &str)]) -> String {
    let mut o = String::new();
    for (k, v) in pairs {
        if !o.is_empty() {
            o.push('&');
        }
        form_encode(k, &mut o);
        o.push('=');
        form_encode(v, &mut o);
    }
    o
}

fn form_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0_usize;
    while let Some(b) = bytes.get(i) {
        match b {
            b'%' => {
                let hex = s.get(i.checked_add(1)?..i.checked_add(3)?)?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i = i.checked_add(3)?;
            }
            b'+' => {
                out.push(b' ');
                i = i.checked_add(1)?;
            }
            other => {
                out.push(*other);
                i = i.checked_add(1)?;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// Member `k` of `v`, `Null` when absent.
fn at<'a>(v: &'a Value, k: &str) -> &'a Value {
    const NULL: Value = Value::Null;
    v.get(k).unwrap_or(&NULL)
}

fn random<const N: usize>() -> Result<[u8; N], SshError> {
    let mut out = [0_u8; N];
    System
        .random()
        .fill_bytes(&mut out)
        .map_err(|_| SshError::Failed(String::from("randomness unavailable")))?;
    Ok(out)
}

/// The Instance key of `--key-file` or `--pkcs11`.
fn instance_key(k: &KeyArgs) -> Result<InstanceKey, SshError> {
    let source = match (&k.key_file, &k.pkcs11) {
        (Some(p), None) => KeySource::File(p.clone()),
        (None, Some(u)) => {
            KeySource::Pkcs11(Pkcs11Uri::parse(u).map_err(|e| SshError::Usage(e.to_string()))?)
        }
        _ => {
            return Err(SshError::Usage(String::from(
                "exactly one of --key-file and --pkcs11",
            )));
        }
    };
    InstanceKey::load(&source).map_err(|e| SshError::Config(e.to_string()))
}

/// A fresh Ed25519 key: its seed, kept secret, and its public key, read back through its
/// PKCS#8 v1 document (RFC 8410).
fn ephemeral() -> Result<(Secret<[u8; 32]>, Ed25519Public), SshError> {
    const PKCS8_V1: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    let seed = Secret::new(random::<32>()?);
    let mut doc = PKCS8_V1.to_vec();
    doc.extend_from_slice(seed.expose());
    let pair = suiss_crypto::signer::SoftSigner::ed25519_from_pkcs8(&Secret::new(doc))
        .map_err(|_| SshError::Failed(String::from("ephemeral key")))?;
    match suiss_crypto::signer::Signer::public_key(&pair) {
        suiss_crypto::cose::PublicKey::Ed25519(k) => Ok((seed, Ed25519Public(k))),
        _ => Err(SshError::Failed(String::from("ephemeral key"))),
    }
}

struct Session<'a> {
    https: Https,
    key: &'a InstanceKey,
    issuer: String,
}

impl Session<'_> {
    fn proof(
        &self,
        method: &str,
        url: &str,
        token: Option<&str>,
        nonce: Option<&str>,
    ) -> Result<String, SshError> {
        struct Rng;
        impl access_sdk::auth::Random for Rng {
            fn fill(&self, out: &mut [u8]) -> Result<(), access_sdk::auth::RandomUnavailable> {
                System
                    .random()
                    .fill_bytes(out)
                    .map_err(|_| access_sdk::auth::RandomUnavailable)
            }
        }
        proof(
            self.key,
            &ProofFor {
                method,
                uri: url,
                access_token: token,
                nonce,
            },
            System.now_ms(),
            &Rng,
        )
        .map_err(|_| SshError::Failed(String::from("DPoP proof")))
    }

    /// One request with a DPoP proof, sent again once with the nonce the server asks for.
    async fn send(
        &self,
        url: &str,
        token: Option<&str>,
        body: (&'static str, Vec<u8>),
    ) -> Result<(u16, Value), SshError> {
        let mut nonce: Option<String> = None;
        for _ in 0..2 {
            let mut headers = vec![(
                String::from("DPoP"),
                self.proof("POST", url, token, nonce.as_deref())?,
            )];
            if let Some(t) = token {
                headers.push((String::from("Authorization"), format!("DPoP {t}")));
            }
            let r = self
                .https
                .send(Request {
                    method: "POST",
                    url: String::from(url),
                    headers,
                    body: Some(body.clone()),
                })
                .await
                .map_err(|e| SshError::Failed(e.to_string()))?;
            let json = r.json();
            let asks =
                r.status == 401 || (r.status == 400 && at(&json, "error") == "use_dpop_nonce");
            match r.header("dpop-nonce") {
                Some(n) if asks && nonce.is_none() => nonce = Some(String::from(n)),
                _ => return Ok((r.status, json)),
            }
        }
        Err(SshError::Failed(String::from(
            "no answer after the DPoP nonce",
        )))
    }
}

/// Waits for the browser's one redirect to the loopback listener and answers it.
async fn callback(
    listener: tokio::net::TcpListener,
    state: &str,
    wait: Duration,
) -> Result<String, SshError> {
    let accept = async {
        let (mut stream, _) = listener
            .accept()
            .await
            .map_err(|e| SshError::Failed(e.to_string()))?;
        let mut buf = vec![0_u8; 8192];
        let n = stream
            .read(&mut buf)
            .await
            .map_err(|e| SshError::Failed(e.to_string()))?;
        let head = String::from_utf8_lossy(buf.get(..n).unwrap_or_default()).into_owned();
        let target = head
            .lines()
            .next()
            .and_then(|l| l.strip_prefix("GET "))
            .and_then(|l| l.split(' ').next())
            .unwrap_or_default()
            .to_owned();
        let query = target
            .strip_prefix("/callback?")
            .unwrap_or_default()
            .to_owned();
        let get = |name: &str| {
            query
                .split('&')
                .filter_map(|p| p.split_once('='))
                .find(|(k, _)| *k == name)
                .and_then(|(_, v)| form_decode(v))
        };
        let page = "Done. Go back to your terminal.";
        let reply = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{page}",
            page.len()
        );
        let _ = stream.write_all(reply.as_bytes()).await;
        if get("state").as_deref() != Some(state) {
            return Err(SshError::Refused(String::from(
                "the sign-in came back for another request",
            )));
        }
        get("code").ok_or_else(|| {
            SshError::Refused(get("error").unwrap_or_else(|| String::from("no code")))
        })
    };
    tokio::time::timeout(wait, accept)
        .await
        .map_err(|_| SshError::Failed(String::from("no sign-in in time")))?
}

/// Opens `url` in the person's browser; the URL is printed either way.
fn open_browser(url: &str) {
    note(&format!("Sign in to get your SSH certificate: {url}"));
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    let _ = std::process::Command::new(opener)
        .arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

/// The browser sign-in: the code flow with PKCE, the DPoP key the Instance key; the access
/// token.
async fn sign_in(s: &Session<'_>, a: &LoginArgs) -> Result<String, SshError> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| SshError::Failed(e.to_string()))?;
    let port = listener
        .local_addr()
        .map_err(|e| SshError::Failed(e.to_string()))?
        .port();
    let redirect = format!("http://127.0.0.1:{port}/callback");
    let verifier = b64url_encode(&random::<32>()?);
    let challenge = b64url_encode(&suiss_crypto::digest::sha256(verifier.as_bytes()));
    let state = b64url_encode(&random::<16>()?);
    let jkt = b64url_encode(s.key.kid());
    let url = format!(
        "{}/authorize?{}",
        s.issuer,
        form(&[
            ("client_id", &a.client_id),
            ("redirect_uri", &redirect),
            ("response_type", "code"),
            ("scope", "openid"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("state", &state),
            ("dpop_jkt", &jkt),
        ])
    );
    open_browser(&url);
    let code = callback(listener, &state, Duration::from_secs(a.wait)).await?;
    let body = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", &redirect),
        ("client_id", &a.client_id),
        ("code_verifier", &verifier),
    ]);
    let (status, tokens) = s
        .send(
            &format!("{}/token", s.issuer),
            None,
            ("application/x-www-form-urlencoded", body.into_bytes()),
        )
        .await?;
    if status != 200 {
        return Err(SshError::Refused(format!("token endpoint: {tokens}")));
    }
    at(&tokens, "access_token")
        .as_str()
        .map(String::from)
        .ok_or_else(|| SshError::Refused(String::from("no access token")))
}

fn b64(v: &Value, k: &str) -> Result<Vec<u8>, SshError> {
    at(v, k)
        .as_str()
        .and_then(|t| b64url_decode(t).ok())
        .ok_or_else(|| SshError::Refused(format!("draft: {k}")))
}

fn id16(v: &Value) -> Result<Id, SshError> {
    v.as_str()
        .and_then(|t| b64url_decode(t).ok())
        .and_then(|b| <[u8; 16]>::try_from(b).ok())
        .map(Id)
        .ok_or_else(|| SshError::Refused(String::from("draft: id")))
}

/// The signed Exercise of `draft`, after checking it names `key` on `group` (WYSIWYS).
fn signed(
    draft: &Value,
    key: &InstanceKey,
    ephemeral: &Ed25519Public,
    group: &str,
) -> Result<String, SshError> {
    let payload_bytes = b64(draft, "payload")?;
    let payload = Payload::from_bytes(&payload_bytes)
        .map_err(|_| SshError::Refused(String::from("draft")))?;
    let intent = IntentEnvelope::from_bytes(&b64(draft, "intent")?)
        .map_err(|_| SshError::Refused(String::from("draft")))?;
    let Payload::ProjectionIssue { bounds, .. } = &payload else {
        return Err(SshError::Refused(String::from("draft: not a projection")));
    };
    let names_key = bounds.authority.params.get(schema::PUBLIC_KEY)
        == Some(&Bound::Eq(EqValue::Bytes(ephemeral.0.to_vec())));
    let names_group =
        bounds.authority.resource == ResourceSelector::Exact(schema::host_group(group));
    if !names_key || !names_group {
        return Err(SshError::Refused(String::from(
            "the draft is not for this key and server group",
        )));
    }
    let h = at(at(draft, "basis"), "holding");
    let basis = ExerciseBasis::Holding(HoldingRef {
        grant: id16(at(h, "grant"))?,
        holder: id16(at(h, "holder"))?,
        since: at(h, "since")
            .as_u64()
            .ok_or_else(|| SshError::Refused(String::from("draft: since")))?,
    });
    let capacity = match at(draft, "capacity") {
        Value::String(s) if s == "own" => Capacity::Own,
        c => Capacity::For(id16(at(c, "for"))?),
    };
    let domain = Digest(
        <[u8; 32]>::try_from(b64(draft, "domain")?)
            .map_err(|_| SshError::Refused(String::from("draft: domain")))?,
    );
    let nonce = b64(draft, "nonce")?;
    let statement = Statement {
        domain,
        nonce: nonce.clone(),
        intent: intent_digest(&intent).map_err(|_| SshError::Refused(String::from("draft")))?,
        mode: Mode::Commit,
        pep: String::from(at(draft, "pep").as_str().unwrap_or_default()),
        capacity,
        basis,
        iat: System.now_ms(),
        exercise: None,
    };
    let ais = key
        .sign_ais(
            &statement
                .to_bytes()
                .map_err(|_| SshError::Failed(String::from("AIS")))?,
        )
        .map_err(|e| SshError::Config(e.to_string()))?;
    encode_exercise(&TokenExercise {
        domain,
        nonce,
        intent,
        payload_bytes,
        payload,
        basis,
        capacity,
        ais,
        target: None,
    })
    .map_err(|_| SshError::Failed(String::from("exercise")))
}

fn write_private(path: &Path, text: &str) -> Result<(), SshError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| SshError::Failed(format!("{}: {e}", path.display())))?;
    f.write_all(text.as_bytes())
        .map_err(|e| SshError::Failed(format!("{}: {e}", path.display())))
}

/// Adds the key and certificate to the agent at `socket`, for `lifetime_s`.
async fn to_agent(socket: &Path, message: &[u8]) -> Result<(), SshError> {
    let mut s = tokio::net::UnixStream::connect(socket)
        .await
        .map_err(failed("ssh-agent"))?;
    s.write_all(message).await.map_err(failed("ssh-agent"))?;
    let mut answer = [0_u8; 5];
    s.read_exact(&mut answer)
        .await
        .map_err(failed("ssh-agent"))?;
    if answer.get(4) == Some(&AGENT_SUCCESS) {
        Ok(())
    } else {
        Err(SshError::Failed(String::from("ssh-agent refused the key")))
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one login, its steps in the order they run"
)]
async fn login(a: &LoginArgs) -> Result<String, SshError> {
    if !a.issuer.starts_with("https://") || !schema::group_ok(&a.host_group) {
        return Err(SshError::Usage(String::from(
            "--issuer must be an https URL and --host-group a server group name",
        )));
    }
    let socket = std::env::var_os("SSH_AUTH_SOCK").map(PathBuf::from);
    if a.out.is_none() && socket.is_none() {
        return Err(SshError::Usage(String::from(
            "no ssh-agent (SSH_AUTH_SOCK) and no --out file",
        )));
    }
    let key = instance_key(&a.key)?;
    let s = Session {
        https: Https::new(&a.ca).map_err(|e| SshError::Config(e.to_string()))?,
        key: &key,
        issuer: a.issuer.trim_end_matches('/').to_owned(),
    };
    let token = sign_in(&s, a).await?;
    let (seed, public) = ephemeral()?;
    let mut ask = serde_json::Map::new();
    ask.insert(String::from("host_group"), json!(a.host_group));
    ask.insert(String::from("public_key"), json!(b64url_encode(&public.0)));
    if !a.principals.is_empty() {
        ask.insert(String::from("principals"), json!(a.principals));
    }
    if let Some(l) = a.lifetime {
        ask.insert(String::from("lifetime_s"), json!(l));
    }
    if let Some(agent) = &a.agent {
        ask.insert(String::from("agent"), json!(agent));
    }
    let ask = Value::Object(ask);
    let url = format!("{}/ssh/certificate", s.issuer);
    let json_body = |v: &Value| ("application/json", v.to_string().into_bytes());
    let (status, drafted) = s.send(&url, Some(&token), json_body(&ask)).await?;
    if status != 200 {
        return Err(SshError::Refused(format!("draft: {drafted}")));
    }
    let exercise = signed(at(&drafted, "draft"), &key, &public, &a.host_group)?;
    let (status, issued) = s
        .send(
            &url,
            Some(&token),
            json_body(&json!({ "exercise": exercise })),
        )
        .await?;
    if status != 200 {
        return Err(SshError::Refused(format!("certificate: {issued}")));
    }
    let line = at(&issued, "certificate")
        .as_str()
        .ok_or_else(|| SshError::Refused(String::from("no certificate")))?;
    let cert = Certificate::of_line(line).map_err(|e| SshError::Refused(e.to_string()))?;
    let (fields, _, _) = cert.parse().map_err(|e| SshError::Refused(e.to_string()))?;
    if fields.key != public {
        return Err(SshError::Refused(String::from(
            "the certificate is for another key",
        )));
    }
    let comment = format!("access:{}", a.host_group);
    let lifetime = fields
        .valid_before
        .saturating_sub(System.now_ms() / 1000)
        .min(u64::from(u32::MAX));
    match (&a.out, &socket) {
        (Some(path), _) => {
            let check = u32::from_be_bytes(random::<4>()?);
            let text = private_key_file(seed.expose(), &public, &comment, check)
                .map_err(|e| SshError::Failed(e.to_string()))?;
            write_private(path, &text)?;
            let mut cert_path = path.clone().into_os_string();
            cert_path.push("-cert.pub");
            std::fs::write(&cert_path, format!("{}\n", cert.line(&comment)))
                .map_err(failed("certificate file"))?;
        }
        (None, Some(sock)) => {
            let message = add_identity(
                &cert,
                seed.expose(),
                &public,
                &comment,
                u32::try_from(lifetime).unwrap_or(u32::MAX),
            )
            .map_err(|e| SshError::Failed(e.to_string()))?;
            to_agent(sock, &message).await?;
        }
        (None, None) => {
            return Err(SshError::Usage(String::from(
                "no ssh-agent and no --out file",
            )));
        }
    }
    Ok(format!(
        "{}\n",
        json!({
            "key_id": at(&issued, "key_id"),
            "serial": at(&issued, "serial"),
            "principals": at(&issued, "principals"),
            "host_group": at(&issued, "host_group"),
            "valid_before": fields.valid_before,
        })
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    #[test]
    fn forms_encode_and_decode() {
        let f = form(&[
            ("redirect_uri", "http://127.0.0.1:5/callback"),
            ("a", "b c"),
        ]);
        assert_eq!(
            f,
            "redirect_uri=http%3A%2F%2F127.0.0.1%3A5%2Fcallback&a=b%20c"
        );
        assert_eq!(form_decode("a%2Fb+c").unwrap(), "a/b c");
        assert_eq!(form_decode("%zz"), None);
    }

    #[test]
    fn a_fresh_key_reads_back_from_its_seed() {
        let (seed, public) = ephemeral().unwrap();
        let (again, _) = ephemeral().unwrap();
        assert_ne!(seed.expose(), again.expose());
        assert_ne!(public.0, [0; 32]);
    }
}
