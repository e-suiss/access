//! `access-local-client`: the headless client of a local Access deployment (OP-149 m.26 (b),
//! (c), (e), m.29 (b)). Each command runs the real protocol against a running Access over TLS
//! verified against the local CA, and prints the result as JSON. Secrets come from files,
//! environment variables and the PKCS#11 token, never from arguments.
//!
//! ```text
//! access-local-client login --issuer <realm issuer> --ca <ca.crt> --client-id <id>
//!     --redirect-uri <uri> --identifier <login>
//!     (--password-env <VAR> [--passkey <label>] | --passkey <label>) [--device-key <label>]
//!     [--hsm-module <path> --hsm-token <label> --hsm-pin-file <path>]
//!     [--resource <client_id>] [--scope <scopes>] [--connect <ip:port>]
//! access-local-client approve --issuer <realm issuer> --api <base> --ca <ca.crt>
//!     --cert <pep.crt> --key <pep.key> --redirect-uri <uri> --identifier <login>
//!     --hsm-module <path> --hsm-token <label> --hsm-pin-file <path>
//!     --device-key <label> --passkey <label> --domain <b64url> --party <b64url>
//!     --grant <b64url> --grant-since <position> --contribute-grant <b64url>
//!     --contribute-since <position> (--intent <envelope.json> | --intent-json <json>)
//!     [--instance <b64url>] [--reason <text>] [--request <pushed-request.json>] [--connect <ip:port>]
//! access-local-client compromise --api <base> --ca <ca.crt> --cert <pep.crt> --key <pep.key>
//!     --domain <b64url> --issuer-party <b64url> --party <b64url> [--occurred-at <ms>]
//!     [--connect <ip:port>]
//! access-local-client stream-status --api <base> --issuer <platform issuer> --ca <ca.crt>
//!     --client-id <id> --client-key <private.jwk> --stream <id> [--status <enabled|paused|disabled>
//!     [--reason <text>]] [--connect <ip:port>]
//! access-local-client service-token --issuer <the caller's realm issuer> --ca <ca.crt>
//!     --client-id <id> --client-key <private.jwk> --resource <the product's client_id>
//!     [--connect <ip:port>]
//! ```
//!
//! `service-token` serves a platform product (OP-149 m.31 (a)) and a tenant realm's
//! `private_key_jwt` API client (m.34 (b)) alike: the issuer is the caller's realm.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::Path;
use std::process::ExitCode;

use access_kernel::digest::Digest;
use access_kernel::json::b64url_decode;
use access_kernel::model::Id;
use access_local_client::ClientError;
use access_local_client::approve::{Approve, approve};
use access_local_client::claims::{Compromise, declare};
use access_local_client::dpop::Es256Key;
use access_local_client::http::{Http, Identity, leaf_der};
use access_local_client::intent::holding;
use access_local_client::login::{Credential, Login, login};
use access_local_client::passkey::{Passkey, relying_party};
use access_local_client::platform::{PlatformClient, StatusChange};
use access_local_client::token::Token;
use suiss_crypto::signer::Signer;

const USAGE: &str = "usage: access-local-client <login | approve | compromise | stream-status | service-token> --<option> <value>...\n\
  login:         --issuer --ca --client-id --redirect-uri --identifier (--password-env | --passkey --hsm-module --hsm-token --hsm-pin-file)\n\
                 [--device-key] [--resource] [--scope] [--connect]\n\
  approve:       --issuer --api --ca --cert --key --redirect-uri --identifier --hsm-module --hsm-token --hsm-pin-file --device-key --passkey\n\
                 --domain --party --grant --grant-since --contribute-grant --contribute-since (--intent | --intent-json) [--instance] [--reason] [--request] [--connect]\n\
  compromise:    --api --ca --cert --key --domain --issuer-party --party [--occurred-at] [--connect]\n\
  stream-status: --api --issuer --ca --client-id --client-key --stream [--status [--reason]] [--connect]\n\
  service-token: --issuer --ca --client-id --client-key --resource [--connect]";

/// `--name value` pairs.
struct Options(BTreeMap<String, String>);

impl Options {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut out = BTreeMap::new();
        let mut it = args.iter();
        while let Some(name) = it.next() {
            let key = name
                .strip_prefix("--")
                .filter(|k| !k.is_empty())
                .ok_or_else(|| format!("unexpected argument {name}"))?;
            let value = it.next().ok_or_else(|| format!("{name} needs a value"))?;
            if out.insert(String::from(key), value.clone()).is_some() {
                return Err(format!("{name} given twice"));
            }
        }
        Ok(Self(out))
    }

    fn required(&self, name: &str) -> Result<&str, String> {
        self.0
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| format!("--{name} is required"))
    }

    fn optional(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }

    fn connect(&self) -> Result<Option<SocketAddr>, String> {
        self.optional("connect")
            .map(|c| {
                c.parse()
                    .map_err(|_| format!("--connect {c} is not ip:port"))
            })
            .transpose()
    }

    fn file(&self, name: &str) -> Result<Vec<u8>, String> {
        let path = self.required(name)?;
        std::fs::read(path).map_err(|e| format!("{path}: {e}"))
    }

    fn json(&self, name: &str) -> Result<serde_json::Value, String> {
        serde_json::from_slice(&self.file(name)?).map_err(|e| format!("--{name}: {e}"))
    }

    fn id16(&self, name: &str) -> Result<Id, String> {
        let text = self.required(name)?;
        b64url_decode(text)
            .ok()
            .and_then(|b| <[u8; 16]>::try_from(b).ok())
            .map(Id)
            .ok_or_else(|| format!("--{name} is not a base64url 16-byte id"))
    }

    fn digest(&self, name: &str) -> Result<Digest, String> {
        let text = self.required(name)?;
        b64url_decode(text)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .map(Digest)
            .ok_or_else(|| format!("--{name} is not a base64url 32-byte digest"))
    }

    fn position(&self, name: &str) -> Result<u64, String> {
        self.required(name)?
            .parse()
            .map_err(|_| format!("--{name} is not a position"))
    }

    /// The token the test user's keys live in (OP-149 m.26 (e), m.28 (b)).
    fn token(&self) -> Result<Token, String> {
        Token::open(
            Path::new(self.required("hsm-module")?),
            self.required("hsm-token")?,
            Path::new(self.required("hsm-pin-file")?),
        )
        .map_err(|e| e.to_string())
    }
}

fn http(o: &Options, identity: Option<&Identity>) -> Result<Http, String> {
    let ca = o.file("ca")?;
    Http::new(&ca, identity, o.connect()?).map_err(|e| e.to_string())
}

/// `login`: the code flow with the password, the passkey, or the password and the passkey as
/// the second factor the realm asks for once the account holds one (OP-149 m.26 (b), (e)); with
/// `--device-key`, the new session is bound to the known device's Instance (OP-149 m.32).
async fn login_command(o: &Options) -> Result<serde_json::Value, String> {
    let step = |e: ClientError| e.to_string();
    let issuer = o.required("issuer")?;
    let (rp_id, origin) = relying_party(issuer).map_err(step)?;
    let password;
    let key;
    let passkey;
    let device;
    let token = match (o.optional("passkey"), o.optional("device-key")) {
        (None, None) => None,
        _ => Some(o.token()?),
    };
    let software = match (o.optional("passkey"), &token) {
        (Some(label), Some(t)) => {
            key = t.signer(label).map_err(step)?;
            passkey = Passkey {
                key: &key,
                rp_id: &rp_id,
                origin: &origin,
            };
            Some(&passkey)
        }
        _ => None,
    };
    let known: Option<&dyn Signer> = match (o.optional("device-key"), &token) {
        (Some(label), Some(t)) => {
            device = t.signer(label).map_err(step)?;
            Some(&device)
        }
        _ => None,
    };
    let credential = match (o.optional("password-env"), software) {
        (Some(var), passkey) => {
            password = std::env::var(var)
                .ok()
                .filter(|p| !p.is_empty())
                .ok_or_else(|| format!("{var} is not set"))?;
            Credential::Password(&password, passkey)
        }
        (None, Some(passkey)) => Credential::Passkey(passkey),
        (None, None) => return Err(String::from("--password-env or --passkey is required")),
    };
    let http = http(o, None)?;
    login(
        &http,
        &Login {
            issuer,
            client_id: o.required("client-id")?,
            redirect_uri: o.required("redirect-uri")?,
            identifier: o.required("identifier")?,
            credential,
            resource: o.optional("resource"),
            scope: o.optional("scope").unwrap_or("openid"),
            device: known,
        },
    )
    .await
    .map_err(step)
}

/// `approve`: an allowed Exercise through the hosted Approval Surface (OP-149 m.29 (b)).
async fn approve_command(o: &Options) -> Result<serde_json::Value, String> {
    let step = |e: ClientError| e.to_string();
    let identity = Identity {
        chain_pem: o.file("cert")?,
        key_pem: o.file("key")?,
    };
    let leaf = leaf_der(&identity.chain_pem).map_err(step)?;
    let http = http(o, Some(&identity))?;
    let issuer = o.required("issuer")?;
    let (rp_id, origin) = relying_party(issuer).map_err(step)?;
    let token = o.token()?;
    let device = token.signer(o.required("device-key")?).map_err(step)?;
    let key = token.signer(o.required("passkey")?).map_err(step)?;
    let passkey = Passkey {
        key: &key,
        rp_id: &rp_id,
        origin: &origin,
    };
    let party = o.id16("party")?;
    let intent = match (o.optional("intent"), o.optional("intent-json")) {
        (Some(_), None) => o.json("intent")?,
        (None, Some(text)) => {
            serde_json::from_str(text).map_err(|e| format!("--intent-json: {e}"))?
        }
        _ => return Err(String::from("exactly one of --intent and --intent-json")),
    };
    let request = o
        .optional("request")
        .map(|_| o.json("request"))
        .transpose()?;
    approve(
        &http,
        &Approve {
            issuer,
            api_base: o.required("api")?,
            redirect_uri: o.required("redirect-uri")?,
            identifier: o.required("identifier")?,
            passkey: &passkey,
            device: &device,
            pep_leaf_der: &leaf,
            domain: o.digest("domain")?,
            party,
            instance: o
                .optional("instance")
                .map(|_| o.id16("instance"))
                .transpose()?,
            intent: &intent,
            basis: holding(o.id16("grant")?, party, o.position("grant-since")?),
            contribution: holding(
                o.id16("contribute-grant")?,
                party,
                o.position("contribute-since")?,
            ),
            reason: o
                .optional("reason")
                .unwrap_or("Local end-to-end test of an allowed Exercise."),
            request: request.as_ref(),
        },
    )
    .await
    .map_err(step)
}

async fn run(command: &str, o: &Options) -> Result<serde_json::Value, String> {
    let step = |e: ClientError| e.to_string();
    match command {
        "login" => login_command(o).await,
        "approve" => approve_command(o).await,
        "compromise" => {
            let identity = Identity {
                chain_pem: o.file("cert")?,
                key_pem: o.file("key")?,
            };
            let leaf = leaf_der(&identity.chain_pem).map_err(step)?;
            let http = http(o, Some(&identity))?;
            let occurred_at = o
                .optional("occurred-at")
                .map(|t| {
                    t.parse::<u64>()
                        .map_err(|_| "--occurred-at is not a number")
                })
                .transpose()?;
            declare(
                &http,
                &Compromise {
                    api_base: o.required("api")?,
                    domain: o.digest("domain")?,
                    issuer: o.id16("issuer-party")?,
                    party: o.id16("party")?,
                    occurred_at,
                    pep_leaf_der: &leaf,
                },
            )
            .await
            .map_err(step)
        }
        "stream-status" => {
            let jwk = String::from_utf8(o.file("client-key")?)
                .map_err(|_| "--client-key is not a text file")?;
            let key = Es256Key::from_private_jwk(&jwk).map_err(step)?;
            let http = http(o, None)?;
            let client = PlatformClient {
                api_base: o.required("api")?,
                issuer: o.required("issuer")?,
                client_id: o.required("client-id")?,
                key: &key,
            };
            let change = o.optional("status").map(|status| StatusChange {
                status,
                reason: o.optional("reason"),
            });
            client
                .stream_status(&http, o.required("stream")?, change.as_ref())
                .await
                .map_err(step)
        }
        "service-token" => {
            let jwk = String::from_utf8(o.file("client-key")?)
                .map_err(|_| "--client-key is not a text file")?;
            let key = Es256Key::from_private_jwk(&jwk).map_err(step)?;
            let http = http(o, None)?;
            let issuer = o.required("issuer")?;
            let client = PlatformClient {
                api_base: issuer,
                issuer,
                client_id: o.required("client-id")?,
                key: &key,
            };
            client
                .service_token(&http, o.required("resource")?)
                .await
                .map_err(step)
        }
        other => Err(format!("unknown command {other}\n{USAGE}")),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((command, rest)) = args.split_first() else {
        #[allow(clippy::print_stderr)]
        {
            eprintln!("{USAGE}");
        }
        return ExitCode::FAILURE;
    };
    let result = Options::parse(rest).and_then(|o| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        runtime.block_on(run(command, &o))
    });
    match result {
        Ok(value) => {
            #[allow(clippy::print_stdout)]
            {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&value).unwrap_or_default()
                );
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            #[allow(clippy::print_stderr)]
            {
                eprintln!("access-local-client: {error}");
            }
            ExitCode::FAILURE
        }
    }
}
