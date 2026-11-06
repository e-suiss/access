//! `access-local-client`: the headless client of a local Access deployment (OP-149 m.26 (b),
//! (c)). Each command runs the real protocol against a running Access over TLS verified against
//! the local CA, and prints the result as JSON. Secrets come from files and environment
//! variables, never from arguments.
//!
//! ```text
//! access-local-client login --issuer <realm issuer> --ca <ca.crt> --client-id <id>
//!     --redirect-uri <uri> --identifier <login> --password-env <VAR> [--resource <client_id>]
//!     [--scope <scopes>] [--connect <ip:port>]
//! access-local-client compromise --api <base> --ca <ca.crt> --cert <pep.crt> --key <pep.key>
//!     --domain <b64url> --issuer-party <b64url> --party <b64url> [--occurred-at <ms>]
//!     [--connect <ip:port>]
//! access-local-client stream-status --api <base> --issuer <platform issuer> --ca <ca.crt>
//!     --client-id <id> --client-key <private.jwk> --stream <id> [--status <enabled|paused|disabled>
//!     [--reason <text>]] [--connect <ip:port>]
//! ```

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::process::ExitCode;

use access_kernel::digest::Digest;
use access_kernel::json::b64url_decode;
use access_kernel::model::Id;
use access_local_client::ClientError;
use access_local_client::claims::{Compromise, declare};
use access_local_client::dpop::Es256Key;
use access_local_client::http::{Http, Identity, leaf_der};
use access_local_client::login::{Login, login};
use access_local_client::platform::{PlatformClient, StatusChange};

const USAGE: &str = "usage: access-local-client <login | compromise | stream-status> --<option> <value>...\n\
  login:         --issuer --ca --client-id --redirect-uri --identifier --password-env [--resource] [--scope] [--connect]\n\
  compromise:    --api --ca --cert --key --domain --issuer-party --party [--occurred-at] [--connect]\n\
  stream-status: --api --issuer --ca --client-id --client-key --stream [--status [--reason]] [--connect]";

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

    fn id16(&self, name: &str) -> Result<Id, String> {
        let text = self.required(name)?;
        b64url_decode(text)
            .ok()
            .and_then(|b| <[u8; 16]>::try_from(b).ok())
            .map(Id)
            .ok_or_else(|| format!("--{name} is not a base64url 16-byte id"))
    }
}

fn http(o: &Options, identity: Option<&Identity>) -> Result<Http, String> {
    let ca = o.file("ca")?;
    Http::new(&ca, identity, o.connect()?).map_err(|e| e.to_string())
}

async fn run(command: &str, o: &Options) -> Result<serde_json::Value, String> {
    let step = |e: ClientError| e.to_string();
    match command {
        "login" => {
            let var = o.required("password-env")?;
            let password = std::env::var(var)
                .ok()
                .filter(|p| !p.is_empty())
                .ok_or_else(|| format!("{var} is not set"))?;
            let http = http(o, None)?;
            login(
                &http,
                &Login {
                    issuer: o.required("issuer")?,
                    client_id: o.required("client-id")?,
                    redirect_uri: o.required("redirect-uri")?,
                    identifier: o.required("identifier")?,
                    password: &password,
                    resource: o.optional("resource"),
                    scope: o.optional("scope").unwrap_or("openid"),
                },
            )
            .await
            .map_err(step)
        }
        "compromise" => {
            let identity = Identity {
                chain_pem: o.file("cert")?,
                key_pem: o.file("key")?,
            };
            let leaf = leaf_der(&identity.chain_pem).map_err(step)?;
            let http = http(o, Some(&identity))?;
            let domain = b64url_decode(o.required("domain")?)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .map(Digest)
                .ok_or("--domain is not a base64url 32-byte digest")?;
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
                    domain,
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
