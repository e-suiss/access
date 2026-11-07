//! The k-anonymity range API client (IDP-3, OP-151 m.3 (o)) against a local mock server: only
//! the five-character prefix is sent, a listed password is listed, and every failure (error
//! status, malformed body, no answer within the deadline) is unavailable, never "not breached"
//! (G50, MD-8).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use access_identity_account::domain::password::Password;
use access_identity_risk::adapters::RangeProbe;
use access_identity_risk::adapters::range_api::RangeApi;
use access_identity_risk::domain::assess::Breach;
use access_identity_risk::ports::{BreachProbe, Fetched, NoAnswer, RangeFetch};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

/// The mock's answers by request path; any other path hangs.
#[derive(Clone, Default)]
struct Mock {
    seen: Arc<Mutex<Vec<String>>>,
}

async fn serve(listener: TcpListener, mock: Mock) {
    loop {
        let (mut tcp, _) = listener.accept().await.unwrap();
        let mock = mock.clone();
        tokio::spawn(async move {
            let mut buf = vec![0; 4096];
            let n = tcp.read(&mut buf).await.unwrap();
            let head = String::from_utf8_lossy(&buf[..n]).into_owned();
            let path = head
                .split_whitespace()
                .nth(1)
                .unwrap_or_default()
                .to_owned();
            mock.seen.lock().unwrap().push(path.clone());
            let (status, body) = match path.as_str() {
                "/v3/range/21BD1" => (
                    200,
                    "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n\
                     2DC183F740EE76F27B78EB39C8AD972A757:52579\r\n",
                ),
                "/v3/range/ABF7A" => (200, "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n"),
                "/v3/range/A94A8" => (503, ""),
                "/v3/range/5BAA6" => (200, "<html>not a range</html>"),
                _ => {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    return;
                }
            };
            let answer = format!(
                "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            tcp.write_all(answer.as_bytes()).await.unwrap();
        });
    }
}

/// Plain HTTP to the mock for `https://ranges.test/...`.
struct ToMock(u16);

impl RangeFetch for ToMock {
    async fn get(&self, url: &str, max_body: usize) -> Result<Fetched, NoAnswer> {
        let path = url.strip_prefix("https://ranges.test").ok_or(NoAnswer)?;
        let mut tcp = TcpStream::connect(("127.0.0.1", self.0))
            .await
            .map_err(|_| NoAnswer)?;
        let request = format!("GET {path} HTTP/1.1\r\nHost: ranges.test\r\n\r\n");
        tcp.write_all(request.as_bytes())
            .await
            .map_err(|_| NoAnswer)?;
        let mut raw = Vec::new();
        tcp.read_to_end(&mut raw).await.map_err(|_| NoAnswer)?;
        let text = String::from_utf8(raw).map_err(|_| NoAnswer)?;
        let (head, body) = text.split_once("\r\n\r\n").ok_or(NoAnswer)?;
        let status = head
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or(NoAnswer)?;
        if body.len() > max_body {
            return Err(NoAnswer);
        }
        Ok(Fetched {
            status,
            body: body.as_bytes().to_vec(),
        })
    }
}

// IDP-3, OP-151 m.3 (o), G50, MD-8: the range API through a local mock
#[tokio::test]
async fn range_api_fails_closed() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mock = Mock::default();
    tokio::spawn(serve(listener, mock.clone()));
    let api = RangeApi::new("https://ranges.test/v3/", ToMock(port))
        .unwrap()
        .with_timeout(Duration::from_millis(300));
    let probe = RangeProbe(api);
    let check = async |pw: &str| probe.check(&Password::presented(pw).unwrap()).await;
    assert_eq!(check("P@ssw0rd").await, Breach::Listed);
    assert_eq!(check("correct horse battery staple").await, Breach::Clean);
    assert_eq!(check("test").await, Breach::Unavailable);
    assert_eq!(check("password").await, Breach::Unavailable);
    assert_eq!(check("hang forever please").await, Breach::Unavailable);
    let seen = mock.seen.lock().unwrap().clone();
    assert!(
        seen.iter().all(|p| p.len() == "/v3/range/21BD1".len()),
        "{seen:?}"
    );
    assert!(seen.contains(&String::from("/v3/range/21BD1")));
}

// OP-151 m.3 (o): the base must be https
#[test]
fn the_base_is_https() {
    assert!(RangeApi::new("http://ranges.test", ()).is_err());
    assert!(RangeApi::new("https://ranges.test?x=1", ()).is_err());
    assert_eq!(
        RangeApi::new("https://ranges.test/", ())
            .unwrap()
            .url("ABCDE"),
        "https://ranges.test/range/ABCDE"
    );
}
