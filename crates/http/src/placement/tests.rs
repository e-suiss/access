#![allow(clippy::unwrap_used, reason = "test code")]

use axum::body::Body;
use axum::http::StatusCode;
use axum::routing::get;
use tower::ServiceExt as _;

use super::*;

struct Fixed(Result<Option<Elsewhere>, Unanswered>);

impl Directory for Fixed {
    fn elsewhere(&self, _domain: [u8; 32]) -> Lookup<'_> {
        let answer = self.0.clone();
        Box::pin(async move { answer })
    }
}

fn app(answer: Result<Option<Elsewhere>, Unanswered>) -> Router {
    route(
        Router::new().route("/access/v1/domains/{d}/metadata", get(|| async { "here" })),
        Arc::new(Fixed(answer)),
    )
}

fn path() -> String {
    format!(
        "/access/v1/domains/{}/metadata",
        access_kernel::json::b64url_encode(&[7; 32])
    )
}

async fn status(r: Router) -> (StatusCode, Option<String>, Option<String>) {
    let res = r
        .oneshot(Request::get(path()).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let h = |n: &str| {
        res.headers()
            .get(n)
            .and_then(|v| v.to_str().ok())
            .map(String::from)
    };
    (res.status(), h(CELL_HEADER), h("location"))
}

// TI-17, CMP-26, OP-158 m.3 (o)
#[tokio::test]
async fn ti_17_the_directory_routes_and_never_decides() {
    assert_eq!(domain_of(&path()), Some([7; 32]));
    assert_eq!(domain_of("/access/v1/domains/x/metadata"), None);
    let (s, cell, location) = status(app(Ok(Some(Elsewhere {
        cell: String::from("cell-b"),
        url: Some(String::from("https://b.access.example/")),
    }))))
    .await;
    assert_eq!(s, StatusCode::MISDIRECTED_REQUEST);
    assert_eq!(cell.as_deref(), Some("cell-b"));
    assert_eq!(
        location,
        Some(format!("https://b.access.example{}", path()))
    );
    assert_eq!(status(app(Ok(None))).await.0, StatusCode::OK);
    let body = format!(
        r#"{{"context":{{"domain":"{}"}}}}"#,
        access_kernel::json::b64url_encode(&[7; 32])
    );
    assert_eq!(body_domain(body.as_bytes()), Some([7; 32]));
    assert_eq!(body_domain(b"{}"), None);
    // TI-17: a directory that cannot answer is not a decision
    assert_eq!(status(app(Err(Unanswered))).await.0, StatusCode::OK);
}
