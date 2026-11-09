//! The hosted login's built web assets (`web/login/dist`, OP-146 m.12 (a), (f)). They are read
//! once at start-up, before the lockdown closes the file system, and served from memory with
//! the security headers of `web/login/security-headers.ts`.

use std::collections::HashMap;
use std::path::Path;

use axum::body::Bytes;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

/// `Content-Security-Policy` of the hosted login (OP-146 m.12 (f), TN-106, IDP-36).
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; font-src 'self'; manifest-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types 'none'";

/// The headers every hosted login page and asset carries (§14.5, OP-146 m.12 (f)).
pub const SECURITY_HEADERS: [(&str, &str); 6] = [
    ("content-security-policy", CONTENT_SECURITY_POLICY),
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "no-referrer"),
    ("cross-origin-opener-policy", "same-origin"),
    ("cross-origin-resource-policy", "same-origin"),
    (
        "permissions-policy",
        "publickey-credentials-get=(self), publickey-credentials-create=(self), camera=(), microphone=(), geolocation=(), payment=()",
    ),
];

/// Most files read (PD).
const MAX_FILES: usize = 4_096;
/// Most bytes read in total (PD).
const MAX_BYTES: u64 = 32 * 1024 * 1024;
/// Deepest directory read.
const MAX_DEPTH: usize = 4;

const INDEX: &str = "index.html";
const IMMUTABLE: &str = "public, max-age=31536000, immutable";

/// Why the assets cannot be served; the server does not start.
#[derive(Debug, thiserror::Error)]
pub enum AssetsError {
    /// The directory or a file could not be read.
    #[error("{0}: {1}")]
    Read(String, std::io::Error),
    /// More files or bytes than allowed, or too deep.
    #[error("the login assets exceed their limits")]
    TooLarge,
    /// No `index.html`.
    #[error("the login assets have no index.html")]
    NoIndex,
}

struct File {
    body: Bytes,
    content_type: &'static str,
}

/// The built login app, in memory.
pub struct Assets {
    files: HashMap<String, File>,
}

fn content_type(name: &str) -> &'static str {
    match name.rsplit_once('.').map(|(_, ext)| ext) {
        Some("html") => "text/html; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json" | "map") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("txt") => "text/plain; charset=utf-8",
        Some("webmanifest") => "application/manifest+json",
        _ => "application/octet-stream",
    }
}

fn walk(
    dir: &Path,
    prefix: &str,
    depth: usize,
    total: &mut u64,
    files: &mut HashMap<String, File>,
) -> Result<(), AssetsError> {
    if depth > MAX_DEPTH {
        return Err(AssetsError::TooLarge);
    }
    let shown = || dir.display().to_string();
    for entry in std::fs::read_dir(dir).map_err(|e| AssetsError::Read(shown(), e))? {
        let entry = entry.map_err(|e| AssetsError::Read(shown(), e))?;
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        let path = entry.path();
        let kind = std::fs::symlink_metadata(&path)
            .map_err(|e| AssetsError::Read(path.display().to_string(), e))?;
        let rel = format!("{prefix}{name}");
        if kind.is_dir() {
            walk(
                &path,
                &format!("{rel}/"),
                depth.saturating_add(1),
                total,
                files,
            )?;
        } else if kind.is_file() {
            *total = total.saturating_add(kind.len());
            if *total > MAX_BYTES || files.len() >= MAX_FILES {
                return Err(AssetsError::TooLarge);
            }
            let body = std::fs::read(&path)
                .map_err(|e| AssetsError::Read(path.display().to_string(), e))?;
            files.insert(
                rel,
                File {
                    content_type: content_type(&name),
                    body: Bytes::from(body),
                },
            );
        }
    }
    Ok(())
}

impl Assets {
    /// Reads `dir`: regular files only, no symbolic links, dot files skipped.
    ///
    /// # Errors
    /// [`AssetsError`].
    pub fn load(dir: &Path) -> Result<Self, AssetsError> {
        let mut files = HashMap::new();
        let mut total = 0;
        walk(dir, "", 0, &mut total, &mut files)?;
        if !files.contains_key(INDEX) {
            return Err(AssetsError::NoIndex);
        }
        Ok(Self { files })
    }

    fn respond(file: &File, cache: &'static str) -> Response {
        let mut response = (StatusCode::OK, file.body.clone()).into_response();
        let h = response.headers_mut();
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(file.content_type),
        );
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
        secure(h);
        response
    }

    /// The app's page, for every route the app draws.
    #[must_use]
    pub fn page(&self) -> Option<Response> {
        self.files.get(INDEX).map(|f| Self::respond(f, "no-cache"))
    }

    /// The app's page served under `base`, its asset references moved there with it.
    #[must_use]
    pub fn page_at(&self, base: &str) -> Option<Response> {
        let file = self.files.get(INDEX)?;
        if base.is_empty() {
            return Some(Self::respond(file, "no-cache"));
        }
        let html = std::str::from_utf8(&file.body).ok()?;
        let moved = File {
            body: html
                .replace("\"/assets/", &format!("\"{base}/assets/"))
                .replace("=/assets/", &format!("={base}/assets/"))
                .into_bytes()
                .into(),
            content_type: file.content_type,
        };
        Some(Self::respond(&moved, "no-cache"))
    }

    /// A built asset under `assets/`; content-hashed, so cached for good.
    #[must_use]
    pub fn asset(&self, path: &str) -> Option<Response> {
        if path
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == "..")
        {
            return None;
        }
        self.files
            .get(&format!("assets/{path}"))
            .map(|f| Self::respond(f, IMMUTABLE))
    }
}

/// Adds [`SECURITY_HEADERS`].
pub fn secure(h: &mut axum::http::HeaderMap) {
    for (name, value) in SECURITY_HEADERS {
        h.insert(name, HeaderValue::from_static(value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn body(r: Response) -> String {
        let b = axum::body::to_bytes(r.into_body(), usize::MAX)
            .await
            .unwrap_or_default();
        String::from_utf8_lossy(&b).into_owned()
    }

    // OP-153 m.2, m.23 (f)
    #[tokio::test]
    async fn a_page_under_a_realm_path_loads_its_assets_from_there() {
        let dir = std::env::temp_dir().join(format!("access-login-page-at-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("assets")).unwrap_or_default();
        std::fs::write(
            dir.join("index.html"),
            "<script type=\"module\" src=\"/assets/a.js\"></script><link href=/assets/a.css>",
        )
        .unwrap_or_default();
        std::fs::write(dir.join("assets/a.js"), "export {};").unwrap_or_default();
        let assets = Assets::load(&dir).unwrap_or_else(|_| Assets {
            files: HashMap::new(),
        });
        let moved = body(assets.page_at("/realms/acme").unwrap_or_default()).await;
        assert_eq!(
            moved,
            "<script type=\"module\" src=\"/realms/acme/assets/a.js\"></script><link href=/realms/acme/assets/a.css>"
        );
        let root = body(assets.page_at("").unwrap_or_default()).await;
        assert!(root.contains("src=\"/assets/a.js\""));
    }
}
