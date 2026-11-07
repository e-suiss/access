//! `endpoint-manifest` (TN-113, OP-151 m.2 M0): every management route is a row of the endpoint
//! permission manifest, so no code under `crates/http/src/api/` adds a route except the
//! manifest's builder, and the management router never gets an unguarded route. `.route(`,
//! `.route_service(`, `.nest(` and `.nest_service(` in the code view of any other file there are
//! violations; comments, strings and test code are not.

use std::path::{Path, PathBuf};

use crate::Violation;
use crate::rules::files::{rel, walk};
use crate::rules::lex::{in_regions, lex, line_at, test_regions};

const RULE: &str = "endpoint-manifest";

/// The management API's code.
const API_DIR: &str = "crates/http/src/api/";

/// The one file that adds routes: the manifest builder.
const BUILDER: &str = "crates/http/src/api/manifest.rs";

const CALLS: &[&str] = &[".route(", ".route_service(", ".nest(", ".nest_service("];

/// Route additions outside the builder in one file's non-test code.
pub(crate) fn violations(rel_path: &str, src: &str) -> Vec<Violation> {
    if !rel_path.starts_with(API_DIR) || rel_path == BUILDER {
        return Vec::new();
    }
    let lexed = lex(src);
    let tests = test_regions(&lexed.code);
    let mut out = Vec::new();
    for call in CALLS {
        for (at, _) in lexed.code.match_indices(call) {
            let line = line_at(&lexed.code, at);
            if in_regions(&tests, line) {
                continue;
            }
            out.push(Violation {
                rule: RULE,
                path: PathBuf::from(format!("{rel_path}:{line}")),
                message: format!(
                    "`{}` outside the manifest builder: add a manifest row and register its handler with `Builder::handle` (TN-113)",
                    call.trim_start_matches('.').trim_end_matches('(')
                ),
            });
        }
    }
    out
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for path in walk(root)? {
        let rel_path = rel(root, &path);
        if rel_path.starts_with(API_DIR) && path.extension().is_some_and(|e| e == "rs") {
            let src = std::fs::read_to_string(&path).map_err(|e| format!("{rel_path}: {e}"))?;
            out.extend(violations(&rel_path, &src));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // TN-113: a route added outside the manifest builder is refused
    #[test]
    fn tn_113_route_outside_the_manifest_is_rejected() {
        let src = "fn r() -> Router { Router::new().route(\"/x\", get(h)).nest(\"/y\", other) }\n";
        let v = violations("crates/http/src/api/app.rs", src);
        assert_eq!(v.len(), 2, "{v:?}");
        assert_eq!(
            violations("crates/http/src/api/app/handlers.rs", src).len(),
            2
        );
    }

    // TN-113: the builder itself, comments, strings, tests and other directories are accepted
    #[test]
    fn tn_113_builder_comments_and_tests_are_accepted() {
        let src = "fn r() { router.route(path, m); }\n";
        assert!(violations(BUILDER, src).is_empty());
        assert!(violations("crates/http/src/login/web.rs", src).is_empty());
        let quiet = "// call .route( here\nconst S: &str = \".route(\";\n#[cfg(test)]\nmod tests {\n    fn t() { r.route(\"/\", g); }\n}\n";
        assert!(violations("crates/http/src/api/app.rs", quiet).is_empty());
    }
}
