//! `layer-order` (GHSA-84jc-3hj2-hwc7, SA-27, OP-158 m.3 (v)): authentication and limits run
//! before the expensive extractors in every router. The shared stack lists its layers in the
//! SA-27 order, both listeners admit through it, no HTTP handler takes a body extractor that
//! parses before the handler authenticates, and the HTTP crate decodes no images.

use std::path::Path;

use crate::Violation;
use crate::rules::files::{is_test_file, read, rel, walk};

const RULE: &str = "layer-order";

const STACK: &str = "crates/http/src/lib.rs";
const SERVER: &str = "bins/access-server/src/main.rs";
const HTTP_MANIFEST: &str = "crates/http/Cargo.toml";

/// The layers of `harden`, innermost first: what layer runs after what (SA-27).
const ORDER: [&str; 6] = [
    "layers::lane",
    "TimeoutLayer::with_status_code",
    "RequestBodyLimitLayer::new",
    "layers::client_rate",
    "edge::confine",
    "CatchPanicLayer::custom",
];

/// The admissions each listener of the server is hardened with.
const LISTENERS: [&str; 2] = [
    "admitting(access_http::layers::CRITICAL)",
    "admitting(access_http::layers::ADMIN)",
];

/// Extractors that read and parse a body before the handler runs.
const BODY_EXTRACTORS: [&str; 8] = [
    ": Json<",
    ": axum::Json<",
    ": Form<",
    ": axum::Form<",
    "extract::Json<",
    "extract::Form<",
    "Multipart",
    "RawForm",
];

/// Image decoders the HTTP crate never depends on.
const IMAGE_CRATES: [&str; 6] = ["image", "png", "jpeg-decoder", "gif", "resvg", "usvg"];

fn violation(path: &str, message: String) -> Violation {
    Violation {
        rule: RULE,
        path: path.into(),
        message,
    }
}

/// The body of `fn harden` in `src`.
fn harden(src: &str) -> Option<&str> {
    let start = src.find("pub fn harden(")?;
    let body = src.get(start..)?;
    let end = body.find("\n}\n")?;
    body.get(..end)
}

/// The violations of the stack's order in `src`.
pub(crate) fn stack_order(src: &str) -> Vec<String> {
    let Some(body) = harden(src) else {
        return vec![String::from("no `pub fn harden(` in the shared stack")];
    };
    let mut out = Vec::new();
    let mut last: Option<(usize, &str)> = None;
    for layer in ORDER {
        let Some(at) = body.find(layer) else {
            out.push(format!("`harden` has no `{layer}` layer"));
            continue;
        };
        if let Some((before, name)) = last
            && at < before
        {
            out.push(format!(
                "`{layer}` is listed before `{name}`; SA-27 wants it outside"
            ));
        }
        last = Some((at, layer));
    }
    out
}

/// The body extractors a non-test source file uses, by line.
pub(crate) fn extractors(src: &str) -> Vec<(usize, &'static str)> {
    src.lines()
        .enumerate()
        .filter(|(_, l)| !l.trim_start().starts_with("//"))
        .flat_map(|(n, l)| {
            BODY_EXTRACTORS
                .iter()
                .filter(move |e| l.contains(**e))
                .map(move |e| (n.saturating_add(1), *e))
        })
        .collect()
}

/// The image crates a manifest names as dependencies.
pub(crate) fn image_crates(manifest: &str) -> Vec<&'static str> {
    IMAGE_CRATES
        .iter()
        .filter(|c| {
            manifest.lines().any(|l| {
                let l = l.trim_start();
                l.strip_prefix(**c)
                    .is_some_and(|rest| rest.trim_start().starts_with('='))
            })
        })
        .copied()
        .collect()
}

/// Runs `layer-order`.
pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    let stack = read(&root.join(STACK))?;
    out.extend(stack_order(&stack).into_iter().map(|m| violation(STACK, m)));
    let server = read(&root.join(SERVER))?;
    for listener in LISTENERS {
        if !server.contains(listener) {
            out.push(violation(
                SERVER,
                format!("a listener is not hardened with `{listener}`"),
            ));
        }
    }
    let manifest = read(&root.join(HTTP_MANIFEST))?;
    for c in image_crates(&manifest) {
        out.push(violation(
            HTTP_MANIFEST,
            format!(
                "`{c}` decodes images in the HTTP crate; decode after authentication elsewhere"
            ),
        ));
    }
    for path in walk(&root.join("crates/http/src"))? {
        let p = rel(root, &path);
        if path.extension().is_none_or(|e| e != "rs") || is_test_file(&p) {
            continue;
        }
        let src = read(&path)?;
        for (line, e) in extractors(&src) {
            out.push(violation(
                &p,
                format!(
                    "line {line}: `{e}` parses the body before the handler authenticates; take `Bytes` and parse after"
                ),
            ));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stack_must_list_its_layers_in_order() {
        let good = "pub fn harden(r) {\n layers::lane\n TimeoutLayer::with_status_code\n RequestBodyLimitLayer::new\n layers::client_rate\n edge::confine\n CatchPanicLayer::custom\n}\n";
        assert_eq!(stack_order(good), Vec::<String>::new());
        let swapped = good.replace(
            "TimeoutLayer::with_status_code\n RequestBodyLimitLayer::new",
            "RequestBodyLimitLayer::new\n TimeoutLayer::with_status_code",
        );
        assert_eq!(stack_order(&swapped).len(), 1);
        let missing = good.replace(" layers::client_rate\n", "");
        assert_eq!(stack_order(&missing).len(), 1);
        assert_eq!(stack_order("fn other() {}").len(), 1);
    }

    #[test]
    fn a_body_extractor_and_an_image_crate_are_found() {
        assert_eq!(
            extractors("async fn h(Json(b): Json<Body>) {}\n// : Json<T>\nasync fn g(b: Bytes) {}"),
            vec![(1, ": Json<")]
        );
        assert_eq!(
            image_crates("[dependencies]\nimage = \"0.25\"\npngx = 1\n"),
            vec!["image"]
        );
    }
}
