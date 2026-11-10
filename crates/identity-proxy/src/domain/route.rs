//! Which registered path pattern a request falls under and the resource it asks about (OP-156
//! m.3 (l)): a pattern is a path prefix matched segment by segment, ASCII case-insensitively;
//! the longest one wins. A path an application could read two ways (`..`, `//`, an encoded
//! slash or backslash) is never matched, so it is refused rather than guessed about.

use access_kernel::model::ResourceRef;

/// Most patterns one registration names.
pub const MAX_ROUTES: usize = 64;

/// Longest pattern.
pub const MAX_ROUTE: usize = 512;

/// The callback path on the application host; its answer sets the proxy cookie.
pub const CALLBACK_PATH: &str = "/access-proxy/v1/callback";

fn segments(path: &str) -> impl Iterator<Item = &str> {
    path.split('/').filter(|s| !s.is_empty())
}

/// Whether `route` is a pattern: `/` or `/`-separated non-empty segments of unreserved
/// characters, no `.` or `..` segment, within [`MAX_ROUTE`].
#[must_use]
pub fn route_ok(route: &str) -> bool {
    if route == "/" {
        return true;
    }
    route.len() <= MAX_ROUTE
        && route.starts_with('/')
        && !route.ends_with('/')
        && route.split('/').skip(1).all(|s| {
            !s.is_empty()
                && s != "."
                && s != ".."
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~'))
        })
}

/// Whether `path` has one reading only.
fn unambiguous(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    !path.contains("//")
        && !path.contains('\\')
        && !lower.contains("%2f")
        && !lower.contains("%5c")
        && !lower.contains("%2e")
        && path.split('/').all(|s| s != "." && s != "..")
}

/// The longest of `routes` that `path` falls under; `None` when none does or `path` is
/// ambiguous.
#[must_use]
pub fn pattern<'a>(routes: &'a [String], path: &str) -> Option<&'a str> {
    if !unambiguous(path) {
        return None;
    }
    let asked: Vec<&str> = segments(path).collect();
    routes
        .iter()
        .filter(|r| {
            let want: Vec<&str> = segments(r).collect();
            want.len() <= asked.len()
                && want
                    .iter()
                    .zip(&asked)
                    .all(|(w, a)| w.eq_ignore_ascii_case(a))
        })
        .max_by_key(|r| segments(r).count())
        .map(String::as_str)
}

/// The resource of a request under `route` of application `app` in `namespace`: the
/// application, then the pattern's segments in lower case.
#[must_use]
pub fn resource(namespace: &str, app: &str, route: &str) -> ResourceRef {
    let mut path = vec![String::from(app)];
    path.extend(segments(route).map(str::to_ascii_lowercase));
    ResourceRef {
        namespace: String::from(namespace),
        path,
        incarnation: 0,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::assert_is_empty, reason = "test code")]

    use super::*;

    fn routes(r: &[&str]) -> Vec<String> {
        r.iter().map(|s| String::from(*s)).collect()
    }

    // OP-156 m.3 (l)
    #[test]
    fn the_longest_pattern_wins_and_an_ambiguous_path_matches_none() {
        let r = routes(&["/", "/admin", "/admin/keys"]);
        assert_eq!(pattern(&r, "/"), Some("/"));
        assert_eq!(pattern(&r, "/wiki/page"), Some("/"));
        assert_eq!(pattern(&r, "/admin"), Some("/admin"));
        assert_eq!(pattern(&r, "/ADMIN/users"), Some("/admin"));
        assert_eq!(pattern(&r, "/admin/keys/1"), Some("/admin/keys"));
        assert_eq!(pattern(&r, "/administrator"), Some("/"));
        for bad in [
            "/admin//keys",
            "/x/../admin",
            "/admin%2Fkeys",
            "/a\\b",
            "/%2e%2e/admin",
        ] {
            assert_eq!(pattern(&r, bad), None, "{bad}");
        }
        assert_eq!(pattern(&routes(&["/admin"]), "/wiki"), None);
        assert_eq!(resource("apps", "wiki", "/Admin").path, ["wiki", "admin"]);
        assert_eq!(resource("apps", "wiki", "/").path, ["wiki"]);
        assert!(route_ok("/") && route_ok("/admin/keys"));
        assert!(!route_ok("/admin/") && !route_ok("admin") && !route_ok("/a/../b"));
    }
}
