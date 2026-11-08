//! N5: the realm's theme record as the hosted pages apply it (TN-106, CMP-15.6, F23, OP-153
//! m.3 (t)): branding is data, never a template. The page draws the name and the logo itself;
//! the colours become CSS custom properties of a generated style sheet; the only outside
//! content is the logo, drawn with `<img>` from an origin the record lists, so an SVG logo
//! cannot run script and there is no upload endpoint (§14.3). Every value is checked again
//! when read; a record that does not check is applied as no branding at all.

use suiss_crypto::dcbor::{self, Limits, Value};

/// The hosted pages' base policy (TN-106, IDP-36): no third-party script, no inline script or
/// style, no framing; `img-src`, between these, takes the branding origins.
const HEAD: [&str; 3] = [
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
];

/// The rest of the base policy, after `img-src`.
const TAIL: [&str; 9] = [
    "connect-src 'self'",
    "font-src 'self'",
    "manifest-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "require-trusted-types-for 'script'",
    "trusted-types 'none'",
];

/// Longest name drawn.
const MAX_NAME: usize = 64;

/// Most image origins.
const MAX_ORIGINS: usize = 8;

/// The report endpoint below the realm issuer.
pub const CSP_REPORTS_PATH: &str = "/csp-reports";

/// How the branding's extra sources are applied (OP-153 m.3 (t)).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CspMode {
    /// The policy with the branding origins is enforced (a new realm's default).
    #[default]
    Enforce,
    /// The base policy is enforced; the one with the branding origins is only reported, so a
    /// new source loads only once the realm moves to `enforce`.
    ReportOnly,
}

/// The theme record, checked.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Theme {
    /// The name the pages show.
    pub display_name: Option<String>,
    /// The logo, `https` and from one of `origins`.
    pub logo_uri: Option<String>,
    /// `#rrggbb`.
    pub primary: Option<String>,
    /// `#rrggbb`.
    pub background: Option<String>,
    /// The `https` origins images may come from.
    pub origins: Vec<String>,
    /// The CSP mode.
    pub csp_mode: CspMode,
}

fn color(s: &str) -> bool {
    s.len() == 7
        && s.strip_prefix('#').is_some_and(|h| {
            h.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        })
}

/// `https://host[:port]` with nothing after it.
fn is_origin(o: &str) -> bool {
    o.strip_prefix("https://").is_some_and(|rest| {
        !rest.is_empty()
            && rest
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b':'))
    })
}

fn origin_of(u: &str) -> Option<&str> {
    let rest = u.strip_prefix("https://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    u.get(..end.checked_add(8)?)
}

fn text<'a>(m: &'a [(Value, Value)], key: &str) -> Option<&'a str> {
    m.iter().find_map(|(k, v)| match (k, v) {
        (Value::Text(k), Value::Text(v)) if k == key => Some(v.as_str()),
        _ => None,
    })
}

impl Theme {
    /// The stored record (`idp.realm.branding`, deterministic CBOR), checked; anything that
    /// does not check is no branding.
    #[must_use]
    pub fn decode(bytes: Option<&[u8]>) -> Self {
        let Some(Value::Map(m)) = bytes.and_then(|b| dcbor::decode(b, Limits::CEILING).ok()) else {
            return Self::default();
        };
        let origins: Vec<String> = m
            .iter()
            .find_map(|(k, v)| match (k, v) {
                (Value::Text(k), Value::Array(a)) if k == "csp_origins" => Some(a),
                _ => None,
            })
            .map(|a| {
                a.iter()
                    .filter_map(|v| match v {
                        Value::Text(t) if is_origin(t) => Some(t.clone()),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        if origins.len() > MAX_ORIGINS {
            return Self::default();
        }
        let display_name = text(&m, "display_name")
            .filter(|n| {
                let len = n.chars().count();
                (1..=MAX_NAME).contains(&len) && !n.chars().any(char::is_control)
            })
            .map(String::from);
        let logo_uri = text(&m, "logo_uri")
            .filter(|u| {
                origin_of(u).is_some_and(|o| origins.iter().any(|x| x == o))
                    && !u.chars().any(|c| c.is_control() || c.is_whitespace())
            })
            .map(String::from);
        let csp_mode = match text(&m, "csp_mode") {
            Some("report_only") => CspMode::ReportOnly,
            _ => CspMode::Enforce,
        };
        Self {
            display_name,
            logo_uri,
            primary: text(&m, "primary_color")
                .filter(|c| color(c))
                .map(String::from),
            background: text(&m, "background_color")
                .filter(|c| color(c))
                .map(String::from),
            origins,
            csp_mode,
        }
    }

    /// The generated style sheet: custom properties only, from checked colours.
    #[must_use]
    pub fn css(&self) -> String {
        let mut out = String::from(":root{");
        if let Some(c) = &self.primary {
            out.push_str("--brand-primary:");
            out.push_str(c);
            out.push(';');
        }
        if let Some(c) = &self.background {
            out.push_str("--brand-background:");
            out.push_str(c);
            out.push(';');
        }
        out.push_str("}\n");
        out
    }

    /// The page's `Content-Security-Policy` and, in report-only mode, its
    /// `Content-Security-Policy-Report-Only` (OP-153 m.3 (t)); both report to `base` +
    /// [`CSP_REPORTS_PATH`].
    #[must_use]
    pub fn csp(&self, base: &str) -> (String, Option<String>) {
        let report = format!("report-uri {base}{CSP_REPORTS_PATH}; report-to csp");
        let policy = |origins: &[String]| {
            let mut img = String::from("img-src 'self'");
            for o in origins {
                img.push(' ');
                img.push_str(o);
            }
            let mut out = HEAD.join("; ");
            out.push_str("; ");
            out.push_str(&img);
            out.push_str("; ");
            out.push_str(&TAIL.join("; "));
            out.push_str("; ");
            out.push_str(&report);
            out
        };
        match self.csp_mode {
            CspMode::Enforce => (policy(&self.origins), None),
            CspMode::ReportOnly => (policy(&[]), Some(policy(&self.origins))),
        }
    }

    /// The JSON the pages read: the name and the logo.
    #[must_use]
    pub fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "display_name": self.display_name,
            "logo_uri": self.logo_uri,
        })
    }
}

/// The `Reporting-Endpoints` value naming the report endpoint `csp`.
#[must_use]
pub fn reporting_endpoints(base: &str) -> String {
    format!("csp=\"{base}{CSP_REPORTS_PATH}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(entries: Vec<(&str, Value)>) -> Vec<u8> {
        let v = Value::Map(
            entries
                .into_iter()
                .map(|(k, v)| (Value::Text(k.into()), v))
                .collect(),
        );
        dcbor::encode(&v, Limits::CEILING).unwrap()
    }

    // TN-106
    #[test]
    fn a_record_is_checked_again_when_read() {
        let ok = record(vec![
            ("display_name", Value::Text("Acme".into())),
            (
                "logo_uri",
                Value::Text("https://cdn.acme.example/l.svg".into()),
            ),
            ("primary_color", Value::Text("#112233".into())),
            ("background_color", Value::Text("red;}body{x".into())),
            (
                "csp_origins",
                Value::Array(vec![Value::Text("https://cdn.acme.example".into())]),
            ),
        ]);
        let t = Theme::decode(Some(&ok));
        assert_eq!(t.display_name.as_deref(), Some("Acme"));
        assert_eq!(
            t.logo_uri.as_deref(),
            Some("https://cdn.acme.example/l.svg")
        );
        assert_eq!(t.background, None);
        assert_eq!(t.css(), ":root{--brand-primary:#112233;}\n");
        let foreign = record(vec![
            ("logo_uri", Value::Text("https://evil.example/l.svg".into())),
            (
                "csp_origins",
                Value::Array(vec![Value::Text("https://cdn.acme.example".into())]),
            ),
        ]);
        assert_eq!(Theme::decode(Some(&foreign)).logo_uri, None);
        assert_eq!(Theme::decode(Some(b"\xff")), Theme::default());
    }

    // TN-106, IDP-36, OP-153 m.3 (t)
    #[test]
    fn the_policy_adds_only_image_origins_and_reports() {
        let mut t = Theme {
            origins: vec![String::from("https://cdn.acme.example")],
            ..Theme::default()
        };
        let (enforced, report_only) = t.csp("/realms/acme");
        assert!(enforced.contains("img-src 'self' https://cdn.acme.example;"));
        assert!(enforced.contains("script-src 'self';"));
        assert!(enforced.contains("frame-ancestors 'none'"));
        assert!(enforced.contains("report-uri /realms/acme/csp-reports"));
        assert!(report_only.is_none());
        t.csp_mode = CspMode::ReportOnly;
        let (enforced, report_only) = t.csp("");
        assert!(enforced.contains("img-src 'self';"));
        assert!(
            report_only
                .unwrap()
                .contains("img-src 'self' https://cdn.acme.example;")
        );
        assert!(!enforced.contains("unsafe"));
    }
}
