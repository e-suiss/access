//! Handles (E56, OP-156 m.3 (w)): a person's or agent's human-readable name, a Suiss
//! subdomain or a domain the person owns, beside the permanent `did:web` identifier. A handle is
//! shown only when both directions agree: the handle's host answers
//! `/.well-known/access-handle` with the DID, and the DID document lists the handle in
//! `alsoKnownAs`. Either one missing or different, and the handle is not shown. A handle is an
//! identifier, never authority; phone numbers and e-mail addresses are only discovery hints.

use serde_json::Value;

/// The path the handle's host answers with the DID.
pub const WELL_KNOWN: &str = "/.well-known/access-handle";

/// Longest well-known answer read.
pub const MAX_ANSWER: usize = 512;

/// A handle: a lowercase DNS name of at least two labels.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Handle(String);

impl Handle {
    /// Parses `text`, lowercased; `None` unless it is a DNS name of at least two labels, each
    /// 1 to 63 letters, digits or inner hyphens, 253 characters at most.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let t = text.trim_end_matches('.').to_ascii_lowercase();
        let labels: Vec<&str> = t.split('.').collect();
        let ok = t.len() <= 253
            && labels.len() >= 2
            && labels.iter().all(|l| {
                (1..=63).contains(&l.len())
                    && !l.starts_with('-')
                    && !l.ends_with('-')
                    && l.chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            });
        ok.then_some(Self(t))
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Where the handle's host answers with the DID.
    #[must_use]
    pub fn well_known_url(&self) -> String {
        format!("https://{}{WELL_KNOWN}", self.0)
    }

    /// The `alsoKnownAs` entry that names it.
    #[must_use]
    pub fn also_known_as(&self) -> String {
        format!("https://{}", self.0)
    }

    /// Whether it is a subdomain of `base`, the realm's Suiss host.
    #[must_use]
    pub fn under(&self, base: &str) -> bool {
        self.0
            .strip_suffix(&base.to_ascii_lowercase())
            .is_some_and(|rest| rest.ends_with('.') && rest.len() > 1)
    }
}

/// Where a handle stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Both directions agree: it may be shown.
    Verified,
    /// The host's answer is missing or names another DID.
    HandleToDid,
    /// The DID document does not list it.
    DidToHandle,
}

/// Checks both directions for `handle` and `did`: `answer` is the body the handle's host gave at
/// [`WELL_KNOWN`] (`None` when it gave none), `document` the DID document.
#[must_use]
pub fn verify(handle: &Handle, did: &str, answer: Option<&[u8]>, document: &Value) -> Verdict {
    let named = answer
        .filter(|a| a.len() <= MAX_ANSWER)
        .and_then(|a| std::str::from_utf8(a).ok())
        .is_some_and(|a| a.trim() == did);
    if !named {
        return Verdict::HandleToDid;
    }
    let listed = document.get("id").and_then(Value::as_str) == Some(did)
        && document
            .get("alsoKnownAs")
            .and_then(Value::as_array)
            .is_some_and(|a| {
                a.iter()
                    .any(|v| v.as_str() == Some(handle.also_known_as().as_str()))
            });
    if listed {
        Verdict::Verified
    } else {
        Verdict::DidToHandle
    }
}

/// The handle to show for a Party: only a verified one, else none (E56 (2)).
#[must_use]
pub fn shown(handle: &Handle, verdict: Verdict) -> Option<&str> {
    (verdict == Verdict::Verified).then(|| handle.as_str())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const DID: &str = "did:web:access.test:realms:acme:u:AAECAwQFBgcICQoLDA0ODw";

    fn doc(also: &[&str]) -> Value {
        json!({ "id": DID, "alsoKnownAs": also })
    }

    // E56, OP-156 m.3 (w), Ek B 4330
    #[test]
    fn a_handle_is_shown_only_when_both_directions_agree() {
        let h = Handle::parse("Ada.Example.org.").unwrap();
        assert_eq!(h.as_str(), "ada.example.org");
        assert_eq!(
            h.well_known_url(),
            "https://ada.example.org/.well-known/access-handle"
        );
        let both = verify(
            &h,
            DID,
            Some(format!("{DID}\n").as_bytes()),
            &doc(&["https://ada.example.org"]),
        );
        assert_eq!(shown(&h, both), Some("ada.example.org"));
        for (answer, document, want) in [
            (
                None,
                doc(&["https://ada.example.org"]),
                Verdict::HandleToDid,
            ),
            (
                Some("did:web:other.test:u:x".as_bytes()),
                doc(&["https://ada.example.org"]),
                Verdict::HandleToDid,
            ),
            (Some(DID.as_bytes()), doc(&[]), Verdict::DidToHandle),
            (
                Some(DID.as_bytes()),
                doc(&["https://eve.example.org"]),
                Verdict::DidToHandle,
            ),
            (
                Some(DID.as_bytes()),
                json!({ "id": "did:web:other", "alsoKnownAs": ["https://ada.example.org"] }),
                Verdict::DidToHandle,
            ),
        ] {
            let v = verify(&h, DID, answer, &document);
            assert_eq!(v, want);
            assert_eq!(shown(&h, v), None);
        }
    }

    // E56 (2)
    #[test]
    fn a_handle_is_a_dns_name_and_a_suiss_handle_a_subdomain() {
        for bad in [
            "ada",
            "-a.example",
            "a..example",
            "a_b.example",
            "ada@example.org",
        ] {
            assert!(Handle::parse(bad).is_none(), "{bad}");
        }
        let h = Handle::parse("ada.acme.suiss.app").unwrap();
        assert!(h.under("acme.suiss.app"));
        assert!(!h.under("suiss.app.evil"));
        assert!(
            !Handle::parse("acme.suiss.app")
                .unwrap()
                .under("acme.suiss.app")
        );
    }
}
