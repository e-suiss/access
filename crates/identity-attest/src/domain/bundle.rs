//! SPIFFE bundles (SPIFFE Trust Domain and Bundle §4, `draft-ietf-oauth-spiffe-client-auth`
//! §6.1, OP-154 m.3 (r)): the JWKS a trust domain's Bundle Endpoint serves, keyed by that trust
//! domain alone. Its `jwt-svid` keys verify JWT-SVIDs and its `x509-svid` certificates are the
//! X.509-SVID roots; a key of any other use verifies nothing.
//!
//! The bundle is refreshed after its `spiffe_refresh_hint`, kept within [5 min, 24 h]; a
//! bundle older than twice that interval verifies no SVID, whether or not a refresh failed.

use access_crypto::oauth::ClientKey;
use access_kernel::json::{self, Json, b64url_decode};

/// Largest bundle document read (PD).
pub const MAX_BUNDLE: usize = 256 * 1024;

/// Most keys read from one bundle.
pub const MAX_KEYS: usize = 64;

/// Shortest refresh interval, seconds (OP-154 m.3 (r)).
pub const MIN_REFRESH_S: u64 = 300;

/// Longest refresh interval, seconds (OP-154 m.3 (r)).
pub const MAX_REFRESH_S: u64 = 86_400;

/// The `use` of a key that verifies JWT-SVIDs.
pub const JWT_SVID: &str = "jwt-svid";

/// The `use` of a certificate that is an X.509-SVID root.
pub const X509_SVID: &str = "x509-svid";

const PRIVATE_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// Why a bundle is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BundleError {
    /// Not a JWKS, larger than [`MAX_BUNDLE`], or holding private key material.
    #[error("malformed bundle")]
    Format,
    /// An older `spiffe_sequence` than the bundle held (rollback).
    #[error("older sequence")]
    Rollback,
}

/// One JWT-SVID key: its `kid` and key. ES256 only (MD-3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JwtKey {
    /// `kid`.
    pub kid: String,
    /// The P-256 key.
    pub key: ClientKey,
}

/// A trust domain's bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle {
    /// The trust domain it was fetched for.
    pub trust_domain: String,
    /// `spiffe_sequence`.
    pub sequence: Option<u64>,
    /// `spiffe_refresh_hint`, seconds.
    pub refresh_hint_s: Option<u64>,
    /// The `jwt-svid` keys.
    pub jwt_keys: Vec<JwtKey>,
    /// The `x509-svid` root certificates, DER.
    pub x509_roots: Vec<Vec<u8>>,
}

fn b64_std_decode(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let body = s.trim_end_matches('=');
    if !s.len().is_multiple_of(4) || s.len().saturating_sub(body.len()) > 2 {
        return None;
    }
    let mut out = Vec::with_capacity(body.len());
    let mut acc = 0_u32;
    let mut bits = 0_u32;
    for c in body.bytes() {
        let v = ALPHABET.iter().position(|a| *a == c)?;
        acc = (acc.wrapping_shl(6) | u32::try_from(v).ok()?) & 0xffff;
        bits = bits.saturating_add(6);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            out.push(u8::try_from(acc.wrapping_shr(bits) & 0xff).ok()?);
        }
    }
    let rest = acc & 1_u32.wrapping_shl(bits).wrapping_sub(1);
    (rest == 0).then_some(out)
}

fn text<'a>(k: &'a Json, name: &str) -> Option<&'a str> {
    k.get(name).and_then(Json::as_str)
}

fn uint(v: Option<&Json>) -> Result<Option<u64>, BundleError> {
    v.map(|v| {
        v.as_int()
            .and_then(|i| u64::try_from(i).ok())
            .ok_or(BundleError::Format)
    })
    .transpose()
}

fn p256(k: &Json) -> Option<ClientKey> {
    if text(k, "kty") != Some("EC") || text(k, "crv") != Some("P-256") {
        return None;
    }
    let x = b64url_decode(text(k, "x")?).ok()?;
    let y = b64url_decode(text(k, "y")?).ok()?;
    if x.len() != 32 || y.len() != 32 {
        return None;
    }
    let mut sec1 = vec![4];
    sec1.extend(x);
    sec1.extend(y);
    Some(ClientKey::P256(sec1))
}

impl Bundle {
    /// Parses the bundle `doc` fetched for `trust_domain`. Keys of an unknown `use` or type are
    /// skipped; a document holding private key material is refused whole.
    ///
    /// # Errors
    /// [`BundleError::Format`].
    pub fn parse(trust_domain: &str, doc: &[u8]) -> Result<Self, BundleError> {
        let top = json::parse(doc, MAX_BUNDLE).map_err(|_| BundleError::Format)?;
        let Some(Json::Array(keys)) = top.get("keys") else {
            return Err(BundleError::Format);
        };
        let mut b = Self {
            trust_domain: String::from(trust_domain),
            sequence: uint(top.get("spiffe_sequence"))?,
            refresh_hint_s: uint(top.get("spiffe_refresh_hint"))?,
            jwt_keys: Vec::new(),
            x509_roots: Vec::new(),
        };
        if keys.len() > MAX_KEYS {
            return Err(BundleError::Format);
        }
        for k in keys {
            let Json::Object(m) = k else {
                return Err(BundleError::Format);
            };
            if m.iter().any(|(n, _)| PRIVATE_MEMBERS.contains(&n.as_str())) {
                return Err(BundleError::Format);
            }
            match text(k, "use") {
                Some(JWT_SVID) => {
                    if let (Some(kid), Some(key)) = (text(k, "kid"), p256(k))
                        && !kid.is_empty()
                    {
                        b.jwt_keys.push(JwtKey {
                            kid: String::from(kid),
                            key,
                        });
                    }
                }
                Some(X509_SVID) => {
                    let Some(Json::Array(chain)) = k.get("x5c") else {
                        continue;
                    };
                    if let [Json::Str(first)] = chain.as_slice()
                        && let Some(der) = b64_std_decode(first)
                    {
                        b.x509_roots.push(der);
                    }
                }
                _ => {}
            }
        }
        Ok(b)
    }

    /// The refresh interval: `spiffe_refresh_hint` kept within [[`MIN_REFRESH_S`],
    /// [`MAX_REFRESH_S`]]; the shortest without a hint.
    #[must_use]
    pub fn refresh_interval_s(&self) -> u64 {
        refresh_interval_s(self.refresh_hint_s)
    }

    /// Whether `next` may replace this bundle: same trust domain, and a sequence that does not
    /// go back (SPIFFE Trust Domain and Bundle §4.1.1).
    ///
    /// # Errors
    /// [`BundleError::Rollback`].
    pub fn replaced_by(&self, next: &Self) -> Result<(), BundleError> {
        if next.trust_domain != self.trust_domain {
            return Err(BundleError::Format);
        }
        match (self.sequence, next.sequence) {
            (Some(old), Some(new)) if new < old => Err(BundleError::Rollback),
            (Some(_), None) => Err(BundleError::Rollback),
            _ => Ok(()),
        }
    }
}

/// The refresh interval of a bundle with `hint`, seconds (OP-154 m.3 (r)).
#[must_use]
pub fn refresh_interval_s(hint: Option<u64>) -> u64 {
    hint.unwrap_or(MIN_REFRESH_S)
        .clamp(MIN_REFRESH_S, MAX_REFRESH_S)
}

/// Whether a bundle fetched at `fetched_ms` is due for a refresh at `now_ms`.
#[must_use]
pub fn refresh_due(fetched_ms: u64, interval_s: u64, now_ms: u64) -> bool {
    now_ms.saturating_sub(fetched_ms) >= interval_s.saturating_mul(1000)
}

/// OP-154 m.3 (r): whether a bundle fetched at `fetched_ms` still verifies SVIDs at `now_ms`:
/// not when it is older than twice its refresh interval.
#[must_use]
pub fn usable(fetched_ms: u64, interval_s: u64, now_ms: u64) -> bool {
    fetched_ms <= now_ms && now_ms.saturating_sub(fetched_ms) <= interval_s.saturating_mul(2_000)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    const DOC: &str = r#"{"keys":[
        {"use":"jwt-svid","kty":"EC","kid":"k1","crv":"P-256",
         "x":"S2V42XlFjNp30CFmOidbWQT9IpZHqJ8JuuJgDBvkdZA","y":"vN0y5TK36VRxZo_E3Gc7S5c0jIRIaHZ53f2UiJ1NFto"},
        {"use":"wit-svid","kty":"EC","kid":"w1","crv":"P-256",
         "x":"18wHLeIgW9wVN6VD1Txgpqy2LszYkMf6J8njVAibvhM","y":"-V4dS4UaLMgP_4fY4j8ir7cl1TXlFdAgcx55o7TkcSA"},
        {"use":"x509-svid","kty":"EC","crv":"P-256","x5c":["MAMCAQA="]}
      ],"spiffe_sequence":10,"spiffe_refresh_hint":30}"#;

    // §11.12.1, OP-154 m.3 (r)
    #[test]
    fn only_svid_keys_of_their_own_use_are_read() {
        let b = Bundle::parse("acme.example", DOC.as_bytes()).unwrap();
        assert_eq!(b.jwt_keys.len(), 1);
        assert_eq!(b.jwt_keys.first().unwrap().kid, "k1");
        assert_eq!(b.x509_roots, vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]);
        assert_eq!(b.sequence, Some(10));
        assert_eq!(b.refresh_interval_s(), MIN_REFRESH_S);
        let private = DOC.replace(r#""kid":"k1","#, r#""kid":"k1","d":"AA","#);
        assert_eq!(
            Bundle::parse("acme.example", private.as_bytes()),
            Err(BundleError::Format)
        );
        assert!(Bundle::parse("acme.example", b"{}").is_err());
    }

    // OP-154 m.3 (r)
    #[test]
    fn the_refresh_hint_is_kept_within_five_minutes_and_a_day() {
        assert_eq!(refresh_interval_s(None), 300);
        assert_eq!(refresh_interval_s(Some(1)), 300);
        assert_eq!(refresh_interval_s(Some(3_600)), 3_600);
        assert_eq!(refresh_interval_s(Some(u64::MAX)), 86_400);
        assert!(!refresh_due(0, 300, 299_999));
        assert!(refresh_due(0, 300, 300_000));
    }

    // OP-154 m.3 (r), AG-30
    #[test]
    fn a_bundle_older_than_twice_its_refresh_interval_verifies_nothing() {
        let fetched = 1_000_000;
        assert!(usable(fetched, 300, fetched + 600_000));
        assert!(!usable(fetched, 300, fetched + 600_001));
        assert!(!usable(fetched + 1, 300, fetched));
    }

    // OP-154 m.3 (r)
    #[test]
    fn a_bundle_never_goes_back_in_sequence() {
        let b = Bundle::parse("acme.example", DOC.as_bytes()).unwrap();
        let older = DOC.replace("\"spiffe_sequence\":10", "\"spiffe_sequence\":9");
        let older = Bundle::parse("acme.example", older.as_bytes()).unwrap();
        assert_eq!(b.replaced_by(&older), Err(BundleError::Rollback));
        assert_eq!(older.replaced_by(&b), Ok(()));
        let other = Bundle::parse("beta.example", DOC.as_bytes()).unwrap();
        assert!(b.replaced_by(&other).is_err());
    }
}
