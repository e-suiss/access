//! A workload credential checked against its trust domain's current bundle (§11.12.1, AG-30,
//! OP-154 m.3 (r)).
//!
//! The kept bundle is used until its refresh interval passes; then the Bundle Endpoint is
//! fetched again and a parsed document that does not go back in sequence replaces it. A failed
//! fetch keeps the old bundle, which stops verifying once it is older than twice its interval.
//! A bundle kept for another endpoint is not used.

use crate::domain::bundle::{Bundle, refresh_due};
use crate::domain::svid::{self, Freshness, SvidError, Verified};
use crate::domain::workload::WorkloadId;
use crate::ports::{Bundles, Kept, Scope, Unavailable};

/// A workload credential.
#[derive(Clone, Copy, Debug)]
pub enum Credential<'a> {
    /// A JWT-SVID client assertion.
    Jwt(&'a str),
    /// An X.509-SVID client certificate chain, leaf first, DER.
    X509(&'a [Vec<u8>]),
}

impl Credential<'_> {
    /// The workload it names, before anything is verified.
    ///
    /// # Errors
    /// [`SvidError`].
    pub fn subject(&self) -> Result<WorkloadId, SvidError> {
        match self {
            Self::Jwt(t) => svid::jwt_subject(t),
            Self::X509(chain) => svid::x509_subject(chain.first().ok_or(SvidError::Format)?),
        }
    }
}

/// The bundle `realm` uses for `trust_domain` at `now_ms`, fetched from `endpoint` when none
/// is kept or it is due; `None` when there is none to use.
///
/// # Errors
/// [`Unavailable`].
pub async fn current_bundle<B: Bundles + ?Sized>(
    bundles: &B,
    realm: Scope,
    (trust_domain, endpoint): (&str, &str),
    now_ms: u64,
) -> Result<Option<(Bundle, u64)>, Unavailable> {
    let kept = bundles
        .kept(realm, trust_domain)
        .await?
        .filter(|k| k.endpoint == endpoint)
        .and_then(|k| {
            Bundle::parse(trust_domain, &k.document)
                .ok()
                .map(|b| (b, k.fetched_ms))
        });
    if let Some((b, at)) = &kept
        && !refresh_due(*at, b.refresh_interval_s(), now_ms)
    {
        return Ok(kept);
    }
    let Some(doc) = bundles.fetch(endpoint).await? else {
        return Ok(kept);
    };
    let Ok(fresh) = Bundle::parse(trust_domain, &doc) else {
        return Ok(kept);
    };
    if let Some((old, _)) = &kept
        && old.replaced_by(&fresh).is_err()
    {
        return Ok(kept);
    }
    bundles
        .keep(
            realm,
            trust_domain,
            Kept {
                endpoint: String::from(endpoint),
                document: doc,
                fetched_ms: now_ms,
            },
        )
        .await?;
    Ok(Some((fresh, now_ms)))
}

/// AG-30: verifies `credential` for the authorization server `issuer` against the current
/// bundle of its trust domain, served at `endpoint`.
///
/// # Errors
/// [`Unavailable`]; a refusal is the inner [`SvidError`].
pub async fn verify<B: Bundles + ?Sized>(
    bundles: &B,
    realm: Scope,
    endpoint: &str,
    (credential, issuer): (Credential<'_>, &str),
    now_ms: u64,
) -> Result<Result<Verified, SvidError>, Unavailable> {
    let subject = match credential.subject() {
        Ok(s) => s,
        Err(e) => return Ok(Err(e)),
    };
    let Some((bundle, fetched_ms)) =
        current_bundle(bundles, realm, (subject.trust_domain(), endpoint), now_ms).await?
    else {
        return Ok(Err(SvidError::Key));
    };
    let at = Freshness { fetched_ms, now_ms };
    Ok(match credential {
        Credential::Jwt(t) => svid::verify_jwt(t, &bundle, issuer, at),
        Credential::X509(chain) => svid::verify_x509(chain, &bundle, at),
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::arithmetic_side_effects,
        reason = "test code"
    )]

    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;
    use crate::ports::Pending;

    #[derive(Default)]
    struct Memory {
        kept: Mutex<HashMap<String, Kept>>,
        served: Mutex<Option<Vec<u8>>>,
        fetches: Mutex<u32>,
    }

    impl Bundles for Memory {
        fn kept<'a>(&'a self, _: Scope, td: &'a str) -> Pending<'a, Option<Kept>> {
            let k = self.kept.lock().unwrap().get(td).cloned();
            Box::pin(async move { Ok(k) })
        }

        fn keep<'a>(&'a self, _: Scope, td: &'a str, kept: Kept) -> Pending<'a, ()> {
            self.kept.lock().unwrap().insert(String::from(td), kept);
            Box::pin(async { Ok(()) })
        }

        fn fetch<'a>(&'a self, _: &'a str) -> Pending<'a, Option<Vec<u8>>> {
            *self.fetches.lock().unwrap() += 1;
            let d = self.served.lock().unwrap().clone();
            Box::pin(async move { Ok(d) })
        }
    }

    const EP: &str = "https://bundle.acme.example/bundle.json";
    const S: Scope = Scope {
        tenant: [1; 16],
        realm: [2; 16],
    };

    fn doc(seq: u64) -> Vec<u8> {
        format!(r#"{{"keys":[],"spiffe_sequence":{seq},"spiffe_refresh_hint":300}}"#).into_bytes()
    }

    fn block<F: Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(f)
    }

    // OP-154 m.3 (r), AG-30
    #[test]
    fn a_bundle_is_refreshed_when_due_and_kept_when_a_refresh_fails() {
        block(async {
            let m = Memory::default();
            *m.served.lock().unwrap() = Some(doc(2));
            let (b, at) = current_bundle(&m, S, ("acme.example", EP), 1_000)
                .await
                .unwrap()
                .unwrap();
            assert_eq!((b.sequence, at), (Some(2), 1_000));
            assert!(
                current_bundle(&m, S, ("acme.example", EP), 200_000)
                    .await
                    .unwrap()
                    .is_some()
            );
            assert_eq!(*m.fetches.lock().unwrap(), 1);
            *m.served.lock().unwrap() = None;
            let (_, at) = current_bundle(&m, S, ("acme.example", EP), 400_000)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(at, 1_000);
            *m.served.lock().unwrap() = Some(doc(1));
            let (b, _) = current_bundle(&m, S, ("acme.example", EP), 500_000)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(b.sequence, Some(2));
            *m.served.lock().unwrap() = Some(doc(3));
            let (b, at) = current_bundle(&m, S, ("acme.example", EP), 600_000)
                .await
                .unwrap()
                .unwrap();
            assert_eq!((b.sequence, at), (Some(3), 600_000));
            *m.served.lock().unwrap() = None;
            assert!(
                current_bundle(&m, S, ("acme.example", "https://other.example/b"), 600_000)
                    .await
                    .unwrap()
                    .is_none()
            );
        });
    }

    // OP-154 m.3 (r), TI-9
    #[test]
    fn without_a_bundle_every_svid_is_refused() {
        block(async {
            let token = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJzcGlmZmU6Ly9hY21lLmV4YW1wbGUvYSJ9.AA";
            let r = verify(
                &crate::ports::NoBundles,
                S,
                EP,
                (Credential::Jwt(token), "https://acme.id.test"),
                1_000,
            )
            .await
            .unwrap();
            assert_eq!(r, Err(SvidError::Key));
        });
    }
}
