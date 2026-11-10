//! Revocation of a verified path, fail-closed (MD-8, §10.2.5, OP-155 m.3 (m)).
//!
//! Every certificate of the path below the CA is asked about at its OCSP responder first. A
//! `revoked` answer refuses at once. When every certificate has a current `good` answer the path
//! stands; otherwise the CRLs of every certificate are fetched and webpki checks the whole path
//! against them. A certificate with no current answer from either source refuses the path: an
//! unknown, unreachable or stale status is never accepted.
//!
//! Answers and CRLs are kept until their `nextUpdate`, at most [`MAX_KEPT_S`]; nothing is kept
//! past it, so a cached answer is never stale.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::domain::cert::Cert;
use crate::domain::crl::{self, Crl, CrlError};
use crate::domain::ocsp::{self, Status};
use crate::domain::path::Path;
use crate::ports::{Fetch, Request};

/// Longest an answer or a CRL is kept, seconds (OP-155 m.3 (m)).
pub const MAX_KEPT_S: u64 = 24 * 3600;

/// Most answers and CRLs kept each (PD).
pub const MAX_ENTRIES: usize = 4096;

/// Why the path is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// A certificate of the path is revoked.
    #[error("revoked")]
    Revoked,
    /// A certificate's status could not be established: unknown, unreachable, stale or
    /// unreadable.
    #[error("status unknown")]
    Unknown,
}

impl Refusal {
    /// The stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Revoked => "certificate-revoked",
            Self::Unknown => "certificate-status-unknown",
        }
    }
}

/// Until when something current until `current_until` is kept, fetched at `now`.
#[must_use]
pub fn kept_until(now: u64, current_until: u64) -> u64 {
    current_until.min(now.saturating_add(MAX_KEPT_S))
}

struct Kept<T> {
    value: T,
    until: u64,
}

fn keep<K: Eq + core::hash::Hash, T>(
    map: &Mutex<HashMap<K, Kept<T>>>,
    key: K,
    kept: Kept<T>,
    now: u64,
) {
    let Ok(mut m) = map.lock() else {
        return;
    };
    if m.len() >= MAX_ENTRIES {
        m.retain(|_, v| v.until > now);
    }
    if m.len() < MAX_ENTRIES {
        m.insert(key, kept);
    }
}

/// The revocation checker with its kept answers.
pub struct Revocation {
    fetch: Arc<dyn Fetch>,
    answers: Mutex<HashMap<[u8; 32], Kept<Status>>>,
    crls: Mutex<HashMap<String, Kept<Arc<Crl>>>>,
}

impl core::fmt::Debug for Revocation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Revocation").finish_non_exhaustive()
    }
}

fn answer_key(cert: &Cert<'_>, issuer: &Cert<'_>) -> [u8; 32] {
    let mut input = Vec::new();
    for part in [cert.issuer, issuer.public_key, cert.serial] {
        input.extend_from_slice(&u32::try_from(part.len()).unwrap_or(u32::MAX).to_be_bytes());
        input.extend_from_slice(part);
    }
    suiss_crypto::digest::sha256(&input)
}

impl Revocation {
    /// A checker fetching through `fetch`.
    #[must_use]
    pub fn new(fetch: Arc<dyn Fetch>) -> Self {
        Self {
            fetch,
            answers: Mutex::new(HashMap::new()),
            crls: Mutex::new(HashMap::new()),
        }
    }

    /// The current OCSP status of `cert` issued by `issuer`, or `None` when no responder gave a
    /// current, signed answer.
    async fn ocsp(&self, cert: &Cert<'_>, issuer: &Cert<'_>, now: u64) -> Option<Status> {
        let key = answer_key(cert, issuer);
        if let Some(s) = self
            .answers
            .lock()
            .ok()
            .and_then(|m| m.get(&key).filter(|k| now < k.until).map(|k| k.value))
        {
            return Some(s);
        }
        let request = ocsp::request(cert, issuer).ok()?;
        for url in cert.ocsp_urls().ok()? {
            let Ok(body) = self
                .fetch
                .fetch(Request::Ocsp {
                    url: &url,
                    body: &request,
                })
                .await
            else {
                continue;
            };
            let Ok(a) = ocsp::check(&body, cert, issuer, now) else {
                continue;
            };
            let kept = Kept {
                value: a.status,
                until: kept_until(now, a.current_until),
            };
            keep(&self.answers, key, kept, now);
            return Some(a.status);
        }
        None
    }

    /// A current CRL from one of `cert`'s distribution points.
    async fn crl(&self, cert: &Cert<'_>, now: u64) -> Option<Arc<Crl>> {
        for url in cert.crl_urls().ok()? {
            if let Some(c) = self.crls.lock().ok().and_then(|m| {
                m.get(&url)
                    .filter(|k| now < k.until)
                    .map(|k| k.value.clone())
            }) {
                return Some(c);
            }
            let Ok(body) = self.fetch.fetch(Request::Crl { url: &url }).await else {
                continue;
            };
            let Ok(c) = crl::parse(&body) else {
                continue;
            };
            if now >= c.next_update {
                continue;
            }
            let c = Arc::new(c);
            let until = kept_until(now, c.next_update);
            keep(
                &self.crls,
                url,
                Kept {
                    value: c.clone(),
                    until,
                },
                now,
            );
            return Some(c);
        }
        None
    }

    /// Checks every certificate of `path`, which ends at `ca[path.anchor]`, at `now` (Unix
    /// seconds).
    ///
    /// # Errors
    /// [`Refusal`].
    pub async fn check(&self, path: &Path, ca: &[Vec<u8>], now: u64) -> Result<(), Refusal> {
        let anchor = ca.get(path.anchor).ok_or(Refusal::Unknown)?;
        let certs: Vec<Cert<'_>> = path
            .certs
            .iter()
            .map(|d| Cert::parse(d))
            .collect::<Result<_, _>>()
            .map_err(|_| Refusal::Unknown)?;
        let top = Cert::parse(anchor).map_err(|_| Refusal::Unknown)?;
        let mut all_good = true;
        for (i, cert) in certs.iter().enumerate() {
            let issuer = certs.get(i.saturating_add(1)).unwrap_or(&top);
            match self.ocsp(cert, issuer, now).await {
                Some(Status::Revoked) => return Err(Refusal::Revoked),
                Some(Status::Good) => {}
                Some(Status::Unknown) | None => all_good = false,
            }
        }
        if all_good {
            return Ok(());
        }
        let mut lists = Vec::with_capacity(certs.len());
        for cert in &certs {
            lists.push(self.crl(cert, now).await.ok_or(Refusal::Unknown)?);
        }
        let refs: Vec<&Crl> = lists.iter().map(AsRef::as_ref).collect();
        match crl::check(&path.certs, core::slice::from_ref(anchor), &refs, now) {
            Ok(()) => Ok(()),
            Err(CrlError::Revoked) => Err(Refusal::Revoked),
            Err(_) => Err(Refusal::Unknown),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::domain::path::verify;
    use crate::ports::{Fetched, Unreachable};
    use crate::testing::{Ca, DAY, LeafSpec, NOW, OcspAnswer, Status as S, serial};

    #[derive(Default)]
    struct Responses {
        by_url: Mutex<HashMap<String, Vec<u8>>>,
        calls: AtomicUsize,
    }

    impl Responses {
        fn set(&self, url: &str, body: Vec<u8>) {
            self.by_url.lock().unwrap().insert(String::from(url), body);
        }
    }

    impl Fetch for Responses {
        fn fetch<'a>(&'a self, request: Request<'a>) -> Fetched<'a> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let url = match request {
                Request::Ocsp { url, .. } | Request::Crl { url } => url,
            };
            let found = self.by_url.lock().unwrap().get(url).cloned();
            Box::pin(async move { found.ok_or(Unreachable) })
        }
    }

    const OCSP: &str = "http://ocsp.example/";
    const CRL: &str = "http://crl.example/ca.crl";

    struct World {
        ca: Ca,
        leaf: Vec<u8>,
        responses: Arc<Responses>,
        revocation: Revocation,
    }

    fn world(ocsp: bool, crl: bool) -> World {
        let ca = Ca::root("Revocation Root");
        let leaf = ca
            .leaf(&LeafSpec {
                ocsp: ocsp.then_some(OCSP),
                crl: crl.then_some(CRL),
                ..LeafSpec::default()
            })
            .der;
        let responses = Arc::new(Responses::default());
        let revocation = Revocation::new(responses.clone());
        World {
            ca,
            leaf,
            responses,
            revocation,
        }
    }

    impl World {
        async fn check(&self, now: u64) -> Result<(), Refusal> {
            let ca = vec![self.ca.der.clone()];
            let path = verify(core::slice::from_ref(&self.leaf), &ca, NOW).unwrap();
            self.revocation.check(&path, &ca, now).await
        }
    }

    // MD-8, OP-155 m.3 (m), Ek B 4663, 4672
    #[tokio::test]
    async fn a_revoked_certificate_is_refused() {
        let w = world(true, true);
        w.responses.set(
            OCSP,
            w.ca.ocsp(&w.leaf, &OcspAnswer::current(S::Revoked), None),
        );
        w.responses.set(CRL, w.ca.crl(&[], NOW - DAY, NOW + DAY));
        assert_eq!(w.check(NOW).await, Err(Refusal::Revoked));
        let w = world(false, true);
        w.responses
            .set(CRL, w.ca.crl(&[&serial(&w.leaf)], NOW - DAY, NOW + DAY));
        assert_eq!(w.check(NOW).await, Err(Refusal::Revoked));
    }

    // MD-8, OP-155 m.3 (m), Ek B 4672
    #[tokio::test]
    async fn an_unreachable_responder_is_refused() {
        let w = world(true, false);
        assert_eq!(w.check(NOW).await, Err(Refusal::Unknown));
        let w = world(false, false);
        assert_eq!(w.check(NOW).await, Err(Refusal::Unknown));
        let w = world(true, true);
        assert_eq!(w.check(NOW).await, Err(Refusal::Unknown));
        w.responses.set(CRL, w.ca.crl(&[], NOW - DAY, NOW + DAY));
        assert_eq!(w.check(NOW).await, Ok(()));
    }

    // MD-8, OP-155 m.3 (m), Ek B 4672
    #[tokio::test]
    async fn a_stale_answer_is_refused() {
        let w = world(true, false);
        let stale = OcspAnswer {
            this_update: NOW - 2 * DAY,
            next_update: Some(NOW - DAY),
            ..OcspAnswer::current(S::Good)
        };
        w.responses.set(OCSP, w.ca.ocsp(&w.leaf, &stale, None));
        assert_eq!(w.check(NOW).await, Err(Refusal::Unknown));
        let w = world(false, true);
        w.responses
            .set(CRL, w.ca.crl(&[], NOW - 3 * DAY, NOW - DAY));
        assert_eq!(w.check(NOW).await, Err(Refusal::Unknown));
        let w = world(true, false);
        w.responses.set(
            OCSP,
            w.ca.ocsp(&w.leaf, &OcspAnswer::current(S::Unknown), None),
        );
        assert_eq!(w.check(NOW).await, Err(Refusal::Unknown));
    }

    // OP-155 m.3 (m)
    #[tokio::test]
    async fn a_good_answer_is_kept_until_its_next_update() {
        let w = world(true, false);
        w.responses.set(
            OCSP,
            w.ca.ocsp(&w.leaf, &OcspAnswer::current(S::Good), None),
        );
        assert_eq!(w.check(NOW).await, Ok(()));
        assert_eq!(w.check(NOW + 60).await, Ok(()));
        assert_eq!(w.responses.calls.load(Ordering::SeqCst), 1);
        w.responses.by_url.lock().unwrap().clear();
        assert_eq!(w.check(NOW + DAY).await, Err(Refusal::Unknown));
        assert_eq!(kept_until(NOW, NOW + 3 * DAY), NOW + MAX_KEPT_S);
        assert_eq!(kept_until(NOW, NOW + 60), NOW + 60);
    }

    // RFC 5280 §6, MD-8
    #[tokio::test]
    async fn an_intermediate_without_a_status_refuses_the_path() {
        let root = Ca::root("Chain Root");
        let mid = root.intermediate("Chain Issuing", None, None);
        let leaf = mid
            .leaf(&LeafSpec {
                ocsp: Some(OCSP),
                ..LeafSpec::default()
            })
            .der;
        let responses = Arc::new(Responses::default());
        responses.set(OCSP, mid.ocsp(&leaf, &OcspAnswer::current(S::Good), None));
        let revocation = Revocation::new(responses);
        let ca = vec![root.der.clone()];
        let path = verify(&[leaf, mid.der.clone()], &ca, NOW).unwrap();
        assert_eq!(path.certs.len(), 2);
        assert_eq!(
            revocation.check(&path, &ca, NOW).await,
            Err(Refusal::Unknown)
        );
    }
}
