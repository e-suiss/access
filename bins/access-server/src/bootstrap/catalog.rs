//! The catalog upgrade of a realm's governing domain (OP-151 m.18 (g), OP-152 m.7 (d)): a
//! domain opened before an `idp.*` catalog gained actions accepts none of them, so their
//! writes are refused there. For each namespace whose current catalog the domain does not fully
//! accept, the founding root signs an `acceptance_establish` of that catalog on the
//! meta-anchor. It widens the domain, so it is CT3 and waits out the domain's time-lock
//! (§13.7.3): the first run opens the Exercise, a run after the lock commits the same nonce and
//! intent. The nonce is a prefix the root's signature derives, followed by the start of the
//! intent's validity, so a later run finds the open attempt and rebuilds the same intent.

use access_authority_core::genesis;
use access_internal_api::idp::{NAMESPACES, spp};
use access_kernel::combinator::{Outcome, Remediation};
use access_kernel::tier;
use access_store::authority::nonces_with_prefix;

use super::{
    Bootstrap, BootstrapError, Decider, Digest, DomainId, Governance, HsmSigner, Id, Instances,
    MetaExercises, Moment, Payload, RealmKeys, SKEW_MS, Serialize, Spp, Tier, Verdict, Window,
    server_time,
};
use suiss_crypto::signer::Signer as _;

/// What the root signs to derive the nonce prefix of one namespace's catalog upgrade.
const CATALOG_LABEL: &[u8] = b"access-bootstrap/catalog:1";

/// Length of the nonce prefix: a SHA-256.
const PREFIX_LEN: usize = 32;

/// Where one namespace's catalog upgrade stands after a run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct CatalogOut {
    /// The `idp.*` namespace.
    pub(crate) namespace: String,
    /// `accepted` once committed, `pending` while the time-lock runs.
    pub(crate) state: &'static str,
    /// When a pending upgrade can commit, trusted milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) after: Option<u64>,
}

/// The start of the validity a nonce of `prefix` carries.
fn validity_start(nonce: &[u8], prefix: &[u8]) -> Option<u64> {
    let rest = nonce.strip_prefix(prefix)?;
    Some(u64::from_be_bytes(<[u8; 8]>::try_from(rest).ok()?))
}

impl<P, K> Bootstrap<'_, P, K>
where
    P: Decider + Governance + Instances + MetaExercises,
    K: RealmKeys,
{
    /// Makes `domain`, founded by `party` whose key is `root`, accept every current `idp.*`
    /// catalog (OP-151 m.18 (g)); reports the namespaces it had to upgrade.
    ///
    /// # Errors
    /// [`BootstrapError`]; an upgrade the authority plane refuses stops the run.
    pub(crate) async fn upgrade_catalog(
        &self,
        domain: Digest,
        root: &HsmSigner,
        party: Id,
    ) -> Result<Vec<CatalogOut>, BootstrapError> {
        self.lead(domain).await?;
        let mut out = Vec::new();
        for namespace in NAMESPACES {
            let package = spp(namespace, party);
            if self.accepts_all(domain, &package).await? {
                continue;
            }
            out.push(self.upgrade(domain, root, party, &package).await?);
        }
        Ok(out)
    }

    async fn accepts_all(&self, domain: Digest, package: &Spp) -> Result<bool, BootstrapError> {
        for (action, _) in package.refs() {
            let accepted = MetaExercises::accepts(self.plane, domain, action)
                .await
                .map_err(|e| BootstrapError::Unavailable(e.0))?;
            if !accepted {
                return Ok(false);
            }
        }
        Ok(true)
    }

    async fn upgrade(
        &self,
        domain: Digest,
        root: &HsmSigner,
        party: Id,
        package: &Spp,
    ) -> Result<CatalogOut, BootstrapError> {
        let mut label = CATALOG_LABEL.to_vec();
        label.extend_from_slice(&domain.0);
        label.extend_from_slice(&package.catalog_digest().0);
        let signature = root
            .sign(&label)
            .map_err(|e| BootstrapError::Unavailable(String::from(e.code())))?;
        let prefix = suiss_crypto::digest::sha256(&signature);
        let now = server_time(self.app).await?;
        // §13.7.3
        let ceiling = tier::validity_ceiling(Tier::Ct3);
        let open = nonces_with_prefix(self.app, &DomainId::from_bytes(domain.0), &prefix)
            .await?
            .into_iter()
            .filter(|r| r.outcome != "deny" && r.nonce.len() == PREFIX_LEN + 8)
            .filter_map(|r| validity_start(&r.nonce, &prefix))
            .filter(|from| now <= from.saturating_add(ceiling))
            .max();
        let from = open.unwrap_or_else(|| now.saturating_sub(SKEW_MS));
        let mut nonce = prefix.to_vec();
        nonce.extend_from_slice(&from.to_be_bytes());
        let w = Moment {
            now,
            validity: Window {
                from,
                until: from.saturating_add(ceiling),
            },
        };
        let payload =
            Payload::AcceptanceEstablish(genesis::schemas(&package.namespace, package.publisher));
        let namespace = package.namespace.clone();
        match self
            .meta_verdict(domain, root, &nonce, payload, party, &w)
            .await?
        {
            Verdict::Committed(_) => Ok(CatalogOut {
                namespace,
                state: "accepted",
                after: None,
            }),
            Verdict::NotAllowed { decision, .. } if decision.outcome == Outcome::RequireAction => {
                let after = decision
                    .blockers
                    .iter()
                    .filter(|b| b.subcode.as_deref() == Some("time-lock"))
                    .find_map(|b| match b.remediation {
                        Remediation::WaitUntil(t) => Some(t),
                        _ => None,
                    })
                    .ok_or_else(|| BootstrapError::Refused(String::from("require_action")))?;
                Ok(CatalogOut {
                    namespace,
                    state: "pending",
                    after: Some(after),
                })
            }
            Verdict::NotAllowed { decision, .. } => {
                Err(BootstrapError::Refused(format!("{:?}", decision.outcome)))
            }
            Verdict::Refused { code, .. } => Err(BootstrapError::Refused(code)),
        }
    }
}
