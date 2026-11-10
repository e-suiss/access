//! CIBA's reach beyond the realm rows in this process (OP-155 m.3 (l), E42): whether the
//! authority plane still asks for an approval of an intent, the person's Relay `CibaInvite`
//! sealed under their DEK, a free `login_hint` looked up by the realm's blind index, and the ping
//! to the client behind the SSRF guard. Also the operator's IP-range → country list for the
//! device verification page (§10.4.1), parsed in-house.

use std::net::IpAddr;
use std::sync::Arc;

use access_identity_account::adapters::pg::PgTx;
use access_identity_account::adapters::system::{SystemClock, SystemEntropy};
use access_identity_account::notify::message::{Address, Body, Message};
use access_identity_account::notify::notifier::OutboxNotifier;
use access_identity_account::notify::ports::Notifier as _;
use access_identity_account::ports::AccountTx as _;
use access_identity_oauth::adapters::outbound::Outbound;
use access_identity_oauth::ports::Unavailable;
use access_identity_oauth::ports::oauth::{CibaInvite, CibaOpening, CibaServices, GeoLookup, Held};
use access_identity_ui::ports::Approvals;
use access_kernel::digest::Digest;
use access_store::Pool;
use access_store::identity::{RealmId, TenantId, TenantTx};
use suiss_crypto::secret::Secret;

use crate::ids::CellIds;
use crate::login::RealmKeks;

/// The validity window an intent's render names, `from..until` in Unix ms (§9.13.3).
fn valid_until(render: &[u8]) -> Option<u64> {
    let r = access_kernel::render::decode(render).ok()?;
    let f = r
        .fields
        .iter()
        .find(|f| f.name == access_kernel::render::VALIDITY)?;
    f.text.split_once("..")?.1.parse().ok()
}

/// CIBA's services over the authority plane `A`, the realm keys and the guarded outbound client.
pub(crate) struct ServerCiba<A> {
    pub(crate) plane: A,
    pub(crate) app: Pool,
    pub(crate) keks: RealmKeks,
    pub(crate) ids: Arc<CellIds>,
    pub(crate) outbound: Outbound,
}

impl<A: Approvals + Send + Sync> CibaServices for ServerCiba<A> {
    fn opening(&self, domain: [u8; 32], intent: [u8; 32]) -> Held<'_, Option<CibaOpening>> {
        Box::pin(async move {
            // §9.14.1 step 1, P54
            let o = self
                .plane
                .opening(Digest(domain), Digest(intent))
                .await
                .map_err(|_| Unavailable)?;
            Ok(o.map(|o| CibaOpening {
                tier: o.tier,
                valid_until: o.render.as_deref().and_then(valid_until),
            }))
        })
    }

    fn invite(&self, invite: CibaInvite) -> Held<'_, ()> {
        Box::pin(async move {
            let kek = self.keks.vault(invite.realm).ok_or(Unavailable)?.kek;
            let ids = self.ids.key().ok_or(Unavailable)?;
            let realm = access_identity_account::app::Realm {
                tenant: invite.tenant,
                realm: invite.realm,
                kek: &*kek,
                ids: &ids,
            };
            let mut t = TenantTx::begin(&self.app, invite.tenant, invite.realm)
                .await
                .map_err(|_| Unavailable)?;
            let Some((kind, stored)) = t.contact(invite.subject).await.map_err(|_| Unavailable)?
            else {
                return t.commit().await.map_err(|_| Unavailable);
            };
            let Some(value) = access_identity_account::app::vault::reveal_with_kek(
                &mut t,
                &*kek,
                invite.subject,
                &stored,
            )
            .await
            .map_err(|_| Unavailable)?
            else {
                return t.commit().await.map_err(|_| Unavailable);
            };
            let (to, valid_since_ms) = if kind == "phone" {
                (Address::Phone(value), None)
            } else {
                let since = t
                    .mailbox_since(invite.subject)
                    .await
                    .map_err(|_| Unavailable)?
                    .and_then(|v| u64::try_from(v).ok())
                    .unwrap_or(1)
                    .max(1);
                (Address::Email(value), Some(since))
            };
            // E42, OP-155 m.3 (l)
            OutboxNotifier::new(&realm, &SystemEntropy, &SystemClock)
                .notify(
                    &mut t,
                    &Message {
                        subject: invite.subject,
                        to,
                        locale: None,
                        valid_since_ms,
                        body: Body::CibaInvite {
                            link: Secret::new(invite.link),
                            client: invite.client,
                            binding_message: invite.binding_message,
                            expires_at_ms: invite.expires_at_ms,
                        },
                    },
                )
                .await
                .map_err(|e| {
                    tracing::warn!(error = %e, "CIBA invitation not queued");
                    Unavailable
                })?;
            t.commit().await.map_err(|_| Unavailable)
        })
    }

    fn login_hint(
        &self,
        tenant: TenantId,
        realm: RealmId,
        hint: String,
    ) -> Held<'_, Option<[u8; 16]>> {
        Box::pin(async move {
            let vault = self.keks.vault(realm).ok_or(Unavailable)?;
            let t = TenantTx::begin(&self.app, tenant, realm)
                .await
                .map_err(|_| Unavailable)?;
            let mut tx = PgTx(t, Some(vault));
            let normalized = access_identity_account::domain::identifier::normalize(&hint);
            let found = tx
                .subject_by_identifier(&normalized)
                .await
                .map_err(|_| Unavailable)?;
            tx.0.commit().await.map_err(|_| Unavailable)?;
            Ok(found)
        })
    }

    fn ping(&self, endpoint: String, token: String, auth_req_id: String) -> Held<'_, bool> {
        Box::pin(async move {
            let body = serde_json::json!({ "auth_req_id": auth_req_id }).to_string();
            // OP-155 m.3 (l)
            let answer = self
                .outbound
                .post(
                    &endpoint,
                    "application/json",
                    &[("Authorization", format!("Bearer {token}"))],
                    body.as_bytes(),
                )
                .await;
            Ok(answer.is_ok_and(|a| (200..300).contains(&a.status)))
        })
    }
}

/// Most ranges an operator list holds.
pub(crate) const MAX_RANGES: usize = 1_000_000;

/// An operator-supplied IP-range → country list (OP-155 m.3 (l)): one `cidr,CC` per line, `#`
/// comments; the longest prefix wins. Read in-house, no dependency.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct CsvGeo {
    v4: Vec<(u32, u8, [u8; 2])>,
    v6: Vec<(u128, u8, [u8; 2])>,
}

impl CsvGeo {
    /// Parses `text`.
    ///
    /// # Errors
    /// The first line that is not `cidr,CC`, by number.
    pub(crate) fn parse(text: &str) -> Result<Self, usize> {
        let mut out = Self::default();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let bad = n.saturating_add(1);
            if out.v4.len().saturating_add(out.v6.len()) >= MAX_RANGES {
                return Err(bad);
            }
            let (cidr, cc) = line.split_once(',').ok_or(bad)?;
            let cc = cc.trim().as_bytes();
            let country: [u8; 2] = match cc {
                [a, b] if a.is_ascii_uppercase() && b.is_ascii_uppercase() => [*a, *b],
                _ => return Err(bad),
            };
            let (addr, len) = cidr.trim().split_once('/').ok_or(bad)?;
            let len: u8 = len.parse().map_err(|_| bad)?;
            match addr.parse::<IpAddr>().map_err(|_| bad)? {
                IpAddr::V4(a) if len <= 32 => {
                    let mask = u32::MAX.checked_shl(32u32.saturating_sub(u32::from(len)));
                    let net = u32::from(a) & mask.unwrap_or(0);
                    out.v4.push((net, len, country));
                }
                IpAddr::V6(a) if len <= 128 => {
                    let mask = u128::MAX.checked_shl(128u32.saturating_sub(u32::from(len)));
                    let net = u128::from(a) & mask.unwrap_or(0);
                    out.v6.push((net, len, country));
                }
                _ => return Err(bad),
            }
        }
        Ok(out)
    }
}

impl GeoLookup for CsvGeo {
    fn country(&self, ip: IpAddr) -> Option<[u8; 2]> {
        match ip {
            IpAddr::V4(a) => {
                let a = u32::from(a);
                self.v4
                    .iter()
                    .filter(|(net, len, _)| {
                        let mask = u32::MAX
                            .checked_shl(32u32.saturating_sub(u32::from(*len)))
                            .unwrap_or(0);
                        a & mask == *net
                    })
                    .max_by_key(|(_, len, _)| *len)
                    .map(|(_, _, c)| *c)
            }
            IpAddr::V6(a) => {
                let a = u128::from(a);
                self.v6
                    .iter()
                    .filter(|(net, len, _)| {
                        let mask = u128::MAX
                            .checked_shl(128u32.saturating_sub(u32::from(*len)))
                            .unwrap_or(0);
                        a & mask == *net
                    })
                    .max_by_key(|(_, len, _)| *len)
                    .map(|(_, _, c)| *c)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // OP-155 m.3 (l), §10.4.1, Ek B 4884
    #[test]
    fn the_operator_list_names_the_longest_matching_range() {
        let geo = CsvGeo::parse(
            "# operator list\n192.0.2.0/24,TR\n192.0.2.128/25,DE\n2001:db8::/32,NL\n\n",
        )
        .unwrap();
        assert_eq!(geo.country("192.0.2.7".parse().unwrap()), Some(*b"TR"));
        assert_eq!(geo.country("192.0.2.200".parse().unwrap()), Some(*b"DE"));
        assert_eq!(geo.country("2001:db8::1".parse().unwrap()), Some(*b"NL"));
        assert_eq!(geo.country("198.51.100.1".parse().unwrap()), None);
        assert_eq!(CsvGeo::parse("10.0.0.0/8,tr"), Err(1));
        assert_eq!(CsvGeo::parse("ok\n10.0.0.0/33,TR"), Err(1));
        assert_eq!(CsvGeo::parse("10.0.0.0/8,TR\n10.0.0.0/40,TR"), Err(2));
    }

    // §9.13.3
    #[test]
    fn a_render_names_its_validity_end() {
        assert_eq!(valid_until(b"not a render"), None);
    }
}
