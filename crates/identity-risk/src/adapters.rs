//! Port implementations (OP-63): the MMDB GeoIP/ASN file, the k-anonymity range API, address
//! pseudonyms in the token, and the PostgreSQL transaction.

pub mod mirror;
pub mod mmdb;
pub mod range_api;

use std::net::IpAddr;

use access_crypto::ip_pseudonym::IpPseudonymKey;
use access_identity_account::AccountError;
use access_identity_account::adapters::pg::PgTx;
use access_identity_account::app::breach::check;
use access_identity_account::domain::password::Password;
use access_identity_account::ports::BreachRanges;
use access_store::identity::TenantTx;

use crate::app::address::octets;
use crate::domain::assess::Breach;
use crate::domain::geo::GeoAnswer;
use crate::ports::{BoxFuture, BreachProbe, GeoResolver, GeoStatus, IpPseudonyms, RiskTx};

impl RiskTx for PgTx {
    fn store(&mut self) -> &mut TenantTx {
        &mut self.0
    }
}

/// No GeoIP/ASN source: every answer is unavailable and the management surface says so.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoGeoSource;

impl GeoResolver for NoGeoSource {
    fn locate(&self, _: IpAddr) -> GeoAnswer {
        GeoAnswer::Unavailable
    }

    fn status(&self) -> GeoStatus {
        GeoStatus::NotConfigured
    }
}

/// No pseudonym key: no address is kept at all.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoPseudonyms;

impl IpPseudonyms for NoPseudonyms {
    fn pseudonym(&self, _: &[u8; 16], _: &[u8; 16], _: IpAddr) -> Option<[u8; 32]> {
        None
    }

    fn prefix(&self, _: &[u8; 16], _: &[u8; 16], _: IpAddr) -> Option<[u8; 32]> {
        None
    }
}

/// Pseudonyms under the cell's key in the token.
pub struct KeyedPseudonyms(pub IpPseudonymKey);

impl IpPseudonyms for KeyedPseudonyms {
    fn pseudonym(&self, tenant: &[u8; 16], realm: &[u8; 16], ip: IpAddr) -> Option<[u8; 32]> {
        self.0.pseudonym(tenant, realm, &octets(ip)).ok()
    }

    fn prefix(&self, tenant: &[u8; 16], realm: &[u8; 16], ip: IpAddr) -> Option<[u8; 32]> {
        self.0.prefix_pseudonym(tenant, realm, &octets(ip)).ok()
    }
}

/// No breach corpus: every check is unavailable, never clean (G50).
#[derive(Clone, Copy, Debug, Default)]
pub struct NoBreachSource;

impl BreachProbe for NoBreachSource {
    fn check<'a>(&'a self, _: &'a Password) -> BoxFuture<'a, Breach> {
        Box::pin(std::future::ready(Breach::Unavailable))
    }
}

/// The check over any range source: the local mirror or the range API.
pub struct RangeProbe<B>(pub B);

impl<B: BreachRanges> BreachProbe for RangeProbe<B> {
    fn check<'a>(&'a self, password: &'a Password) -> BoxFuture<'a, Breach> {
        Box::pin(async move {
            match check(&self.0, password).await {
                Ok(()) => Breach::Clean,
                Err(AccountError::Password(_)) => Breach::Listed,
                Err(_) => Breach::Unavailable,
            }
        })
    }
}
