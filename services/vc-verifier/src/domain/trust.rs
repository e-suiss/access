//! Issuer trust (Ek B 4834, 4835, 5055; §10.3.2, §10.7.2, IDP-21): the services a trusted list
//! names, read from the EU List of Trusted Lists and the national lists it points to, and the
//! issuers configured outside them. Only a granted service counts, only while the list is
//! fresh, and `loa_eidas` high comes only from a PID presentation whose issuer chains to a
//! granted PID provider service: never from an attestation provider, an allow-listed issuer or
//! any method of Access's own.

use serde::{Deserialize, Serialize};

use super::dcql::Format;

/// ETSI service type URIs of a PID provider.
pub const PID_SERVICE_TYPES: &[&str] = &[
    "http://uri.etsi.org/19602/SvcType/PID/Issuance",
    "http://uri.etsi.org/Svc/Svctype/Provider/PID",
];

/// ETSI service type URIs of an electronic attestation of attributes provider.
pub const EAA_SERVICE_TYPES: &[&str] = &[
    "http://uri.etsi.org/TrstSvc/Svctype/EAA/Q",
    "http://uri.etsi.org/TrstSvc/Svctype/EAA/Pub-EAA",
    "http://uri.etsi.org/TrstSvc/Svctype/EAA",
    "http://uri.etsi.org/19602/SvcType/EAA/Issuance",
];

/// The ETSI status of a granted service.
pub const GRANTED: &[&str] = &[
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted",
    "http://uri.etsi.org/19602/SvcStatus/granted",
];

/// SD-JWT VC types of the EU PID.
pub const PID_VCTS: &[&str] = &["urn:eudi:pid:1", "urn:eu.europa.ec.eudi:pid:1"];

/// mdoc doc type of the EU PID.
pub const PID_DOCTYPE: &str = "eu.europa.ec.eudi.pid.1";

/// `loa_eidas` high (§10.1.6: 1 low, 2 substantial, 3 high).
pub const LOA_EIDAS_HIGH: u64 = 3;

/// One service of a trusted list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Service {
    /// The provider's name as listed.
    pub provider: String,
    /// The service type URI.
    pub service_type: String,
    /// The service status URI.
    pub status: String,
    /// The service's digital identities: DER certificates.
    #[serde(with = "super::b64::list")]
    pub certificates: Vec<Vec<u8>>,
}

/// What a granted service is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// A PID provider.
    Pid,
    /// An attestation provider.
    Attestation,
    /// An issuer the operator configured outside the trusted lists; never PID.
    Listed,
}

impl Standing {
    /// The wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Pid => "pid-provider",
            Self::Attestation => "attestation-provider",
            Self::Listed => "configured-issuer",
        }
    }
}

impl Service {
    /// The service's standing, or `None` when it is not granted or of another type.
    #[must_use]
    pub fn standing(&self) -> Option<Standing> {
        if !GRANTED.contains(&self.status.as_str()) {
            return None;
        }
        if PID_SERVICE_TYPES.contains(&self.service_type.as_str()) {
            Some(Standing::Pid)
        } else if EAA_SERVICE_TYPES.contains(&self.service_type.as_str()) {
            Some(Standing::Attestation)
        } else {
            None
        }
    }
}

/// The trusted lists the verifier loaded.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedLists {
    /// The `LoTL`'s sequence number.
    pub sequence: u64,
    /// The earliest `NextUpdate` of the lists read, Unix milliseconds.
    pub next_update_ms: u64,
    /// SHA-256 of each list document as read, `LoTL` first.
    #[serde(with = "super::b64::list")]
    pub digests: Vec<Vec<u8>>,
    /// Whether every list's signature verified.
    pub signature_verified: bool,
    /// Whether every list document matched an operator-pinned snapshot digest.
    #[serde(default)]
    pub pinned: bool,
    /// The services.
    pub services: Vec<Service>,
}

impl TrustedLists {
    /// Whether the lists may be used at `now_ms`: signed or pinned, and before their next
    /// update.
    #[must_use]
    pub fn usable(&self, now_ms: u64) -> bool {
        (self.signature_verified || self.pinned) && now_ms <= self.next_update_ms
    }

    /// The anchors of the granted services and their standing; empty when the lists are not
    /// usable.
    #[must_use]
    pub fn anchors(&self, now_ms: u64) -> (Vec<Vec<u8>>, Vec<Standing>) {
        let mut certs = Vec::new();
        let mut standing = Vec::new();
        if !self.usable(now_ms) {
            return (certs, standing);
        }
        for s in &self.services {
            if let Some(st) = s.standing() {
                for c in &s.certificates {
                    certs.push(c.clone());
                    standing.push(st);
                }
            }
        }
        (certs, standing)
    }
}

/// Whether a credential is the EU PID.
#[must_use]
pub fn is_pid(format: Format, credential_type: &str) -> bool {
    match format {
        Format::SdJwtVc => PID_VCTS.contains(&credential_type),
        Format::Mdoc => credential_type == PID_DOCTYPE,
    }
}

/// Ek B 4835, 5055: `loa_eidas` high only from a PID whose issuer is a granted PID provider.
#[must_use]
pub fn loa_eidas(standing: Standing, format: Format, credential_type: &str) -> Option<u64> {
    (standing == Standing::Pid && is_pid(format, credential_type)).then_some(LOA_EIDAS_HIGH)
}
