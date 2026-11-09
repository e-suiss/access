//! The account changes and realm settings the catalog gained with OP-153 m.25 (b): an
//! administrator's binding of two accounts of one tenant (m.18 (e)), an account import and a
//! migration export with its bundle (m.19 (d)), a guardianship record (m.20 (g)) and the hosted
//! page's CSP mode (m.22 (g)). Each is a deterministic CBOR body the change digest binds.

use access_identity_account::domain::claim_classes::GuardianshipBasis;
use suiss_crypto::dcbor::Value;

use super::Invalid;

/// Most accounts one import names (TN-85, PD): a larger file is split.
pub const MAX_IMPORT_ACCOUNTS: u32 = 100_000;

/// The bundle format a migration export writes (TN-86).
pub const BUNDLE_VERSION: u64 = 1;

/// The HKDF info and AEAD label of a migration bundle (TN-86).
pub const BUNDLE_CONTEXT: &str = "access/migration-bundle/v1";

/// `idp.account.bind` (OP-153 m.18 (e)): an administrator binds `subject` of this realm and
/// `peer_subject` of the tenant's realm `peer_realm` as one person, by `admin_exercise`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountBind {
    /// The account in this realm.
    pub subject: [u8; 16],
    /// Another realm of the same tenant.
    pub peer_realm: [u8; 16],
    /// The account there.
    pub peer_subject: [u8; 16],
}

impl AccountBind {
    pub(crate) fn to_value(self) -> Value {
        Value::Map(vec![
            (Value::text("subject"), Value::Bytes(self.subject.to_vec())),
            (
                Value::text("peer_realm"),
                Value::Bytes(self.peer_realm.to_vec()),
            ),
            (
                Value::text("peer_subject"),
                Value::Bytes(self.peer_subject.to_vec()),
            ),
        ])
    }
}

/// `idp.account.import` (TN-85, OP-153 m.19 (d)): the accounts of one import file, in the line
/// format of `access-server import-accounts`, named by its digest; the file itself travels
/// beside the change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountImport {
    /// SHA-256 of the file's bytes.
    pub file: [u8; 32],
    /// How many lines it holds.
    pub accounts: u32,
}

impl AccountImport {
    pub(crate) fn check(self) -> Result<(), Invalid> {
        if (1..=MAX_IMPORT_ACCOUNTS).contains(&self.accounts) {
            Ok(())
        } else {
            Err(Invalid::Body)
        }
    }

    pub(crate) fn to_value(self) -> Value {
        Value::Map(vec![
            (Value::text("file"), Value::Bytes(self.file.to_vec())),
            (
                Value::text("accounts"),
                Value::Unsigned(u64::from(self.accounts)),
            ),
        ])
    }
}

/// `idp.account.migration_export` (TN-86, OP-153 m.19 (d)): the realm's accounts, encrypted to
/// the P-256 key the receiving deployment bound to this export.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationExport {
    /// The recipient key, SEC1 uncompressed.
    pub recipient: Vec<u8>,
}

impl MigrationExport {
    pub(crate) fn check(&self) -> Result<(), Invalid> {
        if self.recipient.len() == 65 && self.recipient.first() == Some(&0x04) {
            Ok(())
        } else {
            Err(Invalid::Body)
        }
    }

    pub(crate) fn to_value(&self) -> Value {
        Value::Map(vec![(
            Value::text("recipient"),
            Value::Bytes(self.recipient.clone()),
        )])
    }
}

/// A migration bundle (TN-86, OP-153 m.19 (d), `conformance/cddl/migration-bundle.cddl`): the
/// import lines of every account, AES-256-GCM under a key HKDF-SHA256 derives from the ECDH of
/// `epk` and the recipient key with info [`BUNDLE_CONTEXT`]; the AAD is the bundle's dCBOR
/// without `ciphertext`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle {
    /// The exporting realm's issuer.
    pub realm: String,
    /// When it was written, Unix ms.
    pub exported_at: u64,
    /// How many lines the plaintext holds.
    pub accounts: u64,
    /// RFC 7638 thumbprint of the recipient key.
    pub recipient: [u8; 32],
    /// The ephemeral P-256 key, SEC1 uncompressed.
    pub epk: Vec<u8>,
    /// The AES-GCM nonce.
    pub nonce: [u8; 12],
    /// The encrypted import lines.
    pub ciphertext: Vec<u8>,
}

impl Bundle {
    fn fields(&self) -> Vec<(Value, Value)> {
        vec![
            (Value::text("version"), Value::Unsigned(BUNDLE_VERSION)),
            (Value::text("realm"), Value::text(&self.realm)),
            (
                Value::text("exported_at"),
                Value::Unsigned(self.exported_at),
            ),
            (Value::text("accounts"), Value::Unsigned(self.accounts)),
            (
                Value::text("recipient"),
                Value::Bytes(self.recipient.to_vec()),
            ),
            (Value::text("epk"), Value::Bytes(self.epk.clone())),
            (Value::text("nonce"), Value::Bytes(self.nonce.to_vec())),
        ]
    }

    /// The additional data the ciphertext is sealed with.
    #[must_use]
    pub fn aad(&self) -> Value {
        Value::Map(self.fields())
    }

    /// The bundle as written.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut m = self.fields();
        m.push((
            Value::text("ciphertext"),
            Value::Bytes(self.ciphertext.clone()),
        ));
        Value::Map(m)
    }

    /// Reads a bundle; `None` for anything but the written form of [`BUNDLE_VERSION`].
    #[must_use]
    pub fn from_value(v: &Value) -> Option<Self> {
        let Value::Map(m) = v else {
            return None;
        };
        if m.len() != 8 {
            return None;
        }
        let get = |k: &str| {
            m.iter()
                .find(|(key, _)| matches!(key, Value::Text(t) if t == k))
                .map(|(_, v)| v)
        };
        let uint = |k: &str| match get(k) {
            Some(Value::Unsigned(n)) => Some(*n),
            _ => None,
        };
        let bytes = |k: &str| match get(k) {
            Some(Value::Bytes(b)) => Some(b.clone()),
            _ => None,
        };
        if uint("version")? != BUNDLE_VERSION {
            return None;
        }
        let Some(Value::Text(realm)) = get("realm") else {
            return None;
        };
        let epk = bytes("epk").filter(|e| e.len() == 65 && e.first() == Some(&0x04))?;
        Some(Self {
            realm: realm.clone(),
            exported_at: uint("exported_at")?,
            accounts: uint("accounts")?,
            recipient: <[u8; 32]>::try_from(bytes("recipient")?.as_slice()).ok()?,
            epk,
            nonce: <[u8; 12]>::try_from(bytes("nonce")?.as_slice()).ok()?,
            ciphertext: bytes("ciphertext")?,
        })
    }
}

/// `idp.account.guardianship_record` (E53, OP-153 m.20 (g), m.25 (c)): `guardian` stands for
/// `ward` on `basis`; the ward's country sets the majority date its Claim's validity ends at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardianshipRecord {
    /// The guardian's account.
    pub guardian: [u8; 16],
    /// The ward's account.
    pub ward: [u8; 16],
    /// On what basis.
    pub basis: GuardianshipBasis,
    /// The ward's country, ISO 3166-1 alpha-2.
    pub country: String,
}

impl GuardianshipRecord {
    pub(crate) fn check(&self) -> Result<(), Invalid> {
        if self.guardian != self.ward
            && self.country.len() == 2
            && self.country.bytes().all(|b| b.is_ascii_uppercase())
        {
            Ok(())
        } else {
            Err(Invalid::Body)
        }
    }

    pub(crate) fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::text("ward"), Value::Bytes(self.ward.to_vec())),
            (Value::text("basis"), Value::text(self.basis.name())),
            (Value::text("country"), Value::text(&self.country)),
            (
                Value::text("guardian"),
                Value::Bytes(self.guardian.to_vec()),
            ),
        ])
    }
}

/// The hosted page's CSP mode (OP-153 m.22 (g)): the branding origins enforced, or only
/// reported while the base policy is enforced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CspMode {
    /// The policy with the branding origins is enforced; the default.
    Enforce,
    /// Only the base policy is enforced; the branding origins are reported.
    ReportOnly,
}

impl CspMode {
    /// The stored name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Enforce => "enforce",
            Self::ReportOnly => "report_only",
        }
    }

    /// From the stored name.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "enforce" => Some(Self::Enforce),
            "report_only" => Some(Self::ReportOnly),
            _ => None,
        }
    }

    /// The mode a stored branding record carries: `enforce` unless it says `report_only`.
    #[must_use]
    pub fn of(branding: Option<&Value>) -> Self {
        match branding {
            Some(Value::Map(m)) => m
                .iter()
                .find_map(|(k, v)| match (k, v) {
                    (Value::Text(k), Value::Text(v)) if k == "csp_mode" => Self::parse(v),
                    _ => None,
                })
                .unwrap_or(Self::Enforce),
            _ => Self::Enforce,
        }
    }

    /// Whether moving from `current` to `self` loosens the page: enforce to report-only
    /// (OP-153 m.22 (g)).
    #[must_use]
    pub fn loosens(self, current: Self) -> bool {
        current == Self::Enforce && self == Self::ReportOnly
    }

    /// `branding` with this mode: `csp_mode` is kept only when it is not the default, so a
    /// record that never changed mode keeps its bytes.
    #[must_use]
    pub fn applied_to(self, branding: Value) -> Value {
        let mut m = match branding {
            Value::Map(m) => m,
            _ => Vec::new(),
        };
        m.retain(|(k, _)| !matches!(k, Value::Text(t) if t == "csp_mode"));
        if self == Self::ReportOnly {
            m.push((Value::text("csp_mode"), Value::text(self.name())));
        }
        Value::Map(m)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;
    use suiss_crypto::dcbor::{self, Limits};

    // OP-153 m.22 (g), m.25 (b)
    #[test]
    fn report_only_loosens_and_enforce_tightens() {
        use CspMode::{Enforce, ReportOnly};
        assert!(ReportOnly.loosens(Enforce));
        assert!(!Enforce.loosens(ReportOnly));
        assert!(!Enforce.loosens(Enforce));
        let brand = Value::Map(vec![(Value::text("display_name"), Value::text("Acme"))]);
        let relaxed = ReportOnly.applied_to(brand.clone());
        assert_eq!(CspMode::of(Some(&relaxed)), ReportOnly);
        let back = Enforce.applied_to(relaxed);
        assert_eq!(
            dcbor::encode(&back, Limits::CEILING).unwrap(),
            dcbor::encode(&brand, Limits::CEILING).unwrap()
        );
        assert_eq!(CspMode::of(None), Enforce);
    }

    // TN-86, OP-153 m.19 (d)
    #[test]
    fn a_bundle_reads_back_and_nothing_else_reads_as_one() {
        let b = Bundle {
            realm: String::from("https://id.acme.example"),
            exported_at: 1_000,
            accounts: 2,
            recipient: [3; 32],
            epk: [vec![4], vec![5; 64]].concat(),
            nonce: [6; 12],
            ciphertext: vec![7; 40],
        };
        assert_eq!(Bundle::from_value(&b.to_value()), Some(b.clone()));
        assert!(Bundle::from_value(&b.aad()).is_none());
        let mut short = b;
        short.epk = vec![4; 33];
        assert!(Bundle::from_value(&short.to_value()).is_none());
    }

    // TN-85, TN-86, E53, OP-153 m.19 (d), m.20 (g)
    #[test]
    fn account_changes_check_their_shapes() {
        assert!(
            AccountImport {
                file: [1; 32],
                accounts: 0
            }
            .check()
            .is_err()
        );
        assert!(
            AccountImport {
                file: [1; 32],
                accounts: MAX_IMPORT_ACCOUNTS
            }
            .check()
            .is_ok()
        );
        assert!(
            MigrationExport {
                recipient: vec![4; 65]
            }
            .check()
            .is_ok()
        );
        assert!(
            MigrationExport {
                recipient: vec![2; 33]
            }
            .check()
            .is_err()
        );
        let g = |guardian, country: &str| GuardianshipRecord {
            guardian,
            ward: [2; 16],
            basis: GuardianshipBasis::Parent,
            country: String::from(country),
        };
        assert!(g([1; 16], "TR").check().is_ok());
        assert!(g([2; 16], "TR").check().is_err());
        assert!(g([1; 16], "tr").check().is_err());
    }
}
