//! What an attestation becomes (§5.9, §10.1.2, §10.1.3, §11.12.4, L21, AG-31, U20).
//!
//! - The attested runtime class is the `attestation_runtime` Claim's 32-byte value, bound to
//!   the Instance whose key was attested: a requirement on it asks for that runtime, never more
//!   (Ek B 4262).
//! - Device integrity signals (Play Integrity, App Attest risk) only narrow: they become a
//!   `posture_device` verdict, and no verdict grants anything (Ek B 4524).
//! - An Instance (its logical id), its key binding (the `cnf` the Instance proves with: DPoP,
//!   mTLS or a WIT) and its attestations are three records (L21, Ek B 4324, 4547): one never
//!   stands in for another.
//! - Under the attester model (AG-31 model 2) the attester's Acceptance lists the Claim classes
//!   it may sign; a Claim of another class from it is ignored (Ek B 4545).

use access_kernel::claim::Gate;
use access_kernel::claim::body::Verdict;
use access_kernel::model::Id;
use suiss_crypto::digest::context_digest;

use crate::domain::android::{self, SecurityLevel};

/// Digest context of an attested runtime class.
pub const RUNTIME_CONTEXT: &str = "access/attestation-runtime/v1";

/// Digest context of an attestation challenge.
pub const CHALLENGE_CONTEXT: &str = "access/attestation-challenge/v1";

/// How far an attestation challenge's time may be from the trusted time (OP-154 m.3 (s)).
pub const CHALLENGE_SKEW_MS: u64 = 300_000;

/// The challenge an attestation of `instance` at `at_ms` under the realm `issuer` binds
/// (Android `attestationChallenge`, TPM `extraData`): `SHA-256(context ‖ 0x00 ‖ issuer ‖ 0x00 ‖
/// instance ‖ at_ms)`. It is fresh while `at_ms` is within [`CHALLENGE_SKEW_MS`] of the trusted
/// time, so no challenge is stored.
#[must_use]
pub fn challenge(issuer: &str, instance: &[u8; 16], at_ms: u64) -> [u8; 32] {
    let mut input = issuer.as_bytes().to_vec();
    input.push(0);
    input.extend_from_slice(instance);
    input.extend_from_slice(&at_ms.to_be_bytes());
    context_digest(CHALLENGE_CONTEXT, &input).0
}

/// An attested runtime class: where the key lives and what the platform said about the
/// software around it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuntimeClass {
    /// An Android key in hardware.
    Android {
        /// TEE or `StrongBox`.
        level: SecurityLevel,
        /// Booted a verified image with a locked bootloader.
        verified_locked: bool,
    },
    /// An App Attest key of a genuine app on Apple hardware.
    AppleAppAttest {
        /// A production attestation.
        production: bool,
    },
    /// A key generated inside a TPM 2.0 that cannot leave it.
    Tpm,
}

impl RuntimeClass {
    /// The class an Android attestation shows.
    #[must_use]
    pub const fn android(a: &android::Attested) -> Self {
        Self::Android {
            level: a.level,
            verified_locked: a.verified_boot && a.locked,
        }
    }

    /// Its canonical name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Android {
                level: SecurityLevel::StrongBox,
                verified_locked: true,
            } => "android/strongbox/verified",
            Self::Android {
                level: SecurityLevel::StrongBox,
                verified_locked: false,
            } => "android/strongbox",
            Self::Android {
                level: SecurityLevel::Tee,
                verified_locked: true,
            } => "android/tee/verified",
            Self::Android {
                level: SecurityLevel::Tee,
                verified_locked: false,
            } => "android/tee",
            Self::AppleAppAttest { production: true } => "apple/app-attest",
            Self::AppleAppAttest { production: false } => "apple/app-attest/development",
            Self::Tpm => "tpm2",
        }
    }

    /// The `attestation_runtime` value: `SHA-256(context ‖ 0x00 ‖ name)` (OP-154 m.3 (b)).
    #[must_use]
    pub fn digest(self) -> [u8; 32] {
        context_digest(RUNTIME_CONTEXT, self.name().as_bytes()).0
    }
}

/// A device integrity signal another verifier gave (Play Integrity, App Attest fraud metric).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Integrity {
    /// The strongest verdict the source has (`MEETS_STRONG_INTEGRITY`).
    Strong,
    /// The device verdict (`MEETS_DEVICE_INTEGRITY`).
    Device,
    /// Only the basic verdict, or none.
    Basic,
    /// The source said the device or app is not genuine.
    Failed,
}

/// §10.1.3, Ek B 4524: the `posture_device` verdict a signal gives. Only the strongest verdict
/// is compliant; a failed one is not; anything between says nothing. A verdict meets or fails
/// a requirement; it never grants.
#[must_use]
pub const fn posture(signal: Integrity) -> Verdict {
    match signal {
        Integrity::Strong => Verdict::Compliant,
        Integrity::Failed => Verdict::Noncompliant,
        Integrity::Device | Integrity::Basic => Verdict::Unknown,
    }
}

/// An Instance by its logical id: what audit and revocation name (AG-21).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InstanceId(pub Id);

/// How a key binding is proven on each request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BindingMethod {
    /// A DPoP proof (RFC 9449): `cnf.jkt`.
    Dpop,
    /// A client certificate (RFC 8705): `cnf.x5t#S256`.
    Mtls,
    /// A workload identity token's `cnf` (WIMSE).
    Wit,
}

/// The key an Instance currently proves with: a thumbprint and a method, no Instance id. A
/// rekey changes it; the Instance stays.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyBinding {
    /// RFC 7638 thumbprint of the key (or `x5t#S256` for mTLS).
    pub thumbprint: [u8; 32],
    /// How it is proven.
    pub method: BindingMethod,
}

/// An attestation as Access keeps it: a Claim value about a key, bound to an Instance only
/// once there is one; it is neither the Instance nor its key binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attestation {
    /// The attested key.
    pub key: KeyBinding,
    /// The `attestation_runtime` value.
    pub runtime: [u8; 32],
    /// The Instance the Claim is bound to, once the key is an Instance's.
    pub bound: Option<InstanceId>,
    /// When it was verified, Unix milliseconds.
    pub verified_ms: u64,
}

impl Attestation {
    /// An attestation of `key` for `class` verified at `verified_ms`, bound to nothing yet.
    #[must_use]
    pub fn of(key: KeyBinding, class: RuntimeClass, verified_ms: u64) -> Self {
        Self {
            key,
            runtime: class.digest(),
            bound: None,
            verified_ms,
        }
    }

    /// Bound to `instance` when its key is the attested one; `None` when the Instance proves
    /// with another key, which no attestation of this one speaks for (L21).
    #[must_use]
    pub fn bind(self, instance: InstanceId, current: KeyBinding) -> Option<Self> {
        (current.thumbprint == self.key.thumbprint).then_some(Self {
            bound: Some(instance),
            ..self
        })
    }
}

/// AG-31, §11.12.4: whether the Acceptance `gate` lets its attester sign `class` for `use_`: the
/// class must be listed. An attester signing a class outside its Acceptance is ignored.
#[must_use]
pub fn attester_may_sign(gate: &Gate, use_: &str, class: &str) -> bool {
    gate.use_ == use_ && gate.classes.iter().any(|c| c == class)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use access_kernel::model::{SubjectSelector, Window};

    use super::*;

    // §5.9, OP-154 m.3 (b), Ek B 4262
    #[test]
    fn each_runtime_class_has_its_own_value() {
        let all = [
            RuntimeClass::Android {
                level: SecurityLevel::StrongBox,
                verified_locked: true,
            },
            RuntimeClass::Android {
                level: SecurityLevel::StrongBox,
                verified_locked: false,
            },
            RuntimeClass::Android {
                level: SecurityLevel::Tee,
                verified_locked: true,
            },
            RuntimeClass::Android {
                level: SecurityLevel::Tee,
                verified_locked: false,
            },
            RuntimeClass::AppleAppAttest { production: true },
            RuntimeClass::AppleAppAttest { production: false },
            RuntimeClass::Tpm,
        ];
        let digests: std::collections::BTreeSet<[u8; 32]> =
            all.iter().map(|c| c.digest()).collect();
        assert_eq!(digests.len(), all.len());
    }

    // §10.1.3, Ek B 4524
    #[test]
    fn integrity_signals_only_narrow() {
        assert_eq!(posture(Integrity::Strong), Verdict::Compliant);
        assert_eq!(posture(Integrity::Device), Verdict::Unknown);
        assert_eq!(posture(Integrity::Basic), Verdict::Unknown);
        assert_eq!(posture(Integrity::Failed), Verdict::Noncompliant);
    }

    // L21, Ek B 4324, 4547
    #[test]
    fn instance_key_binding_and_attestation_stay_apart() {
        let key = KeyBinding {
            thumbprint: [1; 32],
            method: BindingMethod::Dpop,
        };
        let a = Attestation::of(key, RuntimeClass::Tpm, 5);
        assert_eq!(a.bound, None);
        let i = InstanceId(Id([9; 16]));
        assert_eq!(a.bind(i, key).unwrap().bound, Some(i));
        let rekeyed = KeyBinding {
            thumbprint: [2; 32],
            ..key
        };
        assert_eq!(a.bind(i, rekeyed), None);
    }

    // AG-31, §11.12.4, Ek B 4545
    #[test]
    fn an_attester_signs_only_its_listed_classes() {
        let gate = Gate {
            issuer: Some(Id([4; 16])),
            use_: String::from(access_kernel::claim::PREDICATE_INPUT),
            classes: vec![String::from("attestation_runtime")],
            subject: SubjectSelector::Public,
            floor: std::collections::BTreeMap::new(),
            validity: Window {
                from: 0,
                until: u64::MAX,
            },
            ingest_until: None,
            issued_until: None,
            quota: None,
            anchor: None,
            pinned: None,
        };
        assert!(attester_may_sign(
            &gate,
            access_kernel::claim::PREDICATE_INPUT,
            "attestation_runtime"
        ));
        assert!(!attester_may_sign(
            &gate,
            access_kernel::claim::PREDICATE_INPUT,
            "posture_device"
        ));
        assert!(!attester_may_sign(
            &gate,
            access_kernel::claim::ACTOR_BINDING,
            "attestation_runtime"
        ));
    }
}
