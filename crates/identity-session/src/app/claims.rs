//! The Claims sign-in queues for the realm issuer (§10.1.2, §10.1.5, F17, TN-103, TN-63, OP-150
//! L2): the `authentication` Claim of a login or step-up, bound to the session's device Instance;
//! a passkey's `authenticator_binding` when it is registered; and risk signals. Each is queued in
//! the transaction of its event and issued later by the courier, so sign-in never waits for the
//! authority plane, and no signal gates sign-in (§7.6 TN-O4).

use std::collections::{BTreeMap, BTreeSet};

use access_identity_account::app::claims::emit;
use access_identity_account::domain::claims::{
    self, AuthFacts, Bind, PasskeyFacts, RiskSignal, assertion_evidence, attestation_verdict,
};
use access_identity_webauthn::app::AssertionFacts;
use access_identity_webauthn::domain::ceremony::{AssertionResponse, Signal};
use access_identity_webauthn::domain::credential::{AttestationKind, CredentialRecord};
use access_kernel::claim::body::{AttestationResult, AuthMethod, WebauthnDetail};
use access_kernel::digest::Digest;

use super::SignedIn;
use crate::SessionError;
use crate::domain::assurance::{AssuranceVector, Factor, MethodClass, PasskeyDetail};
use crate::domain::flow::{FlowState, Purpose};
use crate::ports::SessionTx;

/// The assurance vector as Claim levels (§10.1.6, OP-118 m.3): flags are 0 or 1, AAL and the
/// `eIDAS` level 1 to 3.
#[must_use]
pub fn levels(v: &AssuranceVector) -> BTreeMap<String, u64> {
    use crate::domain::assurance::{Aal, LoaEidas};
    let flag = |b: bool| u64::from(b);
    let mut out = BTreeMap::from([
        (
            String::from("aal"),
            match v.aal {
                Aal::Aal1 => 1,
                Aal::Aal2 => 2,
                Aal::Aal3 => 3,
            },
        ),
        (
            String::from("app_controlled_factor"),
            flag(v.app_controlled_factor),
        ),
        (String::from("hardware_bound"), flag(v.hardware_bound)),
        (String::from("human_presence"), flag(v.human_presence)),
        (String::from("non_custodial"), flag(v.non_custodial)),
        (
            String::from("phishing_resistant"),
            flag(v.phishing_resistant),
        ),
        (String::from("synced"), flag(v.synced)),
        (String::from("uv"), flag(v.uv)),
    ]);
    if let Some(l) = v.loa_eidas {
        out.insert(
            String::from("loa_eidas"),
            match l {
                LoaEidas::Low => 1,
                LoaEidas::Substantial => 2,
                LoaEidas::High => 3,
            },
        );
    }
    out
}

/// The method that carries an authentication: the strongest of its steps the §10.1.2 mapping
/// names, a passkey before a TOTP before a password. E-mail codes and recovery codes are no
/// method of the mapping and carry none.
#[must_use]
pub fn method(factors: &[Factor]) -> Option<(AuthMethod, Option<PasskeyDetail>)> {
    let pick = |m: MethodClass| factors.iter().find(|f| f.method == m);
    if let Some(f) = pick(MethodClass::Passkey) {
        return Some((AuthMethod::Webauthn, f.webauthn));
    }
    if pick(MethodClass::Totp).is_some() {
        return Some((AuthMethod::Totp, None));
    }
    pick(MethodClass::Password).map(|_| (AuthMethod::Password, None))
}

/// The details of a passkey step: the assertion's facts and the digest of what was presented.
#[must_use]
pub fn detail(f: &AssertionFacts, r: &AssertionResponse<'_>) -> PasskeyDetail {
    PasskeyDetail {
        aaguid: f.aaguid,
        sign_count: f.sign_count,
        uv: f.user_verified,
        be: f.backup_eligible,
        bs: f.backup_state,
        evidence: assertion_evidence(r.authenticator_data, r.client_data_json, r.signature).0,
    }
}

/// Queues the `authentication` Claim of a completed login or step-up, bound to the session (its
/// device Instance, resolved when issued), and the new-device signal of a login from a browser
/// without a known device marker.
///
/// # Errors
/// [`SessionError`].
pub(crate) async fn signed_in<T: SessionTx>(
    tx: &mut T,
    state: &FlowState,
    signed: &SignedIn,
    unknown_device: bool,
) -> Result<(), SessionError> {
    let r = &signed.result;
    let Some((m, passkey)) = method(&state.factors) else {
        return Ok(());
    };
    let order = claims::authentication(AuthFacts {
        subject: r.subject,
        method: m,
        auth_time: r.assurance.auth_time_ms,
        assurance: levels(&r.assurance),
        webauthn: passkey.map(|p| WebauthnDetail {
            aaguid: p.aaguid,
            sign_count: u64::from(p.sign_count),
            up: true,
            uv: p.uv,
            be: p.be,
            bs: p.bs,
        }),
        evidence: passkey.map(|p| Digest(p.evidence)),
        bind: Bind::Session(signed.session),
    });
    emit(tx, &order).await?;
    if unknown_device && matches!(state.purpose, Purpose::Login) {
        let at = r.assurance.auth_time_ms;
        let signal = claims::risk(
            r.subject,
            RiskSignal::NewDevice,
            Bind::Session(signed.session),
            at,
        );
        emit(tx, &signal).await?;
    }
    Ok(())
}

/// The risk signal a passkey assertion raised (§10.2.4, IDI-5, TN-63).
#[must_use]
pub const fn risk_of(s: Signal) -> RiskSignal {
    match s {
        Signal::SignCountRegressed { .. } => RiskSignal::SignCountRegression,
        Signal::BackupStateLost => RiskSignal::BackupStateLost,
        Signal::BackupStateGained => RiskSignal::BackupStateGained,
    }
}

/// Queues the risk signal Claims of a passkey assertion; they never refuse the sign-in.
///
/// # Errors
/// [`SessionError`].
pub(crate) async fn passkey_signals<T: SessionTx>(
    tx: &mut T,
    subject: [u8; 16],
    signals: &[Signal],
    now: u64,
) -> Result<(), SessionError> {
    for s in signals {
        emit(tx, &claims::risk(subject, risk_of(*s), Bind::None, now)).await?;
    }
    Ok(())
}

fn attestation(k: &AttestationKind) -> (String, AttestationResult) {
    match k {
        AttestationKind::None => (String::from("none"), AttestationResult::None),
        AttestationKind::Unverified(f) => (f.clone(), AttestationResult::None),
        AttestationKind::Verified => (String::from("packed"), AttestationResult::Verified),
    }
}

/// Queues the Claims of a new passkey (IDP-2, §10.1.2 registration row, TN-63): its
/// `authenticator_binding` (public material by digest, attestation as a signal), the
/// AAGUID-change signal when no other passkey of the account has its AAGUID, and the posture
/// verdict of a verified attestation (§10.1.3: attestation is a signal, never an Instance).
///
/// # Errors
/// [`SessionError`].
pub(crate) async fn passkey_registered<T: SessionTx>(
    tx: &mut T,
    subject: [u8; 16],
    sibling: [u8; 16],
    record: &CredentialRecord,
    others: &[CredentialRecord],
    now: u64,
) -> Result<(), SessionError> {
    let att = attestation(&record.attestation);
    let binding = claims::passkey_binding(&PasskeyFacts {
        subject,
        credential: record.id.as_bytes(),
        sibling,
        public_key: &record.public_key,
        alg: record.alg.id(),
        attestation: Some(att.clone()),
        aaguid: record.aaguid.0,
        be: record.backup_eligible,
        transports: record.transports.iter().cloned().collect::<BTreeSet<_>>(),
        at: now,
    });
    emit(tx, &binding).await?;
    if aaguid_changed(record, others) {
        let signal = claims::risk(subject, RiskSignal::AaguidChange, Bind::None, now);
        emit(tx, &signal).await?;
    }
    if att.1 == AttestationResult::Verified {
        let posture = claims::posture(
            subject,
            attestation_verdict(att.1),
            "webauthn-attestation",
            Some(claims::material(
                access_kernel::claim::body::AuthenticatorKind::Passkey,
                record.id.as_bytes(),
                &record.public_key,
            )),
            Bind::None,
            now,
        );
        emit(tx, &posture).await?;
    }
    Ok(())
}

/// Whether the new passkey's AAGUID is one no other live passkey of the account has (TN-63). The
/// all-zero AAGUID says nothing and never counts.
#[must_use]
pub fn aaguid_changed(record: &CredentialRecord, others: &[CredentialRecord]) -> bool {
    let known: Vec<[u8; 16]> = others
        .iter()
        .filter(|o| o.id != record.id && o.deleted_at.is_none() && o.aaguid.0 != [0; 16])
        .map(|o| o.aaguid.0)
        .collect();
    record.aaguid.0 != [0; 16] && !known.is_empty() && !known.contains(&record.aaguid.0)
}
