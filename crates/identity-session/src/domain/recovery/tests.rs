#![allow(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    reason = "test code"
)]

use super::*;

use RecoveryPath::{
    IdentityReproofing, RecoveryContact, RegisteredCode, ResetIntent, SecondAuthenticator,
    SentCode, TemporaryAccessPass,
};

// TN-52
#[test]
fn one_class_is_aal1_and_two_classes_reach_aal2() {
    assert_eq!(achieved(&[]), None);
    assert_eq!(achieved(&[SentCode]), Some(Aal::Aal1));
    assert_eq!(achieved(&[SentCode, SentCode]), Some(Aal::Aal1));
    assert_eq!(achieved(&[RegisteredCode, SentCode]), Some(Aal::Aal2));
    assert_eq!(
        achieved(&[RegisteredCode, SecondAuthenticator]),
        Some(Aal::Aal2)
    );
    assert_eq!(achieved(&[IdentityReproofing]), Some(Aal::Aal2));
    for p in PATHS {
        assert_ne!(
            achieved(&[p]),
            Some(Aal::Aal3),
            "recovery never reaches AAL3"
        );
        assert_eq!(path(p.name()), Some(p));
    }
}

// TN-52, TN-53, INV-40, TNI-4, Ek B 4042
#[test]
fn an_aal2_account_with_only_an_email_code_is_too_weak() {
    assert!(too_weak(Aal::Aal2, &[SentCode]));
    assert!(too_weak(Aal::Aal2, &[]));
    assert!(!too_weak(Aal::Aal1, &[SentCode]));
    assert!(!too_weak(Aal::Aal2, &[SentCode, RegisteredCode]));
    assert!(too_weak(Aal::Aal3, &[SentCode, RegisteredCode]));
}

// TN-54
#[test]
fn the_state_machine_has_no_shortcut() {
    use State::*;
    assert!(Requested.may(EvidenceMet));
    assert!(EvidenceMet.may(CoolingDown));
    assert!(CoolingDown.may(RebindOpen));
    assert!(RebindOpen.may(GracePeriod));
    assert!(GracePeriod.may(Closed));
    assert!(Requested.may(Throttled) && Throttled.may(Locked));
    assert!(CoolingDown.may(Denied));
    for (from, to) in [
        (Requested, RebindOpen),
        (Requested, GracePeriod),
        (CoolingDown, GracePeriod),
        (EvidenceMet, GracePeriod),
        (GracePeriod, Denied),
        (Locked, Requested),
        (Denied, RebindOpen),
        (Closed, Requested),
    ] {
        assert!(!from.may(to), "{from:?} -> {to:?}");
    }
    for s in State::ALL {
        assert_eq!(State::parse(s.name()), Some(s));
        assert!(!(s.terminal() && s.cancellable()));
    }
}

// TN-55, OP-153 m.3 (e), U67
#[test]
fn cooling_is_inverse_to_the_evidence_and_never_shorter_for_high_value() {
    let t = CoolingTable::DEFAULT;
    assert_eq!(t.cooling(&[RegisteredCode], false, false), 0);
    assert_eq!(
        t.cooling(&[RegisteredCode, SecondAuthenticator], false, false),
        0,
        "an authenticator bound to the account is not a second channel"
    );
    assert_eq!(t.cooling(&[SentCode], false, false), DAY_MS);
    assert_eq!(t.cooling(&[RecoveryContact], false, false), DAY_MS);
    assert_eq!(
        t.cooling(&[RegisteredCode, SentCode], false, false),
        4 * HOUR_MS
    );
    assert_eq!(t.cooling(&[RegisteredCode, SentCode], true, false), DAY_MS);
    assert_eq!(t.cooling(&[IdentityReproofing], false, false), HOUR_MS);
    assert_eq!(t.cooling(&[TemporaryAccessPass], false, false), 0);
    assert_eq!(t.cooling(&[ResetIntent], false, false), 0);
    for e in [&[RegisteredCode][..], &[TemporaryAccessPass], &[SentCode]] {
        assert!(t.cooling(e, false, true) >= DAY_MS);
    }
}

// TN-55, §10.1.3, INV-40, Ek B 3531
#[test]
fn a_policy_only_tightens_unless_loosened_as_ct3_and_never_below_the_floor() {
    let base = RecoveryPolicy::DEFAULT;
    assert_eq!(base.validate(), Ok(()));
    let mut longer = base;
    longer.cooling.sent_code_ms = 2 * DAY_MS;
    longer.rebind_aal = Some(2);
    assert_eq!(longer.change(&base), Ok(false));
    assert_eq!(base.change(&longer), Ok(true));
    let mut below = base;
    below.cooling.sent_code_ms = HOUR_MS;
    assert_eq!(below.change(&base), Err(PolicyRefusal::OutOfRange));
    let mut tap = base;
    tap.tap = true;
    assert_eq!(
        tap.change(&base),
        Ok(true),
        "turning passes on loosens (TN-62)"
    );
    assert_eq!(base.change(&tap), Ok(false));
    let mut intent = base;
    intent.intent_ttl_ms = INTENT_TTL_MAX_MS + 1;
    assert_eq!(intent.validate(), Err(PolicyRefusal::OutOfRange));
    let bytes = longer.to_bytes().unwrap();
    assert_eq!(RecoveryPolicy::from_bytes(&bytes), Ok(longer));
}

// TN-56, SEC18
#[test]
fn the_grace_period_refuses_every_listed_action_until_it_ends() {
    for a in Restricted::ALL {
        assert!(grace_refuses(Some(1_000 + GRACE_MS), 1_000, a));
        assert!(!grace_refuses(Some(1_000), 1_000, a));
        assert!(!grace_refuses(None, 1_000, a));
    }
    assert_eq!(GRACE_MS, 24 * HOUR_MS);
}

// TN-59, TN-62
#[test]
fn codes_carry_their_entropy() {
    assert_eq!(link_code_bits(true), 40);
    assert_eq!(link_code_bits(false), 112);
    let short = link_code(&[0xff; 14], true);
    let long = link_code(&[0xff; 14], false);
    assert_eq!(short.replace('-', "").len() * 5, 40);
    assert!(long.replace('-', "").len() * 5 >= 112);
    assert_eq!(tap_code(&[0; TAP_LENGTH_MAX], TAP_LENGTH).len(), TAP_LENGTH);
    assert_eq!(
        tap_code(&[0; TAP_LENGTH_MAX], TAP_LENGTH_MAX).len(),
        TAP_LENGTH_MAX
    );
    assert_eq!(canonical("ab-cd"), "ABCD");
    assert_eq!(backoff_ms(1), 30_000);
    assert_eq!(backoff_ms(2), 60_000);
    assert_eq!(backoff_ms(40), HOUR_MS);
    const { assert!(SENT_CODE_TTL_MS <= 24 * HOUR_MS && LINK_CODE_TTL_MS <= 10 * MINUTE_MS) };
}
