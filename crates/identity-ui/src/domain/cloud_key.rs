//! One's cloud key permission (OP-156 m.3 (w), E59, E46, OP-78): the terms a device Instance's
//! `one.cloud_key/grant` intent must carry and where a recorded permission stands. The
//! permission lets a checked TEE open the named user-keyed classes for one purpose, for at most
//! 24 hours, never past the Mandate that covers acting while the person is away. The record is
//! content-free: no DEK, KEK or data.

use access_internal_api::one::{GRANT, MandateStanding, NAMESPACE, REVOKE};
use access_kernel::intent::{IntentEnvelope, ParamValue};
use access_kernel::model::EqValue;

/// The longest a permission lasts (E59 (2); Ek B 4552 PD closed at 24 hours).
pub const MAX_MS: u64 = 86_400_000;

/// How far ahead of trusted now a permission may start.
pub const SKEW_MS: u64 = 60_000;

/// Most classes one permission names.
pub const MAX_CLASSES: usize = 8;

/// The user-keyed classes a cloud key permission can name (E52, Ek C One classes).
pub const CLASSES: [&str; 7] = [
    "one_memory",
    "one_model",
    "one_observation",
    "one_sensitive",
    "one_provider_trace",
    "one_browser_profile",
    "one_training_lineage",
];

/// The terms of a grant intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Terms {
    /// The work: the name of an action of One's own namespace the Mandate must cover.
    pub purpose: String,
    /// The class names, sorted, no repeats.
    pub classes: Vec<String>,
    /// From, Unix ms.
    pub from: u64,
    /// Until, Unix ms.
    pub until: u64,
    /// The digest of the TEE's measurement.
    pub tee_measurement: [u8; 32],
    /// The digest of the TEE's job key, the only key the DEKs are wrapped to.
    pub job_key: [u8; 32],
    /// The Mandate it is bound to.
    pub mandate: [u8; 16],
}

/// Why a grant or revoke intent is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TermsError {
    /// Not the action this route takes.
    #[error("cloud-key-action")]
    Action,
    /// A parameter is missing or out of shape.
    #[error("cloud-key-terms")]
    Terms,
    /// A class that is not user-keyed.
    #[error("cloud-key-class")]
    Class,
    /// Longer than 24 hours, already over, or starting later than now.
    #[error("cloud-key-window")]
    Window,
}

fn bytes<const N: usize>(p: Option<&ParamValue>) -> Result<[u8; N], TermsError> {
    match p {
        Some(ParamValue::Eq(EqValue::Bytes(b))) => {
            <[u8; N]>::try_from(b.as_slice()).map_err(|_| TermsError::Terms)
        }
        _ => Err(TermsError::Terms),
    }
}

fn purpose_ok(p: &str) -> bool {
    let mut chars = p.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && p.len() <= 64
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn action_is(e: &IntentEnvelope, name: &str) -> bool {
    e.action.namespace == NAMESPACE && e.action.name == name
}

/// The terms of `e`, a `one.cloud_key/grant` intent, at trusted `now`.
///
/// # Errors
/// [`TermsError`].
pub fn grant_terms(e: &IntentEnvelope, now: u64) -> Result<Terms, TermsError> {
    if !action_is(e, GRANT) {
        return Err(TermsError::Action);
    }
    let purpose = match e.params.get("purpose") {
        Some(ParamValue::Eq(EqValue::Text(p))) if purpose_ok(p) => p.clone(),
        _ => return Err(TermsError::Terms),
    };
    let classes = match e.params.get("classes") {
        Some(ParamValue::Eq(EqValue::Text(t))) => {
            let mut c: Vec<String> = t.split(',').map(String::from).collect();
            c.sort();
            c.dedup();
            c
        }
        _ => return Err(TermsError::Terms),
    };
    if classes.is_empty() || classes.len() > MAX_CLASSES {
        return Err(TermsError::Terms);
    }
    if classes.iter().any(|c| !CLASSES.contains(&c.as_str())) {
        return Err(TermsError::Class);
    }
    let Some(ParamValue::Interval(w)) = e.params.get("window") else {
        return Err(TermsError::Terms);
    };
    // E59 (2)
    if w.until <= w.from
        || w.until.saturating_sub(w.from) > MAX_MS
        || w.until <= now
        || w.from > now.saturating_add(SKEW_MS)
    {
        return Err(TermsError::Window);
    }
    Ok(Terms {
        purpose,
        classes,
        from: w.from,
        until: w.until,
        tee_measurement: bytes(e.params.get("tee_measurement"))?,
        job_key: bytes(e.params.get("job_key"))?,
        mandate: bytes(e.params.get("mandate"))?,
    })
}

/// The permission a `one.cloud_key/revoke` intent ends.
///
/// # Errors
/// [`TermsError`].
pub fn revoked_permission(e: &IntentEnvelope) -> Result<[u8; 16], TermsError> {
    if !action_is(e, REVOKE) {
        return Err(TermsError::Action);
    }
    bytes(e.params.get("permission"))
}

/// Where a recorded permission stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// The TEE may hold the wrapped DEKs.
    Live,
    /// The person withdrew it.
    Revoked,
    /// Its window is over.
    Expired,
    /// Its Mandate was revoked, ran out or no longer covers the work.
    MandateEnded,
}

impl State {
    /// The wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::MandateEnded => "mandate_ended",
        }
    }

    /// Whether the TEE's copies must be destroyed now (E59 (3)): every state but `live`.
    #[must_use]
    pub const fn destroy(self) -> bool {
        !matches!(self, Self::Live)
    }
}

/// Where a permission until `until` stands at `now`, revoked or not, given where its Mandate
/// stands (E59 (3)). The Mandate's end ends it; so does a Mandate the head no longer knows.
#[must_use]
pub fn state(revoked: bool, until: u64, mandate: MandateStanding, now: u64) -> State {
    if revoked {
        State::Revoked
    } else if now >= until {
        State::Expired
    } else if matches!(mandate, MandateStanding::Covers(_)) {
        State::Live
    } else {
        State::MandateEnded
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use access_kernel::intent::ContextRefs;
    use access_kernel::model::{ActionRef, Window};

    use super::*;

    const NOW: u64 = 1_800_000_000_000;

    fn grant(params: BTreeMap<String, ParamValue>) -> IntentEnvelope {
        IntentEnvelope {
            provenance: BTreeMap::new(),
            action: ActionRef {
                namespace: String::from(NAMESPACE),
                name: String::from(GRANT),
                major: 1,
                schema: access_kernel::digest::Digest([0; 32]),
            },
            resources: Vec::new(),
            params,
            opaque: BTreeMap::new(),
            recipient: None,
            purpose: None,
            context: ContextRefs::default(),
            validity: Window {
                from: NOW,
                until: NOW + 60_000,
            },
        }
    }

    fn params(classes: &str, from: u64, until: u64) -> BTreeMap<String, ParamValue> {
        BTreeMap::from([
            (
                String::from("purpose"),
                ParamValue::Eq(EqValue::Text(String::from("consolidate"))),
            ),
            (
                String::from("classes"),
                ParamValue::Eq(EqValue::Text(String::from(classes))),
            ),
            (
                String::from("window"),
                ParamValue::Interval(Window { from, until }),
            ),
            (
                String::from("tee_measurement"),
                ParamValue::Eq(EqValue::Bytes(vec![1; 32])),
            ),
            (
                String::from("job_key"),
                ParamValue::Eq(EqValue::Bytes(vec![2; 32])),
            ),
            (
                String::from("mandate"),
                ParamValue::Eq(EqValue::Bytes(vec![3; 16])),
            ),
        ])
    }

    // E59, OP-156 m.3 (w)
    #[test]
    fn a_permission_lasts_at_most_a_day_and_names_only_user_keyed_classes() {
        let t = grant_terms(
            &grant(params("one_model,one_memory,one_memory", NOW, NOW + MAX_MS)),
            NOW,
        )
        .unwrap();
        assert_eq!(t.classes, ["one_memory", "one_model"]);
        assert_eq!(t.until - t.from, MAX_MS);
        assert_eq!(
            grant_terms(&grant(params("one_memory", NOW, NOW + MAX_MS + 1)), NOW),
            Err(TermsError::Window)
        );
        assert_eq!(
            grant_terms(&grant(params("one_memory", NOW - 2, NOW - 1)), NOW),
            Err(TermsError::Window)
        );
        assert_eq!(
            grant_terms(
                &grant(params("one_memory", NOW + SKEW_MS + 1, NOW + 2 * SKEW_MS)),
                NOW
            ),
            Err(TermsError::Window)
        );
        assert_eq!(
            grant_terms(&grant(params("profile", NOW, NOW + 1)), NOW),
            Err(TermsError::Class)
        );
        let mut missing = params("one_memory", NOW, NOW + 1);
        missing.remove("mandate");
        assert_eq!(grant_terms(&grant(missing), NOW), Err(TermsError::Terms));
    }

    // E59
    #[test]
    fn a_permission_ends_with_its_mandate_its_window_or_its_revocation() {
        let covers = MandateStanding::Covers(NOW + MAX_MS);
        assert_eq!(state(false, NOW + 1, covers, NOW), State::Live);
        assert!(!State::Live.destroy());
        for (s, want) in [
            (state(true, NOW + 1, covers, NOW), State::Revoked),
            (state(false, NOW, covers, NOW), State::Expired),
            (
                state(false, NOW + 1, MandateStanding::Ended, NOW),
                State::MandateEnded,
            ),
            (
                state(false, NOW + 1, MandateStanding::Unknown, NOW),
                State::MandateEnded,
            ),
        ] {
            assert_eq!(s, want);
            assert!(s.destroy());
        }
    }
}
