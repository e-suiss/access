//! The Access event ↔ standard CAEP/RISC type table (§12.2.2 TN-41, §9.16) as code, and a
//! stream's profile: whether an Access event with a CAEP counterpart goes with it or instead
//! of it ("birlikte veya onun yerine", §9.16.2 k.3). A counterpart is approximate; a receiver
//! re-queries either way (P33, PI-9). The table adds no Access event type (SI-21).

use access_identity_account::domain::signal::{Family, SignalKind};
use serde_json::{Map, Value, json};

use crate::domain::Invalid;
use crate::domain::catalog::urn;

/// Prefix of the CAEP 1.0 event type URIs.
pub const CAEP_PREFIX: &str = "https://schemas.openid.net/secevent/caep/event-type/";

/// Prefix of the RISC 1.0 event type URIs.
pub const RISC_PREFIX: &str = "https://schemas.openid.net/secevent/risc/event-type/";

/// The type URI of an identity plane signal.
#[must_use]
pub fn signal_uri(kind: SignalKind) -> String {
    let prefix = match kind.family() {
        Family::Caep => CAEP_PREFIX,
        Family::Risc => RISC_PREFIX,
    };
    format!("{prefix}{}", kind.name())
}

/// The signal kind of a CAEP or RISC type URI this transmitter publishes.
#[must_use]
pub fn signal_of(uri: &str) -> Option<SignalKind> {
    SignalKind::ALL.into_iter().find(|k| signal_uri(*k) == uri)
}

/// Every CAEP and RISC type URI this transmitter publishes.
#[must_use]
pub fn signal_uris() -> Vec<String> {
    SignalKind::ALL.into_iter().map(signal_uri).collect()
}

/// Where a row of the table comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// An Access semantic event, by name.
    Access(&'static str),
    /// An identity plane signal.
    Identity(SignalKind),
}

/// One row of the mandatory mapping table (§12.2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Row {
    /// The event.
    pub source: Source,
    /// Its standard type; `None` when CAEP has none.
    pub standard: Option<SignalKind>,
    /// Whether the counterpart is only approximate.
    pub approximate: bool,
}

/// The table of §12.2.2, row by row.
pub const TABLE: [Row; 9] = [
    Row {
        source: Source::Access("instance-terminated"),
        standard: Some(SignalKind::SessionRevoked),
        approximate: true,
    },
    Row {
        source: Source::Access("authority-narrowed"),
        standard: Some(SignalKind::TokenClaimsChange),
        approximate: true,
    },
    Row {
        source: Source::Access("revalidation-required"),
        standard: Some(SignalKind::AssuranceLevelChange),
        approximate: true,
    },
    Row {
        source: Source::Access("authority-revoked"),
        standard: None,
        approximate: false,
    },
    Row {
        source: Source::Identity(SignalKind::CredentialChange),
        standard: Some(SignalKind::CredentialChange),
        approximate: false,
    },
    Row {
        source: Source::Identity(SignalKind::SessionRevoked),
        standard: Some(SignalKind::SessionRevoked),
        approximate: false,
    },
    Row {
        source: Source::Identity(SignalKind::RiskLevelChange),
        standard: Some(SignalKind::RiskLevelChange),
        approximate: false,
    },
    Row {
        source: Source::Identity(SignalKind::AccountDisabled),
        standard: Some(SignalKind::AccountDisabled),
        approximate: false,
    },
    Row {
        source: Source::Identity(SignalKind::AccountPurged),
        standard: Some(SignalKind::AccountPurged),
        approximate: false,
    },
];

/// The CAEP counterpart of an Access event, when it has one.
#[must_use]
pub fn counterpart(access: &str) -> Option<SignalKind> {
    TABLE.iter().find_map(|r| match r.source {
        Source::Access(name) if name == access => r.standard,
        _ => None,
    })
}

/// A stream's profile (§9.16, §9.16.2 k.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Profile {
    /// Access events only; no CAEP counterparts.
    Access,
    /// The CAEP counterpart instead of an Access event that has one.
    Caep,
    /// Both (the default).
    #[default]
    Both,
}

impl Profile {
    /// The stored name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Access => "access",
            Self::Caep => "caep",
            Self::Both => "both",
        }
    }

    /// The profile of a stored or requested name.
    ///
    /// # Errors
    /// [`Invalid`] `profile`.
    pub fn parse(s: &str) -> Result<Self, Invalid> {
        [Self::Access, Self::Caep, Self::Both]
            .into_iter()
            .find(|p| p.name() == s)
            .ok_or(Invalid("profile"))
    }
}

/// The type URIs an Access event `name` is delivered as on a stream with `profile` that
/// requested `events`: its own URN unless the profile is CAEP and it has a counterpart, and its
/// counterpart unless the profile is Access. Each only when the stream requested it.
#[must_use]
pub fn forms(name: &str, profile: Profile, events: &[String]) -> Vec<String> {
    let own = urn(name);
    let standard = counterpart(name).map(signal_uri);
    let mut out = Vec::new();
    if !(profile == Profile::Caep && standard.is_some()) && events.contains(&own) {
        out.push(own);
    }
    if let Some(s) = standard
        && profile != Profile::Access
        && events.contains(&s)
    {
        out.push(s);
    }
    out
}

/// The CAEP event body of an Access event's counterpart: approximate by construction; it names
/// the Access event it stands for and says nothing the Access event does not (§9.16 receiver
/// rule 4).
#[must_use]
pub fn counterpart_body(kind: SignalKind, access: &str, at_ms: u64) -> Value {
    let mut m = Map::new();
    m.insert("event_timestamp".into(), (at_ms / 1000).into());
    m.insert("initiating_entity".into(), "policy".into());
    m.insert("reason_admin".into(), json!({ "en": access }));
    match kind {
        SignalKind::TokenClaimsChange => {
            m.insert("claims".into(), json!({}));
        }
        SignalKind::AssuranceLevelChange => {
            m.insert("namespace".into(), "urn:suiss:access:assurance".into());
            m.insert("current_level".into(), access.into());
            m.insert("change_direction".into(), "decrease".into());
        }
        _ => {}
    }
    Value::Object(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    // TN-41, §12.2.2
    #[test]
    fn the_mapping_table_is_complete() {
        let expect = [
            (
                Source::Access("instance-terminated"),
                Some(SignalKind::SessionRevoked),
            ),
            (
                Source::Access("authority-narrowed"),
                Some(SignalKind::TokenClaimsChange),
            ),
            (
                Source::Access("revalidation-required"),
                Some(SignalKind::AssuranceLevelChange),
            ),
            (Source::Access("authority-revoked"), None),
            (
                Source::Identity(SignalKind::CredentialChange),
                Some(SignalKind::CredentialChange),
            ),
            (
                Source::Identity(SignalKind::SessionRevoked),
                Some(SignalKind::SessionRevoked),
            ),
            (
                Source::Identity(SignalKind::RiskLevelChange),
                Some(SignalKind::RiskLevelChange),
            ),
            (
                Source::Identity(SignalKind::AccountDisabled),
                Some(SignalKind::AccountDisabled),
            ),
            (
                Source::Identity(SignalKind::AccountPurged),
                Some(SignalKind::AccountPurged),
            ),
        ];
        assert_eq!(TABLE.len(), expect.len());
        for (source, standard) in expect {
            let rows: Vec<_> = TABLE.iter().filter(|r| r.source == source).collect();
            assert_eq!(rows.len(), 1, "{source:?}");
            assert_eq!(rows[0].standard, standard, "{source:?}");
        }
        for k in [SignalKind::AccountDisabled, SignalKind::AccountPurged] {
            assert_eq!(k.family(), Family::Risc);
        }
    }

    // TN-41, §9.16
    #[test]
    fn authority_revoked_has_no_caep_counterpart() {
        assert_eq!(counterpart("authority-revoked"), None);
        let events = vec![
            urn("authority-revoked"),
            signal_uri(SignalKind::SessionRevoked),
        ];
        for p in [Profile::Access, Profile::Caep, Profile::Both] {
            assert_eq!(
                forms("authority-revoked", p, &events),
                vec![urn("authority-revoked")]
            );
        }
    }

    // §9.16, §9.16.2 k.3
    #[test]
    fn the_profile_decides_with_or_instead() {
        let caep = signal_uri(SignalKind::SessionRevoked);
        let own = urn("instance-terminated");
        let both = vec![own.clone(), caep.clone()];
        assert_eq!(
            forms("instance-terminated", Profile::Both, &both),
            vec![own.clone(), caep.clone()]
        );
        assert_eq!(
            forms("instance-terminated", Profile::Caep, &both),
            vec![caep.clone()]
        );
        assert_eq!(
            forms("instance-terminated", Profile::Access, &both),
            vec![own.clone()]
        );
        assert_eq!(
            forms("instance-terminated", Profile::Both, &[]),
            Vec::<String>::new()
        );
        assert_eq!(Profile::default(), Profile::Both);
        assert!(Profile::parse("other").is_err());
    }

    // TN-41
    #[test]
    fn standard_uris_are_the_official_ones() {
        assert_eq!(
            signal_uri(SignalKind::SessionRevoked),
            "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
        );
        assert_eq!(
            signal_uri(SignalKind::AccountPurged),
            "https://schemas.openid.net/secevent/risc/event-type/account-purged"
        );
        assert_eq!(signal_uris().len(), 12);
        for u in signal_uris() {
            assert_eq!(signal_uri(signal_of(&u).unwrap()), u);
        }
    }
}
