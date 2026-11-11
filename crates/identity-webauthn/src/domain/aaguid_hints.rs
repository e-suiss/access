//! The community AAGUID list as a hint (§10.2.4, P-ID-7, IDI-3, OP-148, OP-158 m.3 (y)): it
//! names the authenticator model a passkey reports, for the person and the console to read.
//! It is never a trust input: nothing here feeds attestation, assurance or a policy, and a
//! model it names is no more trusted than one it does not. The list is the operator's file in
//! the community format, `{ "<aaguid>": { "name": "…", … } }`.

use std::collections::BTreeMap;

use access_kernel::json::{Json, parse};

use super::ids::Aaguid;

/// Ceiling for the list file (PD).
pub const MAX_LIST: usize = 4 * 1024 * 1024;

/// Longest name kept, in characters.
pub const MAX_NAME: usize = 64;

/// Why a list is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HintListError {
    /// Larger than [`MAX_LIST`].
    #[error("aaguid hint list too large")]
    Size,
    /// Not a JSON object of AAGUIDs.
    #[error("aaguid hint list malformed")]
    Format,
}

/// What the list says about a model; a label, not a claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hint {
    /// The display name, printable and at most [`MAX_NAME`] characters.
    pub name: String,
}

/// The community list, by AAGUID.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AaguidHints {
    names: BTreeMap<[u8; 16], Hint>,
}

fn printable(name: &str) -> Option<String> {
    let kept: String = name
        .chars()
        .filter(|c| {
            !c.is_control() && !matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        .take(MAX_NAME)
        .collect();
    let kept = kept.trim().to_owned();
    (!kept.is_empty()).then_some(kept)
}

impl AaguidHints {
    /// Parses the community list; entries that are not a canonical AAGUID with a name are
    /// skipped, and the all-zero AAGUID is never named (it says nothing about the model).
    ///
    /// # Errors
    /// [`HintListError`].
    pub fn parse(bytes: &[u8]) -> Result<Self, HintListError> {
        if bytes.len() > MAX_LIST {
            return Err(HintListError::Size);
        }
        let Json::Object(entries) = parse(bytes, MAX_LIST).map_err(|_| HintListError::Format)?
        else {
            return Err(HintListError::Format);
        };
        let mut names = BTreeMap::new();
        for (key, value) in entries {
            let Some(aaguid) = Aaguid::parse(&key).filter(|a| *a != Aaguid::ZERO) else {
                continue;
            };
            let Some(name) = value.get("name").and_then(Json::as_str).and_then(printable) else {
                continue;
            };
            names.insert(aaguid.0, Hint { name });
        }
        Ok(Self { names })
    }

    /// The hint for `aaguid`, if the list names it.
    #[must_use]
    pub fn hint(&self, aaguid: Aaguid) -> Option<&Hint> {
        self.names.get(&aaguid.0)
    }

    /// Models the list names.
    #[must_use]
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Whether the list names none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    const LIST: &str = r#"{
        "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4": { "name": "Google Password Manager", "icon_dark": "data:x" },
        "fbfc3007-154e-4ecc-8c0b-6e020557d7bd": { "name": "iCloud Keychain\u0007\u202e" },
        "00000000-0000-0000-0000-000000000000": { "name": "Anything" },
        "not-an-aaguid": { "name": "Skipped" },
        "adce0002-35bc-c60a-648b-0b25f1f05503": { "icon_light": "data:y" }
    }"#;

    // §10.2.4, P-ID-7, OP-158
    #[test]
    fn the_community_list_names_models_and_nothing_more() {
        let hints = AaguidHints::parse(LIST.as_bytes()).unwrap();
        assert_eq!(hints.len(), 2);
        let gpm = Aaguid::parse("ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4").unwrap();
        assert_eq!(hints.hint(gpm).unwrap().name, "Google Password Manager");
        let icloud = Aaguid::parse("fbfc3007-154e-4ecc-8c0b-6e020557d7bd").unwrap();
        assert_eq!(hints.hint(icloud).unwrap().name, "iCloud Keychain");
        assert!(hints.hint(Aaguid::ZERO).is_none());
        let unnamed = Aaguid::parse("adce0002-35bc-c60a-648b-0b25f1f05503").unwrap();
        assert!(hints.hint(unnamed).is_none());
    }

    // IDI-3, P-ID-7
    #[test]
    fn a_hint_opens_no_attestation_allowlist() {
        use crate::domain::mds::MdsBlob;
        let hints = AaguidHints::parse(LIST.as_bytes()).unwrap();
        let gpm = Aaguid::parse("ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4").unwrap();
        assert!(hints.hint(gpm).is_some());
        let metadata = MdsBlob {
            serial: 1,
            next_update: 0,
            entries: Vec::new(),
        };
        assert!(
            metadata.entry(gpm).is_none(),
            "a named model is still unknown to MDS"
        );
    }

    // OP-158
    #[test]
    fn malformed_or_oversized_lists_are_refused() {
        assert_eq!(AaguidHints::parse(b"[]"), Err(HintListError::Format));
        assert_eq!(AaguidHints::parse(b"{"), Err(HintListError::Format));
        assert_eq!(AaguidHints::parse(&[0xff]), Err(HintListError::Format));
        assert_eq!(
            AaguidHints::parse(&vec![b' '; MAX_LIST + 1]),
            Err(HintListError::Size)
        );
        let long = format!(
            r#"{{"ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4": {{"name": "{}"}}}}"#,
            "x".repeat(200)
        );
        let hints = AaguidHints::parse(long.as_bytes()).unwrap();
        let gpm = Aaguid::parse("ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4").unwrap();
        assert_eq!(hints.hint(gpm).unwrap().name.chars().count(), MAX_NAME);
    }
}
