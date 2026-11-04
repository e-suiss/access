//! Retention classes (Ek C C.0, OP-74 m.1, OP-75, OP-77).

use core::fmt;
use core::str::FromStr;

/// A retention class. A key is per subject and class (OP-74 m.1); the name is the Ek C C.0 name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum Class {
    /// `profile`: account and profile fields.
    Profile,
    /// `kyc`: identification, verification documents and results, beneficial owner.
    Kyc,
    /// `transaction`: payment, transfer and commercial transaction records.
    Transaction,
    /// `aml_report`: suspicious-activity reports, internal assessment and supporting documents.
    AmlReport,
    /// `audit`: authentication, authority, access and administration events.
    Audit,
    /// `traffic`: IP, port, session start and end, data volume.
    Traffic,
    /// `consent`: commercial message consent and its proof.
    Consent,
    /// `message_log`: commercial message send, delivery and rejection records.
    MessageLog,
    /// `contract`: contract, pre-contract information, withdrawal and delivery records.
    Contract,
    /// `ledger`: commercial books, financial statements, commercial correspondence.
    Ledger,
    /// `tax`: tax books and documents.
    Tax,
    /// `dsr_log`: data subject requests and their answers.
    DsrLog,
    /// `erasure_log`: erasure, destruction, hold placement and lifting, readable exports.
    ErasureLog,
    /// `suppression`: the keyed-hash suppression list.
    Suppression,
    /// `work_record`: Work record bodies (OP-75).
    WorkRecord,
    /// `work_evidence`: Work evidence bodies and attachments (OP-75).
    WorkEvidence,
    /// `work_draft`: unrecorded chat text and unshared human drafts (OP-75).
    WorkDraft,
    /// `agent_trace`: the part of an agent's run trace Work keeps (OP-75).
    AgentTrace,
    /// `one_memory`: Suiss One memory records, episodes and behaviour profile (OP-77).
    OneMemory,
    /// `one_model`: personal adapters and small personal models (OP-77).
    OneModel,
    /// `one_observation`: raw observation such as audio, screenshots, location samples (OP-77).
    OneObservation,
    /// `one_sensitive`: inferences and records in special categories (OP-77).
    OneSensitive,
    /// `one_provider_trace`: which processor received which data class (OP-77).
    OneProviderTrace,
    /// `one_browser_profile`: the agent browser profile and its session state (OP-77).
    OneBrowserProfile,
    /// `one_training_lineage`: the content-free lineage of a training contribution (OP-77).
    OneTrainingLineage,
}

impl Class {
    /// Every class, in Ek C C.0 order.
    pub const ALL: [Self; 25] = [
        Self::Profile,
        Self::Kyc,
        Self::Transaction,
        Self::AmlReport,
        Self::Audit,
        Self::Traffic,
        Self::Consent,
        Self::MessageLog,
        Self::Contract,
        Self::Ledger,
        Self::Tax,
        Self::DsrLog,
        Self::ErasureLog,
        Self::Suppression,
        Self::WorkRecord,
        Self::WorkEvidence,
        Self::WorkDraft,
        Self::AgentTrace,
        Self::OneMemory,
        Self::OneModel,
        Self::OneObservation,
        Self::OneSensitive,
        Self::OneProviderTrace,
        Self::OneBrowserProfile,
        Self::OneTrainingLineage,
    ];

    /// The Ek C C.0 name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Profile => "profile",
            Self::Kyc => "kyc",
            Self::Transaction => "transaction",
            Self::AmlReport => "aml_report",
            Self::Audit => "audit",
            Self::Traffic => "traffic",
            Self::Consent => "consent",
            Self::MessageLog => "message_log",
            Self::Contract => "contract",
            Self::Ledger => "ledger",
            Self::Tax => "tax",
            Self::DsrLog => "dsr_log",
            Self::ErasureLog => "erasure_log",
            Self::Suppression => "suppression",
            Self::WorkRecord => "work_record",
            Self::WorkEvidence => "work_evidence",
            Self::WorkDraft => "work_draft",
            Self::AgentTrace => "agent_trace",
            Self::OneMemory => "one_memory",
            Self::OneModel => "one_model",
            Self::OneObservation => "one_observation",
            Self::OneSensitive => "one_sensitive",
            Self::OneProviderTrace => "one_provider_trace",
            Self::OneBrowserProfile => "one_browser_profile",
            Self::OneTrainingLineage => "one_training_lineage",
        }
    }
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A name that is not an Ek C C.0 class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("unknown retention class")]
pub struct UnknownClass;

impl FromStr for Class {
    type Err = UnknownClass;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|c| c.name() == s)
            .ok_or(UnknownClass)
    }
}

#[cfg(test)]
mod tests;
