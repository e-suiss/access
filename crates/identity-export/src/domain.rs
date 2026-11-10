//! The export projection's rules and wire forms (OP-41, OP-156 m.3 (s)): sink declarations, the
//! "copy — not the record" label, the OCSF field table and the renderings each adapter sends.
//! Sans-I/O.

pub mod collector;
pub mod copy;
pub mod fields;
pub mod leef;
pub mod otlp;
pub mod parquet;
pub mod s3;
pub mod secret;
pub mod sink;
pub mod syslog;

/// Why a sink declaration is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Invalid {
    /// The name is not a lower-case label of at most 63 characters.
    #[error("sink name")]
    Name,
    /// The endpoint is not an `https` URL Access requests, or `host:port` for syslog.
    #[error("sink endpoint")]
    Endpoint,
    /// The adapter, preset, format or settings do not fit together.
    #[error("sink settings")]
    Settings,
    /// A secret is missing where the adapter needs one, given where it takes none, or malformed.
    #[error("sink secret")]
    Secret,
}

impl Invalid {
    /// The stable problem code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        "invalid-export-sink"
    }
}
