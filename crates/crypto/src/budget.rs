//! Size budgets of the carriers a post-quantum artefact travels in (CR-38, CR-43, OP-159 m.3
//! (p)): an HTTP header, a cookie, one QR code (version 40-L, byte mode) and an NFC record. An
//! artefact over its carrier's budget is not produced.

/// A carrier with a size budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Carrier {
    /// An HTTP header such as `Authorization` or `DPoP`.
    Header,
    /// A cookie; it carries only an opaque session id (CR-38).
    Cookie,
    /// One QR code, version 40-L in byte mode.
    Qr,
    /// One NFC record.
    Nfc,
}

/// The artefact is larger than its carrier's budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("over the {} budget", .0.name())]
pub struct OverBudget(pub Carrier);

impl Carrier {
    /// Every carrier.
    pub const ALL: [Self; 4] = [Self::Header, Self::Cookie, Self::Qr, Self::Nfc];

    /// Its name in the budget vectors.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Header => "header",
            Self::Cookie => "cookie",
            Self::Qr => "qr",
            Self::Nfc => "nfc",
        }
    }

    /// The carrier a name names.
    #[must_use]
    pub fn of_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.name() == name)
    }

    /// Its budget in bytes (CR-43, PD).
    #[must_use]
    pub const fn budget(self) -> usize {
        match self {
            Self::Header | Self::Nfc => 8_192,
            Self::Cookie => 4_096,
            Self::Qr => 2_953,
        }
    }

    /// Whether `len` bytes fit.
    ///
    /// # Errors
    /// [`OverBudget`].
    pub const fn check(self, len: usize) -> Result<(), OverBudget> {
        if len <= self.budget() {
            Ok(())
        } else {
            Err(OverBudget(self))
        }
    }
}
