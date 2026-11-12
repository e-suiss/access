//! OP-91, INV-12, OP-159 m.3 (ee): the authority write permit. Only this layer mints it; every
//! commit of the core spends one.

pub use access_authority_sequencer::permit::WritePermit;

/// A permit for one commit of the core.
pub(crate) const fn issue() -> WritePermit {
    WritePermit::mint()
}
