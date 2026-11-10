//! The export projection of the audit log (OP-41, OP-44, OP-156 m.3 (s), X22): every realm audit
//! event, none sampled, goes to the realm's registered sinks as a copy labelled "copy — not the
//! record", in the sink's wire form. A sink that refuses keeps its cursor where it was, so
//! nothing is lost; the audit question is answered from the record.

pub mod adapters;
pub mod app;
pub mod domain;
pub mod ports;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
