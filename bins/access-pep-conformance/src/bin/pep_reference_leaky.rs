//! The negative-control PEP adapter (OP-150 m.1 (a)): it leaks effects on faults and the
//! harness must flag it.

use access_pep_conformance::reference::{Leaky, serve};

fn main() -> std::io::Result<()> {
    serve("access negative control (leaky)", Leaky::new)
}
