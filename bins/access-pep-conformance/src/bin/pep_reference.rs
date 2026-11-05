//! The fail-closed reference PEP adapter (OP-150 m.1 (a)); the harness must pass it.

use access_pep_conformance::reference::{Reference, serve};

fn main() -> std::io::Result<()> {
    serve("access reference PEP (fail-closed)", Reference::new)
}
