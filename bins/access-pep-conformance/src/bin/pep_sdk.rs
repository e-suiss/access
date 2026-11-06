//! The `access_sdk` PEP adapter (OP-150 m.2 L10): the Rust SDK under the conformance harness.

use access_pep_conformance::reference::serve;
use access_pep_conformance::sdk::Sdk;

fn main() -> std::io::Result<()> {
    serve("esuiss-access-sdk (Rust PEP SDK)", Sdk::new)
}
