//! OP-140 m.3: the vectors shipped in the `suiss-crypto` package are byte-identical copies of
//! `conformance/vectors`, and `vectors/MANIFEST` lists the SHA-256 of each.

use std::fmt::Write as _;
use std::path::Path;

use sha2::{Digest as _, Sha256};

use super::files::{read_bytes, rel, walk};
use crate::Violation;

const RULE: &str = "shared-vectors";
const SHIPPED: &str = "crates/suiss-crypto/vectors";

fn v(path: &str, message: String) -> Violation {
    Violation {
        rule: RULE,
        path: path.into(),
        message,
    }
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let base = root.join(SHIPPED);
    let mut out = Vec::new();
    let mut manifest = String::new();
    let mut files: Vec<String> = walk(&base)?
        .iter()
        .map(|p| rel(&base, p))
        .filter(|r| r != "MANIFEST")
        .collect();
    files.sort();
    for file in &files {
        let shipped = read_bytes(&base.join(file))?;
        let source = root.join("conformance/vectors").join(file);
        match std::fs::read(&source) {
            Ok(original) if original == shipped => {}
            Ok(_) => out.push(v(
                &format!("{SHIPPED}/{file}"),
                format!("differs from conformance/vectors/{file}; copy it again"),
            )),
            Err(_) => out.push(v(
                &format!("{SHIPPED}/{file}"),
                format!("conformance/vectors/{file} does not exist; the package only ships copies"),
            )),
        }
        let digest = Sha256::digest(&shipped);
        for b in digest {
            let _ = write!(manifest, "{b:02x}");
        }
        let _ = writeln!(manifest, "  {file}");
    }
    match std::fs::read_to_string(base.join("MANIFEST")) {
        Ok(m) if m == manifest => {}
        _ => out.push(v(
            &format!("{SHIPPED}/MANIFEST"),
            String::from("out of date; run `just shared-vectors`"),
        )),
    }
    Ok(out)
}
