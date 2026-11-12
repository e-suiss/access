//! Inclusion evidence for an artefact signed under a superseded binding key (L0-SIG-64,
//! L0-SIG-80, P18, U27, OP-159 m.17 (a), Ek B 5780): `--evidence` is the inclusion proof bundle
//! the domain serves for the record in the cited checkpoint, `--log` and `--cosigners` the keys
//! that verify that checkpoint, and `--at-size`, `--at-root` and `--at-path` the consistency
//! path to the checkpoint the key is superseded at, when it is a later one.

use access_verifier::artefact::Evidence;
use suiss_crypto::note::Verifier;

use crate::args::{Options, Usage};
use crate::commands::Outcome;

/// The `--evidence` of `o`, `None` when not given; a bundle that is not one rejects as
/// `bundle`.
pub(crate) fn read(o: &Options) -> Result<Result<Option<Evidence>, Outcome>, Usage> {
    let at = ["at-size", "at-root", "at-path"].map(|n| o.has(n));
    if !o.has("evidence") {
        if o.has("log") || o.has("cosigners") || at.contains(&true) {
            return Err(Usage(
                "--log, --cosigners and --at-* go with --evidence".to_owned(),
            ));
        }
        return Ok(Ok(None));
    }
    if at.contains(&true) && at.contains(&false) {
        return Err(Usage(
            "give all of --at-size, --at-root and --at-path, or none".to_owned(),
        ));
    }
    let log = Verifier::parse(o.text("log")?).map_err(|_| Usage("--log: not a vkey".into()))?;
    let witnesses = o
        .words("cosigners")
        .iter()
        .map(|c| Verifier::parse(c).map_err(|_| Usage(format!("--cosigners: not a vkey: {c}"))))
        .collect::<Result<Vec<_>, _>>()?;
    if witnesses.is_empty() {
        return Err(Usage("--cosigners: one or more witness vkeys".into()));
    }
    let consistency = if at.contains(&true) {
        Some((o.uint("at-size")?, o.hash("at-root")?, o.hashes("at-path")?))
    } else {
        None
    };
    Ok(Evidence::from_bundle(
        &o.file("evidence")?,
        (o.text("origin")?, log, witnesses),
        consistency,
    )
    .map(Some)
    .ok_or_else(|| Outcome::Reject("bundle".to_owned())))
}
