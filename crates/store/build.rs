//! `sqlx::migrate!()` embeds the migrations at compile time without telling Cargo about the
//! directory, so a new migration file would leave stale artefacts behind (OP-66).
fn main() {
    println!("cargo:rerun-if-changed=migrations");
    println!("cargo:rerun-if-changed=bootstrap");
}
