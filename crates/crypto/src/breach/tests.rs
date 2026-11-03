use super::*;

// IDP-3: the protocol's published example, "P@ssw0rd"
#[test]
fn matches_the_range_protocol() {
    assert_eq!(
        &range_digest(b"P@ssw0rd"),
        b"21BD12DC183F740EE76F27B78EB39C8AD972A757"
    );
}
