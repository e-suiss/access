use super::*;

// L2-BUD-1, OP-159 m.3 (p), (q)
#[test]
fn a_pap_over_the_header_budget_goes_by_reference_and_an_offline_one_never_does() {
    assert_eq!(text_len(6_144), 8_192);
    assert_eq!(plan(b"not a pap", &[0; 6_144]), Carried::Inline(None));
    let Carried::Reference { size, .. } = plan(b"not a pap", &[1; 6_145]) else {
        panic!("by reference");
    };
    assert_eq!(size, 6_145);
    assert_eq!(
        fetch_path(&Digest([0; 32]), &[0; 32]),
        "/access/v1/domains/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/projections/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );
}
