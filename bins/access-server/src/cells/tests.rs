use super::*;
use access_kernel::verify::key_scope::Declarations;

// HL-40, T28, OP-158 m.3 (p)
#[test]
fn hl_40_a_single_node_cell_declares_itself_so() {
    let mut p = CellProfile {
        cell: String::from("small"),
        region: Some(String::from("eu-central")),
        class: String::from("regional"),
        durability: String::from("single-node"),
        dedicated_to: None,
    };
    let d = with_cell(Declarations::default(), &p);
    assert_eq!(d.durability, Some(Durability::SingleNode));
    assert_eq!(
        d.residency,
        Some(Residency::new(
            String::from("eu-central"),
            DrClass::Regional
        ))
    );
    // HL-40: nothing a cell declares about itself acknowledges a SEC23 write
    assert!(!d.acknowledges());
    p.durability = String::from("replicated");
    p.region = None;
    let d = with_cell(d, &p);
    assert_eq!(d.durability, Some(Durability::Replicated));
    assert_eq!(d.residency, None);
}
