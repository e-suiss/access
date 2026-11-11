#![allow(clippy::indexing_slicing, reason = "test code")]

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
    // HL-40
    assert!(!d.acknowledges());
    p.durability = String::from("replicated");
    p.region = None;
    let d = with_cell(d, &p);
    assert_eq!(d.durability, Some(Durability::Replicated));
    assert_eq!(d.residency, None);
}

fn cell(name: &str, dedicated_to: Option<&str>) -> config::Cell {
    config::Cell {
        name: String::from(name),
        region: Some(String::from("eu-central")),
        class: String::from("regional"),
        url: Some(format!("https://{name}.access.example")),
        dedicated_to: dedicated_to.map(String::from),
    }
}

// OP-158 m.3 (o), CMP-26, OP-12, OP-48
#[test]
fn cmp_26_the_cells_list_names_this_cell_and_each_cell_once() {
    let none = config::Cells::default();
    assert!(none.valid());
    assert_eq!(none.name(), "pool-default");
    let two = config::Cells {
        this: Some(String::from("eu-1")),
        cell: vec![
            cell("eu-1", None),
            cell("acme", Some("0190f1c2-7d3e-7a10-8000-5d1e4a6b2c01")),
        ],
    };
    assert!(two.valid());
    let mut other = two.clone();
    other.this = Some(String::from("us-1"));
    assert!(!other.valid(), "this cell is not listed");
    let mut twice = two.clone();
    twice.cell.push(cell("eu-1", None));
    assert!(!twice.valid());
    let mut bad = two.clone();
    bad.cell[1].dedicated_to = Some(String::from("acme"));
    assert!(!bad.valid());
    let mut class = two;
    class.cell[0].class = String::from("global");
    assert!(!class.valid());
    let mut config = Config::default();
    config.cells = config::Cells {
        this: Some(String::from("acme")),
        cell: vec![cell("acme", Some("0190f1c2-7d3e-7a10-8000-5d1e4a6b2c01"))],
    };
    let p = profile(&config);
    assert_eq!(p.cell, "acme");
    assert_eq!(p.region.as_deref(), Some("eu-central"));
    assert_eq!(p.durability, "replicated");
    assert_eq!(p.dedicated_to.map(|t| t[0]), Some(0x01));
}
