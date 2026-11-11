//! A realm's residency and its placement and durability reads through the admin REST surface on
//! the real server path (CMP-26, OP-30, T28, HL-40, OP-158 m.3 (o), (p)): `putResidency`
//! commits `idp.realm.residency` only for the region and class this cell declares, and the
//! placement and durability reads say where the realm is served and what a loss can cost.

use access_store::placement::{self, CellProfile};

use super::*;

fn cell(class: &str) -> CellProfile {
    CellProfile {
        cell: String::from("eu-central-1"),
        region: Some(String::from("eu-central")),
        class: String::from(class),
        durability: String::from("replicated"),
        dedicated_to: None,
    }
}

// CMP-26, OP-30, MD-5, T28, OP-158 m.3 (o), Ek B 5721, 5768, 5958, 5959
#[tokio::test]
async fn op_30_a_realm_declares_residency_only_in_its_cells_region_and_reads_it_back() {
    let c = console("w9-residency", false).await;
    let none = c
        .put_setting(
            "residency",
            "putResidency",
            serde_json::json!({ "region": "eu-central", "class": "regional" }),
        )
        .await;
    assert_eq!(
        none.status,
        StatusCode::MISDIRECTED_REQUEST,
        "{}",
        none.body
    );
    assert_eq!(none.body["code"], "placement-mismatch");
    placement::declare_cell(&c.w.db.app, &cell("regional"))
        .await
        .unwrap();
    for (region, class) in [
        ("tr-central", "regional"),
        ("eu-central", "multi-region-sync"),
    ] {
        let away = c
            .put_setting(
                "residency",
                "putResidency",
                serde_json::json!({ "region": region, "class": class }),
            )
            .await;
        assert_eq!(
            away.status,
            StatusCode::MISDIRECTED_REQUEST,
            "{}",
            away.body
        );
    }
    let set = c
        .put_setting(
            "residency",
            "putResidency",
            serde_json::json!({ "region": "eu-central", "class": "regional" }),
        )
        .await;
    assert_eq!(set.status, StatusCode::OK, "{}", set.body);

    // TI-17
    let (s, placed, _) = c.rest_read("/admin/v1/realms/acme/placement").await;
    assert_eq!(s, StatusCode::OK, "{placed}");
    assert_eq!(placed["cell"], "eu-central-1");
    assert_eq!(placed["region"], "eu-central");
    assert_eq!(placed["residency"]["region"], "eu-central");
    assert_eq!(placed["residency"]["class"], "regional");
    assert_eq!(placed["routing_only"], true);
    assert_eq!(placed["realm"], serde_json::Value::Null);

    // OP-29, T28
    let (s, d, _) = c.rest_read("/admin/v1/realms/acme/durability").await;
    assert_eq!(s, StatusCode::OK, "{d}");
    assert_eq!(d["durability"], "replicated");
    assert_eq!(d["class"], "regional");
    assert_eq!(d["rpo_s"], 0);
    let dr = c
        .put_setting(
            "dr-profile",
            "putDrProfile",
            serde_json::json!({ "rpo_s": 300 }),
        )
        .await;
    assert_eq!(dr.status, StatusCode::OK, "{}", dr.body);
    let (_, d, _) = c.rest_read("/admin/v1/realms/acme/durability").await;
    assert_eq!(d["rpo_s"], 300);
    assert_eq!(d["dr_profile"]["rpo_s"], 300);

    // HL-40
    placement::declare_cell(
        &c.w.db.app,
        &CellProfile {
            durability: String::from("single-node"),
            ..cell("regional")
        },
    )
    .await
    .unwrap();
    let (_, d, _) = c.rest_read("/admin/v1/realms/acme/durability").await;
    assert_eq!(d["durability"], "single-node");
    assert_eq!(d["rpo_s"], serde_json::Value::Null);
}
