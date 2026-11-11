use super::*;

const V: PolicyVersion = PolicyVersion::new(1);

fn t() -> TenantId {
    TenantId::new("t1")
}

// OP-77, Ek C C.3.7
#[test]
fn every_one_class_but_the_lineage_is_user_keyed_and_goes_with_the_account() {
    for c in Class::ALL {
        let one = c.name().starts_with("one_");
        let lineage = c == Class::OneTrainingLineage;
        assert_eq!(c.is_user_keyed(), one && !lineage, "{c}");
        assert_eq!(c.shredded_with_account(), one && !lineage, "{c}");
        assert_eq!(Schedule::one_default(t(), c, V).is_some(), one, "{c}");
    }
}

// OP-77, Ek C C.3.7, C.5 #26, #27
#[test]
fn the_one_defaults_follow_ek_c() {
    let s = |c| Schedule::one_default(t(), c, V).unwrap();
    assert_eq!(s(Class::OneMemory).length, Length::Until(Event::Removed));
    assert_eq!(s(Class::OneModel).length, Length::Until(Event::Removed));
    assert_eq!(s(Class::OneSensitive).length, Length::Until(Event::Removed));
    assert_eq!(
        s(Class::OneObservation).length,
        Length::For(Period::Days(3))
    );
    assert_eq!(s(Class::OneObservation).max, Some(Period::Days(3)));
    assert_eq!(
        s(Class::OneProviderTrace).length,
        Length::For(Period::Years(3))
    );
    assert_eq!(
        s(Class::OneBrowserProfile).length,
        Length::Until(Event::MandateEnded)
    );
    let lineage = s(Class::OneTrainingLineage);
    assert_eq!(lineage.length, Length::For(Period::Years(3)));
    assert_eq!(lineage.start, Event::ModelWithdrawn);
}

// OP-77, Ek C C.3.7
#[test]
fn one_data_maps_to_its_class_and_an_export_to_its_most_restrictive_source() {
    assert_eq!(OneData::TaskRecord.class(), Class::OneMemory);
    assert_eq!(OneData::EffectEvidence.class(), Class::OneMemory);
    assert_eq!(OneData::BrowserSnapshot.class(), Class::OneBrowserProfile);
    assert_eq!(OneData::ConsentRecord.class(), Class::Audit);
    assert_eq!(OneData::ConsentRecord.start(), Some(Event::ConsentEnded));
    assert_eq!(OneData::TaskRecord.start(), None);
    assert_eq!(
        export_class(&[Class::OneMemory, Class::OneObservation, Class::OneModel]),
        Some(Class::OneObservation)
    );
    assert_eq!(
        export_class(&[Class::OneMemory, Class::OneBrowserProfile]),
        Some(Class::OneBrowserProfile)
    );
    assert_eq!(export_class(&[Class::Audit, Class::Profile]), None);
    assert_eq!(EXPORT_DOWNLOAD_DAYS, 7);
}
