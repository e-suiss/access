use super::{Event, Length, Period, PolicyVersion, Schedule};
use crate::class::Class;
use crate::ids::TenantId;

// OP-147 m.5, Ek C.3.6, C.5
#[test]
fn work_defaults_follow_ek_c() {
    let t = TenantId::new("t1");
    let v = PolicyVersion::new(7);
    let length = |c| Schedule::work_default(t.clone(), c, v).map(|s| s.length);
    assert_eq!(
        length(Class::WorkRecord),
        Some(Length::Until(Event::TenantClosed))
    );
    assert_eq!(
        length(Class::WorkEvidence),
        Some(Length::Until(Event::TenantClosed))
    );
    assert_eq!(
        length(Class::WorkDraft),
        Some(Length::Until(Event::Removed))
    );
    assert_eq!(
        length(Class::AgentTrace),
        Some(Length::For(Period::Days(400)))
    );
    let s = Schedule::work_default(t.clone(), Class::AgentTrace, v).unwrap();
    assert_eq!(s.start, Event::Recorded);
    assert_eq!(s.max, None);
    assert_eq!(s.version, v);
    assert_eq!(s.tenant, t);
    for class in Class::ALL {
        let work = matches!(
            class,
            Class::WorkRecord | Class::WorkEvidence | Class::WorkDraft | Class::AgentTrace
        );
        assert_eq!(length(class).is_some(), work, "{class}");
    }
}

// OP-147 m.4
#[cfg(feature = "serde")]
#[test]
fn schedule_wire_form() {
    let s = Schedule::work_default(
        TenantId::new("t1"),
        Class::AgentTrace,
        PolicyVersion::new(3),
    )
    .unwrap();
    let json = serde_json::to_value(&s).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "tenant": "t1",
            "class": "agent_trace",
            "basis": "Ek C C.3.6, C.5 #25",
            "length": {"for": {"days": 400}},
            "start": "recorded",
            "max": null,
            "version": 3,
        })
    );
    assert_eq!(serde_json::from_value::<Schedule>(json).unwrap(), s);
}
