use super::{Class, UnknownClass};

// OP-147 m.2, OP-74 m.1
#[test]
fn names_are_the_ek_c_names() {
    let names: [&str; 25] = Class::ALL.map(Class::name);
    assert_eq!(
        names,
        [
            "profile",
            "kyc",
            "transaction",
            "aml_report",
            "audit",
            "traffic",
            "consent",
            "message_log",
            "contract",
            "ledger",
            "tax",
            "dsr_log",
            "erasure_log",
            "suppression",
            "work_record",
            "work_evidence",
            "work_draft",
            "agent_trace",
            "one_memory",
            "one_model",
            "one_observation",
            "one_sensitive",
            "one_provider_trace",
            "one_browser_profile",
            "one_training_lineage",
        ]
    );
}

// OP-147 m.2
#[test]
fn names_parse_back_and_nothing_else_parses() {
    for class in Class::ALL {
        assert_eq!(class.name().parse::<Class>(), Ok(class));
        assert_eq!(alloc::format!("{class}"), class.name());
    }
    assert_eq!("Profile".parse::<Class>(), Err(UnknownClass));
    assert_eq!("".parse::<Class>(), Err(UnknownClass));
    assert_eq!("work".parse::<Class>(), Err(UnknownClass));
}

// OP-147 m.4
#[cfg(feature = "serde")]
#[test]
fn wire_names_are_the_ek_c_names() {
    for class in Class::ALL {
        let json = serde_json::to_string(&class).unwrap();
        assert_eq!(json, alloc::format!("\"{}\"", class.name()));
        assert_eq!(serde_json::from_str::<Class>(&json).unwrap(), class);
    }
}
