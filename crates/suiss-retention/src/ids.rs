//! Typed identifiers issued by Access (OP-64).

use alloc::string::String;

macro_rules! id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[cfg_attr(
            feature = "serde",
            derive(serde::Serialize, serde::Deserialize),
            serde(transparent)
        )]
        pub struct $name(String);

        impl $name {
            /// Wraps an identifier as Access issued it.
            #[must_use]
            pub fn new(id: impl Into<String>) -> Self {
                Self(id.into())
            }

            /// The identifier as Access issued it.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

id! {
    /// A tenant.
    TenantId
}

id! {
    /// A subject: the pseudonymous key person of a record (OP-74 m.1).
    SubjectId
}

id! {
    /// A litigation, regulator or law-enforcement hold.
    HoldId
}

id! {
    /// One of the person's devices holding a copy of a user-keyed key (E52).
    DeviceId
}

id! {
    /// A user-keyed record's own key (E66).
    RecordKeyId
}

id! {
    /// A job in an attested TEE holding a wrapped copy under a cloud key permission (E59).
    JobId
}
