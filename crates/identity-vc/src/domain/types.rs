//! The closed set of person-attribute credential types (E55; Ek B 4196, 5039): verified name,
//! age over 16, 18 and 21, email and phone verification, household membership. A request for
//! any other type is refused before anything is read or signed.

/// A person-attribute credential type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PersonAttribute {
    /// The person's verified name.
    VerifiedName,
    /// The person is over 16.
    AgeOver16,
    /// The person is over 18.
    AgeOver18,
    /// The person is over 21.
    AgeOver21,
    /// The person's email address is verified.
    EmailVerified,
    /// The person's phone number is verified.
    PhoneVerified,
    /// The person is a member of a household.
    HouseholdMember,
}

/// Every type, in wire order.
pub const ALL: [PersonAttribute; 7] = [
    PersonAttribute::VerifiedName,
    PersonAttribute::AgeOver16,
    PersonAttribute::AgeOver18,
    PersonAttribute::AgeOver21,
    PersonAttribute::EmailVerified,
    PersonAttribute::PhoneVerified,
    PersonAttribute::HouseholdMember,
];

/// Why a type is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("credential-type-refused")]
pub struct TypeRefused;

impl PersonAttribute {
    /// The wire name: the credential configuration id and the last `vct` segment.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::VerifiedName => "verified_name",
            Self::AgeOver16 => "age_over_16",
            Self::AgeOver18 => "age_over_18",
            Self::AgeOver21 => "age_over_21",
            Self::EmailVerified => "email_verified",
            Self::PhoneVerified => "phone_verified",
            Self::HouseholdMember => "household_member",
        }
    }

    /// The type of a wire name.
    ///
    /// # Errors
    /// [`TypeRefused`] for every name outside the set (Ek B 5039).
    pub fn parse(name: &str) -> Result<Self, TypeRefused> {
        ALL.into_iter()
            .find(|t| t.name() == name)
            .ok_or(TypeRefused)
    }

    /// The `vct`: `<issuer>/vc/<name>`, under the realm issuer.
    #[must_use]
    pub fn vct(self, issuer: &str) -> String {
        format!("{}/vc/{}", issuer.trim_end_matches('/'), self.name())
    }

    /// The type of a `vct` under `issuer`.
    ///
    /// # Errors
    /// [`TypeRefused`].
    pub fn of_vct(issuer: &str, vct: &str) -> Result<Self, TypeRefused> {
        let prefix = format!("{}/vc/", issuer.trim_end_matches('/'));
        vct.strip_prefix(&prefix)
            .ok_or(TypeRefused)
            .and_then(Self::parse)
    }

    /// Whether the attribute is a fact about the person (a boolean claim) rather than a value.
    #[must_use]
    pub const fn boolean(self) -> bool {
        !matches!(self, Self::VerifiedName)
    }
}
