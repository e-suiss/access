//! The schemas the SCIM server knows (RFC 7643 §4, RFC 9944, IDP-23, IDP-35): User with the
//! enterprise and the Access HR extensions, Group and Device. Attribute names match without
//! regard to ASCII case (RFC 7643 §2.1); the server answers with the spelling here.

/// An attribute's data type (RFC 7643 §2.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Type {
    /// `string`.
    String,
    /// `boolean`.
    Boolean,
    /// `decimal`.
    Decimal,
    /// `integer`.
    Integer,
    /// `dateTime` (RFC 3339).
    DateTime,
    /// `reference`.
    Reference,
    /// `complex`.
    Complex,
}

impl Type {
    /// The schema name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Boolean => "boolean",
            Self::Decimal => "decimal",
            Self::Integer => "integer",
            Self::DateTime => "dateTime",
            Self::Reference => "reference",
            Self::Complex => "complex",
        }
    }
}

/// When a client may write an attribute (RFC 7643 §2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mutability {
    /// Only the server writes it; a client's value is ignored.
    ReadOnly,
    /// Any time.
    ReadWrite,
    /// Once, when the resource or the value is created.
    Immutable,
    /// Written, never returned.
    WriteOnly,
}

impl Mutability {
    /// The schema name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ReadOnly => "readOnly",
            Self::ReadWrite => "readWrite",
            Self::Immutable => "immutable",
            Self::WriteOnly => "writeOnly",
        }
    }
}

/// When the server returns an attribute (RFC 7643 §2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Returned {
    /// Always, even when not asked.
    Always,
    /// Never.
    Never,
    /// Unless excluded.
    Default,
    /// Only when asked.
    Request,
}

impl Returned {
    /// The schema name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::Never => "never",
            Self::Default => "default",
            Self::Request => "request",
        }
    }
}

/// One attribute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the RFC 7643 attribute characteristics, one flag each"
)]
pub struct Attr {
    /// Its name.
    pub name: &'static str,
    /// Its type.
    pub ty: Type,
    /// Whether it holds a list.
    pub multi: bool,
    /// Whether a resource must carry it.
    pub required: bool,
    /// Whether string comparison keeps case.
    pub case_exact: bool,
    /// Who writes it when.
    pub mutability: Mutability,
    /// When it is returned.
    pub returned: Returned,
    /// Whether the server keeps it unique (`server`) rather than `none`.
    pub unique: bool,
    /// Whether the server indexes it, so `co`, `sw` and `ew` are served on it.
    pub indexed: bool,
    /// Its sub-attributes, for a complex attribute.
    pub sub: &'static [Attr],
    /// Its canonical values, when it has them.
    pub canonical: &'static [&'static str],
}

const fn a(name: &'static str, ty: Type) -> Attr {
    Attr {
        name,
        ty,
        multi: false,
        required: false,
        case_exact: false,
        mutability: Mutability::ReadWrite,
        returned: Returned::Default,
        unique: false,
        indexed: false,
        sub: &[],
        canonical: &[],
    }
}

const fn s(name: &'static str) -> Attr {
    a(name, Type::String)
}

const fn complex(name: &'static str, sub: &'static [Attr]) -> Attr {
    Attr {
        sub,
        ..a(name, Type::Complex)
    }
}

const fn multi(name: &'static str, sub: &'static [Attr]) -> Attr {
    Attr {
        multi: true,
        ..complex(name, sub)
    }
}

const fn read_only(attr: Attr) -> Attr {
    Attr {
        mutability: Mutability::ReadOnly,
        ..attr
    }
}

const TYPED: [Attr; 4] = [
    s("value"),
    s("display"),
    s("type"),
    a("primary", Type::Boolean),
];

const NAME: [Attr; 6] = [
    s("formatted"),
    s("familyName"),
    s("givenName"),
    s("middleName"),
    s("honorificPrefix"),
    s("honorificSuffix"),
];

const ADDRESS: [Attr; 8] = [
    s("formatted"),
    s("streetAddress"),
    s("locality"),
    s("region"),
    s("postalCode"),
    s("country"),
    s("type"),
    a("primary", Type::Boolean),
];

const USER_GROUP: [Attr; 4] = [
    read_only(s("value")),
    read_only(a("$ref", Type::Reference)),
    read_only(s("display")),
    read_only(s("type")),
];

/// The core User schema URN.
pub const USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
/// The enterprise User extension URN.
pub const ENTERPRISE: &str = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
/// The Access HR extension URN (IDP-35): start and end dates and the employment status.
pub const HR: &str = "urn:suiss:access:scim:schemas:extension:hr:1.0:User";
/// The core Group schema URN.
pub const GROUP: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
/// The core Device schema URN (RFC 9944).
pub const DEVICE: &str = "urn:ietf:params:scim:schemas:core:2.0:Device";

const USER_ATTRS: [Attr; 21] = [
    Attr {
        required: true,
        unique: true,
        indexed: true,
        ..s("userName")
    },
    complex("name", &NAME),
    s("displayName"),
    s("nickName"),
    a("profileUrl", Type::Reference),
    s("title"),
    s("userType"),
    s("preferredLanguage"),
    s("locale"),
    s("timezone"),
    a("active", Type::Boolean),
    Attr {
        mutability: Mutability::WriteOnly,
        returned: Returned::Never,
        case_exact: true,
        ..s("password")
    },
    multi("emails", &TYPED),
    multi("phoneNumbers", &TYPED),
    multi("ims", &TYPED),
    multi("photos", &TYPED),
    multi("addresses", &ADDRESS),
    read_only(multi("groups", &USER_GROUP)),
    multi("entitlements", &TYPED),
    multi("roles", &TYPED),
    multi("x509Certificates", &TYPED),
];

const MANAGER: [Attr; 3] = [
    s("value"),
    a("$ref", Type::Reference),
    read_only(s("displayName")),
];

const ENTERPRISE_ATTRS: [Attr; 6] = [
    s("employeeNumber"),
    s("costCenter"),
    s("organization"),
    s("division"),
    s("department"),
    complex("manager", &MANAGER),
];

const HR_ATTRS: [Attr; 3] = [
    a("startDate", Type::DateTime),
    a("endDate", Type::DateTime),
    Attr {
        canonical: &["pre_hire", "active", "leave", "terminated"],
        ..s("employmentStatus")
    },
];

const MEMBER: [Attr; 4] = [
    Attr {
        mutability: Mutability::Immutable,
        case_exact: true,
        ..s("value")
    },
    Attr {
        mutability: Mutability::Immutable,
        ..a("$ref", Type::Reference)
    },
    read_only(s("display")),
    Attr {
        mutability: Mutability::Immutable,
        canonical: &["User", "Group"],
        ..s("type")
    },
];

const GROUP_ATTRS: [Attr; 2] = [
    Attr {
        required: true,
        indexed: true,
        ..s("displayName")
    },
    multi("members", &MEMBER),
];

const DEVICE_GROUP: [Attr; 3] = [
    read_only(s("value")),
    read_only(a("$ref", Type::Reference)),
    read_only(s("display")),
];

const DEVICE_ATTRS: [Attr; 4] = [
    Attr {
        indexed: true,
        ..s("displayName")
    },
    Attr {
        required: true,
        ..a("active", Type::Boolean)
    },
    a("mudUrl", Type::Reference),
    read_only(multi("groups", &DEVICE_GROUP)),
];

const META: [Attr; 5] = [
    read_only(s("resourceType")),
    read_only(a("created", Type::DateTime)),
    read_only(a("lastModified", Type::DateTime)),
    read_only(a("location", Type::Reference)),
    Attr {
        case_exact: true,
        ..read_only(s("version"))
    },
];

/// The attributes every resource carries (RFC 7643 §3.1).
pub const COMMON: [Attr; 3] = [
    Attr {
        case_exact: true,
        returned: Returned::Always,
        unique: true,
        indexed: true,
        ..read_only(s("id"))
    },
    Attr {
        case_exact: true,
        indexed: true,
        ..s("externalId")
    },
    read_only(complex("meta", &META)),
];

/// A schema: its URN, names and attributes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Schema {
    /// The URN.
    pub id: &'static str,
    /// Its name.
    pub name: &'static str,
    /// What it describes.
    pub description: &'static str,
    /// Its attributes.
    pub attrs: &'static [Attr],
}

/// The core User schema.
pub const USER_SCHEMA: Schema = Schema {
    id: USER,
    name: "User",
    description: "User Account",
    attrs: &USER_ATTRS,
};

/// The enterprise User extension.
pub const ENTERPRISE_SCHEMA: Schema = Schema {
    id: ENTERPRISE,
    name: "EnterpriseUser",
    description: "Enterprise User",
    attrs: &ENTERPRISE_ATTRS,
};

/// The Access HR extension (IDP-35).
pub const HR_SCHEMA: Schema = Schema {
    id: HR,
    name: "HrUser",
    description: "Employment dates and status, each a Claim of the provisioning client",
    attrs: &HR_ATTRS,
};

/// The core Group schema.
pub const GROUP_SCHEMA: Schema = Schema {
    id: GROUP,
    name: "Group",
    description: "Group",
    attrs: &GROUP_ATTRS,
};

/// The core Device schema (RFC 9944).
pub const DEVICE_SCHEMA: Schema = Schema {
    id: DEVICE,
    name: "Device",
    description: "Device; an identity-plane device record, never an Instance",
    attrs: &DEVICE_ATTRS,
};

/// Every schema, in the order `/Schemas` lists them.
pub const ALL: [Schema; 5] = [
    USER_SCHEMA,
    ENTERPRISE_SCHEMA,
    HR_SCHEMA,
    GROUP_SCHEMA,
    DEVICE_SCHEMA,
];

/// A resource type the server serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// `User`.
    User,
    /// `Group`.
    Group,
    /// `Device` (RFC 9944).
    Device,
}

impl Kind {
    /// Every kind.
    pub const ALL: [Self; 3] = [Self::User, Self::Group, Self::Device];

    /// The resource type name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::User => "User",
            Self::Group => "Group",
            Self::Device => "Device",
        }
    }

    /// The endpoint below the SCIM base.
    #[must_use]
    pub const fn endpoint(self) -> &'static str {
        match self {
            Self::User => "Users",
            Self::Group => "Groups",
            Self::Device => "Devices",
        }
    }

    /// The stored name.
    #[must_use]
    pub const fn stored(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Group => "group",
            Self::Device => "device",
        }
    }

    /// The kind of a stored name.
    #[must_use]
    pub fn of_stored(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.stored() == s)
    }

    /// The core schema.
    #[must_use]
    pub const fn core(self) -> Schema {
        match self {
            Self::User => USER_SCHEMA,
            Self::Group => GROUP_SCHEMA,
            Self::Device => DEVICE_SCHEMA,
        }
    }

    /// The extensions a resource of the kind may carry.
    #[must_use]
    pub const fn extensions(self) -> &'static [Schema] {
        match self {
            Self::User => &[ENTERPRISE_SCHEMA, HR_SCHEMA],
            Self::Group | Self::Device => &[],
        }
    }
}

/// Where a path lands: the extension that holds it, if any, and the attribute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Located {
    /// The extension URN, `None` for the core schema and the common attributes.
    pub extension: Option<&'static str>,
    /// The attribute.
    pub attr: &'static Attr,
}

fn find(attrs: &'static [Attr], name: &str) -> Option<&'static Attr> {
    attrs.iter().find(|x| x.name.eq_ignore_ascii_case(name))
}

/// The attribute `name` of `kind` under the schema `urn` (`None`: core or common).
#[must_use]
pub fn locate(kind: Kind, urn: Option<&str>, name: &str) -> Option<Located> {
    match urn {
        None => find(&COMMON, name)
            .or_else(|| find(kind.core().attrs, name))
            .map(|attr| Located {
                extension: None,
                attr,
            }),
        Some(u) if u.eq_ignore_ascii_case(kind.core().id) => find(&COMMON, name)
            .or_else(|| find(kind.core().attrs, name))
            .map(|attr| Located {
                extension: None,
                attr,
            }),
        Some(u) => {
            let ext = kind
                .extensions()
                .iter()
                .find(|e| e.id.eq_ignore_ascii_case(u))?;
            find(ext.attrs, name).map(|attr| Located {
                extension: Some(ext.id),
                attr,
            })
        }
    }
}

/// The sub-attribute `name` of `attr`.
#[must_use]
pub fn sub_attr(attr: &Attr, name: &str) -> Option<&'static Attr> {
    find(attr.sub, name)
}

/// The extension of `kind` whose URN is `urn`, without regard to case.
#[must_use]
pub fn extension(kind: Kind, urn: &str) -> Option<&'static Schema> {
    kind.extensions()
        .iter()
        .find(|e| e.id.eq_ignore_ascii_case(urn))
}
