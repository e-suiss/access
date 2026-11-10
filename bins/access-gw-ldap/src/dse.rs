//! The root DSE and the subschema subentry (§10.6.3, RFC 4512 §5.1 and §4.2). The root DSE is
//! the one entry an anonymous client may read; `cn=Subschema` describes every attribute type and
//! object class the directory publishes.

use ldap3_proto::proto::{
    LdapPartialAttribute, LdapSearchResultEntry, OID_PASSWORD_MODIFY, OID_WHOAMI,
};

/// The `StartTLS` extended operation (RFC 4511 §4.14.1).
pub const OID_STARTTLS: &str = "1.3.6.1.4.1.1466.20037";

/// The simple paged results control (RFC 2696).
pub const OID_PAGED: &str = "1.2.840.113556.1.4.319";

/// The subschema subentry's DN.
pub const SUBSCHEMA: &str = "cn=Subschema";

fn attr(name: &str, values: &[&str]) -> LdapPartialAttribute {
    LdapPartialAttribute {
        atype: String::from(name),
        vals: values.iter().map(|v| v.as_bytes().to_vec()).collect(),
    }
}

/// The root DSE of the gateway serving realm `slug`.
#[must_use]
pub fn root(slug: &str, starttls: bool) -> LdapSearchResultEntry {
    let context = format!("o={slug}");
    let mut extensions = vec![OID_WHOAMI, OID_PASSWORD_MODIFY];
    if starttls {
        extensions.push(OID_STARTTLS);
    }
    LdapSearchResultEntry {
        dn: String::new(),
        attributes: vec![
            attr("objectClass", &["top"]),
            attr("namingContexts", &[&context]),
            attr("defaultNamingContext", &[&context]),
            attr("subschemaSubentry", &[SUBSCHEMA]),
            attr("supportedLDAPVersion", &["3"]),
            attr("supportedSASLMechanisms", &["EXTERNAL"]),
            attr("supportedExtension", &extensions),
            attr("supportedControl", &[OID_PAGED]),
            attr("supportedFeatures", &["1.3.6.1.4.1.4203.1.5.1"]),
            attr("vendorName", &["Suiss"]),
            attr(
                "vendorVersion",
                &[concat!("Access ", env!("CARGO_PKG_VERSION"))],
            ),
        ],
    }
}

const ATTRIBUTE_TYPES: &[&str] = &[
    "( 2.5.4.0 NAME 'objectClass' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
    "( 2.5.4.41 NAME 'name' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
    "( 2.5.4.3 NAME 'cn' SUP name )",
    "( 2.5.4.4 NAME 'sn' SUP name )",
    "( 2.5.4.10 NAME 'o' SUP name )",
    "( 2.5.4.11 NAME 'ou' SUP name )",
    "( 2.5.4.13 NAME 'description' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
    "( 2.5.4.31 NAME 'member' SUP distinguishedName )",
    "( 2.5.4.49 NAME 'distinguishedName' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
    "( 0.9.2342.19200300.100.1.1 NAME 'uid' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
    "( 0.9.2342.19200300.100.1.3 NAME 'mail' EQUALITY caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
    "( 2.16.840.1.113730.3.1.241 NAME 'displayName' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
    "( 1.3.6.1.1.1.1.0 NAME 'uidNumber' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
    "( 1.3.6.1.1.1.1.1 NAME 'gidNumber' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
    "( 1.3.6.1.1.1.1.3 NAME 'homeDirectory' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )",
    "( 1.3.6.1.1.1.1.12 NAME 'memberUid' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
    "( 1.2.840.113556.1.2.102 NAME 'memberOf' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 NO-USER-MODIFICATION USAGE dSAOperation )",
    "( 1.3.6.1.1.16.4 NAME 'entryUUID' EQUALITY uuidMatch ORDERING uuidOrderingMatch SYNTAX 1.3.6.1.1.16.1 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
    "( 1.3.6.1.1.20 NAME 'entryDN' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
    "( 2.5.18.9 NAME 'hasSubordinates' EQUALITY booleanMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
    "( 2.5.18.10 NAME 'subschemaSubentry' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
];

const OBJECT_CLASSES: &[&str] = &[
    "( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )",
    "( 2.5.6.4 NAME 'organization' SUP top STRUCTURAL MUST o MAY description )",
    "( 2.5.6.5 NAME 'organizationalUnit' SUP top STRUCTURAL MUST ou MAY description )",
    "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY description )",
    "( 2.5.6.7 NAME 'organizationalPerson' SUP person STRUCTURAL MAY ou )",
    "( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' SUP organizationalPerson STRUCTURAL MAY ( displayName $ mail $ uid ) )",
    "( 1.3.6.1.1.1.2.0 NAME 'posixAccount' SUP top AUXILIARY MUST ( cn $ uid $ uidNumber $ gidNumber $ homeDirectory ) )",
    "( 2.5.6.9 NAME 'groupOfNames' SUP top STRUCTURAL MUST cn MAY ( member $ description ) )",
    "( 1.3.6.1.1.1.2.2 NAME 'posixGroup' SUP top AUXILIARY MUST gidNumber MAY ( memberUid $ description ) )",
    "( 2.5.17.0 NAME 'subentry' SUP top STRUCTURAL MUST cn )",
    "( 2.5.20.1 NAME 'subschema' AUXILIARY MAY ( attributeTypes $ objectClasses $ ldapSyntaxes $ matchingRules ) )",
];

const SYNTAXES: &[&str] = &[
    "( 1.3.6.1.4.1.1466.115.121.1.7 DESC 'Boolean' )",
    "( 1.3.6.1.4.1.1466.115.121.1.12 DESC 'DN' )",
    "( 1.3.6.1.4.1.1466.115.121.1.15 DESC 'Directory String' )",
    "( 1.3.6.1.4.1.1466.115.121.1.26 DESC 'IA5 String' )",
    "( 1.3.6.1.4.1.1466.115.121.1.27 DESC 'INTEGER' )",
    "( 1.3.6.1.4.1.1466.115.121.1.38 DESC 'OID' )",
    "( 1.3.6.1.1.16.1 DESC 'UUID' )",
];

const MATCHING_RULES: &[&str] = &[
    "( 2.5.13.0 NAME 'objectIdentifierMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
    "( 2.5.13.1 NAME 'distinguishedNameMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
    "( 2.5.13.2 NAME 'caseIgnoreMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
    "( 2.5.13.13 NAME 'booleanMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )",
    "( 2.5.13.14 NAME 'integerMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )",
    "( 1.3.6.1.4.1.1466.109.114.2 NAME 'caseIgnoreIA5Match' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
    "( 1.2.840.113556.1.4.1941 NAME 'inChainMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
];

/// `cn=Subschema`.
#[must_use]
pub fn subschema() -> LdapSearchResultEntry {
    LdapSearchResultEntry {
        dn: String::from(SUBSCHEMA),
        attributes: vec![
            attr("objectClass", &["top", "subentry", "subschema"]),
            attr("cn", &["Subschema"]),
            attr("attributeTypes", ATTRIBUTE_TYPES),
            attr("objectClasses", OBJECT_CLASSES),
            attr("ldapSyntaxes", SYNTAXES),
            attr("matchingRules", MATCHING_RULES),
        ],
    }
}

/// `e` with only the attributes asked for (RFC 4511 §4.5.1.8); the root DSE and the subentry
/// hold operational attributes only, so an empty list or `*` returns their object class alone
/// and `+` returns the rest.
#[must_use]
pub fn select(
    mut e: LdapSearchResultEntry,
    asked: &[String],
    types_only: bool,
) -> LdapSearchResultEntry {
    let all_ops = asked.iter().any(|a| a == "+");
    let user = asked.is_empty() || asked.iter().any(|a| a == "*");
    e.attributes.retain(|a| {
        let named = asked.iter().any(|x| x.eq_ignore_ascii_case(&a.atype));
        let is_user = a.atype == "objectClass" || a.atype == "cn";
        named || all_ops && !is_user || user && is_user
    });
    if types_only {
        for a in &mut e.attributes {
            a.vals.clear();
        }
    }
    e
}
