//! The discovery documents (RFC 7644 §4, RFC 9865 §4; OP-155 m.3 (g), Ek B 4813): patch,
//! filter (at most 1000 results) and `ETag`s are supported; Bulk, sorting and password change are
//! not, and `/Me` is not served. Pages are index-based by default, at most 200 long, with
//! ten-minute cursors.

use serde_json::{Value, json};

use super::schema::{self, Attr, Kind, Schema};

/// Most resources one list query returns (OP-155 m.3 (g)).
pub const MAX_RESULTS: usize = 1000;
/// Longest page (OP-155 m.3 (g)).
pub const MAX_PAGE: usize = 200;
/// Page length when the request names none (OP-155 m.3 (g)).
pub const DEFAULT_PAGE: usize = 100;
/// Cursor lifetime in seconds (OP-155 m.3 (g)).
pub const CURSOR_TIMEOUT_S: u64 = 600;

const LIST: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const SPC: &str = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
const RESOURCE_TYPE: &str = "urn:ietf:params:scim:schemas:core:2.0:ResourceType";
const SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Schema";

/// `GET /ServiceProviderConfig`; `base` is the SCIM base URL.
#[must_use]
pub fn service_provider_config(base: &str) -> Value {
    json!({
        "schemas": [SPC],
        "patch": { "supported": true },
        "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
        "filter": { "supported": true, "maxResults": MAX_RESULTS },
        "changePassword": { "supported": false },
        "sort": { "supported": false },
        "etag": { "supported": true },
        "pagination": {
            "cursor": true,
            "index": true,
            "defaultPaginationMethod": "index",
            "defaultPageSize": DEFAULT_PAGE,
            "maxPageSize": MAX_PAGE,
            "cursorTimeout": CURSOR_TIMEOUT_S,
        },
        "authenticationSchemes": [{
            "type": "oauthbearertoken",
            "name": "Bearer secret",
            "description": "The opaque bearer secret shown once when the client was registered",
            "primary": true,
        }],
        "meta": {
            "resourceType": "ServiceProviderConfig",
            "location": format!("{base}/ServiceProviderConfig"),
        },
    })
}

fn resource_type(kind: Kind, base: &str) -> Value {
    let extensions: Vec<Value> = kind
        .extensions()
        .iter()
        .map(|e| json!({ "schema": e.id, "required": false }))
        .collect();
    json!({
        "schemas": [RESOURCE_TYPE],
        "id": kind.name(),
        "name": kind.name(),
        "endpoint": format!("/{}", kind.endpoint()),
        "description": kind.core().description,
        "schema": kind.core().id,
        "schemaExtensions": extensions,
        "meta": {
            "resourceType": "ResourceType",
            "location": format!("{base}/ResourceTypes/{}", kind.name()),
        },
    })
}

fn list(resources: &[Value]) -> Value {
    json!({
        "schemas": [LIST],
        "totalResults": resources.len(),
        "itemsPerPage": resources.len(),
        "startIndex": 1,
        "Resources": resources,
    })
}

/// `GET /ResourceTypes`.
#[must_use]
pub fn resource_types(base: &str) -> Value {
    list(
        &Kind::ALL
            .iter()
            .map(|k| resource_type(*k, base))
            .collect::<Vec<_>>(),
    )
}

/// `GET /ResourceTypes/{name}`.
#[must_use]
pub fn resource_type_named(base: &str, name: &str) -> Option<Value> {
    Kind::ALL
        .into_iter()
        .find(|k| k.name() == name)
        .map(|k| resource_type(k, base))
}

fn attribute(a: &Attr) -> Value {
    let mut v = json!({
        "name": a.name,
        "type": a.ty.name(),
        "multiValued": a.multi,
        "description": "",
        "required": a.required,
        "caseExact": a.case_exact,
        "mutability": a.mutability.name(),
        "returned": a.returned.name(),
        "uniqueness": if a.unique { "server" } else { "none" },
    });
    if let Some(o) = v.as_object_mut() {
        if !a.sub.is_empty() {
            o.insert(
                String::from("subAttributes"),
                Value::Array(a.sub.iter().map(attribute).collect()),
            );
        }
        if !a.canonical.is_empty() {
            o.insert(
                String::from("canonicalValues"),
                Value::from(a.canonical.to_vec()),
            );
        }
    }
    v
}

fn schema_doc(s: &Schema, base: &str) -> Value {
    json!({
        "schemas": [SCHEMA],
        "id": s.id,
        "name": s.name,
        "description": s.description,
        "attributes": s.attrs.iter().map(attribute).collect::<Vec<_>>(),
        "meta": {
            "resourceType": "Schema",
            "location": format!("{base}/Schemas/{}", s.id),
        },
    })
}

/// `GET /Schemas`.
#[must_use]
pub fn schemas(base: &str) -> Value {
    list(
        &schema::ALL
            .iter()
            .map(|s| schema_doc(s, base))
            .collect::<Vec<_>>(),
    )
}

/// `GET /Schemas/{urn}`.
#[must_use]
pub fn schema_named(base: &str, urn: &str) -> Option<Value> {
    schema::ALL
        .iter()
        .find(|s| s.id == urn)
        .map(|s| schema_doc(s, base))
}
