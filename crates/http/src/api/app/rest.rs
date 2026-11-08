//! Helpers resource handlers share (OP-65, TN-112): listing with filter, page size and cursor;
//! the `Link` to the next page; `ETag`/`If-Match`; and JSON Merge Patch bodies. Each refusal is
//! a catalogue code; `code.problem()` is the response.

use std::collections::BTreeMap;

use access_parse::scim::{self, Filter, FilterError};
use axum::http::{HeaderMap, HeaderValue, header};
use serde_json::Value;

use super::Ctx;
use crate::api::domain::conditional::{self, Precondition};
use crate::api::domain::merge_patch;
use crate::api::domain::page::{self, CURSOR, FILTER, QueryError};
use crate::api::ports::Env;
use crate::problem::{Code, codes};

/// One list request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageRequest {
    /// Page size, 1 to 100.
    pub size: u32,
    /// The position to continue after; `None` for the first page.
    pub after: Option<Vec<u8>>,
    /// The filter, over the endpoint's attributes only.
    pub filter: Option<Filter>,
    /// The query parameters as given.
    pub params: BTreeMap<String, String>,
    context: Vec<u8>,
}

/// Reads a list request: the row's query parameters, `page[size]`, `cursor` and `filter`.
///
/// # Errors
/// `unknown-query-parameter`, `invalid-page-size`, `invalid-cursor`, `invalid-filter`,
/// `unknown-filter-attribute` or `filter-too-complex`.
pub fn page_request<E: Env>(
    ctx: &Ctx<E>,
    query: Option<&str>,
    filterable: &[&'static str],
) -> Result<PageRequest, &'static Code> {
    let params = page::parameters(query, ctx.row.query).map_err(|e| match e {
        QueryError::Unknown => &codes::UNKNOWN_QUERY_PARAMETER,
        QueryError::PageSize => &codes::INVALID_PAGE_SIZE,
    })?;
    let size = page::page_size(&params).map_err(|_| &codes::INVALID_PAGE_SIZE)?;
    let filter = params
        .get(FILTER)
        .map(|f| scim::parse(f, filterable))
        .transpose()
        .map_err(|e| match e {
            FilterError::UnknownAttribute => &codes::UNKNOWN_FILTER_ATTRIBUTE,
            FilterError::TooComplex => &codes::FILTER_TOO_COMPLEX,
            _ => &codes::INVALID_FILTER,
        })?;
    let context = page::cursor_context(ctx.row.operation_id, &ctx.scope.key(), &params);
    let after = params
        .get(CURSOR)
        .map(|c| {
            ctx.api
                .env()
                .cursors()
                .open(&context, c)
                .ok_or(&codes::INVALID_CURSOR)
        })
        .transpose()?;
    Ok(PageRequest {
        size,
        after,
        filter,
        params,
        context,
    })
}

/// The `Link` header to the page after `position` of the list at `path`.
///
/// # Errors
/// `unavailable` when the cursor cannot be sealed.
pub fn next_link<E: Env>(
    ctx: &Ctx<E>,
    request: &PageRequest,
    path: &str,
    position: &[u8],
) -> Result<(header::HeaderName, HeaderValue), &'static Code> {
    let cursor = ctx
        .api
        .env()
        .cursors()
        .seal(&request.context, position)
        .map_err(|_| &codes::UNAVAILABLE)?;
    let link = page::next_link(path, &request.params, &cursor);
    HeaderValue::from_str(&link)
        .map(|v| (header::LINK, v))
        .map_err(|_| &codes::INTERNAL)
}

/// Checks `If-Match` against the resource's current tag (`None` when it does not exist).
///
/// # Errors
/// `precondition-required` (428) or `precondition-failed` (412).
pub fn require_match(headers: &HeaderMap, current: Option<&str>) -> Result<(), &'static Code> {
    let values = headers
        .get_all(header::IF_MATCH)
        .iter()
        .filter_map(|v| v.to_str().ok());
    conditional::if_match(values, current).map_err(|p| match p {
        Precondition::Required => &codes::PRECONDITION_REQUIRED,
        Precondition::Failed => &codes::PRECONDITION_FAILED,
    })
}

/// Reads a JSON Merge Patch body that touches only `members`, and applies it to `target`.
///
/// # Errors
/// `invalid-merge-patch`.
pub fn apply_patch(target: &mut Value, body: &[u8], members: &[&str]) -> Result<(), &'static Code> {
    let invalid = &codes::INVALID_MERGE_PATCH;
    access_parse::json::check(body, body.len(), access_parse::json::MAX_DEPTH)
        .map_err(|_| invalid)?;
    let patch: Value = serde_json::from_slice(body).map_err(|_| invalid)?;
    merge_patch::check(&patch, members).map_err(|_| invalid)?;
    merge_patch::apply(target, &patch).map_err(|_| invalid)
}
