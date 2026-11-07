//! JSON Merge Patch (RFC 7396; TN-112 k.2): `PATCH` bodies. An explicit `null` removes a member;
//! an absent member leaves it as it is; a non-object value replaces. A resource names the
//! members a patch may touch, and any other member is refused, never ignored.

use serde_json::{Map, Value};

/// Deepest patch applied.
pub const MAX_DEPTH: usize = 16;

/// Why a patch is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PatchError {
    /// Not an object at the top, a member the resource does not let a patch touch, or nested
    /// deeper than [`MAX_DEPTH`].
    #[error("invalid merge patch")]
    Invalid,
}

/// Applies `patch` to `target` (RFC 7396 §2).
///
/// # Errors
/// [`PatchError::Invalid`] when nested deeper than [`MAX_DEPTH`].
pub fn apply(target: &mut Value, patch: &Value) -> Result<(), PatchError> {
    apply_at(target, patch, 0)
}

fn apply_at(target: &mut Value, patch: &Value, depth: usize) -> Result<(), PatchError> {
    if depth > MAX_DEPTH {
        return Err(PatchError::Invalid);
    }
    let Value::Object(members) = patch else {
        *target = patch.clone();
        return Ok(());
    };
    if !target.is_object() {
        *target = Value::Object(Map::new());
    }
    let Value::Object(object) = target else {
        return Err(PatchError::Invalid);
    };
    for (name, value) in members {
        if value.is_null() {
            object.remove(name);
        } else {
            let slot = object.entry(name.clone()).or_insert(Value::Null);
            apply_at(slot, value, depth.saturating_add(1))?;
        }
    }
    Ok(())
}

/// Checks that `patch` is an object whose top-level members are all in `members`.
///
/// # Errors
/// [`PatchError::Invalid`].
pub fn check(patch: &Value, members: &[&str]) -> Result<(), PatchError> {
    let Value::Object(object) = patch else {
        return Err(PatchError::Invalid);
    };
    if object.keys().all(|k| members.contains(&k.as_str())) {
        Ok(())
    } else {
        Err(PatchError::Invalid)
    }
}
