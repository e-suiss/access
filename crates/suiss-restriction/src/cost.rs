//! Static weighted cost over the policy's JSON AST, and input shape limits (OP-104 m.2, m.3).

use serde_json::Value;

use crate::{CompileError, InputRejected, Limits};

fn weight(op: &str) -> u64 {
    match op {
        "contains" | "in" => 64,
        "containsAll" | "containsAny" => 4096,
        "like" => 1024,
        _ => 0,
    }
}

fn walk(v: &Value, depth: usize, max_depth: usize) -> Result<u64, CompileError> {
    let d = depth.checked_add(1).ok_or(CompileError::AstTooDeep)?;
    if d > max_depth {
        return Err(CompileError::AstTooDeep);
    }
    let add = |a: u64, b: u64| a.checked_add(b).ok_or(CompileError::CostTooHigh);
    match v {
        Value::Object(m) => {
            let mut c: u64 = 1;
            for (k, x) in m {
                c = add(add(c, weight(k))?, walk(x, d, max_depth)?)?;
            }
            Ok(c)
        }
        Value::Array(items) => {
            let mut c: u64 = 1;
            for x in items {
                c = add(c, walk(x, d, max_depth)?)?;
            }
            Ok(c)
        }
        Value::String(s) => add(
            1,
            u64::try_from(s.len())
                .map_err(|_| CompileError::CostTooHigh)?
                .checked_div(16)
                .unwrap_or(0),
        ),
        _ => Ok(1),
    }
}

/// Weighted cost of one policy: 1 per node, literals `1 + len/16`, `contains`/`in` 64,
/// `containsAll`/`containsAny` 4096, `like` 1024.
pub(crate) fn of(est: &Value, max_depth: usize) -> Result<u64, CompileError> {
    walk(est, 0, max_depth)
}

fn shape(v: &Value, depth: usize, l: &Limits) -> Result<(), InputRejected> {
    let d = depth.checked_add(1).ok_or(InputRejected)?;
    if d > l.input_nesting {
        return Err(InputRejected);
    }
    match v {
        Value::String(s) if s.len() > l.input_string => Err(InputRejected),
        Value::Array(items) if items.len() > l.input_collection.max(l.input_entities) => {
            Err(InputRejected)
        }
        Value::Object(m) if m.len() > l.input_collection => Err(InputRejected),
        Value::Array(items) => items.iter().try_for_each(|x| shape(x, d, l)),
        Value::Object(m) => m.values().try_for_each(|x| shape(x, d, l)),
        Value::Number(n) if !(n.is_i64() || n.is_u64()) => Err(InputRejected),
        _ => Ok(()),
    }
}

/// Input JSON limits: nesting, collection and string sizes, integers only.
pub(crate) fn check_input(v: &Value, l: &Limits) -> Result<(), InputRejected> {
    shape(v, 0, l)
}
