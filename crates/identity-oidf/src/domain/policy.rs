//! Metadata policy (OpenID Federation 1.0 §6.1, §10.7.1 item 4): the seven standard operators,
//! merged top-down along a chain and applied to the subject's metadata. A policy only narrows;
//! any conflict, and any operator outside the seven, refuses the chain.

use access_kernel::json::Json;

/// The operators, in the order they are applied.
pub const OPERATORS: [&str; 7] = [
    "value",
    "add",
    "default",
    "one_of",
    "subset_of",
    "superset_of",
    "essential",
];

/// Why a metadata policy is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PolicyError {
    /// An operator outside the seven.
    #[error("operator")]
    Operator,
    /// An operator value of the wrong shape.
    #[error("shape")]
    Shape,
    /// Two operators, or a superior's and a subordinate's, contradict each other.
    #[error("conflict")]
    Conflict,
    /// An essential parameter is missing after the policy.
    #[error("essential")]
    Essential,
    /// The metadata value does not satisfy `one_of` or `superset_of`.
    #[error("value")]
    Value,
}

impl PolicyError {
    /// The stable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Operator => "oidf-policy-operator",
            Self::Shape => "oidf-policy-shape",
            Self::Conflict => "oidf-policy-conflict",
            Self::Essential => "oidf-policy-essential",
            Self::Value => "oidf-policy-value",
        }
    }
}

type Members = Vec<(String, Json)>;

fn members(v: &Json) -> Result<&Members, PolicyError> {
    match v {
        Json::Object(m) => Ok(m),
        _ => Err(PolicyError::Shape),
    }
}

fn get<'a>(m: &'a Members, k: &str) -> Option<&'a Json> {
    m.iter().find(|(n, _)| n == k).map(|(_, v)| v)
}

fn set(m: &mut Members, k: &str, v: Json) {
    match m.iter_mut().find(|(n, _)| n == k) {
        Some(slot) => slot.1 = v,
        None => m.push((String::from(k), v)),
    }
}

fn remove(m: &mut Members, k: &str) {
    m.retain(|(n, _)| n != k);
}

fn array(v: &Json) -> Result<&Vec<Json>, PolicyError> {
    match v {
        Json::Array(a) => Ok(a),
        _ => Err(PolicyError::Shape),
    }
}

fn union(a: &[Json], b: &[Json]) -> Vec<Json> {
    let mut out = a.to_vec();
    for v in b {
        if !out.contains(v) {
            out.push(v.clone());
        }
    }
    out
}

fn intersection(a: &[Json], b: &[Json]) -> Vec<Json> {
    a.iter().filter(|v| b.contains(v)).cloned().collect()
}

fn subset(a: &[Json], b: &[Json]) -> bool {
    a.iter().all(|v| b.contains(v))
}

/// The values a metadata value stands for: an array's items, or the single value.
fn items(v: &Json) -> Vec<Json> {
    match v {
        Json::Array(a) => a.clone(),
        other => vec![other.clone()],
    }
}

/// Checks one parameter's operators on their own: known names, shapes, and the combinations
/// the specification allows.
fn check_param(ops: &Members) -> Result<(), PolicyError> {
    for (name, v) in ops {
        match name.as_str() {
            "add" | "subset_of" | "superset_of" => {
                array(v)?;
            }
            "one_of" => {
                if array(v)?.iter().any(|i| matches!(i, Json::Array(_))) {
                    return Err(PolicyError::Shape);
                }
            }
            "essential" => {
                if !matches!(v, Json::Bool(_)) {
                    return Err(PolicyError::Shape);
                }
            }
            "default" => {
                if matches!(v, Json::Null) {
                    return Err(PolicyError::Shape);
                }
            }
            "value" => {}
            _ => return Err(PolicyError::Operator),
        }
    }
    let value = get(ops, "value");
    let add = get(ops, "add").map(array).transpose()?;
    let default = get(ops, "default");
    let one_of = get(ops, "one_of").map(array).transpose()?;
    let subset_of = get(ops, "subset_of").map(array).transpose()?;
    let superset_of = get(ops, "superset_of").map(array).transpose()?;
    let essential = matches!(get(ops, "essential"), Some(Json::Bool(true)));
    let ok = |c: bool| {
        if c {
            Ok(())
        } else {
            Err(PolicyError::Conflict)
        }
    };
    if let Some(v) = value {
        if matches!(v, Json::Null) {
            ok(!essential && add.is_none())?;
        } else {
            let vs = items(v);
            ok(add.is_none_or(|a| subset(a, &vs)))?;
            ok(one_of.is_none_or(|o| o.contains(v)))?;
            ok(subset_of.is_none_or(|s| subset(&vs, s)))?;
            ok(superset_of.is_none_or(|s| subset(s, &vs)))?;
        }
    }
    ok(!(add.is_some() && one_of.is_some()))?;
    ok(!(one_of.is_some() && (subset_of.is_some() || superset_of.is_some())))?;
    if let (Some(a), Some(s)) = (add, subset_of) {
        ok(subset(a, s))?;
    }
    if let (Some(sup), Some(sub)) = (superset_of, subset_of) {
        ok(subset(sup, sub))?;
    }
    if let Some(d) = default {
        let ds = items(d);
        ok(one_of.is_none_or(|o| o.contains(d)))?;
        ok(subset_of.is_none_or(|s| subset(&ds, s)))?;
        ok(superset_of.is_none_or(|s| subset(s, &ds)))?;
    }
    Ok(())
}

fn merge_param(sup: &Members, sub: &Members) -> Result<Members, PolicyError> {
    check_param(sup)?;
    check_param(sub)?;
    let mut out = Members::new();
    for op in OPERATORS {
        let merged = match (get(sup, op), get(sub, op)) {
            (None, None) => continue,
            (Some(v), None) | (None, Some(v)) => v.clone(),
            (Some(a), Some(b)) => match op {
                "value" | "default" => {
                    if a == b {
                        a.clone()
                    } else {
                        return Err(PolicyError::Conflict);
                    }
                }
                "add" | "superset_of" => Json::Array(union(array(a)?, array(b)?)),
                "one_of" => {
                    let i = intersection(array(a)?, array(b)?);
                    if i.is_empty() {
                        return Err(PolicyError::Conflict);
                    }
                    Json::Array(i)
                }
                "subset_of" => Json::Array(intersection(array(a)?, array(b)?)),
                _ => Json::Bool(matches!(a, Json::Bool(true)) || matches!(b, Json::Bool(true))),
            },
        };
        out.push((String::from(op), merged));
    }
    check_param(&out)?;
    Ok(out)
}

/// Merges a superior's policy with its subordinate's, both keyed by entity type then by
/// parameter (OpenID Federation 1.0 §6.1.4.1).
///
/// # Errors
/// [`PolicyError`].
pub fn merge(superior: &Json, subordinate: &Json) -> Result<Json, PolicyError> {
    let (sup, sub) = (members(superior)?, members(subordinate)?);
    let mut out = Members::new();
    let mut types: Vec<&String> = sup.iter().map(|(k, _)| k).collect();
    for (k, _) in sub {
        if !types.contains(&k) {
            types.push(k);
        }
    }
    for t in types {
        let empty = Json::Object(Vec::new());
        let a = members(get(sup, t).unwrap_or(&empty))?;
        let b = members(get(sub, t).unwrap_or(&empty))?;
        let mut params: Vec<&String> = a.iter().map(|(k, _)| k).collect();
        for (k, _) in b {
            if !params.contains(&k) {
                params.push(k);
            }
        }
        let mut merged = Members::new();
        for p in params {
            let x = members(get(a, p).unwrap_or(&empty))?;
            let y = members(get(b, p).unwrap_or(&empty))?;
            merged.push((p.clone(), Json::Object(merge_param(x, y)?)));
        }
        out.push((t.clone(), Json::Object(merged)));
    }
    Ok(Json::Object(out))
}

fn apply_param(md: &mut Members, name: &str, ops: &Members) -> Result<(), PolicyError> {
    check_param(ops)?;
    for op in OPERATORS {
        let Some(v) = get(ops, op) else {
            continue;
        };
        match op {
            "value" => {
                if matches!(v, Json::Null) {
                    remove(md, name);
                } else {
                    set(md, name, v.clone());
                }
            }
            "add" => {
                let current = match get(md, name) {
                    None => Vec::new(),
                    Some(c) => array(c).map_err(|_| PolicyError::Value)?.clone(),
                };
                set(md, name, Json::Array(union(&current, array(v)?)));
            }
            "default" => {
                if get(md, name).is_none() {
                    set(md, name, v.clone());
                }
            }
            "one_of" => {
                if let Some(c) = get(md, name)
                    && !array(v)?.contains(c)
                {
                    return Err(PolicyError::Value);
                }
            }
            "subset_of" => {
                if let Some(c) = get(md, name) {
                    let kept = intersection(&items(c), array(v)?);
                    if kept.is_empty() {
                        remove(md, name);
                    } else {
                        set(md, name, Json::Array(kept));
                    }
                }
            }
            "superset_of" => {
                if let Some(c) = get(md, name)
                    && !subset(array(v)?, &items(c))
                {
                    return Err(PolicyError::Value);
                }
            }
            _ => {
                if matches!(v, Json::Bool(true)) && get(md, name).is_none() {
                    return Err(PolicyError::Essential);
                }
            }
        }
    }
    Ok(())
}

/// Applies a merged policy to metadata, both keyed by entity type; a policy for a type the
/// metadata does not have is ignored.
///
/// # Errors
/// [`PolicyError`].
pub fn apply(policy: &Json, metadata: &Json) -> Result<Json, PolicyError> {
    let pol = members(policy)?;
    let mut out = members(metadata)?.clone();
    for (t, md) in &mut out {
        let Some(tp) = get(pol, t) else {
            continue;
        };
        let Json::Object(md) = md else {
            return Err(PolicyError::Shape);
        };
        for (p, ops) in members(tp)? {
            apply_param(md, p, members(ops)?)?;
        }
    }
    Ok(Json::Object(out))
}

#[cfg(test)]
mod tests;
