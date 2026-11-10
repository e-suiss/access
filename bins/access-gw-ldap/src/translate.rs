//! LDAP filters and attribute lists into the edge channel's shapes (§10.6.3). The codec's filter
//! is walked with an explicit stack; its depth is already bounded by the BER check, and the
//! channel's [`Filter::new`] bounds it again at 16.

use access_internal_api::edge::ldap::{Filter, FilterError, Node, attribute_name};
use ldap3_proto::proto::{LdapFilter, LdapMatchingRuleAssertion};

/// The in-chain matching rule (`LDAP_MATCHING_RULE_IN_CHAIN`).
pub const IN_CHAIN: &str = "1.2.840.113556.1.4.1941";

fn name(n: &str) -> Option<String> {
    attribute_name(n).then(|| String::from(n))
}

fn leaf(attr: &str, make: impl FnOnce(String) -> Node) -> Node {
    name(attr).map_or(Node::Undefined, make)
}

fn extensible(m: &LdapMatchingRuleAssertion) -> Node {
    match (&m.matching_rule, &m.type_) {
        (Some(rule), Some(t)) if rule == IN_CHAIN && !m.dn_attributes => {
            leaf(t, |a| Node::Chain(a, m.match_value.clone()))
        }
        _ => Node::Undefined,
    }
}

/// The edge filter of `f`, in prefix order.
///
/// # Errors
/// [`FilterError`] when it is deeper than 16, larger than 255 nodes or empty.
pub fn filter(f: &LdapFilter) -> Result<Filter, FilterError> {
    let mut nodes = Vec::new();
    let mut todo: Vec<&LdapFilter> = vec![f];
    while let Some(next) = todo.pop() {
        if nodes.len() > access_internal_api::edge::ldap::MAX_FILTER_NODES {
            return Err(FilterError::Size);
        }
        let node = match next {
            LdapFilter::And(items) | LdapFilter::Or(items) => {
                let n = u16::try_from(items.len()).map_err(|_| FilterError::Size)?;
                if n == 0 {
                    return Err(FilterError::Shape);
                }
                todo.extend(items.iter().rev());
                if matches!(next, LdapFilter::And(_)) {
                    Node::And(n)
                } else {
                    Node::Or(n)
                }
            }
            LdapFilter::Not(inner) => {
                todo.push(inner);
                Node::Not
            }
            LdapFilter::Equality(a, v) => leaf(a, |a| Node::Eq(a, v.clone())),
            LdapFilter::GreaterOrEqual(a, v) => leaf(a, |a| Node::Ge(a, v.clone())),
            LdapFilter::LessOrEqual(a, v) => leaf(a, |a| Node::Le(a, v.clone())),
            LdapFilter::Approx(a, v) => leaf(a, |a| Node::Approx(a, v.clone())),
            LdapFilter::Present(a) => leaf(a, Node::Present),
            LdapFilter::Substring(a, s) => leaf(a, |a| {
                Node::Substr(
                    a,
                    s.initial.clone().unwrap_or_default(),
                    s.any.clone(),
                    s.final_.clone().unwrap_or_default(),
                )
            }),
            LdapFilter::Extensible(m) => extensible(m),
        };
        nodes.push(node);
    }
    Filter::new(nodes)
}

/// The attributes a search asks for, as the channel takes them: descriptors without options;
/// anything else is dropped.
#[must_use]
pub fn attributes(asked: &[String]) -> Vec<String> {
    asked
        .iter()
        .filter(|a| matches!(a.as_str(), "*" | "+" | "1.1") || attribute_name(a))
        .take(access_internal_api::edge::ldap::MAX_ATTRIBUTES)
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    fn eq(a: &str, v: &str) -> LdapFilter {
        LdapFilter::Equality(String::from(a), String::from(v))
    }

    // §10.6.3, OP-155 m.3 (n)
    #[test]
    fn filters_translate_in_prefix_order() {
        let f = LdapFilter::And(vec![
            eq("objectClass", "person"),
            LdapFilter::Not(Box::new(eq("uid", "bob"))),
            LdapFilter::Extensible(LdapMatchingRuleAssertion {
                matching_rule: Some(String::from(IN_CHAIN)),
                type_: Some(String::from("memberOf")),
                match_value: String::from("cn=staff,ou=groups,o=corp"),
                dn_attributes: false,
            }),
        ]);
        let got = filter(&f).unwrap();
        assert_eq!(
            got.nodes(),
            &[
                Node::And(3),
                Node::Eq(String::from("objectClass"), String::from("person")),
                Node::Not,
                Node::Eq(String::from("uid"), String::from("bob")),
                Node::Chain(
                    String::from("memberOf"),
                    String::from("cn=staff,ou=groups,o=corp")
                ),
            ]
        );
        let mut deep = eq("uid", "a");
        for _ in 0..17 {
            deep = LdapFilter::Not(Box::new(deep));
        }
        assert_eq!(filter(&deep), Err(FilterError::Depth));
        let odd = eq("cn;lang-en", "x");
        assert_eq!(filter(&odd).unwrap().nodes(), &[Node::Undefined]);
    }
}
