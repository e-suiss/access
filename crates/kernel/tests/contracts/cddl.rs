//! A CDDL (RFC 8610) validator for the subset the contracts are written in: type and group
//! choices, maps with member keys and computed keys, arrays with labels, occurrences, group
//! references, value ranges, the `.size`, `.regexp`, `.le` and `.ge` controls and the prelude
//! types. Rules are parsed when first reached, so the rest of a file may use more of CDDL.

use std::collections::BTreeMap;

use suiss_crypto::dcbor::Value;

use super::edn;
use super::regex::Regex;

#[derive(Clone, Debug)]
enum Tok {
    Name(String),
    Text(String),
    Int(i128),
    Punct(&'static str),
}

#[derive(Clone, Debug)]
enum Type {
    Choice(Vec<Type>),
    Prelude(&'static str),
    Ref(String),
    Text(String),
    Int(i128),
    Bool(bool),
    Range(i128, i128),
    Map(Group),
    Array(Group),
    Control(Box<Type>, &'static str, Box<Type>),
}

type Group = Vec<Vec<Entry>>;

#[derive(Clone, Debug)]
struct Entry {
    min: usize,
    max: usize,
    kind: EntryKind,
}

#[derive(Clone, Debug)]
enum EntryKind {
    Member(String, Type),
    Computed(Type, Type),
    Item(Type),
    Group(Group),
    GroupRef(String),
}

pub struct Cddl {
    rules: BTreeMap<String, String>,
}

impl Cddl {
    pub fn new(sources: &[&str]) -> Self {
        let mut rules = BTreeMap::new();
        let mut current: Option<String> = None;
        for line in sources.iter().flat_map(|s| s.lines()) {
            let line = line.split(';').next().unwrap_or_default();
            let starts_rule = line.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
                && line.contains('=')
                && !line.trim_end().ends_with(',');
            if starts_rule {
                let (name, rest) = line.split_once('=').unwrap();
                let name = name.trim().to_owned();
                rules.insert(name.clone(), rest.to_owned());
                current = Some(name);
            } else if let Some(name) = &current {
                let body = rules.get_mut(name).unwrap();
                body.push('\n');
                body.push_str(line);
            }
        }
        Self { rules }
    }

    pub fn validate(&self, rule: &str, v: &Value) -> Result<(), String> {
        if self.check(&Type::Ref(rule.to_owned()), v) {
            Ok(())
        } else {
            Err(format!("{} does not match {rule}", describe(v)))
        }
    }

    fn rule(&self, name: &str) -> Rule {
        let body = self
            .rules
            .get(name)
            .unwrap_or_else(|| panic!("no rule {name}"));
        let toks = lex(body);
        let mut p = Parser { toks, at: 0 };
        let is_group = matches!(p.toks.first(), Some(Tok::Punct("(")))
            && p.toks.iter().any(|t| matches!(t, Tok::Punct(":" | "=>")));
        let rule = if is_group {
            p.at = 1;
            let g = p.group(")");
            p.expect(")");
            Rule::Group(g)
        } else {
            Rule::Type(p.ty())
        };
        assert_eq!(p.at, p.toks.len(), "rule {name} not fully parsed");
        rule
    }

    fn check(&self, t: &Type, v: &Value) -> bool {
        match t {
            Type::Choice(alts) => alts.iter().any(|a| self.check(a, v)),
            Type::Prelude(p) => prelude(p, v),
            Type::Ref(name) => match prelude_name(name) {
                Some(p) => prelude(p, v),
                None => match self.rule(name) {
                    Rule::Type(t) => self.check(&t, v),
                    Rule::Group(_) => false,
                },
            },
            Type::Text(s) => matches!(v, Value::Text(x) if x == s),
            Type::Int(n) => int_of(v) == Some(*n),
            Type::Bool(b) => matches!(v, Value::Bool(x) if x == b),
            Type::Range(lo, hi) => int_of(v).is_some_and(|n| *lo <= n && n <= *hi),
            Type::Map(g) => match v {
                Value::Map(entries) => self
                    .alternatives(g)
                    .iter()
                    .any(|alt| self.map_matches(alt, entries)),
                _ => false,
            },
            Type::Array(g) => match v {
                Value::Array(items) => self
                    .alternatives(g)
                    .iter()
                    .any(|alt| self.array_matches(alt, items)),
                _ => false,
            },
            Type::Control(base, op, arg) => self.check(base, v) && self.control(v, op, arg),
        }
    }

    fn control(&self, v: &Value, op: &str, arg: &Type) -> bool {
        match (op, v) {
            (".size", Value::Bytes(b)) => size_ok(b.len(), arg),
            (".size", Value::Text(t)) => size_ok(t.len(), arg),
            (".size", Value::Unsigned(n)) => match arg {
                Type::Int(bytes) => *bytes >= 8 || u128::from(*n) < 1u128 << (8 * bytes),
                _ => false,
            },
            (".size", Value::Negative(_)) => matches!(arg, Type::Int(8)),
            (".regexp", Value::Text(t)) => match arg {
                Type::Text(re) => Regex::new(re, true).is_match(t),
                _ => false,
            },
            (".le", _) => matches!((int_of(v), arg), (Some(n), Type::Int(m)) if n <= *m),
            (".ge", _) => matches!((int_of(v), arg), (Some(n), Type::Int(m)) if n >= *m),
            _ => false,
        }
    }

    fn alternatives(&self, g: &Group) -> Vec<Vec<Entry>> {
        let mut out = Vec::new();
        for alt in g {
            let mut acc: Vec<Vec<Entry>> = vec![Vec::new()];
            for e in alt {
                let expanded: Vec<Vec<Entry>> = match &e.kind {
                    EntryKind::GroupRef(name) => match self.rule(name) {
                        Rule::Group(inner) => self.alternatives(&inner),
                        Rule::Type(t) => vec![vec![Entry {
                            kind: EntryKind::Item(t),
                            ..e.clone()
                        }]],
                    },
                    EntryKind::Group(inner) if e.min == 1 && e.max == 1 => self.alternatives(inner),
                    _ => vec![vec![e.clone()]],
                };
                acc = acc
                    .iter()
                    .flat_map(|a| {
                        expanded.iter().map(move |x| {
                            let mut y = a.clone();
                            y.extend(x.iter().cloned());
                            y
                        })
                    })
                    .collect();
            }
            out.extend(acc);
        }
        out
    }

    fn map_matches(&self, entries: &[Entry], map: &[(Value, Value)]) -> bool {
        let mut used = vec![false; map.len()];
        for e in entries {
            if let EntryKind::Member(key, t) = &e.kind {
                match map
                    .iter()
                    .position(|(k, _)| matches!(k, Value::Text(x) if x == key))
                {
                    Some(i) => {
                        if !self.check(t, &map[i].1) {
                            return false;
                        }
                        used[i] = true;
                    }
                    None if e.min > 0 => return false,
                    None => {}
                }
            }
        }
        for e in entries {
            let computed: Vec<(Type, Type)> = match &e.kind {
                EntryKind::Computed(k, t) => vec![(k.clone(), t.clone())],
                EntryKind::Group(inner) => self
                    .alternatives(inner)
                    .into_iter()
                    .flatten()
                    .filter_map(|x| match x.kind {
                        EntryKind::Computed(k, t) => Some((k, t)),
                        EntryKind::Member(k, t) => Some((Type::Text(k), t)),
                        _ => None,
                    })
                    .collect(),
                _ => continue,
            };
            let mut count = 0;
            for (i, (k, v)) in map.iter().enumerate() {
                if !used[i]
                    && computed
                        .iter()
                        .any(|(kt, vt)| self.check(kt, k) && self.check(vt, v))
                {
                    used[i] = true;
                    count += 1;
                }
            }
            if count < e.min || count > e.max {
                return false;
            }
        }
        used.iter().all(|u| *u)
    }

    fn array_matches(&self, entries: &[Entry], items: &[Value]) -> bool {
        let Some((first, rest)) = entries.split_first() else {
            return items.is_empty();
        };
        let t = match &first.kind {
            EntryKind::Item(t) | EntryKind::Member(_, t) => t.clone(),
            other => panic!("array entry {other:?} is not supported"),
        };
        let mut n = 0;
        loop {
            if n >= first.min && self.array_matches(rest, &items[n..]) {
                return true;
            }
            if n == first.max || n == items.len() || !self.check(&t, &items[n]) {
                return false;
            }
            n += 1;
        }
    }
}

enum Rule {
    Type(Type),
    Group(Group),
}

fn size_ok(len: usize, arg: &Type) -> bool {
    let len = i128::try_from(len).unwrap();
    match arg {
        Type::Int(n) => len == *n,
        Type::Range(lo, hi) => *lo <= len && len <= *hi,
        _ => false,
    }
}

fn int_of(v: &Value) -> Option<i128> {
    match v {
        Value::Unsigned(n) => Some(i128::from(*n)),
        Value::Negative(n) => Some(-1 - i128::from(*n)),
        _ => None,
    }
}

fn prelude_name(name: &str) -> Option<&'static str> {
    [
        "uint", "nint", "int", "bstr", "bytes", "tstr", "text", "bool", "any",
    ]
    .into_iter()
    .find(|p| *p == name)
}

fn prelude(p: &str, v: &Value) -> bool {
    match p {
        "uint" => matches!(v, Value::Unsigned(_)),
        "nint" => matches!(v, Value::Negative(_)),
        "int" => matches!(v, Value::Unsigned(_) | Value::Negative(_)),
        "bstr" | "bytes" => matches!(v, Value::Bytes(_)),
        "tstr" | "text" => matches!(v, Value::Text(_)),
        "bool" => matches!(v, Value::Bool(_)),
        _ => true,
    }
}

fn describe(v: &Value) -> String {
    format!("{v:?}")
}

const PUNCT: [&str; 17] = [
    "=>", "//", "...", "..", ".size", ".regexp", ".le", ".ge", "{", "}", "[", "]", "(", ")", ",",
    ":", "/",
];

fn lex(src: &str) -> Vec<Tok> {
    let c: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut at = 0;
    while at < c.len() {
        let ch = c[at];
        if ch.is_whitespace() {
            at += 1;
        } else if ch == '"' {
            out.push(Tok::Text(edn::text(&c, &mut at)));
        } else if ch == '?' || ch == '+' || ch == '*' {
            out.push(Tok::Punct(match ch {
                '?' => "?",
                '+' => "+",
                _ => "*",
            }));
            at += 1;
        } else if ch == '-' || ch.is_ascii_digit() {
            let start = at;
            at += 1;
            while at < c.len() && c[at].is_ascii_digit() {
                at += 1;
            }
            let n: String = c[start..at].iter().collect();
            out.push(Tok::Int(n.parse().unwrap()));
        } else if ch.is_ascii_alphabetic() || ch == '_' || ch == '$' {
            let start = at;
            while at < c.len() && (c[at].is_ascii_alphanumeric() || "-_$".contains(c[at])) {
                at += 1;
            }
            out.push(Tok::Name(c[start..at].iter().collect()));
        } else {
            let rest: String = c[at..].iter().take(8).collect();
            let p = PUNCT
                .iter()
                .find(|p| rest.starts_with(**p))
                .unwrap_or_else(|| panic!("unexpected {rest:?}"));
            out.push(Tok::Punct(p));
            at += p.chars().count();
        }
    }
    out
}

struct Parser {
    toks: Vec<Tok>,
    at: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.at)
    }

    fn is(&self, p: &str) -> bool {
        matches!(self.peek(), Some(Tok::Punct(x)) if *x == p)
    }

    fn expect(&mut self, p: &str) {
        assert!(self.is(p), "expected {p} at {:?}", self.peek());
        self.at += 1;
    }

    fn ty(&mut self) -> Type {
        let mut alts = vec![self.ty1()];
        while self.is("/") {
            self.at += 1;
            alts.push(self.ty1());
        }
        if alts.len() == 1 {
            alts.pop().unwrap()
        } else {
            Type::Choice(alts)
        }
    }

    fn ty1(&mut self) -> Type {
        let base = self.ty2();
        if self.is("..") {
            self.at += 1;
            let hi = self.ty2();
            return match (base, hi) {
                (Type::Int(lo), Type::Int(hi)) => Type::Range(lo, hi),
                other => panic!("range {other:?}"),
            };
        }
        for op in [".size", ".regexp", ".le", ".ge"] {
            if self.is(op) {
                self.at += 1;
                let arg = self.ty2();
                return Type::Control(Box::new(base), op, Box::new(arg));
            }
        }
        base
    }

    fn ty2(&mut self) -> Type {
        let tok = self.peek().cloned().expect("a type");
        self.at += 1;
        match tok {
            Tok::Int(n) => Type::Int(n),
            Tok::Text(s) => Type::Text(s),
            Tok::Name(n) if n == "true" => Type::Bool(true),
            Tok::Name(n) if n == "false" => Type::Bool(false),
            Tok::Name(n) => prelude_name(&n).map_or(Type::Ref(n), Type::Prelude),
            Tok::Punct("{") => {
                let g = self.group("}");
                self.expect("}");
                Type::Map(g)
            }
            Tok::Punct("[") => {
                let g = self.group("]");
                self.expect("]");
                Type::Array(g)
            }
            Tok::Punct("(") => {
                let t = self.ty();
                self.expect(")");
                t
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    fn group(&mut self, close: &str) -> Group {
        let mut alts = vec![Vec::new()];
        loop {
            if self.is(close) {
                return alts;
            }
            if self.is("//") {
                self.at += 1;
                alts.push(Vec::new());
                continue;
            }
            if self.is(",") {
                self.at += 1;
                continue;
            }
            let e = self.entry(close);
            alts.last_mut().unwrap().push(e);
        }
    }

    fn occurrence(&mut self) -> (usize, usize) {
        match self.peek() {
            Some(Tok::Punct("?")) => {
                self.at += 1;
                (0, 1)
            }
            Some(Tok::Punct("*")) => {
                self.at += 1;
                (0, usize::MAX)
            }
            Some(Tok::Punct("+")) => {
                self.at += 1;
                (1, usize::MAX)
            }
            Some(Tok::Int(n)) if matches!(self.toks.get(self.at + 1), Some(Tok::Punct("*"))) => {
                let n = usize::try_from(*n).unwrap();
                self.at += 2;
                (n, usize::MAX)
            }
            _ => (1, 1),
        }
    }

    fn entry(&mut self, close: &str) -> Entry {
        let (min, max) = self.occurrence();
        if let (Some(Tok::Name(n) | Tok::Text(n)), Some(Tok::Punct(":"))) =
            (self.peek().cloned(), self.toks.get(self.at + 1))
        {
            self.at += 2;
            let t = self.ty();
            return Entry {
                min,
                max,
                kind: EntryKind::Member(n, t),
            };
        }
        if self.is("(") && self.paren_is_group() {
            self.at += 1;
            let g = self.group(")");
            self.expect(")");
            return Entry {
                min,
                max,
                kind: EntryKind::Group(g),
            };
        }
        let t = self.ty();
        if self.is("=>") {
            self.at += 1;
            let v = self.ty();
            return Entry {
                min,
                max,
                kind: EntryKind::Computed(t, v),
            };
        }
        let kind = match (&t, close) {
            (Type::Ref(name), "}") => EntryKind::GroupRef(name.clone()),
            _ => EntryKind::Item(t),
        };
        Entry { min, max, kind }
    }

    fn paren_is_group(&self) -> bool {
        let mut depth = 0;
        for t in &self.toks[self.at..] {
            match t {
                Tok::Punct("(" | "{" | "[") => depth += 1,
                Tok::Punct(")" | "}" | "]") => {
                    depth -= 1;
                    if depth == 0 {
                        return false;
                    }
                }
                Tok::Punct("=>" | ":" | "//") if depth == 1 => return true,
                _ => {}
            }
        }
        false
    }
}
