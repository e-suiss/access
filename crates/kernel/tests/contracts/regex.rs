//! The regular expressions the contracts use: literals, `\` escapes, classes with ranges and
//! negation, groups and the quantifiers `?`, `*`, `+`, `{m}`, `{m,n}`; `^` and `$` anchor.

use std::collections::BTreeSet;

#[derive(Debug)]
enum Atom {
    Char(char),
    Class(Vec<(char, char)>, bool),
    Group(Vec<Piece>),
}

#[derive(Debug)]
struct Piece {
    atom: Atom,
    min: usize,
    max: usize,
}

pub struct Regex {
    pieces: Vec<Piece>,
    start: bool,
    end: bool,
}

impl Regex {
    pub fn new(pattern: &str, anchored: bool) -> Self {
        let mut chars: Vec<char> = pattern.chars().collect();
        let mut start = anchored;
        let mut end = anchored;
        if chars.first() == Some(&'^') {
            chars.remove(0);
            start = true;
        }
        if chars.last() == Some(&'$') && chars.len() >= 2 && chars[chars.len() - 2] != '\\' {
            chars.pop();
            end = true;
        }
        let mut at = 0;
        let pieces = seq(&chars, &mut at);
        assert_eq!(at, chars.len(), "unsupported pattern {pattern}");
        Self { pieces, start, end }
    }

    pub fn is_match(&self, text: &str) -> bool {
        let input: Vec<char> = text.chars().collect();
        let starts: Vec<usize> = if self.start {
            vec![0]
        } else {
            (0..=input.len()).collect()
        };
        starts.into_iter().any(|s| {
            let ends = run(&self.pieces, &input, BTreeSet::from([s]));
            if self.end {
                ends.contains(&input.len())
            } else {
                !ends.is_empty()
            }
        })
    }
}

fn seq(p: &[char], at: &mut usize) -> Vec<Piece> {
    let mut out = Vec::new();
    while *at < p.len() && p[*at] != ')' {
        let atom = match p[*at] {
            '(' => {
                *at += 1;
                let inner = seq(p, at);
                assert_eq!(p.get(*at), Some(&')'));
                *at += 1;
                Atom::Group(inner)
            }
            '[' => class(p, at),
            '\\' => {
                *at += 2;
                Atom::Char(p[*at - 1])
            }
            c => {
                *at += 1;
                Atom::Char(c)
            }
        };
        let (min, max) = quantifier(p, at);
        out.push(Piece { atom, min, max });
    }
    out
}

fn class(p: &[char], at: &mut usize) -> Atom {
    *at += 1;
    let negated = p[*at] == '^';
    if negated {
        *at += 1;
    }
    let mut ranges = Vec::new();
    while p[*at] != ']' {
        let mut lo = p[*at];
        if lo == '\\' {
            *at += 1;
            lo = p[*at];
        }
        *at += 1;
        if p[*at] == '-' && p[*at + 1] != ']' {
            ranges.push((lo, p[*at + 1]));
            *at += 2;
        } else {
            ranges.push((lo, lo));
        }
    }
    *at += 1;
    Atom::Class(ranges, negated)
}

fn quantifier(p: &[char], at: &mut usize) -> (usize, usize) {
    match p.get(*at) {
        Some('?') => {
            *at += 1;
            (0, 1)
        }
        Some('*') => {
            *at += 1;
            (0, usize::MAX)
        }
        Some('+') => {
            *at += 1;
            (1, usize::MAX)
        }
        Some('{') => {
            let close = p[*at..].iter().position(|c| *c == '}').unwrap() + *at;
            let body: String = p[*at + 1..close].iter().collect();
            *at = close + 1;
            match body.split_once(',') {
                Some((a, b)) => (a.parse().unwrap(), b.parse().unwrap()),
                None => {
                    let n = body.parse().unwrap();
                    (n, n)
                }
            }
        }
        _ => (1, 1),
    }
}

fn run(pieces: &[Piece], input: &[char], mut at: BTreeSet<usize>) -> BTreeSet<usize> {
    for piece in pieces {
        let mut reached = BTreeSet::new();
        let mut frontier = at;
        for count in 0.. {
            if count >= piece.min {
                reached.extend(frontier.iter().copied());
            }
            if count == piece.max || frontier.is_empty() {
                break;
            }
            let next: BTreeSet<usize> = frontier
                .iter()
                .flat_map(|&i| one(&piece.atom, input, i))
                .filter(|j| !reached.contains(j) || count < piece.min)
                .collect();
            if next == frontier {
                break;
            }
            frontier = next;
        }
        at = reached;
    }
    at
}

fn one(atom: &Atom, input: &[char], i: usize) -> BTreeSet<usize> {
    match atom {
        Atom::Char(c) => input
            .get(i)
            .filter(|x| *x == c)
            .map(|_| i + 1)
            .into_iter()
            .collect(),
        Atom::Class(ranges, negated) => input
            .get(i)
            .filter(|x| ranges.iter().any(|(lo, hi)| lo <= *x && *x <= hi) != *negated)
            .map(|_| i + 1)
            .into_iter()
            .collect(),
        Atom::Group(inner) => run(inner, input, BTreeSet::from([i])),
    }
}

#[test]
fn the_contract_patterns_match() {
    let ident = Regex::new("[a-z][a-z0-9_]{0,62}", true);
    assert!(ident.is_match("approve"));
    assert!(!ident.is_match("Approve"));
    assert!(!ident.is_match("co-sign"));
    assert!(!ident.is_match(&"a".repeat(64)));
    let ns = Regex::new("[a-z][a-z0-9_-]{0,62}(\\.[a-z][a-z0-9_-]{0,62}){0,7}", true);
    assert!(ns.is_match("work.tasks"));
    assert!(!ns.is_match("work..tasks"));
    let digest = Regex::new("^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$", false);
    assert!(digest.is_match(&"A".repeat(43)));
    assert!(!digest.is_match(&"B".repeat(43)));
    let url = Regex::new("https://[!-~]{1,2040}", true);
    assert!(url.is_match("https://acme.example/access/v1/keys/{kid}"));
    assert!(!url.is_match("https://acme.example/a b"));
    assert!(!url.is_match("http://acme.example"));
    let loose = Regex::new("b+c", false);
    assert!(loose.is_match("abbcd"));
}
