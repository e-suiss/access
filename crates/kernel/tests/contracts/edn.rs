//! CBOR extended diagnostic notation (RFC 8949 §8, RFC 8610 Appendix G) for the values the
//! examples use: unsigned and negative integers, text, `h'…'` byte strings, `true`, `false`,
//! arrays and maps.

use suiss_crypto::dcbor::Value;

pub fn parse(text: &str) -> Value {
    let chars: Vec<char> = text.chars().collect();
    let mut at = 0;
    let v = value(&chars, &mut at);
    skip(&chars, &mut at);
    assert_eq!(at, chars.len(), "trailing input in {text}");
    v
}

fn skip(c: &[char], at: &mut usize) {
    while *at < c.len() && (c[*at].is_whitespace() || c[*at] == ',') {
        *at += 1;
    }
}

fn value(c: &[char], at: &mut usize) -> Value {
    skip(c, at);
    match c[*at] {
        '{' => {
            *at += 1;
            let mut entries = Vec::new();
            loop {
                skip(c, at);
                if c[*at] == '}' {
                    *at += 1;
                    break;
                }
                let k = value(c, at);
                skip(c, at);
                assert_eq!(c[*at], ':');
                *at += 1;
                entries.push((k, value(c, at)));
            }
            Value::Map(entries)
        }
        '[' => {
            *at += 1;
            let mut items = Vec::new();
            loop {
                skip(c, at);
                if c[*at] == ']' {
                    *at += 1;
                    break;
                }
                items.push(value(c, at));
            }
            Value::Array(items)
        }
        '"' => Value::Text(text(c, at)),
        'h' => {
            *at += 2;
            let end = c[*at..].iter().position(|x| *x == '\'').unwrap() + *at;
            let hex: String = c[*at..end].iter().filter(|x| !x.is_whitespace()).collect();
            *at = end + 1;
            Value::Bytes(
                (0..hex.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                    .collect(),
            )
        }
        't' => {
            *at += 4;
            Value::Bool(true)
        }
        'f' => {
            *at += 5;
            Value::Bool(false)
        }
        _ => {
            let start = *at;
            while *at < c.len() && (c[*at] == '-' || c[*at].is_ascii_digit()) {
                *at += 1;
            }
            let n: String = c[start..*at].iter().collect();
            Value::int(n.parse().unwrap())
        }
    }
}

pub fn text(c: &[char], at: &mut usize) -> String {
    *at += 1;
    let mut out = String::new();
    while c[*at] != '"' {
        if c[*at] == '\\' {
            *at += 1;
        }
        out.push(c[*at]);
        *at += 1;
    }
    *at += 1;
    out
}
