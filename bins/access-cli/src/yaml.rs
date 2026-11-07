//! The YAML the `GitOps` commands read and write (TN-123 item 1). Writing is deterministic: map
//! keys sorted, block style, strings always double-quoted (so `no`, `on` or `1.0` never change
//! type), integers and booleans plain, `null` spelled out. Reading accepts the subset a person
//! edits by hand: block maps and sequences, comments, plain and quoted scalars, and JSON flow
//! values on one line. Anchors, aliases, tags, block scalars and several documents are refused
//! with the line number, never guessed.

use std::fmt::Write as _;

use serde_json::{Map, Number, Value};

/// Why a document is refused.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("line {line}: {what}")]
pub(crate) struct YamlError {
    pub(crate) line: usize,
    pub(crate) what: &'static str,
}

fn err<T>(line: usize, what: &'static str) -> Result<T, YamlError> {
    Err(YamlError { line, what })
}

// ---------------------------------------------------------------- writing

fn scalar(v: &Value) -> String {
    match v {
        Value::Null => String::from("null"),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => Value::String(s.clone()).to_string(),
        Value::Array(a) if a.is_empty() => String::from("[]"),
        Value::Object(o) if o.is_empty() => String::from("{}"),
        other => other.to_string(),
    }
}

fn nested(v: &Value) -> bool {
    match v {
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
        _ => false,
    }
}

fn sorted(o: &Map<String, Value>) -> Vec<(&String, &Value)> {
    let mut v: Vec<_> = o.iter().collect();
    v.sort_by(|a, b| a.0.cmp(b.0));
    v
}

fn key_text(k: &str) -> String {
    let plain = !k.is_empty()
        && k.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'/'))
        && k.bytes().next().is_none_or(|b| b != b'-');
    if plain {
        k.to_owned()
    } else {
        Value::String(k.to_owned()).to_string()
    }
}

fn write_map(out: &mut String, o: &Map<String, Value>, indent: usize) {
    for (k, v) in sorted(o) {
        let pad = " ".repeat(indent);
        if nested(v) {
            let _ = writeln!(out, "{pad}{}:", key_text(k));
            write_value(out, v, indent.saturating_add(2));
        } else {
            let _ = writeln!(out, "{pad}{}: {}", key_text(k), scalar(v));
        }
    }
}

fn write_value(out: &mut String, v: &Value, indent: usize) {
    match v {
        Value::Object(o) => write_map(out, o, indent),
        Value::Array(items) => {
            let pad = " ".repeat(indent);
            for item in items {
                match item {
                    Value::Object(o) if !o.is_empty() => {
                        let mut inner = String::new();
                        write_map(&mut inner, o, indent.saturating_add(2));
                        let first = inner.get(indent.saturating_add(2)..).unwrap_or("");
                        let _ = write!(out, "{pad}- {first}");
                    }
                    Value::Array(a) if !a.is_empty() => {
                        let _ = writeln!(out, "{pad}-");
                        write_value(out, item, indent.saturating_add(2));
                    }
                    other => {
                        let _ = writeln!(out, "{pad}- {}", scalar(other));
                    }
                }
            }
        }
        other => {
            let _ = writeln!(out, "{}{}", " ".repeat(indent), scalar(other));
        }
    }
}

/// The YAML text of `v`, with an optional leading comment line.
pub(crate) fn to_string(v: &Value, comment: Option<&str>) -> String {
    let mut out = String::new();
    if let Some(c) = comment {
        for line in c.lines() {
            let _ = writeln!(out, "# {line}");
        }
    }
    if nested(v) {
        write_value(&mut out, v, 0);
    } else {
        let _ = writeln!(out, "{}", scalar(v));
    }
    out
}

// ---------------------------------------------------------------- reading

#[derive(Clone, Debug)]
struct Line {
    no: usize,
    indent: usize,
    text: String,
}

fn strip_comment(s: &str) -> &str {
    let mut quote: Option<char> = None;
    let mut prev_space = true;
    for (i, c) in s.char_indices() {
        match (quote, c) {
            (None, '"' | '\'') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            (None, '#') if prev_space => return s.get(..i).unwrap_or(s),
            _ => {}
        }
        prev_space = c == ' ';
    }
    s
}

fn lines(text: &str) -> Result<Vec<Line>, YamlError> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let no = i.saturating_add(1);
        if raw.contains('\t') {
            return err(no, "tab characters are not allowed");
        }
        let body = strip_comment(raw).trim_end();
        if body.trim().is_empty() {
            continue;
        }
        if body == "---" && out.is_empty() {
            continue;
        }
        if body.starts_with("---") || body.starts_with("...") || body.starts_with('%') {
            return err(no, "one document only");
        }
        let indent = body.len().saturating_sub(body.trim_start().len());
        out.push(Line {
            no,
            indent,
            text: body.trim_start().to_owned(),
        });
    }
    Ok(out)
}

fn plain(text: &str, no: usize) -> Result<Value, YamlError> {
    let t = text.trim();
    if t.starts_with('&') || t.starts_with('*') || t.starts_with('!') {
        return err(no, "anchors, aliases and tags are not supported");
    }
    if t.starts_with('|') || t.starts_with('>') {
        return err(no, "block scalars are not supported; use a quoted string");
    }
    if t.starts_with('"') || t.starts_with('[') || t.starts_with('{') {
        return serde_json::from_str(t).or_else(|_| err(no, "not a valid quoted or flow value"));
    }
    if let Some(inner) = t.strip_prefix('\'') {
        let inner = inner.strip_suffix('\'').ok_or(YamlError {
            line: no,
            what: "unterminated single-quoted string",
        })?;
        return Ok(Value::String(inner.replace("''", "'")));
    }
    match t {
        "null" | "~" | "" => return Ok(Value::Null),
        "true" => return Ok(Value::Bool(true)),
        "false" => return Ok(Value::Bool(false)),
        _ => {}
    }
    let lower = t.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "yes" | "no" | "on" | "off" | "y" | "n" | "true" | "false" | "null"
    ) {
        return err(no, "ambiguous plain scalar; quote it");
    }
    if let Ok(i) = t.parse::<i64>() {
        return Ok(Value::Number(Number::from(i)));
    }
    if t.parse::<f64>().is_ok() || t.starts_with("0x") || t.starts_with("0o") {
        return err(no, "only integers are numbers here; quote it");
    }
    if t.contains(": ") || t.ends_with(':') {
        return err(no, "a plain scalar may not contain ': '");
    }
    Ok(Value::String(t.to_owned()))
}

fn split_key(text: &str, no: usize) -> Result<Option<(String, String)>, YamlError> {
    let (key, rest) = if let Some(after) = text.strip_prefix('"') {
        let end = after.find('"').ok_or(YamlError {
            line: no,
            what: "unterminated key",
        })?;
        let k_text = text.get(..end.saturating_add(2)).unwrap_or("");
        let k: String = serde_json::from_str(k_text).or_else(|_| err(no, "bad quoted key"))?;
        let rest = text.get(end.saturating_add(2)..).unwrap_or("");
        let Some(rest) = rest.strip_prefix(':') else {
            return Ok(None);
        };
        (k, rest)
    } else {
        let Some(at) = text
            .find(": ")
            .or_else(|| text.ends_with(':').then(|| text.len().saturating_sub(1)))
        else {
            return Ok(None);
        };
        if text.starts_with('[') || text.starts_with('{') {
            return Ok(None);
        }
        let k = text.get(..at).unwrap_or("").trim().to_owned();
        (k, text.get(at.saturating_add(1)..).unwrap_or(""))
    };
    if key.is_empty() {
        return err(no, "empty key");
    }
    Ok(Some((key, rest.trim().to_owned())))
}

struct Parser {
    lines: Vec<Line>,
    at: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Line> {
        self.lines.get(self.at)
    }

    fn block(&mut self, indent: usize) -> Result<Value, YamlError> {
        let Some(first) = self.peek().cloned() else {
            return Ok(Value::Null);
        };
        if first.text == "-" || first.text.starts_with("- ") {
            self.sequence(indent)
        } else {
            self.mapping(indent)
        }
    }

    fn value_after(&mut self, rest: &str, indent: usize, no: usize) -> Result<Value, YamlError> {
        if !rest.is_empty() {
            return plain(rest, no);
        }
        match self.peek() {
            Some(next) if next.indent > indent => {
                let i = next.indent;
                self.block(i)
            }
            Some(next) if next.indent == indent && next.text.starts_with('-') => {
                self.sequence(indent)
            }
            _ => Ok(Value::Null),
        }
    }

    fn mapping(&mut self, indent: usize) -> Result<Value, YamlError> {
        let mut out = Map::new();
        while let Some(line) = self.peek().cloned() {
            if line.indent < indent {
                break;
            }
            if line.indent > indent {
                return err(line.no, "unexpected indentation");
            }
            if line.text.starts_with("- ") || line.text == "-" {
                break;
            }
            let (k, rest) = split_key(&line.text, line.no)?.ok_or(YamlError {
                line: line.no,
                what: "expected `key: value`",
            })?;
            self.at = self.at.saturating_add(1);
            let v = self.value_after(&rest, indent, line.no)?;
            if out.insert(k, v).is_some() {
                return err(line.no, "duplicate key");
            }
        }
        Ok(Value::Object(out))
    }

    fn sequence(&mut self, indent: usize) -> Result<Value, YamlError> {
        let mut out = Vec::new();
        while let Some(line) = self.peek().cloned() {
            if line.indent != indent || !(line.text == "-" || line.text.starts_with("- ")) {
                if line.indent > indent {
                    return err(line.no, "unexpected indentation");
                }
                break;
            }
            let rest = line.text.get(1..).unwrap_or("").trim_start().to_owned();
            if rest.is_empty() {
                self.at = self.at.saturating_add(1);
                out.push(self.value_after("", indent, line.no)?);
                continue;
            }
            let item_indent = indent
                .saturating_add(line.text.len())
                .saturating_sub(rest.len());
            if split_key(&rest, line.no)?.is_some() {
                if let Some(l) = self.lines.get_mut(self.at) {
                    l.indent = item_indent;
                    l.text.clone_from(&rest);
                }
                out.push(self.mapping(item_indent)?);
            } else {
                self.at = self.at.saturating_add(1);
                out.push(plain(&rest, line.no)?);
            }
        }
        Ok(Value::Array(out))
    }
}

/// Parses a document of the supported subset.
pub(crate) fn from_str(text: &str) -> Result<Value, YamlError> {
    let lines = lines(text)?;
    let indent = lines.first().map_or(0, |l| l.indent);
    let mut p = Parser { lines, at: 0 };
    let v = p.block(indent)?;
    if let Some(l) = p.peek() {
        return err(l.no, "unexpected content");
    }
    Ok(v)
}

#[cfg(test)]
mod tests;
