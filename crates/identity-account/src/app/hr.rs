//! HR records (OP-156 m.3 (q), IDP-35, C13, TN-109): a JSONL batch of at most 10 000 records or
//! an RFC 4180 CSV file of at most 10 MB with the fixed columns and a header row. Every record
//! of a file is read before anything is written; one bad record refuses the whole file.
//!
//! Each record is the newest version of a person's record under its HR source, sealed under the
//! person's profile key. Its values are stated as the source's HR Claims, the same classes the
//! SCIM HR extension states (OP-155 m.9 (c)). A Claim selects nobody until the domain accepts the
//! source's issuer for `subject-selection` (INV-16, TN-95): nothing here writes a Grant. A
//! person's start and end dates are kept as dates still to apply; the HR job applies them.
//!
//! A mover's changed values are taken back at once and the new ones wait 24 hours (TN-109): a
//! new holding episode of a reserved or CT3 rule-shaped Grant never starts on the import itself.

use std::collections::BTreeMap;

use access_kernel::model::EqValue;
use access_store::audit::AuditEvent;
use access_store::idp::Bound;
use serde::{Deserialize, Serialize};

use crate::AccountError;
use crate::adapters::pg::PgTx;
use crate::app::sealing::new_subject_key;
use crate::app::vault::{self, PiiClass};
use crate::app::{Actor, Realm, events};
use crate::domain::claims::{BINDING_TTL_MS, Bind, ClaimOrder, Content, line};
use crate::domain::identifier::{Identifier, IdentifierKind};
use crate::domain::status::AccountStatus;
use crate::ports::AccountTx;

/// Most records in one batch (OP-156 m.3 (q)).
pub const MAX_RECORDS: usize = 10_000;

/// Largest CSV file, in bytes (OP-156 m.3 (q)).
pub const MAX_CSV_BYTES: usize = 10 * 1024 * 1024;

/// The CSV columns: a header row names each at most once, `employee_id` and `email` always.
pub const COLUMNS: [&str; 8] = [
    "employee_id",
    "email",
    "department",
    "title",
    "manager",
    "start_date",
    "end_date",
    "employment_status",
];

/// The HR Claim classes, as the SCIM HR extension states them (IDP-35, OP-155 m.9 (c)).
pub const CLASSES: [&str; 6] = [
    "hr_department",
    "hr_title",
    "hr_manager",
    "hr_start",
    "hr_end",
    "hr_employment_status",
];

/// How long a mover's new values wait before they are stated (TN-109): 24 hours.
pub const COOLING_MS: u64 = 86_400_000;

/// How long a passkey setup invitation is good for (OP-156 m.3 (q)): 7 days.
pub const INVITE_TTL_MS: u64 = 7 * 86_400_000;

/// The field the record's values are sealed under.
pub const SEALED_FIELD: &str = "hr_record";

/// How long an HR Claim holds before the source states it again: as a binding Claim.
pub const TTL_MS: u64 = BINDING_TTL_MS;

/// Longest text value.
pub const MAX_TEXT: usize = 256;

/// Longest employee id.
pub const MAX_EMPLOYEE_ID: usize = 128;

/// One HR record: who, and what the HR system says about them.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    /// The HR system's id of the person, unique within the source.
    pub employee_id: String,
    /// The person's work e-mail address: the account's identifier.
    pub email: String,
    /// Department.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,
    /// Job title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// The manager's employee id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manager: Option<String>,
    /// The start date, Unix ms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_ms: Option<u64>,
    /// The end date, Unix ms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_ms: Option<u64>,
    /// The employment status as the HR system names it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub employment_status: Option<String>,
}

impl core::fmt::Debug for Record {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Record")
            .field("start_ms", &self.start_ms)
            .field("end_ms", &self.end_ms)
            .finish_non_exhaustive()
    }
}

/// One JSONL line as it is sent: dates are `YYYY-MM-DD` or RFC 3339 UTC.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Line {
    employee_id: String,
    email: String,
    #[serde(default)]
    department: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    manager: Option<String>,
    #[serde(default)]
    start_date: Option<String>,
    #[serde(default)]
    end_date: Option<String>,
    #[serde(default)]
    employment_status: Option<String>,
}

/// What is wrong with a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Fault {
    /// Not one JSON object of the record format, or a CSV row of another width.
    #[error("not a record")]
    Format,
    /// A CSV header with a column outside the fixed set (OP-156 m.3 (q)).
    #[error("unknown column")]
    UnknownColumn,
    /// A CSV header that names a column twice.
    #[error("column named twice")]
    DuplicateColumn,
    /// A CSV header without `employee_id` or `email`.
    #[error("missing column")]
    MissingColumn,
    /// A missing or malformed employee id.
    #[error("employee id")]
    EmployeeId,
    /// A malformed e-mail address.
    #[error("email")]
    Email,
    /// A value too long or with control characters.
    #[error("value")]
    Value,
    /// A date that is not `YYYY-MM-DD` or RFC 3339 UTC, or an end before the start.
    #[error("date")]
    Date,
    /// The same employee id twice in one file.
    #[error("employee id repeated")]
    Repeated,
}

/// Why a file was refused; nothing of it was written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Refused {
    /// No record.
    #[error("no record")]
    Empty,
    /// More than [`MAX_RECORDS`] records.
    #[error("too many records")]
    TooMany,
    /// A CSV file over [`MAX_CSV_BYTES`].
    #[error("file too large")]
    TooLarge,
    /// The record on 1-based line `line` (the header is line 1 of a CSV file).
    #[error("line {line}: {fault}")]
    Line {
        /// The line.
        line: u64,
        /// What is wrong.
        fault: Fault,
    },
}

/// An import file's format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// One JSON object per line.
    Jsonl,
    /// RFC 4180.
    Csv,
}

impl Format {
    /// The stored name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Jsonl => "jsonl",
            Self::Csv => "csv",
        }
    }
}

/// The SHA-256 of an import file: what `idp.hr.import` names.
#[must_use]
pub fn file_digest(text: &str) -> [u8; 32] {
    suiss_crypto::digest::sha256(text.as_bytes())
}

fn digits(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

const fn leap(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

const fn days_in(year: u64, month: u64) -> u64 {
    match month {
        2 if leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days from 1970-01-01 to `year`-`month`-`day`, all three already in range.
fn days_since_epoch(year: u64, month: u64, day: u64) -> u64 {
    let mut days = 0_u64;
    for y in 1970..year {
        days = days.saturating_add(if leap(y) { 366 } else { 365 });
    }
    for m in 1..month {
        days = days.saturating_add(days_in(year, m));
    }
    days.saturating_add(day.saturating_sub(1))
}

/// A date as Unix ms: `YYYY-MM-DD` (midnight UTC) or `YYYY-MM-DDTHH:MM:SSZ`.
#[must_use]
pub fn date_ms(text: &str) -> Option<u64> {
    let (date, time) = match text.split_once('T') {
        Some((d, t)) => (d, Some(t.strip_suffix('Z')?)),
        None => (text, None),
    };
    let fields: Vec<&str> = date.split('-').collect();
    let [year, month, day] = fields.as_slice() else {
        return None;
    };
    if year.len() != 4 || month.len() != 2 || day.len() != 2 {
        return None;
    }
    let (year, month, day) = (digits(year)?, digits(month)?, digits(day)?);
    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || day < 1
        || day > days_in(year, month)
    {
        return None;
    }
    let mut seconds = days_since_epoch(year, month, day).saturating_mul(86_400);
    if let Some(t) = time {
        let parts: Vec<&str> = t.split(':').collect();
        let [hour, minute, second] = parts.as_slice() else {
            return None;
        };
        if hour.len() != 2 || minute.len() != 2 || second.len() != 2 {
            return None;
        }
        let (hour, minute, second) = (digits(hour)?, digits(minute)?, digits(second)?);
        if hour > 23 || minute > 59 || second > 59 {
            return None;
        }
        seconds = seconds
            .saturating_add(hour.saturating_mul(3_600))
            .saturating_add(minute.saturating_mul(60))
            .saturating_add(second);
    }
    seconds.checked_mul(1000)
}

fn text(v: Option<String>) -> Result<Option<String>, Fault> {
    match v.map(|s| String::from(s.trim())) {
        None => Ok(None),
        Some(s) if s.is_empty() => Ok(None),
        Some(s) if s.chars().count() <= MAX_TEXT && !s.chars().any(char::is_control) => Ok(Some(s)),
        Some(_) => Err(Fault::Value),
    }
}

fn date(v: Option<String>) -> Result<Option<u64>, Fault> {
    match v.map(|s| String::from(s.trim())) {
        None => Ok(None),
        Some(s) if s.is_empty() => Ok(None),
        Some(s) => date_ms(&s).map(Some).ok_or(Fault::Date),
    }
}

impl Line {
    fn record(self) -> Result<Record, Fault> {
        let employee_id = String::from(self.employee_id.trim());
        if employee_id.is_empty()
            || employee_id.chars().count() > MAX_EMPLOYEE_ID
            || employee_id.chars().any(char::is_control)
        {
            return Err(Fault::EmployeeId);
        }
        let email =
            Identifier::new(IdentifierKind::Email, self.email.trim()).map_err(|_| Fault::Email)?;
        let r = Record {
            employee_id,
            email: String::from(email.value()),
            department: text(self.department)?,
            title: text(self.title)?,
            manager: text(self.manager)?,
            start_ms: date(self.start_date)?,
            end_ms: date(self.end_date)?,
            employment_status: text(self.employment_status)?,
        };
        if let (Some(s), Some(e)) = (r.start_ms, r.end_ms)
            && e < s
        {
            return Err(Fault::Date);
        }
        Ok(r)
    }
}

fn unique(records: &[(u64, Record)]) -> Result<(), Refused> {
    let mut seen = std::collections::BTreeSet::new();
    for (line, r) in records {
        if !seen.insert(r.employee_id.as_str()) {
            return Err(Refused::Line {
                line: *line,
                fault: Fault::Repeated,
            });
        }
    }
    Ok(())
}

fn finish(records: Vec<(u64, Record)>) -> Result<Vec<Record>, Refused> {
    if records.is_empty() {
        return Err(Refused::Empty);
    }
    if records.len() > MAX_RECORDS {
        return Err(Refused::TooMany);
    }
    unique(&records)?;
    Ok(records.into_iter().map(|(_, r)| r).collect())
}

/// The records of a JSONL batch, every one checked.
///
/// # Errors
/// [`Refused`]: the first bad record refuses the whole batch.
pub fn parse_jsonl(text: &str) -> Result<Vec<Record>, Refused> {
    let mut out = Vec::new();
    for (n, raw) in (1_u64..).zip(text.lines()) {
        if raw.trim().is_empty() {
            continue;
        }
        if out.len() >= MAX_RECORDS {
            return Err(Refused::TooMany);
        }
        let fault = |fault| Refused::Line { line: n, fault };
        let line: Line = serde_json::from_str(raw).map_err(|_| fault(Fault::Format))?;
        out.push((n, line.record().map_err(fault)?));
    }
    finish(out)
}

/// The fields of RFC 4180 `text`, row by row with each row's first line number. A quoted field
/// may hold commas, doubled quotes and line breaks; a stray quote is [`Fault::Format`].
fn csv_rows(text: &str) -> Result<Vec<(u64, Vec<String>)>, Refused> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut was_quoted = false;
    let mut line = 1_u64;
    let mut row_line = 1_u64;
    let mut chars = text.chars().peekable();
    let bad = |line| Refused::Line {
        line,
        fault: Fault::Format,
    };
    while let Some(c) = chars.next() {
        if quoted {
            match c {
                '"' if chars.peek() == Some(&'"') => {
                    chars.next();
                    field.push('"');
                }
                '"' => quoted = false,
                '\n' => {
                    line = line.saturating_add(1);
                    field.push('\n');
                }
                c => field.push(c),
            }
            continue;
        }
        match c {
            '"' if field.is_empty() && !was_quoted => {
                quoted = true;
                was_quoted = true;
            }
            '"' => return Err(bad(line)),
            ',' => {
                row.push(core::mem::take(&mut field));
                was_quoted = false;
            }
            '\r' if chars.peek() == Some(&'\n') => {}
            '\n' => {
                row.push(core::mem::take(&mut field));
                was_quoted = false;
                if !(row.len() == 1 && row.first().is_some_and(String::is_empty)) {
                    rows.push((row_line, core::mem::take(&mut row)));
                }
                row.clear();
                line = line.saturating_add(1);
                row_line = line;
            }
            _ if was_quoted => return Err(bad(line)),
            c => field.push(c),
        }
    }
    if quoted {
        return Err(bad(line));
    }
    if !field.is_empty() || was_quoted || !row.is_empty() {
        row.push(field);
        rows.push((row_line, row));
    }
    Ok(rows)
}

/// The records of an RFC 4180 CSV file with a header row of the fixed columns, every one
/// checked.
///
/// # Errors
/// [`Refused`]: an unknown, repeated or missing column, or the first bad record, refuses the
/// whole file.
pub fn parse_csv(text: &str) -> Result<Vec<Record>, Refused> {
    if text.len() > MAX_CSV_BYTES {
        return Err(Refused::TooLarge);
    }
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut rows = csv_rows(text)?.into_iter();
    let Some((_, header)) = rows.next() else {
        return Err(Refused::Empty);
    };
    let head = |fault| Refused::Line { line: 1, fault };
    let mut columns = Vec::with_capacity(header.len());
    for name in &header {
        let name = name.trim();
        let Some(known) = COLUMNS.iter().find(|c| **c == name) else {
            return Err(head(Fault::UnknownColumn));
        };
        if columns.contains(known) {
            return Err(head(Fault::DuplicateColumn));
        }
        columns.push(*known);
    }
    if !columns.contains(&"employee_id") || !columns.contains(&"email") {
        return Err(head(Fault::MissingColumn));
    }
    let mut out = Vec::new();
    for (n, fields) in rows {
        if out.len() >= MAX_RECORDS {
            return Err(Refused::TooMany);
        }
        let fault = |fault| Refused::Line { line: n, fault };
        if fields.len() != columns.len() {
            return Err(fault(Fault::Format));
        }
        let mut by: BTreeMap<&str, String> = BTreeMap::new();
        for (c, v) in columns.iter().zip(fields) {
            by.insert(c, v);
        }
        let line = Line {
            employee_id: by.remove("employee_id").unwrap_or_default(),
            email: by.remove("email").unwrap_or_default(),
            department: by.remove("department"),
            title: by.remove("title"),
            manager: by.remove("manager"),
            start_date: by.remove("start_date"),
            end_date: by.remove("end_date"),
            employment_status: by.remove("employment_status"),
        };
        out.push((n, line.record().map_err(fault)?));
    }
    finish(out)
}

/// The records of `text` in `format`.
///
/// # Errors
/// [`Refused`].
pub fn parse(format: Format, text: &str) -> Result<Vec<Record>, Refused> {
    match format {
        Format::Jsonl => parse_jsonl(text),
        Format::Csv => parse_csv(text),
    }
}

/// The value each HR Claim class states for `r`; a class without a value is absent.
#[must_use]
pub fn values(r: &Record) -> BTreeMap<&'static str, EqValue> {
    let mut out = BTreeMap::new();
    let mut put = |class, v: Option<EqValue>| {
        if let Some(v) = v {
            out.insert(class, v);
        }
    };
    put("hr_department", r.department.clone().map(EqValue::Text));
    put("hr_title", r.title.clone().map(EqValue::Text));
    put("hr_manager", r.manager.clone().map(EqValue::Text));
    let int = |ms: Option<u64>| ms.and_then(|m| i64::try_from(m).ok()).map(EqValue::Int);
    put("hr_start", int(r.start_ms));
    put("hr_end", int(r.end_ms));
    put(
        "hr_employment_status",
        r.employment_status.clone().map(EqValue::Text),
    );
    out
}

/// What of `after` stays as it was in `before`: every value that changed or is new is left
/// out. It is what a mover holds during the cooling (TN-109).
#[must_use]
pub fn kept(before: &Record, after: &Record) -> Record {
    let same = |a: &Option<String>, b: &Option<String>| if a == b { b.clone() } else { None };
    Record {
        employee_id: after.employee_id.clone(),
        email: after.email.clone(),
        department: same(&before.department, &after.department),
        title: same(&before.title, &after.title),
        manager: same(&before.manager, &after.manager),
        start_ms: (before.start_ms == after.start_ms)
            .then_some(after.start_ms)
            .flatten(),
        end_ms: (before.end_ms == after.end_ms)
            .then_some(after.end_ms)
            .flatten(),
        employment_status: same(&before.employment_status, &after.employment_status),
    }
}

/// The line of a subject's `class` Claims from HR source `source`.
#[must_use]
pub fn hr_line(source: &str, class: &str) -> [u8; 32] {
    line(&[b"hr_source", source.as_bytes(), class.as_bytes()])
}

/// The HR Claim orders that take `before` to `after` for `subject` (IDP-35): a new or changed
/// value is stated, a value that went away is retracted, an unchanged one is left alone.
#[must_use]
pub fn orders(
    subject: [u8; 16],
    source: &str,
    (before, after): (
        &BTreeMap<&'static str, EqValue>,
        &BTreeMap<&'static str, EqValue>,
    ),
    at: u64,
) -> Vec<ClaimOrder> {
    let order = |class: &str, value: EqValue, retract| ClaimOrder {
        subject,
        class: String::from(class),
        at,
        ttl_ms: TTL_MS,
        content: Content::Scalar(value),
        assurance: BTreeMap::new(),
        bind: Bind::None,
        line: Some(hr_line(source, class)),
        retract,
    };
    let mut out = Vec::new();
    for class in CLASSES {
        match (before.get(class), after.get(class)) {
            (o, Some(n)) if o != Some(n) => out.push(order(class, n.clone(), false)),
            (Some(o), None) => out.push(order(class, o.clone(), true)),
            _ => {}
        }
    }
    out
}

/// The realm's blind index of `employee_id` under `source`: a record's key.
///
/// # Errors
/// [`AccountError::Vault`].
pub fn person(
    v: &vault::Vault,
    (tenant, realm): (&[u8; 16], &[u8; 16]),
    source: &str,
    employee_id: &str,
) -> Result<[u8; 32], AccountError> {
    v.index_of(tenant, realm, &format!("hr\u{0}{source}\u{0}{employee_id}"))
}

/// Seals `r` under `subject`'s profile key.
///
/// # Errors
/// [`AccountError`].
pub async fn seal(
    tx: &mut PgTx,
    subject: [u8; 16],
    r: &Record,
) -> Result<([u8; 12], Vec<u8>), AccountError> {
    let v = tx.vault()?.clone();
    let dek = vault::class_key(&mut tx.0, &v, subject, PiiClass::Profile, true)
        .await?
        .ok_or(AccountError::Shredded)?;
    let text = serde_json::to_vec(r).map_err(|_| AccountError::Corrupt)?;
    let sealed = vault::seal(&tx.0, &dek, subject, PiiClass::Profile, SEALED_FIELD, &text)?;
    Ok((sealed.nonce, sealed.ciphertext))
}

/// Opens a record sealed by [`seal`]; `None` once `subject`'s profile key is shredded.
///
/// # Errors
/// [`AccountError`].
pub async fn open(
    tx: &mut PgTx,
    subject: [u8; 16],
    (nonce, ciphertext): &([u8; 12], Vec<u8>),
) -> Result<Option<Record>, AccountError> {
    let v = tx.vault()?.clone();
    let Some(dek) = vault::class_key(&mut tx.0, &v, subject, PiiClass::Profile, false).await?
    else {
        return Ok(None);
    };
    let text = vault::open(
        &tx.0,
        &dek,
        subject,
        PiiClass::Profile,
        SEALED_FIELD,
        &suiss_crypto::envelope::Sealed {
            nonce: *nonce,
            ciphertext: ciphertext.clone(),
        },
    )?;
    serde_json::from_str(&text)
        .map(Some)
        .map_err(|_| AccountError::Corrupt)
}

/// What an import did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Imported {
    /// Records read.
    pub records: u64,
    /// Records that changed a person's record.
    pub changed: u64,
    /// Accounts created for people new to the realm, `staged` until their start date.
    pub created: u64,
    /// Records the same as the person's record already was.
    pub unchanged: u64,
}

async fn account(
    tx: &mut PgTx,
    realm: &Realm<'_>,
    r: &Record,
    who: &Actor<'_>,
) -> Result<([u8; 16], bool), AccountError> {
    if let Some(s) = tx.subject_by_identifier(&r.email).await? {
        return Ok((s, false));
    }
    let wrapped = new_subject_key(realm)?;
    let subject = tx
        .insert_subject(AccountStatus::Staged, realm.kek.id(), &wrapped)
        .await?;
    let id = Identifier::new(IdentifierKind::Email, &r.email).map_err(|_| AccountError::Corrupt)?;
    if !tx.add_identifier(subject, &id).await? {
        return Err(AccountError::IdentifierTaken);
    }
    tx.audit(&AuditEvent {
        event_type: "account.created",
        actor: who.actor,
        target: &realm.external(subject)?,
        correlation: who.correlation,
    })
    .await?;
    // OP-151 m.3 (i)
    events::created(tx, realm, subject).await?;
    Ok((subject, true))
}

async fn dates(
    tx: &mut PgTx,
    (source, person, subject): (&str, &[u8; 32], [u8; 16]),
    (before, after): (Option<&Record>, &Record),
    (created, now): (bool, u64),
) -> Result<(), AccountError> {
    let start = match (before.and_then(|b| b.start_ms), after.start_ms) {
        (b, Some(a)) if b != Some(a) => Some(a),
        (_, None) if created => Some(now),
        _ => None,
    };
    if let Some(at) = start {
        tx.0.put_hr_due((source, person, "start"), subject, at, "pending")
            .await?;
    }
    let old_end = before.and_then(|b| b.end_ms);
    if old_end != after.end_ms {
        let open = tx.0.hr_due_of(source, person, "end").await?;
        match after.end_ms {
            Some(at) => {
                tx.0.put_hr_due((source, person, "end"), subject, at, "pending")
                    .await?;
            }
            None if open.as_ref().is_some_and(|d| d.state == "pending") => {
                let at = open.map_or(now, |d| d.due_ms);
                tx.0.put_hr_due((source, person, "end"), subject, at, "void")
                    .await?;
            }
            None => {}
        }
    }
    Ok(())
}

/// Writes `records` of an `idp.hr.import` of `source` bound by `bound`, in the decision's
/// transaction: a person new to the realm gets a `staged` account, a changed record its next
/// version, a mover's changed values first a version without them (TN-109), and a changed start
/// or end date its date to apply. An unchanged record writes nothing.
///
/// # Errors
/// [`AccountError`]; the caller rolls the decision's transaction back.
pub async fn apply(
    tx: &mut PgTx,
    realm: &Realm<'_>,
    (source, bound): (&str, &Bound),
    records: &[Record],
    (now, who): (u64, &Actor<'_>),
) -> Result<Imported, AccountError> {
    let v = tx.vault()?.clone();
    let scope = (*realm.tenant.as_bytes(), *realm.realm.as_bytes());
    let mut out = Imported::default();
    for r in records {
        out.records = out.records.saturating_add(1);
        let key = person(&v, (&scope.0, &scope.1), source, &r.employee_id)?;
        let versions = tx.0.hr_record_versions(source, &key).await?;
        let newest = match versions.last() {
            Some(row) => Some((row.subject, open(tx, row.subject, &row.sealed).await?)),
            None => None,
        };
        let (subject, created, before) = match newest {
            Some((s, Some(b))) => (s, false, Some(b)),
            Some((_, None)) => continue,
            None => {
                let (s, created) = account(tx, realm, r, who).await?;
                (s, created, None)
            }
        };
        if before.as_ref() == Some(r) {
            out.unchanged = out.unchanged.saturating_add(1);
            continue;
        }
        let mut issue_after = now;
        if let Some(b) = &before {
            let held = kept(b, r);
            if held != *b {
                let sealed = seal(tx, subject, &held).await?;
                tx.0.insert_hr_record(&access_store::hr::NewRecord {
                    source,
                    person: key,
                    subject,
                    import: bound,
                    start_ms: held.start_ms,
                    end_ms: held.end_ms,
                    sealed: (&sealed.0, &sealed.1),
                    issue_after_ms: now,
                })
                .await?;
            }
            // TN-109
            if held != *r {
                issue_after = now.saturating_add(COOLING_MS);
            }
        }
        let sealed = seal(tx, subject, r).await?;
        tx.0.insert_hr_record(&access_store::hr::NewRecord {
            source,
            person: key,
            subject,
            import: bound,
            start_ms: r.start_ms,
            end_ms: r.end_ms,
            sealed: (&sealed.0, &sealed.1),
            issue_after_ms: issue_after,
        })
        .await?;
        dates(
            tx,
            (source, &key, subject),
            (before.as_ref(), r),
            (created, now),
        )
        .await?;
        out.changed = out.changed.saturating_add(1);
        if created {
            out.created = out.created.saturating_add(1);
        }
    }
    tx.audit(&AuditEvent {
        event_type: "hr.imported",
        actor: who.actor,
        target: source,
        correlation: who.correlation,
    })
    .await?;
    Ok(out)
}

/// What the next HR Claims of one person's record under a source are.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Next {
    /// Nothing left to state.
    Done,
    /// The next version still cools until `until` and is the newest: wait.
    Wait {
        /// Unix ms.
        until: u64,
    },
    /// The next version still cools but a newer one replaced it: it is skipped.
    Skip {
        /// The version.
        version: u64,
    },
    /// The orders that state version `version` after the last stated one; after a version the
    /// domain did not accept, every value is stated again.
    Issue {
        /// The version.
        version: u64,
        /// The account.
        subject: [u8; 16],
        /// The orders, possibly none.
        orders: Vec<ClaimOrder>,
    },
    /// The person's profile key was shredded: the version is skipped.
    Shredded {
        /// The version.
        version: u64,
    },
}

/// The next HR Claims of `person`'s record under `source` at `now`.
///
/// # Errors
/// [`AccountError`].
pub async fn next(
    tx: &mut PgTx,
    source: &str,
    person: &[u8; 32],
    now: u64,
) -> Result<Next, AccountError> {
    let versions = tx.0.hr_record_versions(source, person).await?;
    let Some(pos) = versions.iter().position(|v| v.claims.is_none()) else {
        return Ok(Next::Done);
    };
    let Some(row) = versions.get(pos) else {
        return Ok(Next::Done);
    };
    let newer = versions.len() > pos.saturating_add(1);
    if row.issue_after_ms > now {
        return Ok(if newer {
            Next::Skip {
                version: row.version,
            }
        } else {
            Next::Wait {
                until: row.issue_after_ms,
            }
        });
    }
    let last = versions
        .get(..pos)
        .unwrap_or_default()
        .iter()
        .rev()
        .find(|v| matches!(v.claims.as_deref(), Some("issued" | "quarantined")));
    let before = match last {
        Some(l) if l.claims.as_deref() == Some("quarantined") => BTreeMap::new(),
        Some(l) => match open(tx, l.subject, &l.sealed).await? {
            Some(r) => values(&r),
            None => {
                return Ok(Next::Shredded {
                    version: row.version,
                });
            }
        },
        None => BTreeMap::new(),
    };
    let Some(after) = open(tx, row.subject, &row.sealed).await? else {
        return Ok(Next::Shredded {
            version: row.version,
        });
    };
    Ok(Next::Issue {
        version: row.version,
        subject: row.subject,
        orders: orders(row.subject, source, (&before, &values(&after)), now),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // OP-156 m.3 (q)
    #[test]
    fn dates_are_days_or_utc_times() {
        assert_eq!(date_ms("1970-01-01"), Some(0));
        assert_eq!(date_ms("2026-12-01"), Some(1_796_083_200_000));
        assert_eq!(date_ms("2026-12-01T09:30:00Z"), Some(1_796_117_400_000));
        assert_eq!(date_ms("2028-02-29"), Some(1_835_395_200_000));
        for bad in [
            "2027-02-29",
            "2026-13-01",
            "26-12-01",
            "2026-12-01T09:30:00+03:00",
            "2026/12/01",
            "",
        ] {
            assert_eq!(date_ms(bad), None, "{bad}");
        }
    }

    // OP-156 m.3 (q), IDP-35
    #[test]
    fn a_batch_is_read_whole_or_refused_whole() {
        let ok = concat!(
            r#"{"employee_id":"E1","email":"ada@acme.example","department":"R&D","start_date":"2026-12-01"}"#,
            "\n\n",
            r#"{"employee_id":"E2","email":"bob@acme.example","end_date":"2026-12-31T17:00:00Z"}"#,
        );
        let r = parse_jsonl(ok).unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].department.as_deref(), Some("R&D"));
        assert_eq!(r[1].end_ms, date_ms("2026-12-31T17:00:00Z"));
        let unknown = format!(
            "{ok}\n{}",
            r#"{"employee_id":"E3","email":"c@acme.example","salary":1}"#
        );
        assert_eq!(
            parse_jsonl(&unknown),
            Err(Refused::Line {
                line: 4,
                fault: Fault::Format
            })
        );
        let twice = format!(
            "{ok}\n{}",
            r#"{"employee_id":"E1","email":"d@acme.example"}"#
        );
        assert!(matches!(
            parse_jsonl(&twice),
            Err(Refused::Line {
                fault: Fault::Repeated,
                ..
            })
        ));
        assert_eq!(parse_jsonl("\n\n"), Err(Refused::Empty));
        let backwards = r#"{"employee_id":"E1","email":"a@acme.example","start_date":"2026-12-02","end_date":"2026-12-01"}"#;
        assert!(parse_jsonl(backwards).is_err());
        let mut many = String::new();
        for i in 0..=MAX_RECORDS {
            many.push_str(r#"{"employee_id":"E"#);
            many.push_str(&i.to_string());
            many.push_str(r#"","email":"p"#);
            many.push_str(&i.to_string());
            many.push_str("@acme.example\"}\n");
        }
        assert_eq!(parse_jsonl(&many), Err(Refused::TooMany));
    }

    // OP-156 m.3 (q)
    #[test]
    fn a_csv_file_has_the_fixed_columns_and_rfc_4180_quoting() {
        let ok = "employee_id,email,title,start_date\r\nE1,ada@acme.example,\"Engineer, \"\"Platform\"\"\",2026-12-01\r\nE2,bob@acme.example,,\r\n";
        let r = parse_csv(ok).unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].title.as_deref(), Some("Engineer, \"Platform\""));
        assert_eq!(r[1].title, None);
        assert_eq!(
            parse_csv("employee_id,email,title\nE1,a@acme.example,\"Two\nlines\"\n"),
            Err(Refused::Line {
                line: 2,
                fault: Fault::Value
            })
        );
        assert!(parse_csv("employee_id,email,salary\nE1,a@acme.example,1\n").is_err());
        assert_eq!(
            parse_csv("employee_id,email,salary\nE1,a@acme.example,1\n"),
            Err(Refused::Line {
                line: 1,
                fault: Fault::UnknownColumn
            })
        );
        assert_eq!(
            parse_csv("email,title\na@acme.example,x\n"),
            Err(Refused::Line {
                line: 1,
                fault: Fault::MissingColumn
            })
        );
        assert_eq!(
            parse_csv("employee_id,email,email\nE1,a@acme.example,b@acme.example\n"),
            Err(Refused::Line {
                line: 1,
                fault: Fault::DuplicateColumn
            })
        );
        assert_eq!(
            parse_csv("employee_id,email\nE1,a@acme.example,extra\n"),
            Err(Refused::Line {
                line: 2,
                fault: Fault::Format
            })
        );
        assert!(parse_csv("employee_id,email\nE1,\"a@acme.example\n").is_err());
        assert!(parse_csv("employee_id,email\nE1,a\"b@acme.example\n").is_err());
        assert_eq!(parse_csv(""), Err(Refused::Empty));
        let big = "x".repeat(MAX_CSV_BYTES + 1);
        assert_eq!(parse_csv(&big), Err(Refused::TooLarge));
    }

    // IDP-35, TN-109
    #[test]
    fn a_mover_keeps_only_what_did_not_change_while_cooling() {
        let before = Record {
            employee_id: String::from("E1"),
            email: String::from("ada@acme.example"),
            department: Some(String::from("R&D")),
            title: Some(String::from("Engineer")),
            ..Record::default()
        };
        let after = Record {
            department: Some(String::from("Finance")),
            ..before.clone()
        };
        let held = kept(&before, &after);
        assert_eq!(held.department, None);
        assert_eq!(held.title.as_deref(), Some("Engineer"));
        let retract = orders([1; 16], "workday", (&values(&before), &values(&held)), 5);
        assert_eq!(retract.len(), 1);
        assert!(retract[0].retract);
        assert_eq!(retract[0].class, "hr_department");
        let state = orders([1; 16], "workday", (&values(&held), &values(&after)), 6);
        assert_eq!(state.len(), 1);
        assert!(!state[0].retract);
        assert_eq!(
            state[0].content,
            Content::Scalar(EqValue::Text(String::from("Finance")))
        );
        assert_ne!(
            hr_line("workday", "hr_title"),
            hr_line("personio", "hr_title")
        );
    }
}
