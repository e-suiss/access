//! The HR systems a connector reads, in the order they ship (OP-156 m.3 (q)): `Personio`,
//! `BambooHR`, `HiBob`, `Workday`, SAP `SuccessFactors`, then Kolay İK and Logo. Each maps one page of
//! its documented employee listing to [`Record`]s; a person without an id or a work address is
//! left out and counted. Sans-I/O: the page is JSON already read.

use serde_json::Value;

use super::Record;

/// An HR system.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vendor {
    /// Personio, `GET /v1/company/employees`.
    Personio,
    /// `BambooHR`, a custom report as JSON.
    BambooHr,
    /// `HiBob`, `POST /v1/people/search`.
    HiBob,
    /// Workday, a Report-as-a-Service report as JSON.
    Workday,
    /// SAP `SuccessFactors`, `OData` v2 `User`.
    SuccessFactors,
    /// Kolay İK, the employee listing.
    KolayIk,
    /// Logo (İK), the personnel listing.
    Logo,
}

impl Vendor {
    /// Every vendor, in the order they ship.
    pub const ALL: [Self; 7] = [
        Self::Personio,
        Self::BambooHr,
        Self::HiBob,
        Self::Workday,
        Self::SuccessFactors,
        Self::KolayIk,
        Self::Logo,
    ];

    /// The name Access's `idp.hr.connector_register` takes.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Personio => "personio",
            Self::BambooHr => "bamboohr",
            Self::HiBob => "hibob",
            Self::Workday => "workday",
            Self::SuccessFactors => "successfactors",
            Self::KolayIk => "kolayik",
            Self::Logo => "logo",
        }
    }

    /// From its name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.name() == name)
    }

    /// The records of one page, and how many people were left out.
    ///
    /// # Errors
    /// [`Malformed`] when the page is not this vendor's listing.
    pub fn records(self, page: &Value) -> Result<(Vec<Record>, u32), Malformed> {
        let (list, map): (&Value, fn(&Value) -> Option<Record>) = match self {
            Self::Personio => (at(page, &["data"]), personio),
            Self::BambooHr => (at(page, &["employees"]), bamboohr),
            Self::HiBob => (at(page, &["employees"]), hibob),
            Self::Workday => (at(page, &["Report_Entry"]), workday),
            Self::SuccessFactors => (at(page, &["d", "results"]), successfactors),
            Self::KolayIk => (at(page, &["data", "items"]), kolayik),
            Self::Logo => (at(page, &["Items"]), logo),
        };
        let items = list.as_array().ok_or(Malformed)?;
        let mut out = Vec::with_capacity(items.len().min(10_000));
        let mut left = 0_u32;
        for item in items {
            match map(item) {
                Some(r) => out.push(r),
                None => left = left.saturating_add(1),
            }
        }
        Ok((out, left))
    }
}

/// A page that is not the vendor's listing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("not the vendor's employee listing")]
pub struct Malformed;

static NULL: Value = Value::Null;

/// The member at `path` of `v`, or null.
fn at<'a>(v: &'a Value, path: &[&str]) -> &'a Value {
    path.iter().fold(v, |v, k| v.get(*k).unwrap_or(&NULL))
}

fn text(v: &Value) -> Option<String> {
    let s = match v {
        Value::String(s) => s.trim().to_owned(),
        Value::Number(n) => n.to_string(),
        _ => return None,
    };
    (!s.is_empty()).then_some(s)
}

/// `YYYY-MM-DD` from a date or a date-time, `None` for an empty or zero date.
fn date(v: &Value) -> Option<String> {
    let s = v.as_str()?.trim();
    let d = s.get(..10)?;
    let b = d.as_bytes();
    let shape = b.len() == 10
        && b.iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            _ => c.is_ascii_digit(),
        });
    (shape && !d.starts_with("0000")).then(|| d.to_owned())
}

/// `YYYY-MM-DD` of an `OData` v2 `/Date(ms)/` or `/Date(ms+0000)/`.
fn odata_date(v: &Value) -> Option<String> {
    let s = v.as_str()?.strip_prefix("/Date(")?.strip_suffix(")/")?;
    let digits: String = s.chars().take_while(char::is_ascii_digit).collect();
    let days = digits.parse::<u64>().ok()?.checked_div(86_400_000)?;
    Some(civil(days))
}

fn civil(days: u64) -> String {
    let leap = |y: u64| (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400);
    let mut rest = days;
    let mut year = 1970_u64;
    loop {
        let n = if leap(year) { 366 } else { 365 };
        if rest < n {
            break;
        }
        rest = rest.saturating_sub(n);
        year = year.saturating_add(1);
    }
    let months = [
        31,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1_u64;
    for m in months {
        if rest < m {
            break;
        }
        rest = rest.saturating_sub(m);
        month = month.saturating_add(1);
    }
    format!("{year:04}-{month:02}-{:02}", rest.saturating_add(1))
}

fn person(employee_id: Option<String>, email: Option<String>) -> Option<Record> {
    let email = email?;
    email
        .contains('@')
        .then(|| Record {
            employee_id: employee_id.unwrap_or_default(),
            email,
            ..Record::default()
        })
        .filter(|r| !r.employee_id.is_empty())
}

fn personio(v: &Value) -> Option<Record> {
    let a = at(v, &["attributes"]);
    let field = |name: &str| at(a, &[name, "value"]);
    Some(Record {
        department: text(at(field("department"), &["attributes", "name"])),
        title: text(field("position")),
        manager: text(at(field("supervisor"), &["attributes", "id", "value"])),
        start_date: date(field("hire_date")),
        end_date: date(field("termination_date")),
        employment_status: text(field("status")),
        ..person(text(field("id")), text(field("email")))?
    })
}

fn bamboohr(v: &Value) -> Option<Record> {
    Some(Record {
        department: text(at(v, &["department"])),
        title: text(at(v, &["jobTitle"])),
        manager: text(at(v, &["supervisorEId"])),
        start_date: date(at(v, &["hireDate"])),
        end_date: date(at(v, &["terminationDate"])),
        employment_status: text(at(v, &["status"])),
        ..person(text(at(v, &["id"])), text(at(v, &["workEmail"])))?
    })
}

fn hibob(v: &Value) -> Option<Record> {
    let w = at(v, &["work"]);
    Some(Record {
        department: text(at(w, &["department"])),
        title: text(at(w, &["title"])),
        manager: text(at(w, &["reportsTo", "id"])),
        start_date: date(at(w, &["startDate"])),
        end_date: date(at(v, &["internal", "terminationDate"])),
        employment_status: text(at(v, &["internal", "lifecycleStatus"])),
        ..person(text(at(v, &["id"])), text(at(v, &["email"])))?
    })
}

fn workday(v: &Value) -> Option<Record> {
    Some(Record {
        department: text(at(v, &["Supervisory_Organization"])),
        title: text(at(v, &["Business_Title"])),
        manager: text(at(v, &["Manager_Employee_ID"])),
        start_date: date(at(v, &["Hire_Date"])),
        end_date: date(at(v, &["Termination_Date"])),
        employment_status: text(at(v, &["Worker_Status"])),
        ..person(
            text(at(v, &["Employee_ID"])),
            text(at(v, &["Email_-_Work"])),
        )?
    })
}

fn successfactors(v: &Value) -> Option<Record> {
    Some(Record {
        department: text(at(v, &["department"])),
        title: text(at(v, &["title"])),
        manager: text(at(v, &["manager", "userId"])),
        start_date: odata_date(at(v, &["hireDate"])),
        end_date: odata_date(at(v, &["lastDateWorked"])),
        employment_status: match at(v, &["status"]).as_str() {
            Some("t") => Some(String::from("active")),
            Some("f") => Some(String::from("inactive")),
            _ => None,
        },
        ..person(text(at(v, &["userId"])), text(at(v, &["email"])))?
    })
}

fn kolayik(v: &Value) -> Option<Record> {
    Some(Record {
        department: text(at(v, &["unit"])),
        title: text(at(v, &["title"])),
        manager: text(at(v, &["managerId"])),
        start_date: date(at(v, &["employmentStartDate"])),
        end_date: date(at(v, &["terminationDate"])),
        employment_status: text(at(v, &["status"])),
        ..person(text(at(v, &["id"])), text(at(v, &["workEmail"])))?
    })
}

fn logo(v: &Value) -> Option<Record> {
    Some(Record {
        department: text(at(v, &["Departman"])),
        title: text(at(v, &["Unvan"])),
        manager: text(at(v, &["YoneticiSicilNo"])),
        start_date: date(at(v, &["IseGirisTarihi"])),
        end_date: date(at(v, &["IstenCikisTarihi"])),
        employment_status: text(at(v, &["Durum"])),
        ..person(text(at(v, &["SicilNo"])), text(at(v, &["EPosta"])))?
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-156 m.3 (q)
    #[test]
    fn dates_come_as_days() {
        assert_eq!(civil(0), "1970-01-01");
        assert_eq!(civil(20_788), "2026-12-01");
        assert_eq!(
            odata_date(&Value::from("/Date(1796083200000)/")).as_deref(),
            Some("2026-12-01")
        );
        assert_eq!(date(&Value::from("0000-00-00")), None);
        assert_eq!(
            date(&Value::from("2026-12-01T00:00:00+01:00")).as_deref(),
            Some("2026-12-01")
        );
        assert_eq!(Vendor::parse("kolayik"), Some(Vendor::KolayIk));
        assert_eq!(Vendor::parse("spreadsheet"), None);
    }
}
