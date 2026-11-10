//! What a client sends back, checked against the step it was given: a field or method the
//! step did not offer is refused (TN-106 rule 4). The contract is not a security boundary;
//! this check only keeps clients honest about its shape.

use core::fmt;
use std::collections::BTreeMap;

use serde::Deserialize;
use zeroize::Zeroize;

use super::flow::Ui;
use super::node::{FieldName, Method, Node};

/// A submitted value. `Debug` does not print it; it is wiped on drop.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct FieldValue(String);

impl FieldValue {
    /// Wraps a value.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// The value.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for FieldValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FieldValue(..)")
    }
}

impl Drop for FieldValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The request body of `POST /v1/login/flows/{flow}`.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    /// The method, as named by a node of the step.
    pub method: Method,
    /// Field values by name.
    #[serde(default)]
    pub fields: BTreeMap<String, FieldValue>,
}

/// A submission that matches its step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checked {
    /// The method.
    pub method: Method,
    /// Field values.
    pub fields: BTreeMap<FieldName, FieldValue>,
}

impl Checked {
    /// A field's value.
    #[must_use]
    pub fn get(&self, name: FieldName) -> Option<&str> {
        self.fields.get(&name).map(FieldValue::expose)
    }
}

/// Why a submission does not match its step. Answered as one RFC 9457 problem; the detail
/// stays in logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SubmissionError {
    /// The step offers no such method.
    #[error("method not offered by this step")]
    Method,
    /// A field the step did not offer for this method, a read-only field, or an unknown name.
    #[error("field not offered by this step")]
    Field,
    /// A required field is missing or empty.
    #[error("required field {0:?} missing")]
    Missing(FieldName),
    /// A value is longer than its limit.
    #[error("field {0:?} too long")]
    TooLong(FieldName),
}

/// The RFC 9457 problem for a refused submission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Problem {
    /// HTTP status.
    pub status: u16,
    /// Problem type suffix.
    pub code: &'static str,
    /// Title.
    pub title: &'static str,
}

impl SubmissionError {
    /// One answer for every shape error.
    #[must_use]
    pub const fn problem(self) -> Problem {
        Problem {
            status: 400,
            code: "invalid-submission",
            title: "The submission does not match the sign-in step",
        }
    }
}

fn implicit(method: Method) -> Option<FieldName> {
    match method {
        Method::Passkey | Method::PasskeyRegister => Some(FieldName::PasskeyCredential),
        _ => None,
    }
}

impl Ui {
    /// Checks a submission against this step.
    ///
    /// # Errors
    ///
    /// [`SubmissionError`] when the method or a field was not offered, a required field is
    /// empty, or a value is too long.
    pub fn check(&self, submission: Submission) -> Result<Checked, SubmissionError> {
        let method = submission.method;
        if !self.nodes.iter().any(|n| n.method() == Some(method)) {
            return Err(SubmissionError::Method);
        }
        let mut offered: Vec<(FieldName, bool, u32)> = self
            .nodes
            .iter()
            .filter_map(|n| match n {
                Node::Input {
                    name,
                    method: m,
                    required,
                    max_length,
                    read_only: false,
                    ..
                } if *m == method => Some((*name, *required, *max_length)),
                // TN-36
                Node::Option { name, .. } => Some((*name, false, name.max_length())),
                _ => None,
            })
            .collect();
        if let Some(name) = implicit(method) {
            offered.push((name, true, name.max_length()));
        }
        let mut fields = BTreeMap::new();
        for (raw, value) in submission.fields {
            let name = FieldName::parse(&raw).ok_or(SubmissionError::Field)?;
            let &(_, _, max) = offered
                .iter()
                .find(|(n, _, _)| *n == name)
                .ok_or(SubmissionError::Field)?;
            let len = value.expose().chars().count();
            if u32::try_from(len).map_or(true, |l| l > max) {
                return Err(SubmissionError::TooLong(name));
            }
            fields.insert(name, value);
        }
        for (name, required, _) in offered {
            let empty = fields.get(&name).is_none_or(|v| v.expose().is_empty());
            if required && empty {
                return Err(SubmissionError::Missing(name));
            }
        }
        Ok(Checked { method, fields })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::domain::flow::{FlowId, SecondFactors};
    use crate::domain::node::PasskeyOptions;

    fn options() -> PasskeyOptions {
        PasskeyOptions::new(json!({ "challenge": "AAAA", "allowCredentials": [] })).unwrap()
    }

    fn flow() -> FlowId {
        FlowId::parse("lgf_01").unwrap()
    }

    fn submit(body: serde_json::Value) -> Submission {
        serde_json::from_value(body).unwrap()
    }

    // TN-106
    #[test]
    fn offered_fields_pass() {
        let ui = Ui::authenticate(flow(), "ada", options(), &[]);
        let ok = ui
            .check(submit(
                json!({"method": "password", "fields": {"password": "hunter2hunter2"}}),
            ))
            .unwrap();
        assert_eq!(ok.method, Method::Password);
        assert_eq!(ok.get(FieldName::Password), Some("hunter2hunter2"));
        let passkey = ui
            .check(submit(
                json!({"method": "passkey", "fields": {"passkey_credential": "{}"}}),
            ))
            .unwrap();
        assert_eq!(passkey.get(FieldName::PasskeyCredential), Some("{}"));
        assert!(ui.check(submit(json!({"method": "restart"}))).is_ok());
    }

    // TN-106
    #[test]
    fn fabricated_fields_and_methods_are_refused() {
        let ui = Ui::authenticate(flow(), "ada", options(), &[]);
        let refused = |body| ui.check(submit(body)).unwrap_err();
        assert_eq!(
            refused(json!({"method": "totp", "fields": {"totp_code": "123456"}})),
            SubmissionError::Method
        );
        assert_eq!(
            refused(json!({"method": "password", "fields": {"password": "x", "role": "admin"}})),
            SubmissionError::Field
        );
        assert_eq!(
            refused(
                json!({"method": "password", "fields": {"password": "x", "identifier": "eve"}})
            ),
            SubmissionError::Field
        );
        assert_eq!(
            refused(json!({"method": "restart", "fields": {"identifier": "eve"}})),
            SubmissionError::Field
        );
        assert_eq!(
            refused(json!({"method": "password", "fields": {"password": ""}})),
            SubmissionError::Missing(FieldName::Password)
        );
        assert_eq!(
            refused(json!({"method": "password", "fields": {"password": "p".repeat(129)}})),
            SubmissionError::TooLong(FieldName::Password)
        );
        assert!(
            serde_json::from_value::<Submission>(json!({"method": "password", "script": "x"}))
                .is_err()
        );
        assert!(serde_json::from_value::<Submission>(json!({"method": "eval"})).is_err());
    }

    // TN-106
    #[test]
    fn second_factor_fields_belong_to_their_method() {
        let ui = Ui::second_factor(
            flow(),
            SecondFactors {
                totp: true,
                recovery_code: false,
                passkey: false,
                push: false,
            },
            None,
            &[],
        );
        assert!(
            ui.check(submit(
                json!({"method": "totp", "fields": {"totp_code": "123456"}})
            ))
            .is_ok()
        );
        assert_eq!(
            ui.check(submit(
                json!({"method": "recovery_code", "fields": {"recovery_code": "a"}})
            ))
            .unwrap_err(),
            SubmissionError::Method
        );
        assert_eq!(SubmissionError::Field.problem().status, 400);
    }

    // TN-36, X33
    #[test]
    fn options_go_with_every_method_of_their_step() {
        let mut ui = Ui::authenticate(flow(), "ada", options(), &[]);
        ui.nodes.push(Node::Option {
            name: FieldName::KeepSignedIn,
            label: crate::domain::message::TextId::KeepSignedInLabel.into(),
            checked: false,
        });
        let ok = ui
            .check(submit(json!({"method": "password",
                "fields": {"password": "hunter2hunter2", "keep_signed_in": "true"}})))
            .unwrap();
        assert_eq!(ok.get(FieldName::KeepSignedIn), Some("true"));
        assert!(
            ui.check(submit(json!({"method": "restart",
            "fields": {"keep_signed_in": "true"}})))
                .is_ok()
        );
        assert_eq!(
            ui.check(submit(json!({"method": "password",
                "fields": {"password": "x", "remember_device": "true"}})))
                .unwrap_err(),
            SubmissionError::Field
        );
    }

    // OP-64
    #[test]
    fn values_do_not_print() {
        let v = FieldValue::new("hunter2".into());
        assert_eq!(format!("{v:?}"), "FieldValue(..)");
        let s = submit(json!({"method": "password", "fields": {"password": "hunter2"}}));
        assert!(!format!("{s:?}").contains("hunter2"));
    }
}
